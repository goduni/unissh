//! Windows: session lock/unlock over WTS, and suspend over the power broadcast.
//!
//! Both arrive as window messages, so the listener needs a window to receive
//! them — Tauri's own is not usable for it, because we would have to subclass a
//! window proc that wry owns and that already carries the webview's own message
//! handling. Instead this owns a hidden top-level window of its own on a
//! dedicated thread: nothing is ever drawn in it, `WS_EX_TOOLWINDOW` keeps it
//! out of the taskbar and out of Alt+Tab, and it is never shown.
//!
//! It is a *top-level* window rather than the cheaper message-only kind on
//! purpose: `WM_POWERBROADCAST` is broadcast to top-level windows, and a
//! message-only window is not one of those and would never see a suspend.
//! `RegisterSuspendResumeNotification` asks for the same notification
//! explicitly on top of that, because the broadcast alone is not something the
//! documentation promises every app; where both arrive, the second is swallowed
//! by the grace module's "a lock is already owed" state.
//!
//! Win+L, the lock screen after a screensaver and a fast-user-switch away all
//! surface as `WTS_SESSION_LOCK` for this session, which is exactly the set we
//! want: each one means the desk is empty.

use std::sync::OnceLock;

use tauri::AppHandle;
use windows_sys::core::w;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Power::RegisterSuspendResumeNotification;
use windows_sys::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
    TranslateMessage, CW_USEDEFAULT, DEVICE_NOTIFY_WINDOW_HANDLE, MSG, PBT_APMSUSPEND,
    WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDCLASSW, WS_EX_TOOLWINDOW, WS_OVERLAPPED,
    WTS_SESSION_LOCK, WTS_SESSION_UNLOCK,
};

use super::{emit, SystemLockSignal};

/// The window proc is a bare `extern "system" fn` with nowhere to put a captured
/// handle, and there is exactly one app to notify, so it reads it from here.
/// Set before the window exists, so no message can arrive first.
static APP: OnceLock<AppHandle> = OnceLock::new();

pub fn start(app: &AppHandle) {
    if APP.set(app.clone()).is_err() {
        return; // already started
    }
    let spawned = std::thread::Builder::new()
        .name("system-lock".to_string())
        .spawn(|| unsafe { run() });
    if let Err(e) = spawned {
        log::warn!("system-lock: could not start the listener thread ({e})");
    }
}

/// Create the window, subscribe, and pump messages until the process ends.
///
/// # Safety
/// Runs on its own thread and touches only the window it created itself.
unsafe fn run() {
    let instance = GetModuleHandleW(std::ptr::null());
    let class = WNDCLASSW {
        lpfnWndProc: Some(wnd_proc),
        hInstance: instance,
        // Distinct enough that no other window class can collide with it.
        lpszClassName: w!("UniSSHSystemLock"),
        ..Default::default()
    };
    // A zero atom means the class could not be registered; CreateWindowExW
    // below would then fail too, so let that be the single place we give up.
    RegisterClassW(&class);

    let hwnd = CreateWindowExW(
        WS_EX_TOOLWINDOW,
        w!("UniSSHSystemLock"),
        std::ptr::null(),
        WS_OVERLAPPED, // never shown: no WS_VISIBLE
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        0,
        0,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        instance,
        std::ptr::null(),
    );
    if hwnd.is_null() {
        log::warn!("system-lock: could not create the listener window; not watching");
        return;
    }

    if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) == 0 {
        // Terminal Services not running, or the call was refused. Suspend still
        // works; only lock/unlock is lost.
        log::info!("system-lock: no session lock notifications on this machine");
    }
    if RegisterSuspendResumeNotification(hwnd as _, DEVICE_NOTIFY_WINDOW_HANDLE) == 0 {
        log::info!("system-lock: relying on the power broadcast alone for suspend");
    }

    let mut msg = MSG::default();
    // GetMessageW returns 0 on WM_QUIT and -1 on error; both end the loop.
    while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if let Some(app) = APP.get() {
        match msg {
            WM_WTSSESSION_CHANGE => match wparam as u32 {
                WTS_SESSION_LOCK => emit(app, SystemLockSignal::ScreenLock),
                WTS_SESSION_UNLOCK => emit(app, SystemLockSignal::ScreenUnlock),
                _ => {}
            },
            // Only the "we are going down" event matters. A resume finds the
            // vault already locked and has nothing to add.
            WM_POWERBROADCAST if wparam as u32 == PBT_APMSUSPEND => {
                emit(app, SystemLockSignal::Suspend);
            }
            _ => {}
        }
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}
