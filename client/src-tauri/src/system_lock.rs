//! Locking the vault when the *operating system* says the user left.
//!
//! Auto-lock only ever watched this window. A screen lock — the single clearest
//! "I am leaving" anyone gives a computer — did nothing, and closing the lid
//! suspended the machine with the vault open and an idle timer that does not
//! tick while asleep. This module is the missing half: a small native listener
//! per desktop, each of which emits one application event.
//!
//! Everything past the emit lives in the front end. The Rust side never touches
//! vault state; the event is routed into the same `lockInstance()` the lock
//! button and the idle timer call, so there stays exactly one place where
//! zeroize can be got wrong. The grace period, the dedup, the "already locked"
//! guard and the setting are all decided there too (`support/systemLock.ts`) —
//! which is why this file reports what happened and nothing else.
//!
//! **Emitting is best-effort**, following the precedent of the auth-prompt and
//! agent-approval observers: a listener that cannot be registered logs and
//! leaves the app running exactly as it ran before this feature existed. There
//! are real desktops that emit neither signal, and "your setup is not one we can
//! detect" has to degrade to today's behaviour rather than to a broken app.
//!
//! Mobile is untouched. Nothing here is compiled for iOS or Android: app
//! backgrounding on a phone is a different question with a different answer.

use serde::Serialize;
use tauri::{AppHandle, Emitter};

/// What the OS told us. Serialised in kebab-case to match the TypeScript
/// `SystemLockSignal` union verbatim.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemLockSignal {
    /// The session locked (screen lock, lid-close lock, screensaver).
    ScreenLock,
    /// The session unlocked again — the user is back. Cancels a pending lock.
    ScreenUnlock,
    /// The machine is going to sleep. Never graced: it is going down now.
    Suspend,
}

#[derive(Clone, Serialize)]
struct SystemLockEvent {
    signal: SystemLockSignal,
}

/// Push one signal at the front end. Failure is not propagated — there may be no
/// window left to tell (shutdown, a dead webview), and a lock nobody can act on
/// is not worth tearing anything down over.
fn emit(app: &AppHandle, signal: SystemLockSignal) {
    log::info!("system-lock: {signal:?}");
    let _ = app.emit("system-lock", SystemLockEvent { signal });
}

#[cfg(target_os = "macos")]
#[path = "system_lock/macos.rs"]
mod imp;

#[cfg(target_os = "windows")]
#[path = "system_lock/windows.rs"]
mod imp;

#[cfg(target_os = "linux")]
#[path = "system_lock/linux.rs"]
mod imp;

/// Desktops we have no listener for, and both mobile targets.
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
mod imp {
    pub fn start(_app: &tauri::AppHandle) {}
}

/// Register the platform listeners. Call once, from `setup`.
pub fn start(app: &AppHandle) {
    imp::start(app);
}
