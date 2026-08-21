//! macOS: the screen-lock distributed notification, and the workspace's
//! will-sleep notification.
//!
//! `com.apple.screenIsLocked` / `com.apple.screenIsUnlocked` are posted by
//! loginwindow on the *distributed* notification centre — the system-wide one,
//! not the per-process centre — which is why this is the one place in the app
//! that reaches for `NSDistributedNotificationCenter`. Sleep is a different
//! centre again: `NSWorkspace` posts `NSWorkspaceWillSleepNotification` on its
//! own, and posts it *before* the machine goes down, which is the only reason
//! locking on sleep is possible at all.
//!
//! The distributed observers are registered with an explicit suspension
//! behaviour of `DeliverImmediately`, and that is the whole reason this file
//! defines an Objective-C class instead of taking the tidier block-based
//! observer API — only the selector-based call accepts the behaviour. A
//! distributed centre can be suspended, and the default `Coalesce` behaviour
//! *holds* notifications while it is, delivering them when it resumes. Every
//! notification this file cares about arrives while the app is in the
//! background by definition, so that is the one delivery mode that would be
//! useless: "the screen locked" is worth nothing if it arrives when the user is
//! already back. Asking for immediate delivery costs nothing and removes the
//! question of when, exactly, AppKit decides to suspend the centre.
//!
//! Notification centres do not retain selector-based observers, so the observer
//! is deliberately leaked: it must outlive every notification, which is to say
//! the process.
//!
//! **Sleep here is best-effort, unlike the other two desktops.** Linux holds a
//! logind delay inhibitor and Windows blocks its own message loop, so both wait
//! for the front end to confirm the vault is shut. Neither trick is available
//! on macOS: the will-sleep notification is delivered on the main thread, and
//! blocking there would starve the very webview that has to do the locking. In
//! practice the machine takes long enough to go down that the lock lands, but
//! it is not a guarantee, and `IORegisterForSystemPower` (whose callback can be
//! taken on a thread of our own, with `IOAllowPowerChange` deferred) is the
//! documented way to make it one if a device test shows it is needed.

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol};
use objc2::{define_class, msg_send, sel, AnyThread, DefinedClass};
use objc2_app_kit::{NSWorkspace, NSWorkspaceWillSleepNotification};
use objc2_foundation::{
    NSDistributedNotificationCenter, NSNotificationSuspensionBehavior, NSString,
};
use tauri::AppHandle;

use super::{emit, SystemLockSignal};

struct Ivars {
    app: AppHandle,
}

define_class!(
    // SAFETY:
    // - `NSObject` imposes no subclassing requirements.
    // - The only ivar is an `AppHandle`, which is `Send + Sync`.
    // - `LockObserver` does not implement `Drop`.
    #[unsafe(super(NSObject))]
    #[ivars = Ivars]
    struct LockObserver;

    impl LockObserver {
        #[unsafe(method(unisshScreenIsLocked:))]
        fn screen_is_locked(&self, _notification: *mut AnyObject) {
            emit(&self.ivars().app, SystemLockSignal::ScreenLock);
        }

        #[unsafe(method(unisshScreenIsUnlocked:))]
        fn screen_is_unlocked(&self, _notification: *mut AnyObject) {
            emit(&self.ivars().app, SystemLockSignal::ScreenUnlock);
        }

        #[unsafe(method(unisshWillSleep:))]
        fn will_sleep(&self, _notification: *mut AnyObject) {
            emit(&self.ivars().app, SystemLockSignal::Suspend);
        }
    }

    // For `respondsToSelector:` in `start` — the guard that keeps a missing
    // method from becoming an exception raised inside a notification.
    unsafe impl NSObjectProtocol for LockObserver {}
);

impl LockObserver {
    fn new(app: AppHandle) -> Retained<Self> {
        let this = Self::alloc().set_ivars(Ivars { app });
        unsafe { msg_send![super(this), init] }
    }
}

pub fn start(app: &AppHandle) {
    let observer = LockObserver::new(app.clone());

    // Registering a selector the observer does not answer to is not a quiet
    // mistake: it is an unrecognised-selector exception raised inside the
    // notification, i.e. a crash at the exact moment the user locks the screen.
    // The class is defined right above, so this should never fire — but "should
    // never" is worth one branch when the alternative is that failure mode, and
    // the same probe already guards the Tahoe metrics call in lib.rs.
    let selectors = [
        sel!(unisshScreenIsLocked:),
        sel!(unisshScreenIsUnlocked:),
        sel!(unisshWillSleep:),
    ];
    if !selectors.iter().all(|s| observer.respondsToSelector(*s)) {
        log::warn!("system-lock: observer is missing its selectors; not watching");
        return;
    }

    // SAFETY: the selectors are the ones this class implements (just checked),
    // and the observer outlives every notification (it is leaked at the end).
    unsafe {
        let distributed = NSDistributedNotificationCenter::defaultCenter();
        for (name, selector) in [
            ("com.apple.screenIsLocked", selectors[0]),
            ("com.apple.screenIsUnlocked", selectors[1]),
        ] {
            distributed.addObserver_selector_name_object_suspensionBehavior(
                &observer,
                selector,
                Some(&NSString::from_str(name)),
                None,
                NSNotificationSuspensionBehavior::DeliverImmediately,
            );
        }

        // The workspace centre is a plain in-process one: no suspension, and no
        // string to spell — AppKit exports the name.
        NSWorkspace::sharedWorkspace()
            .notificationCenter()
            .addObserver_selector_name_object(
                &observer,
                selectors[2],
                Some(NSWorkspaceWillSleepNotification),
                None,
            );
    }

    // Registered, and never unregistered: see the module docs.
    std::mem::forget(observer);
}
