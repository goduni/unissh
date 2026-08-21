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
//! observer API — only the selector-based call accepts the behaviour. It
//! matters here more than anywhere else it could: an AppKit application's
//! distributed centre is suspended while the app is not active, and under the
//! default `Coalesce` a suspended centre *holds* the notification until the app
//! comes forward again. Our app is by definition not the front app when the
//! screen locks, so the default would deliver "the screen locked" at the exact
//! moment the user is already back — the one moment it is worthless.
//!
//! Notification centres do not retain selector-based observers, so the observer
//! is deliberately leaked: it must outlive every notification, which is to say
//! the process.

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
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
);

impl LockObserver {
    fn new(app: AppHandle) -> Retained<Self> {
        let this = Self::alloc().set_ivars(Ivars { app });
        unsafe { msg_send![super(this), init] }
    }
}

pub fn start(app: &AppHandle) {
    let observer = LockObserver::new(app.clone());

    // SAFETY: the selectors below are the ones this class implements, and the
    // observer outlives every notification (it is leaked at the end).
    unsafe {
        let distributed = NSDistributedNotificationCenter::defaultCenter();
        for (name, selector) in [
            ("com.apple.screenIsLocked", sel!(unisshScreenIsLocked:)),
            ("com.apple.screenIsUnlocked", sel!(unisshScreenIsUnlocked:)),
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
                sel!(unisshWillSleep:),
                Some(NSWorkspaceWillSleepNotification),
                None,
            );
    }

    // Registered, and never unregistered: see the module docs.
    std::mem::forget(observer);
}
