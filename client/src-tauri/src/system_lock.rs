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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Mutex;
use std::time::Duration;

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
#[serde(rename_all = "camelCase")]
struct SystemLockEvent {
    signal: SystemLockSignal,
    /// Present only on a suspend, and only to be handed straight back to
    /// `system_lock_ack`. See [`ack`] for why it is not enough to just say
    /// "done".
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<u64>,
}

/// Push one signal at the front end. Failure is not propagated — there may be no
/// window left to tell (shutdown, a dead webview), and a lock nobody can act on
/// is not worth tearing anything down over.
fn emit(app: &AppHandle, signal: SystemLockSignal) {
    emit_with_token(app, signal, None);
}

fn emit_with_token(app: &AppHandle, signal: SystemLockSignal, token: Option<u64>) {
    log::info!("system-lock: {signal:?}");
    let _ = app.emit("system-lock", SystemLockEvent { signal, token });
}

/// How long a suspend may be held open while the front end shuts the vault.
///
/// Each OS states its own allowance and neither is ours to exceed, so this is
/// per-platform rather than one number that happens to suit one of them:
///
/// * **Linux** — logind's `InhibitDelayMaxSec` defaults to 5s. A delay
///   inhibitor held past it is overridden and the machine sleeps anyway, with a
///   warning in the journal.
/// * **Windows** — the `PBT_APMSUSPEND` documentation is explicit: "The system
///   allows approximately two seconds for an application to handle this
///   notification. If an application is still performing operations after its
///   time allotment has expired, the system may interrupt the application."
///   Staying inside it means we hand back of our own accord instead of being
///   cut off mid-hand-off.
///
/// Locking is a handful of milliseconds when the webview is responsive, so
/// either way this is the bound on a pathological case, not a budget anything
/// is expected to spend. macOS has no entry here because it cannot hold a
/// suspend open at all — see `macos.rs`.
#[cfg(target_os = "linux")]
const SUSPEND_GRACE: Duration = Duration::from_secs(3);
#[cfg(target_os = "windows")]
const SUSPEND_GRACE: Duration = Duration::from_millis(1_500);

#[cfg(any(target_os = "linux", target_os = "windows"))]
/// The hand-off currently open, if any: which suspend it belongs to, and how to
/// release it.
static SUSPEND_ACK: Mutex<Option<(u64, SyncSender<()>)>> = Mutex::new(None);

#[cfg(any(target_os = "linux", target_os = "windows"))]
/// Names each suspend hand-off. Only ever incremented.
static NEXT_SUSPEND: AtomicU64 = AtomicU64::new(1);

#[cfg(any(target_os = "linux", target_os = "windows"))]
/// Announce a suspend and wait, bounded, for the front end to say the vault is
/// shut — then let the caller release whatever is holding the machine awake.
///
/// This is the whole difference between "we asked" and "it happened". Without
/// it the event is posted at a webview that is about to lose its CPU, and the
/// machine can perfectly well suspend with the keys still in memory, which is
/// the exact thing this feature exists to prevent.
///
/// The front end acks whether or not it locked, so a user who turned the
/// feature off does not pay for a suspend that waits.
fn emit_suspend_and_wait(app: &AppHandle) {
    let (token, rx) = arm_suspend_ack();
    emit_with_token(app, SystemLockSignal::Suspend, Some(token));
    wait_suspend_ack(rx, SUSPEND_GRACE);
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
/// Open the hand-off. Must happen BEFORE the emit: an ack that arrives first
/// would otherwise find nothing to notify and the wait would run its full
/// course with the work already done.
fn arm_suspend_ack() -> (u64, Receiver<()>) {
    let token = NEXT_SUSPEND.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = sync_channel(1);
    *SUSPEND_ACK.lock().expect("suspend ack") = Some((token, tx));
    (token, rx)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
/// Wait for the ack, then close the hand-off — so an ack that arrives after the
/// deadline is dropped rather than left to satisfy the *next* suspend.
fn wait_suspend_ack(rx: Receiver<()>, timeout: Duration) {
    if rx.recv_timeout(timeout).is_err() {
        log::warn!("system-lock: no lock confirmation before suspend; going down anyway");
    }
    SUSPEND_ACK.lock().expect("suspend ack").take();
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
/// The front end reporting that it has finished with a suspend signal.
///
/// The token is what makes this safe, and it is not ceremony. An ack is a
/// statement about ONE suspend: if a hand-off gave up waiting and the machine
/// went down, the answer it was waiting for can still arrive later — on resume,
/// from a webview that has finally caught up. An untargeted "done" would then
/// release whatever suspend happens to be open at that moment, which is exactly
/// the moment a vault is still unlocked. So an ack that does not name the
/// hand-off it belongs to is dropped.
pub fn ack(token: u64) {
    let mut slot = SUSPEND_ACK.lock().expect("suspend ack");
    if slot.as_ref().is_some_and(|(open, _)| *open == token) {
        if let Some((_, tx)) = slot.take() {
            let _ = tx.send(());
        }
    }
}

/// macOS cannot hold a suspend open (see `macos.rs`), so it never hands out a
/// token and the front end never acks. Should one arrive anyway, there is
/// nothing waiting on it.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn ack(_token: u64) {}

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

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[cfg(test)]
mod tests {
    use super::*;

    /// One test, start to finish, because the hand-off is a process-global:
    /// split into several the harness would run them in parallel and have them
    /// ack each other.
    #[test]
    fn suspend_hand_off() {
        let quick = Duration::from_millis(200);

        // An ack for a hand-off that was never opened must not panic.
        ack(1);

        // The ordinary case: the front end answers, and the machine is released
        // when it does rather than after the full grace.
        let (token, rx) = arm_suspend_ack();
        let start = std::time::Instant::now();
        std::thread::spawn(move || ack(token));
        wait_suspend_ack(rx, Duration::from_secs(5));
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "an answered suspend waited out the timeout instead of the answer"
        );

        // A webview that never answers must not hold the machine awake past the
        // grace: logind overrides us anyway, and a laptop that will not sleep is
        // worse than a vault that locked late.
        let (abandoned, rx) = arm_suspend_ack();
        let start = std::time::Instant::now();
        wait_suspend_ack(rx, quick);
        assert!(start.elapsed() >= quick, "the wait did not wait");

        // THE ONE THAT MATTERS. The next suspend opens, and only then does the
        // abandoned one's answer finally turn up — from a webview catching up
        // after the resume. It is about a suspend that is over, so it must not
        // release this one, whose vault may still be wide open.
        let (_current, rx) = arm_suspend_ack();
        let start = std::time::Instant::now();
        ack(abandoned);
        wait_suspend_ack(rx, quick);
        assert!(
            start.elapsed() >= quick,
            "a stale ack released the following suspend"
        );
    }
}
