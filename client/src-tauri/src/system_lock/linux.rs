//! Linux: logind first, the desktop's own screensaver as a fallback.
//!
//! Neither source is enough on its own. `org.freedesktop.login1` is the one
//! place a *suspend* is announced before it happens (`PrepareForSleep`), and it
//! is also where a session `Lock`/`Unlock` shows up on a system that routes
//! locking through logind — but plenty of desktops lock their screen without
//! ever telling logind. GNOME and KDE both announce it on the session bus
//! instead, as `ActiveChanged` on their screensaver interface.
//!
//! So we listen to both and make no attempt to work out which desktop is in
//! play. Where both fire for one lock, the second announcement is swallowed by
//! the grace module's "a lock is already owed" state — that is what makes the
//! doubling harmless, and it is why this file does not try to pick a winner.
//!
//! Two threads, one per bus, each blocking on its own message stream. Any
//! failure — no D-Bus at all, no logind, no session bus — logs once and ends
//! that thread; the app then behaves exactly as it did before this feature.

use tauri::AppHandle;
use zbus::blocking::{fdo::DBusProxy, Connection, MessageIterator};
use zbus::message::Type;
use zbus::zvariant::OwnedObjectPath;
use zbus::MatchRule;

use super::{emit, SystemLockSignal};

const LOGIND: &str = "org.freedesktop.login1";
const LOGIND_MANAGER: &str = "org.freedesktop.login1.Manager";
const LOGIND_SESSION: &str = "org.freedesktop.login1.Session";

/// The screensaver interfaces worth asking about. GNOME's own name and the
/// freedesktop one KDE (and most of the rest) implement. Matching by interface
/// rather than by owner is deliberate: the rule is accepted whether or not
/// anything currently provides the interface, so a desktop that starts its
/// screensaver later is still heard.
const SCREENSAVERS: [&str; 3] = [
    "org.gnome.ScreenSaver",
    "org.freedesktop.ScreenSaver",
    "org.kde.screensaver",
];

pub fn start(app: &AppHandle) {
    spawn("system-lock-logind", app.clone(), watch_logind);
    spawn("system-lock-screensaver", app.clone(), watch_screensaver);
}

fn spawn(name: &'static str, app: AppHandle, run: fn(&AppHandle) -> zbus::Result<()>) {
    let spawned = std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            if let Err(e) = run(&app) {
                // Info, not warn: a container, a bare X session or a desktop
                // with no screensaver service is a legitimate environment, and
                // this is a feature degrading, not a fault.
                log::info!("{name}: not watching ({e})");
            }
        });
    if let Err(e) = spawned {
        log::warn!("{name}: could not start the listener thread ({e})");
    }
}

/// System bus: `PrepareForSleep` from the manager, `Lock`/`Unlock` from our own
/// session object.
fn watch_logind(app: &AppHandle) -> zbus::Result<()> {
    let bus = Connection::system()?;
    let dbus = DBusProxy::new(&bus)?;

    // Suspend first, and unconditionally: it is the half that has no fallback
    // anywhere else, so it must survive a session lookup that fails.
    dbus.add_match_rule(
        MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(LOGIND)?
            .interface(LOGIND_MANAGER)?
            .member("PrepareForSleep")?
            .build(),
    )?;

    // Scope the lock signals to THIS session. Without the path filter we would
    // also hear another logged-in user's screen lock, which is none of our
    // business and would zeroize a vault whose owner never left.
    match session_path(&bus) {
        Ok(path) => {
            let rule = MatchRule::builder()
                .msg_type(Type::Signal)
                .sender(LOGIND)?
                .path(path.as_ref())?
                .interface(LOGIND_SESSION)?
                .build();
            if let Err(e) = dbus.add_match_rule(rule) {
                log::info!("system-lock-logind: no session lock signals ({e})");
            }
        }
        // Not fatal: the screensaver listener covers locking on most desktops,
        // and `PrepareForSleep` above is already subscribed.
        Err(e) => log::info!("system-lock-logind: no session object ({e})"),
    }

    for msg in MessageIterator::from(bus) {
        let msg = msg?;
        let header = msg.header();
        let Some(member) = header.member() else {
            continue;
        };
        match member.as_str() {
            "PrepareForSleep" => {
                // `true` = going down, `false` = coming back. Only the first is
                // a reason to lock; a resume finds the vault already locked and
                // has nothing to say.
                if msg.body().deserialize::<bool>().unwrap_or(false) {
                    emit(app, SystemLockSignal::Suspend);
                }
            }
            "Lock" => emit(app, SystemLockSignal::ScreenLock),
            "Unlock" => emit(app, SystemLockSignal::ScreenUnlock),
            _ => {}
        }
    }
    Ok(())
}

/// Our logind session object path, resolved from this process's PID.
fn session_path(bus: &Connection) -> zbus::Result<OwnedObjectPath> {
    bus.call_method(
        Some(LOGIND),
        "/org/freedesktop/login1",
        Some(LOGIND_MANAGER),
        "GetSessionByPID",
        &(std::process::id()),
    )?
    .body()
    .deserialize()
}

/// Session bus: `ActiveChanged(bool)` from whichever screensaver is there.
fn watch_screensaver(app: &AppHandle) -> zbus::Result<()> {
    let bus = Connection::session()?;
    let dbus = DBusProxy::new(&bus)?;
    let mut watching = 0usize;
    for interface in SCREENSAVERS {
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .interface(interface)?
            .member("ActiveChanged")?
            .build();
        match dbus.add_match_rule(rule) {
            Ok(()) => watching += 1,
            Err(e) => log::info!("system-lock-screensaver: {interface} unavailable ({e})"),
        }
    }
    if watching == 0 {
        return Ok(()); // nothing to wait for; don't park a thread on it
    }

    for msg in MessageIterator::from(bus) {
        let msg = msg?;
        let header = msg.header();
        match header.member() {
            Some(m) if m.as_str() == "ActiveChanged" => {}
            _ => continue,
        }
        // Active = the screensaver/lock screen is up.
        let active: bool = msg.body().deserialize().unwrap_or(false);
        emit(
            app,
            if active {
                SystemLockSignal::ScreenLock
            } else {
                SystemLockSignal::ScreenUnlock
            },
        );
    }
    Ok(())
}
