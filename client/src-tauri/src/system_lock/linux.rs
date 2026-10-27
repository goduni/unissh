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
//! Sleep needs one more thing than a subscription. `PrepareForSleep(true)` is
//! not a warning, it is a starting gun: logind emits it only *after* every
//! delay inhibitor has been released, and then suspends. Merely hearing it and
//! posting an event at a webview that is about to lose its CPU would let the
//! machine go down with the keys still in memory — the exact thing this feature
//! exists to prevent. So we hold a `delay` inhibitor of our own, and let go of
//! it only once the front end confirms the vault is shut (or the bounded wait
//! runs out). The inhibitor is retaken on resume, ready for the next one.
//!
//! Only logind is heard on the system bus: `unissh_automation::logind` (shared
//! with `unissh mcp`) drops any signal that does not come from the current
//! owner of `org.freedesktop.login1` on its own objects. A match rule alone is
//! no filter, since any local user may unicast a signal to our unique name: an
//! `Unlock` from anyone would otherwise resume agent access.
//!
//! Two threads, one per bus, each blocking on its own message stream. Any
//! failure — no D-Bus at all, no logind, no session bus — logs once and ends
//! that thread; the app then behaves exactly as it did before this feature.

use tauri::AppHandle;
use unissh_automation::logind::{
    Header, Heard, Logind, LOGIND, MANAGER, MANAGER_PATH, PROPERTIES, SESSION,
};
use zbus::blocking::{fdo::DBusProxy, Connection, MessageIterator};
use zbus::message::Type;
use zbus::names::{BusName, InterfaceName, MemberName, UniqueName};
use zbus::zvariant::{ObjectPath, OwnedFd, OwnedObjectPath, OwnedValue};
use zbus::MatchRule;

use super::{emit, emit_suspend_and_wait, SystemLockSignal};

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
        .name(name.to_owned())
        .spawn(move || {
            if let Err(e) = run(&app) {
                // The screensaver at info: a bare X session or a desktop with
                // no screensaver service is a legitimate environment. logind
                // at warn: without it a sleep no longer locks the vault, and
                // whoever relies on that should be able to see it.
                if name == "system-lock-logind" {
                    log::warn!("{name}: not watching ({e})");
                } else {
                    log::info!("{name}: not watching ({e})");
                }
            }
        });
    if let Err(e) = spawned {
        log::warn!("{name}: could not start the listener thread ({e})");
    }
}

/// System bus: `PrepareForSleep` from the manager, `Lock`/`Unlock` from our own
/// session object, all from logind's current owner only.
fn watch_logind(app: &AppHandle) -> zbus::Result<()> {
    let bus = Connection::system()?;
    // Before anything is asked, so that nothing said after it is missed.
    let messages = MessageIterator::from(&bus);
    let dbus = DBusProxy::new(&bus)?;

    // Who owns logind's name, and every change of it, from the bus itself.
    dbus.add_match_rule(
        MatchRule::builder()
            .msg_type(Type::Signal)
            .sender("org.freedesktop.DBus")?
            .interface("org.freedesktop.DBus")?
            .member("NameOwnerChanged")?
            .add_arg(LOGIND)?
            .build(),
    )?;
    // Suspend first, and unconditionally: it is the half that has no fallback
    // anywhere else, so it must survive a session lookup that fails.
    dbus.add_match_rule(
        MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(LOGIND)?
            .path(MANAGER_PATH)?
            .interface(MANAGER)?
            .member("PrepareForSleep")?
            .build(),
    )?;
    let owner = dbus
        .get_name_owner(BusName::from_static_str(LOGIND)?)?
        .as_str()
        .to_owned();

    // Held from now until the machine actually goes down, then retaken on the
    // way back up. A failure here is not fatal: we still hear the signal and
    // still ask for a lock, we just cannot promise it finishes first.
    let mut inhibitor = match take_sleep_inhibitor(&bus) {
        Ok(fd) => Some(fd),
        Err(e) => {
            log::warn!("system-lock-logind: sleep will not wait for the lock ({e})");
            None
        }
    };

    // Scope the lock signals to THIS session. Without the path filter we would
    // also hear another logged-in user's screen lock, which is none of our
    // business and would zeroize a vault whose owner never left.
    let session = match session_path(&bus) {
        Ok(path) => {
            let rule = MatchRule::builder()
                .msg_type(Type::Signal)
                .sender(LOGIND)?
                .path(path.as_ref())?
                .interface(SESSION)?
                .build();
            if let Err(e) = dbus.add_match_rule(rule) {
                log::warn!("system-lock-logind: no session lock signals ({e})");
            }
            Some(path)
        }
        // Not fatal: the screensaver listener covers locking on most desktops,
        // and `PrepareForSleep` above is already subscribed.
        Err(e) => {
            log::warn!("system-lock-logind: no session object ({e})");
            None
        }
    };
    let mut logind = Logind::new(Some(owner), session.as_ref().map(|p| p.as_str().to_owned()));

    for msg in messages {
        let msg = msg?;
        let Some(heard) = logind.heard(&seen(&msg.header())) else {
            continue;
        };
        match heard {
            Heard::OwnerChanged => {
                if let Ok((name, _, new)) = msg.body().deserialize::<(String, String, String)>() {
                    logind.owner_changed(&name, &new);
                }
            }
            Heard::Sleep => {
                // `true` = going down, `false` = coming back.
                if msg.body().deserialize::<bool>().unwrap_or(false) {
                    emit_suspend_and_wait(app);
                    // Only now: dropping the descriptor is what tells logind we
                    // are finished and the machine may sleep.
                    drop(inhibitor.take());
                } else {
                    // A lock screen that came up on the way down without a
                    // word to either listener still keeps agent access paused.
                    let locked = session
                        .as_ref()
                        .is_some_and(|path| locked_hint(&bus, path).unwrap_or(false));
                    if locked {
                        log::info!("system-lock-logind: awake, but the session is locked");
                    } else {
                        super::wake(app);
                    }
                    // Re-arm the inhibitor for the next sleep.
                    inhibitor = take_sleep_inhibitor(&bus).ok();
                }
            }
            Heard::Lock => emit(app, SystemLockSignal::ScreenLock),
            Heard::Unlock => emit(app, SystemLockSignal::ScreenUnlock),
            // Not subscribed here: the screensaver listener follows the lock
            // screen on the session bus.
            Heard::SessionProperties => {}
        }
    }
    log::warn!("system-lock-logind: the system bus closed; no longer watching");
    Ok(())
}

/// The parts of a message's header that decide whether it is logind's.
fn seen<'h>(header: &'h zbus::message::Header<'_>) -> Header<'h> {
    Header {
        signal: header.message_type() == Type::Signal,
        sender: header.sender().map(UniqueName::as_str),
        path: header.path().map(ObjectPath::as_str),
        interface: header.interface().map(InterfaceName::as_str),
        member: header.member().map(MemberName::as_str),
    }
}

/// Whether the session's lock screen is up, as the desktop told logind.
fn locked_hint(bus: &Connection, session: &OwnedObjectPath) -> zbus::Result<bool> {
    let value: OwnedValue = bus
        .call_method(
            Some(LOGIND),
            session.as_str(),
            Some(PROPERTIES),
            "Get",
            &(SESSION, "LockedHint"),
        )?
        .body()
        .deserialize()?;
    Ok(bool::try_from(value)?)
}

/// Take a `delay` inhibitor on sleep. Holding the returned descriptor is what
/// keeps logind waiting; dropping it says "go ahead".
///
/// `delay`, not `block`: we are asking for a moment to finish something, not
/// claiming the right to refuse. logind caps that moment at `InhibitDelayMaxSec`
/// (5s by default) and suspends regardless once it passes, which is the correct
/// outcome — a hung webview must not be able to stop a laptop from sleeping.
fn take_sleep_inhibitor(bus: &Connection) -> zbus::Result<OwnedFd> {
    bus.call_method(
        Some(LOGIND),
        MANAGER_PATH,
        Some(MANAGER),
        "Inhibit",
        &(
            "sleep",
            "UniSSH",
            "Locking the vault before the machine sleeps",
            "delay",
        ),
    )?
    .body()
    .deserialize()
}

/// Our logind session object path, resolved from this process's PID.
fn session_path(bus: &Connection) -> zbus::Result<OwnedObjectPath> {
    bus.call_method(
        Some(LOGIND),
        MANAGER_PATH,
        Some(MANAGER),
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
    let mut watching = 0_usize;
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
