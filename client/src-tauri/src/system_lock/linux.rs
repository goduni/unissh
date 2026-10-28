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
//! The system bus takes two connections, for the reason given in
//! `unissh_automation::logind`: a flood unicast to a connection with an open
//! stream stalls every method reply on it, so one connection only listens
//! (its rules added before its stream opens, nothing asked after) and the other
//! only asks, never streams, and gives up after `CALL_TIMEOUT`. A sleep's
//! vault lock asks the bus nothing; a wake's lock check is bounded, and one
//! that fails leaves agent access paused.
//!
//! Two threads, one per bus, each parked in `zbus::block_on` on its own
//! message stream: zbus has no blocking API, and its own runtime does the work
//! of the connections built on a thread inside that thread's `block_on`. So the
//! sleep's wait for the front end, which blocks the thread, also holds up its
//! connections for that bounded wait: nothing is asked of the bus meanwhile,
//! and what arrives waits in the socket until the stream is read again. Any
//! failure — no D-Bus at all, no logind, no session bus — logs once and ends
//! that thread; the app then behaves exactly as it did before this feature.

use futures_util::StreamExt;
use tauri::AppHandle;
use unissh_automation::logind::{
    display_session, locked_after_wake, Header, Heard, Logind, SessionLookup, WakeCheck,
    CALL_TIMEOUT, LOGIND, MANAGER, MANAGER_PATH, PROPERTIES, SESSION, SESSION_LOOKUPS, USER,
};
use zbus::connection::Builder;
use zbus::message::Type;
use zbus::names::{InterfaceName, MemberName, UniqueName};
use zbus::{
    Connection, MatchRule, MessageStream, ObjectPath, OwnedFd, OwnedObjectPath, OwnedVariant,
};

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
    spawn("system-lock-logind", app.clone(), |app| {
        zbus::block_on(watch_logind(app))
    });
    spawn("system-lock-screensaver", app.clone(), |app| {
        zbus::block_on(watch_screensaver(app))
    });
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
async fn watch_logind(app: &AppHandle) -> zbus::Result<()> {
    // `calls` only asks and `watch` only listens: see the module docs.
    let calls = Builder::system()
        .method_timeout(CALL_TIMEOUT)
        .build()
        .await?;
    let watch = Builder::system()
        .method_timeout(CALL_TIMEOUT)
        .build()
        .await?;

    // Scope the lock signals to THIS session. Without the path filter we would
    // also hear another logged-in user's screen lock, which is none of our
    // business and would zeroize a vault whose owner never left.
    let session = match session_path(&calls).await {
        Ok(path) => Some(path),
        // Not fatal: the screensaver listener covers locking on most desktops,
        // and `PrepareForSleep` below is subscribed regardless.
        Err(e) => {
            log::warn!("system-lock-logind: no session object ({e})");
            None
        }
    };

    subscribe(&watch, session.as_ref()).await?;
    // From here on `watch` is only read; what changes after the questions
    // below is in the stream, what changed before is in their answers.
    let mut messages = MessageStream::from(&watch);
    let owner = name_owner(&calls).await?;

    // Held from now until the machine actually goes down, then retaken on the
    // way back up. A failure here is not fatal: we still hear the signal and
    // still ask for a lock, we just cannot promise it finishes first.
    let mut inhibitor = sleep_inhibitor(&calls).await;
    let mut logind = Logind::new(Some(owner), session.as_ref().map(|p| p.as_str().to_owned()));

    while let Some(msg) = messages.next().await {
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
                    // word to either listener still keeps agent access paused,
                    // and so does a check that fails or times out.
                    let check = wake_check(&calls, session.as_ref()).await;
                    if locked_after_wake(super::is_screen_locked(), check) {
                        log::info!("system-lock-logind: awake; agent access stays paused until the session unlocks");
                    } else {
                        super::wake(app);
                    }
                    // Re-arm the inhibitor for the next sleep.
                    inhibitor = sleep_inhibitor(&calls).await;
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

/// The watch connection's rules: logind's owner, its sleep, and `session`'s
/// lock. Only before the watch stream is open.
async fn subscribe(watch: &Connection, session: Option<&OwnedObjectPath>) -> zbus::Result<()> {
    // Who owns logind's name, and every change of it, from the bus itself.
    add_match(
        watch,
        MatchRule::builder()
            .msg_type(Type::Signal)
            .sender("org.freedesktop.DBus")
            .interface("org.freedesktop.DBus")
            .member("NameOwnerChanged")
            .add_arg(LOGIND)
            .build()?,
    )
    .await?;
    // Suspend unconditionally: it is the half that has no fallback anywhere
    // else, so it must survive a session lookup that failed.
    add_match(
        watch,
        MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(LOGIND)
            .path(MANAGER_PATH)
            .interface(MANAGER)
            .member("PrepareForSleep")
            .build()?,
    )
    .await?;
    if let Some(path) = session {
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(LOGIND)
            .path(path.as_str())
            .interface(SESSION)
            .build()?;
        if let Err(e) = add_match(watch, rule).await {
            log::warn!("system-lock-logind: no session lock signals ({e})");
        }
    }
    Ok(())
}

/// The session's `LockedHint` on waking up; a failure (or a timeout) is
/// `WakeCheck::Failed`, which keeps agent access paused.
async fn wake_check(calls: &Connection, session: Option<&OwnedObjectPath>) -> WakeCheck {
    let Some(path) = session else {
        return WakeCheck::NoSession;
    };
    match locked_hint(calls, path).await {
        Ok(locked) => WakeCheck::Hint(locked),
        Err(e) => {
            log::warn!(
                "system-lock-logind: awake, but the lock state is unknown; agent access stays paused ({e})"
            );
            WakeCheck::Failed
        }
    }
}

/// `take_sleep_inhibitor`, or `None` and a warning.
async fn sleep_inhibitor(calls: &Connection) -> Option<OwnedFd> {
    take_sleep_inhibitor(calls)
        .await
        .inspect_err(|e| {
            log::warn!("system-lock-logind: the next sleep will not wait for the lock ({e})");
        })
        .ok()
}

/// `AddMatch` on `bus`, only ever before its stream is open (on the system
/// bus, that is the watch connection).
async fn add_match(bus: &Connection, rule: MatchRule<'_>) -> zbus::Result<()> {
    bus.call_method(
        Some("org.freedesktop.DBus"),
        "/org/freedesktop/DBus",
        Some("org.freedesktop.DBus"),
        "AddMatch",
        &rule.to_string(),
    )
    .await?;
    Ok(())
}

/// Who owns logind's name now.
async fn name_owner(calls: &Connection) -> zbus::Result<String> {
    calls
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetNameOwner",
            &LOGIND,
        )
        .await?
        .body()
        .deserialize()
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
async fn locked_hint(bus: &Connection, session: &OwnedObjectPath) -> zbus::Result<bool> {
    let value: OwnedVariant = bus
        .call_method(
            Some(LOGIND),
            session.as_str(),
            Some(PROPERTIES),
            "Get",
            &(SESSION, "LockedHint"),
        )
        .await?
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
async fn take_sleep_inhibitor(bus: &Connection) -> zbus::Result<OwnedFd> {
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
    )
    .await?
    .body()
    .deserialize()
}

/// Our logind session object: the first of `SESSION_LOOKUPS` to find one, or
/// the last failure.
async fn session_path(calls: &Connection) -> zbus::Result<OwnedObjectPath> {
    let mut failed = None;
    for lookup in SESSION_LOOKUPS {
        match look_up_session(calls, lookup).await {
            Ok(path) => return Ok(path),
            Err(e) => {
                log::debug!("system-lock-logind: session lookup {lookup:?} failed ({e})");
                failed = Some(e);
            }
        }
    }
    Err(failed.unwrap_or_else(|| zbus::Error::Failure("no session lookup".into())))
}

async fn look_up_session(
    calls: &Connection,
    lookup: SessionLookup,
) -> zbus::Result<OwnedObjectPath> {
    match lookup {
        SessionLookup::Auto => calls
            .call_method(
                Some(LOGIND),
                MANAGER_PATH,
                Some(MANAGER),
                "GetSession",
                &"auto",
            )
            .await?
            .body()
            .deserialize(),
        SessionLookup::ByPid => calls
            .call_method(
                Some(LOGIND),
                MANAGER_PATH,
                Some(MANAGER),
                "GetSessionByPID",
                &std::process::id(),
            )
            .await?
            .body()
            .deserialize(),
        SessionLookup::UserDisplay => {
            // SAFETY: getuid takes nothing, cannot fail and touches no memory.
            let uid = unsafe { libc::getuid() };
            let user: OwnedObjectPath = calls
                .call_method(Some(LOGIND), MANAGER_PATH, Some(MANAGER), "GetUser", &uid)
                .await?
                .body()
                .deserialize()?;
            let value: OwnedVariant = calls
                .call_method(
                    Some(LOGIND),
                    user.as_str(),
                    Some(PROPERTIES),
                    "Get",
                    &(USER, "Display"),
                )
                .await?
                .body()
                .deserialize()?;
            let (id, path) = <(String, OwnedObjectPath)>::try_from(value)?;
            let session = display_session(&id, path.as_str())
                .ok_or_else(|| zbus::Error::Failure("the user has no display session".into()))?;
            Ok(OwnedObjectPath::try_from(session)?)
        }
    }
}

/// Session bus: `ActiveChanged(bool)` from whichever screensaver is there.
async fn watch_screensaver(app: &AppHandle) -> zbus::Result<()> {
    let bus = Builder::session().build().await?;
    let mut watching = 0_usize;
    for interface in SCREENSAVERS {
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .interface(interface)
            .member("ActiveChanged")
            .build()?;
        match add_match(&bus, rule).await {
            Ok(()) => watching += 1,
            Err(e) => log::info!("system-lock-screensaver: {interface} unavailable ({e})"),
        }
    }
    if watching == 0 {
        return Ok(()); // nothing to wait for; don't park a thread on it
    }

    let mut messages = MessageStream::from(bus);
    while let Some(msg) = messages.next().await {
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
