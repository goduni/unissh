//! `unissh mcp` pauses when the session locks or the machine goes to sleep, as
//! the desktop app does (`client/src-tauri/src/system_lock/linux.rs`).
//!
//! Linux only, through logind on the system bus: the session's `Lock`/`Unlock`
//! and the manager's `PrepareForSleep`. A lock or a sleep suspends the broker
//! (live access revoked, running commands cancelled, saved grants kept); an
//! unlock, or a wake while the session is not locked, resumes it, and the saved
//! grants come back. That is the desktop's native half: what the desktop's
//! Settings add on top (locking the vault itself after a grace period) has no
//! counterpart here, since the CLI keeps the vaults open for the life of the
//! process. Unlike the desktop, there is no screensaver (session bus) fallback;
//! the session's `LockedHint` stands in for it where the desktop maintains it
//! (GNOME, KDE): it pauses when the hint goes up, resumes when it comes down,
//! and a wake while it is up stays paused. A desktop that locks without
//! telling logind at all does not pause the CLI.
//!
//! Only logind is heard: [`unissh_automation::logind`] drops a signal that does
//! not come from the current owner of `org.freedesktop.login1` on its own
//! objects, so another local user cannot unicast an `Unlock` to resume access.
//!
//! Elsewhere (macOS, Windows) and without logind (a container, no D-Bus), this
//! does nothing.

use std::sync::Arc;

use unissh_automation::Broker;

/// Suspends `broker` on a session lock or a sleep and resumes it after, for as
/// long as it is polled. Never completes: a missing bus just leaves it idle.
pub async fn pause_on_lock(broker: &Arc<Broker>) {
    #[cfg(target_os = "linux")]
    match linux::watch(broker).await {
        // Warn: whoever relies on the pause should know it is not there.
        Ok(()) => log::warn!("system lock: logind went away; access no longer pauses on lock"),
        Err(e) => log::warn!("system lock: not watching; access does not pause on lock ({e})"),
    }
    #[cfg(not(target_os = "linux"))]
    let _ = broker;
    std::future::pending::<()>().await;
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;

    use futures_util::StreamExt;
    use unissh_automation::logind::{
        display_session, locked_after_wake, Header, Heard, Logind, SessionLookup, WakeCheck,
        CALL_TIMEOUT, LOGIND, MANAGER, MANAGER_PATH, PROPERTIES, SESSION, SESSION_LOOKUPS, USER,
    };
    use unissh_automation::Broker;
    use zbus::connection::Builder;
    use zbus::message::Type;
    use zbus::names::{InterfaceName, MemberName, UniqueName};
    use zbus::{
        Connection, MatchRule, Message, MessageStream, ObjectPath, OwnedFd, OwnedObjectPath,
        OwnedVariant,
    };

    /// Follows logind until the bus goes away.
    ///
    /// Two connections, for the reason in [`unissh_automation::logind`]: a
    /// flood unicast to a connection with an open stream stalls every reply
    /// on it. `watch` only listens (its rules added before its stream opens,
    /// nothing asked after); `calls` only asks, never streams, and times out.
    pub async fn watch(broker: &Broker) -> zbus::Result<()> {
        let calls = Builder::system()
            .method_timeout(CALL_TIMEOUT)
            .build()
            .await?;
        let watch = Builder::system()
            .method_timeout(CALL_TIMEOUT)
            .build()
            .await?;
        // Only THIS session's lock: another user's screen lock is not ours.
        let session = match session_path(&calls).await {
            Ok(path) => Some(path),
            Err(e) => {
                log::warn!("system lock: no session object; only sleep pauses access ({e})");
                None
            }
        };
        subscribe(&watch, session.as_ref()).await?;
        // From here on `watch` is only read; what changes after the questions
        // below is in the stream, what changed before is in their answers.
        let mut messages = MessageStream::from(&watch);
        let owner = name_owner(&calls).await?;
        // Held until the machine goes down, so that logind waits for the
        // suspend below; retaken on the way back up.
        let mut inhibitor = sleep_inhibitor(&calls).await;
        let mut logind = Logind::new(Some(owner), session.as_ref().map(|p| p.as_str().to_owned()));
        let mut pause = Pause {
            broker,
            screen_locked: false,
        };
        if let Some(path) = &session {
            match locked_hint(&calls, path).await {
                Ok(true) => pause.locked(),
                Ok(false) => {}
                Err(e) => log::warn!("system lock: could not read the session's lock state ({e})"),
            }
        }
        while let Some(message) = messages.next().await {
            let message = message?;
            let Some(heard) = logind.heard(&seen(&message.header())) else {
                continue;
            };
            match heard {
                Heard::OwnerChanged => {
                    if let Ok((name, _, new)) =
                        message.body().deserialize::<(String, String, String)>()
                    {
                        logind.owner_changed(&name, &new);
                    }
                }
                // `true` = going down, `false` = coming back.
                Heard::Sleep => {
                    if message.body().deserialize::<bool>().unwrap_or(false) {
                        broker.suspend();
                        eprintln!("unissh mcp: the machine is going to sleep; access paused");
                        // Only now: letting go is what tells logind to go ahead.
                        drop(inhibitor.take());
                    } else {
                        // The lock screen may have come up on the way down
                        // without a word to us: ask, and stay paused if so,
                        // or if the answer does not come.
                        let check = wake_check(&calls, session.as_ref()).await;
                        pause.awake(check);
                        inhibitor = sleep_inhibitor(&calls).await;
                    }
                }
                Heard::Lock => pause.locked(),
                Heard::Unlock => pause.unlocked(),
                Heard::SessionProperties => match changed_locked_hint(&message) {
                    Some(true) if !pause.screen_locked => pause.locked(),
                    Some(false) if pause.screen_locked => pause.unlocked(),
                    _ => {}
                },
            }
        }
        Ok(())
    }

    /// Whether the session's screen is locked, and what that does to access.
    struct Pause<'b> {
        broker: &'b Broker,
        /// Set by `Lock`/`Unlock`, by the session's `LockedHint`, and by a
        /// wake whose check failed.
        screen_locked: bool,
    }

    impl Pause<'_> {
        fn locked(&mut self) {
            self.screen_locked = true;
            self.broker.suspend();
            eprintln!("unissh mcp: the session locked; access paused until it unlocks");
        }

        fn unlocked(&mut self) {
            self.screen_locked = false;
            self.broker.resume();
            eprintln!("unissh mcp: the session unlocked; access resumed");
        }

        /// Back from sleep: resumes unless the screen is locked, by what we
        /// heard before or by `check`; a failed check counts as locked.
        fn awake(&mut self, check: WakeCheck) {
            self.screen_locked = locked_after_wake(self.screen_locked, check);
            if check == WakeCheck::Failed {
                eprintln!(
                    "unissh mcp: awake, but the session's lock state is unknown; access stays paused until it unlocks"
                );
            } else if self.screen_locked {
                eprintln!("unissh mcp: awake, but the session is locked; access stays paused");
            } else {
                self.broker.resume();
                eprintln!("unissh mcp: awake; access resumed");
            }
        }
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

    /// `LockedHint` from a session's `PropertiesChanged`, if it is among them.
    fn changed_locked_hint(message: &Message) -> Option<bool> {
        let (interface, mut changed, _) = message
            .body()
            .deserialize::<(String, HashMap<String, OwnedVariant>, Vec<String>)>()
            .ok()?;
        if interface != SESSION {
            return None;
        }
        bool::try_from(changed.remove("LockedHint")?).ok()
    }

    /// The watch connection's rules: logind's owner, its sleep, and `session`'s
    /// lock and properties. Only before the watch stream is open.
    async fn subscribe(watch: &Connection, session: Option<&OwnedObjectPath>) -> zbus::Result<()> {
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
            for interface in [SESSION, PROPERTIES] {
                let rule = MatchRule::builder()
                    .msg_type(Type::Signal)
                    .sender(LOGIND)
                    .path(path.as_str())
                    .interface(interface)
                    .build()?;
                if let Err(e) = add_match(watch, rule).await {
                    log::warn!("system lock: no session lock signals ({e})");
                }
            }
        }
        Ok(())
    }

    /// The session's `LockedHint` on waking up; a failure (or a timeout) is
    /// [`WakeCheck::Failed`], which keeps access paused.
    async fn wake_check(calls: &Connection, session: Option<&OwnedObjectPath>) -> WakeCheck {
        let Some(path) = session else {
            return WakeCheck::NoSession;
        };
        match locked_hint(calls, path).await {
            Ok(locked) => WakeCheck::Hint(locked),
            Err(e) => {
                log::warn!("system lock: could not read the session's lock state on wake ({e})");
                WakeCheck::Failed
            }
        }
    }

    /// `AddMatch` on `bus`: only ever on the watch connection, before its
    /// stream is open.
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

    /// Whether the session's lock screen is up, as the desktop told logind.
    async fn locked_hint(calls: &Connection, session: &OwnedObjectPath) -> zbus::Result<bool> {
        let value: OwnedVariant = calls
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
        bool::try_from(value)
    }

    /// [`take_sleep_inhibitor`], or `None` and a warning.
    async fn sleep_inhibitor(calls: &Connection) -> Option<OwnedFd> {
        take_sleep_inhibitor(calls)
            .await
            .inspect_err(|e| {
                log::warn!(
                    "system lock: the next sleep will not wait for MCP access to pause ({e})"
                );
            })
            .ok()
    }

    /// A `delay` inhibitor on sleep: logind waits (up to its `InhibitDelayMaxSec`)
    /// until the returned descriptor is dropped.
    async fn take_sleep_inhibitor(calls: &Connection) -> zbus::Result<OwnedFd> {
        calls
            .call_method(
                Some(LOGIND),
                MANAGER_PATH,
                Some(MANAGER),
                "Inhibit",
                &(
                    "sleep",
                    "UniSSH",
                    "Pausing MCP access before the machine sleeps",
                    "delay",
                ),
            )
            .await?
            .body()
            .deserialize()
    }

    /// This process's logind session object: the first of [`SESSION_LOOKUPS`]
    /// to find one, or the last failure.
    async fn session_path(calls: &Connection) -> zbus::Result<OwnedObjectPath> {
        let mut failed = None;
        for lookup in SESSION_LOOKUPS {
            match look_up_session(calls, lookup).await {
                Ok(path) => return Ok(path),
                Err(e) => {
                    log::debug!("system lock: session lookup {lookup:?} failed ({e})");
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
                let uid = rustix::process::getuid().as_raw();
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
                let session = display_session(&id, path.as_str()).ok_or_else(|| {
                    zbus::Error::Failure("the user has no display session".into())
                })?;
                Ok(OwnedObjectPath::try_from(session)?)
            }
        }
    }
}
