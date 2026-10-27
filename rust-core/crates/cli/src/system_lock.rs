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
        Header, Heard, Logind, LOGIND, MANAGER, MANAGER_PATH, PROPERTIES, SESSION,
    };
    use unissh_automation::Broker;
    use zbus::fdo::DBusProxy;
    use zbus::message::Type;
    use zbus::names::{BusName, InterfaceName, MemberName, UniqueName};
    use zbus::zvariant::{ObjectPath, OwnedFd, OwnedObjectPath, OwnedValue};
    use zbus::{Connection, MatchRule, Message, MessageStream};

    /// Follows logind until the bus goes away.
    pub async fn watch(broker: &Broker) -> zbus::Result<()> {
        let bus = Connection::system().await?;
        // Before anything is asked, so that nothing said after it is missed.
        let mut messages = MessageStream::from(&bus);
        let dbus = DBusProxy::new(&bus).await?;
        dbus.add_match_rule(
            MatchRule::builder()
                .msg_type(Type::Signal)
                .sender("org.freedesktop.DBus")?
                .interface("org.freedesktop.DBus")?
                .member("NameOwnerChanged")?
                .add_arg(LOGIND)?
                .build(),
        )
        .await?;
        dbus.add_match_rule(
            MatchRule::builder()
                .msg_type(Type::Signal)
                .sender(LOGIND)?
                .path(MANAGER_PATH)?
                .interface(MANAGER)?
                .member("PrepareForSleep")?
                .build(),
        )
        .await?;
        let owner = dbus
            .get_name_owner(BusName::from_static_str(LOGIND)?)
            .await?
            .as_str()
            .to_owned();
        // Held until the machine goes down, so that logind waits for the
        // suspend below; retaken on the way back up.
        let mut inhibitor = match take_sleep_inhibitor(&bus).await {
            Ok(fd) => Some(fd),
            Err(e) => {
                log::warn!("system lock: sleep will not wait for MCP access to pause ({e})");
                None
            }
        };
        // Only THIS session's lock: another user's screen lock is not ours.
        let session = match session_path(&bus).await {
            Ok(path) => {
                for interface in [SESSION, PROPERTIES] {
                    let rule = MatchRule::builder()
                        .msg_type(Type::Signal)
                        .sender(LOGIND)?
                        .path(path.as_ref())?
                        .interface(interface)?
                        .build();
                    if let Err(e) = dbus.add_match_rule(rule).await {
                        log::warn!("system lock: no session lock signals ({e})");
                    }
                }
                Some(path)
            }
            Err(e) => {
                log::warn!("system lock: no session object; only sleep pauses access ({e})");
                None
            }
        };
        let mut logind = Logind::new(Some(owner), session.as_ref().map(|p| p.as_str().to_owned()));
        let mut pause = Pause {
            broker,
            screen_locked: false,
        };
        if let Some(path) = &session {
            if locked_hint(&bus, path).await.unwrap_or(false) {
                pause.locked();
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
                        inhibitor = take_sleep_inhibitor(&bus).await.ok();
                        // The lock screen may have come up on the way down
                        // without a word to us: ask, and stay paused if so.
                        let hint = match &session {
                            Some(path) => locked_hint(&bus, path).await.ok(),
                            None => None,
                        };
                        pause.awake(hint);
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
        /// Set by `Lock`/`Unlock` and by the session's `LockedHint`.
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
        /// heard before or by `hint`, the session's `LockedHint` now.
        fn awake(&mut self, hint: Option<bool>) {
            if let Some(locked) = hint {
                self.screen_locked = locked;
            }
            if self.screen_locked {
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
            .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
            .ok()?;
        if interface != SESSION {
            return None;
        }
        bool::try_from(changed.remove("LockedHint")?).ok()
    }

    /// Whether the session's lock screen is up, as the desktop told logind.
    async fn locked_hint(bus: &Connection, session: &OwnedObjectPath) -> zbus::Result<bool> {
        let value: OwnedValue = bus
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

    /// A `delay` inhibitor on sleep: logind waits (up to its `InhibitDelayMaxSec`)
    /// until the returned descriptor is dropped.
    async fn take_sleep_inhibitor(bus: &Connection) -> zbus::Result<OwnedFd> {
        bus.call_method(
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

    /// This process's logind session object.
    async fn session_path(bus: &Connection) -> zbus::Result<OwnedObjectPath> {
        bus.call_method(
            Some(LOGIND),
            MANAGER_PATH,
            Some(MANAGER),
            "GetSessionByPID",
            &(std::process::id()),
        )
        .await?
        .body()
        .deserialize()
    }
}
