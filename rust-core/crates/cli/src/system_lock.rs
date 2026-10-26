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
//! process. Unlike the desktop, there is no screensaver (session bus) fallback:
//! a desktop that locks without telling logind does not pause the CLI.
//!
//! Elsewhere (macOS, Windows) and without logind (a container, no D-Bus), this
//! does nothing.

use std::sync::Arc;

use unissh_automation::Broker;

/// Suspends `broker` on a session lock or a sleep and resumes it after, for as
/// long as it is polled. Never completes: a missing bus just leaves it idle.
pub async fn pause_on_lock(broker: &Arc<Broker>) {
    #[cfg(target_os = "linux")]
    if let Err(e) = linux::watch(broker).await {
        // Info, not warn: no D-Bus or no logind is a legitimate environment.
        log::info!("system lock: not watching ({e})");
    }
    #[cfg(not(target_os = "linux"))]
    let _ = broker;
    std::future::pending::<()>().await;
}

#[cfg(target_os = "linux")]
mod linux {
    use futures_util::StreamExt;
    use unissh_automation::Broker;
    use zbus::fdo::DBusProxy;
    use zbus::message::Type;
    use zbus::zvariant::{OwnedFd, OwnedObjectPath};
    use zbus::{Connection, MatchRule, MessageStream};

    const LOGIND: &str = "org.freedesktop.login1";
    const LOGIND_MANAGER: &str = "org.freedesktop.login1.Manager";
    const LOGIND_SESSION: &str = "org.freedesktop.login1.Session";

    /// Follows logind until the bus goes away.
    pub async fn watch(broker: &Broker) -> zbus::Result<()> {
        let bus = Connection::system().await?;
        let dbus = DBusProxy::new(&bus).await?;
        dbus.add_match_rule(
            MatchRule::builder()
                .msg_type(Type::Signal)
                .sender(LOGIND)?
                .interface(LOGIND_MANAGER)?
                .member("PrepareForSleep")?
                .build(),
        )
        .await?;
        // Held until the machine goes down, so that logind waits for the
        // suspend below; retaken on the way back up.
        let mut inhibitor = match take_sleep_inhibitor(&bus).await {
            Ok(fd) => Some(fd),
            Err(e) => {
                log::info!("system lock: sleep will not wait for MCP access to pause ({e})");
                None
            }
        };
        // Only THIS session's lock: another user's screen lock is not ours.
        match session_path(&bus).await {
            Ok(path) => {
                let rule = MatchRule::builder()
                    .msg_type(Type::Signal)
                    .sender(LOGIND)?
                    .path(path.as_ref())?
                    .interface(LOGIND_SESSION)?
                    .build();
                if let Err(e) = dbus.add_match_rule(rule).await {
                    log::info!("system lock: no session lock signals ({e})");
                }
            }
            Err(e) => log::info!("system lock: no session object ({e})"),
        }
        // As on the desktop: a signal in the moment before this is not heard.
        let mut messages = MessageStream::from(&bus);
        let mut screen_locked = false;
        while let Some(message) = messages.next().await {
            let message = message?;
            let header = message.header();
            let Some(member) = header.member() else {
                continue;
            };
            match member.as_str() {
                // `true` = going down, `false` = coming back.
                "PrepareForSleep" => {
                    if message.body().deserialize::<bool>().unwrap_or(false) {
                        broker.suspend();
                        eprintln!("unissh mcp: the machine is going to sleep; access paused");
                        // Only now: letting go is what tells logind to go ahead.
                        drop(inhibitor.take());
                    } else {
                        inhibitor = take_sleep_inhibitor(&bus).await.ok();
                        if !screen_locked {
                            broker.resume();
                            eprintln!("unissh mcp: awake; access resumed");
                        }
                    }
                }
                "Lock" => {
                    screen_locked = true;
                    broker.suspend();
                    eprintln!("unissh mcp: the session locked; access paused until it unlocks");
                }
                "Unlock" => {
                    screen_locked = false;
                    broker.resume();
                    eprintln!("unissh mcp: the session unlocked; access resumed");
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// A `delay` inhibitor on sleep: logind waits (up to its `InhibitDelayMaxSec`)
    /// until the returned descriptor is dropped.
    async fn take_sleep_inhibitor(bus: &Connection) -> zbus::Result<OwnedFd> {
        bus.call_method(
            Some(LOGIND),
            "/org/freedesktop/login1",
            Some(LOGIND_MANAGER),
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
            "/org/freedesktop/login1",
            Some(LOGIND_MANAGER),
            "GetSessionByPID",
            &(std::process::id()),
        )
        .await?
        .body()
        .deserialize()
    }
}
