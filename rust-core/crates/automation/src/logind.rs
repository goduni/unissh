//! Which logind messages a lock watcher may act on: the one rule shared by the
//! desktop's watcher (`client/src-tauri/src/system_lock/linux.rs`) and the
//! CLI's (`rust-core/crates/cli/src/system_lock.rs`). Each drives its own bus
//! connection (blocking there, async here); this decides, without the bus.
//!
//! A match rule is no filter: any local process may unicast a signal to our
//! unique name, with any member, path and interface it likes, and the bus
//! delivers it whatever we subscribed to. The bus does stamp the sender,
//! though, and nobody but the bus can send as `org.freedesktop.DBus`, nor as
//! whoever owns `org.freedesktop.login1` right now. So a signal counts only
//! when it comes from the current owner of logind's name (asked with
//! `GetNameOwner` at start and followed through the bus's `NameOwnerChanged`)
//! and from the object and interface logind itself would use.
//!
//! The same local user can also flood our unique name, and that is a second,
//! separate problem: not what we act on, but whether we get to ask anything at
//! all. zbus reads a connection's socket in one task, which hands a method
//! reply to its caller and then broadcasts every message to the connection's
//! open streams. A plain `MessageStream`/`MessageIterator` holds 64 messages
//! and never drops one: once it is full the reader waits for it to drain, and
//! a reply queued on the socket behind the flood never reaches its caller, so
//! a watcher that asks the bus something while not reading its own stream (at
//! start, or on wake) waits for ever. Hence two connections per watcher:
//!
//! - the *watch* connection only listens. Its match rules are added before its
//!   stream exists; until then zbus has nowhere to queue a message and drops
//!   it, so the `AddMatch` replies cannot be stuck behind anything. Once the
//!   stream is open, nothing is ever asked on it again. A rule is per
//!   connection, so it has to be added there, and this ordering is what makes
//!   that safe.
//! - the *calls* connection only asks (the session, logind's owner,
//!   `LockedHint`, the inhibitor). It never opens a stream, so whatever is
//!   unicast to it is dropped on arrival and no reply waits behind it; and it
//!   carries [`CALL_TIMEOUT`], so even a reply logind itself never sends ends
//!   in an error instead of a hang.
//!
//! The state is read on the calls connection only after the watch stream is
//! open, so a change between the two is either in the reply or in the stream.

use std::time::Duration;

/// logind's well-known bus name.
pub const LOGIND: &str = "org.freedesktop.login1";
/// logind's manager object.
pub const MANAGER_PATH: &str = "/org/freedesktop/login1";
/// The manager interface (`PrepareForSleep`, `Inhibit`, the session lookups).
pub const MANAGER: &str = "org.freedesktop.login1.Manager";
/// The session interface (`Lock`, `Unlock`, `LockedHint`).
pub const SESSION: &str = "org.freedesktop.login1.Session";
/// The user interface (`Display`).
pub const USER: &str = "org.freedesktop.login1.User";
/// The interface of `PropertiesChanged`.
pub const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

/// How long a call on the calls connection may wait for its reply. Past it the
/// call fails, logged at warn; a check that fails on wake leaves access paused.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// One way of finding this process's logind session, tried in
/// [`SESSION_LOOKUPS`] order until one finds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLookup {
    /// `GetSession("auto")`: the caller's session, which logind resolves for a
    /// process under the user's systemd manager too (where GNOME and KDE start
    /// apps, and where a PID belongs to no session at all).
    Auto,
    /// `GetSessionByPID(own pid)`: for a logind too old to know `auto`.
    ByPid,
    /// The `Display` session of `GetUser(own uid)`: the user's graphical
    /// session, when the process itself belongs to none. Read it with
    /// [`display_session`].
    UserDisplay,
}

/// The order the lookups are tried in: the precise answers first, the user's
/// display session (right for a desktop app, a guess for a shell) last.
pub const SESSION_LOOKUPS: [SessionLookup; 3] = [
    SessionLookup::Auto,
    SessionLookup::ByPid,
    SessionLookup::UserDisplay,
];

/// Where a watcher's session came from: the session its environment names, or
/// one of [`SESSION_LOOKUPS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSource<'a> {
    /// `GetSession(id)` for the `$XDG_SESSION_ID` the process inherited: the
    /// login session a shell was started in. A tmux pane whose server runs in
    /// a systemd user scope still carries it, though logind finds no session
    /// by its PID there and `auto` answers the user's display session (another
    /// tty, perhaps).
    Environment(&'a str),
    /// One of the lookups that ask logind about the process itself.
    Lookup(SessionLookup),
}

impl SessionSource<'_> {
    /// Whether the session is only a guess at this process's own: anything
    /// but the session its environment names. A watcher says which session it
    /// follows then, so that a wrong one can be noticed.
    pub const fn is_fallback(self) -> bool {
        !matches!(self, Self::Environment(_))
    }
}

/// The order a watcher looks its session up in: the session `$XDG_SESSION_ID`
/// names (`xdg_session_id`; unset or empty is none), then [`SESSION_LOOKUPS`].
pub fn session_sources(xdg_session_id: Option<&str>) -> impl Iterator<Item = SessionSource<'_>> {
    xdg_session_id
        .filter(|id| !id.is_empty())
        .map(SessionSource::Environment)
        .into_iter()
        .chain(SESSION_LOOKUPS.into_iter().map(SessionSource::Lookup))
}

/// The session id in a session object's path, as `loginctl` shows it: the
/// last path element with logind's `_xx` hex escapes undone
/// (`/org/freedesktop/login1/session/_34` is session `4`).
pub fn session_id(path: &str) -> String {
    let mut rest = path.rsplit('/').next().unwrap_or(path).as_bytes();
    let mut id = Vec::with_capacity(rest.len());
    while let Some((&first, tail)) = rest.split_first() {
        let escaped = tail
            .get(..2)
            .filter(|_| first == b'_')
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                id.push(byte);
                rest = tail.get(2..).unwrap_or_default();
            }
            None => {
                id.push(first);
                rest = tail;
            }
        }
    }
    String::from_utf8_lossy(&id).into_owned()
}

/// The session in a user's `Display` property `(id, path)`. logind reports
/// `("", "/")` when the user has no display session: that is not one.
pub fn display_session(id: &str, path: &str) -> Option<String> {
    (!id.is_empty() && path != "/" && !path.is_empty()).then(|| path.to_owned())
}

/// What a watcher could learn about the lock screen on waking up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeCheck {
    /// No session object to ask: only what was heard before counts.
    NoSession,
    /// The session's `LockedHint`, read just now.
    Hint(bool),
    /// The read failed or timed out.
    Failed,
}

/// Whether the screen counts as locked after a wake: `locked_before` is what
/// the watcher had heard. A check that failed counts as locked, so access stays
/// paused (fail closed) until an unlock is heard.
pub const fn locked_after_wake(locked_before: bool, check: WakeCheck) -> bool {
    match check {
        WakeCheck::NoSession => locked_before,
        WakeCheck::Hint(locked) => locked,
        WakeCheck::Failed => true,
    }
}

/// The bus itself: the only sender of `NameOwnerChanged`.
const BUS: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";

/// A received message's header, as the bus delivered it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Header<'a> {
    /// Whether it is a signal (not a call, reply or error).
    pub signal: bool,
    /// The sender the bus stamped on it.
    pub sender: Option<&'a str>,
    /// The object path.
    pub path: Option<&'a str>,
    /// The interface.
    pub interface: Option<&'a str>,
    /// The member.
    pub member: Option<&'a str>,
}

/// What an accepted message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Heard {
    /// The manager's `PrepareForSleep(bool)`: `true` going down, `false` back up.
    Sleep,
    /// Our session's `Lock`.
    Lock,
    /// Our session's `Unlock`.
    Unlock,
    /// `PropertiesChanged` on our session (`LockedHint` among them, perhaps).
    SessionProperties,
    /// The bus's `NameOwnerChanged`: pass its arguments to [`Logind::owner_changed`].
    OwnerChanged,
}

/// Who logind is and which session is ours.
#[derive(Debug, Clone, Default)]
pub struct Logind {
    owner: Option<String>,
    session: Option<String>,
}

impl Logind {
    /// `owner` is `GetNameOwner(org.freedesktop.login1)` (`None` if nobody owns
    /// it); `session` is this process's session object, if it has one.
    pub const fn new(owner: Option<String>, session: Option<String>) -> Self {
        Self { owner, session }
    }

    /// Whether `header` is a message to act on, and as what. `None` drops it.
    pub fn heard(&self, header: &Header<'_>) -> Option<Heard> {
        if !header.signal {
            return None;
        }
        let at = |path: &str, interface: &str| {
            header.path == Some(path) && header.interface == Some(interface)
        };
        if header.sender == Some(BUS) {
            return (at(BUS_PATH, BUS) && header.member == Some("NameOwnerChanged"))
                .then_some(Heard::OwnerChanged);
        }
        let owner = self.owner.as_deref()?;
        if header.sender != Some(owner) {
            return None;
        }
        if at(MANAGER_PATH, MANAGER) {
            return (header.member == Some("PrepareForSleep")).then_some(Heard::Sleep);
        }
        let session = self.session.as_deref()?;
        if at(session, SESSION) {
            return match header.member {
                Some("Lock") => Some(Heard::Lock),
                Some("Unlock") => Some(Heard::Unlock),
                _ => None,
            };
        }
        (at(session, PROPERTIES) && header.member == Some("PropertiesChanged"))
            .then_some(Heard::SessionProperties)
    }

    /// Applies `NameOwnerChanged(name, old, new)`, only ever called for a
    /// message [`Self::heard`] accepted as [`Heard::OwnerChanged`]. An empty
    /// `new` means logind left the bus: nothing is accepted until it is back.
    pub fn owner_changed(&mut self, name: &str, new_owner: &str) {
        if name == LOGIND {
            self.owner = (!new_owner.is_empty()).then(|| new_owner.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        display_session, locked_after_wake, session_id, session_sources, Header, Heard, Logind,
        SessionLookup, SessionSource, WakeCheck, MANAGER, MANAGER_PATH, PROPERTIES, SESSION,
        SESSION_LOOKUPS,
    };

    const OWNER: &str = ":1.7";
    const SESSION_PATH: &str = "/org/freedesktop/login1/session/_34";

    fn logind() -> Logind {
        Logind::new(Some(OWNER.into()), Some(SESSION_PATH.into()))
    }

    fn signal<'a>(
        sender: &'a str,
        path: &'a str,
        interface: &'a str,
        member: &'a str,
    ) -> Header<'a> {
        Header {
            signal: true,
            sender: Some(sender),
            path: Some(path),
            interface: Some(interface),
            member: Some(member),
        }
    }

    /// Only logind's current owner, on logind's own object and interface, in a
    /// signal, is heard: a unicast from anyone else is dropped, whatever it says.
    #[test]
    fn only_logind_on_its_own_objects_is_heard() {
        let logind = logind();
        let heard = |h: Header<'_>| logind.heard(&h);
        assert_eq!(
            heard(signal(OWNER, MANAGER_PATH, MANAGER, "PrepareForSleep")),
            Some(Heard::Sleep)
        );
        assert_eq!(
            heard(signal(OWNER, SESSION_PATH, SESSION, "Lock")),
            Some(Heard::Lock)
        );
        assert_eq!(
            heard(signal(OWNER, SESSION_PATH, SESSION, "Unlock")),
            Some(Heard::Unlock)
        );
        assert_eq!(
            heard(signal(OWNER, SESSION_PATH, PROPERTIES, "PropertiesChanged")),
            Some(Heard::SessionProperties)
        );
        // Another sender: a local user's `dbus-send --dest=<our name>`.
        assert_eq!(
            heard(signal(":1.99", SESSION_PATH, SESSION, "Unlock")),
            None
        );
        assert_eq!(
            heard(signal(":1.99", MANAGER_PATH, MANAGER, "PrepareForSleep")),
            None
        );
        // logind's well-known name is never a stamped sender.
        assert_eq!(
            heard(signal(
                "org.freedesktop.login1",
                SESSION_PATH,
                SESSION,
                "Unlock"
            )),
            None
        );
        // The right sender, the wrong object or interface.
        assert_eq!(
            heard(signal(
                OWNER,
                "/org/freedesktop/login1/session/_9",
                SESSION,
                "Unlock"
            )),
            None
        );
        assert_eq!(
            heard(signal(OWNER, SESSION_PATH, MANAGER, "PrepareForSleep")),
            None
        );
        assert_eq!(heard(signal(OWNER, MANAGER_PATH, SESSION, "Unlock")), None);
        assert_eq!(heard(signal(OWNER, MANAGER_PATH, MANAGER, "Unlock")), None);
        // Not a signal.
        let call = Header {
            signal: false,
            ..signal(OWNER, SESSION_PATH, SESSION, "Unlock")
        };
        assert_eq!(heard(call), None);
        // No session object: only the manager is heard.
        let sessionless = Logind::new(Some(OWNER.into()), None);
        assert_eq!(
            sessionless.heard(&signal(OWNER, SESSION_PATH, SESSION, "Unlock")),
            None
        );
        assert_eq!(
            sessionless.heard(&signal(OWNER, MANAGER_PATH, MANAGER, "PrepareForSleep")),
            Some(Heard::Sleep)
        );
    }

    /// The owner follows the bus's own `NameOwnerChanged`, and only the bus's.
    #[test]
    fn the_owner_follows_the_bus_alone() {
        let mut logind = logind();
        let bus = signal(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameOwnerChanged",
        );
        assert_eq!(logind.heard(&bus), Some(Heard::OwnerChanged));
        let forged = Header {
            sender: Some(":1.99"),
            ..bus
        };
        assert_eq!(logind.heard(&forged), None);
        let elsewhere = Header {
            path: Some("/x"),
            ..bus
        };
        assert_eq!(logind.heard(&elsewhere), None);

        logind.owner_changed("org.example.Other", ":1.99");
        assert!(logind
            .heard(&signal(OWNER, SESSION_PATH, SESSION, "Lock"))
            .is_some());
        logind.owner_changed("org.freedesktop.login1", "");
        assert_eq!(
            logind.heard(&signal(OWNER, SESSION_PATH, SESSION, "Lock")),
            None
        );
        logind.owner_changed("org.freedesktop.login1", ":1.42");
        assert_eq!(
            logind.heard(&signal(":1.42", SESSION_PATH, SESSION, "Lock")),
            Some(Heard::Lock)
        );
        assert_eq!(
            logind.heard(&signal(OWNER, SESSION_PATH, SESSION, "Lock")),
            None
        );
    }

    /// The caller's own session first, then by PID, then the user's display
    /// session; logind's "no display session" is not a session.
    #[test]
    fn the_session_is_looked_up_precise_first() {
        assert_eq!(
            SESSION_LOOKUPS,
            [
                SessionLookup::Auto,
                SessionLookup::ByPid,
                SessionLookup::UserDisplay
            ]
        );
        assert_eq!(
            display_session("2", "/org/freedesktop/login1/session/_32").as_deref(),
            Some("/org/freedesktop/login1/session/_32")
        );
        assert_eq!(display_session("", "/"), None);
        assert_eq!(display_session("2", "/"), None);
    }

    /// The session `$XDG_SESSION_ID` names comes first and is the only one that
    /// is not a fallback; unset or empty, the lookups alone are tried.
    #[test]
    fn the_environment_session_comes_first() {
        let lookups = SESSION_LOOKUPS.map(SessionSource::Lookup);
        let mut with_env = vec![SessionSource::Environment("4")];
        with_env.extend(lookups);
        assert_eq!(session_sources(Some("4")).collect::<Vec<_>>(), with_env);
        assert_eq!(session_sources(None).collect::<Vec<_>>(), lookups);
        assert_eq!(session_sources(Some("")).collect::<Vec<_>>(), lookups);
        assert!(!SessionSource::Environment("4").is_fallback());
        assert!(lookups.iter().all(|source| source.is_fallback()));
    }

    /// A session path names its session as `loginctl` does.
    #[test]
    fn a_session_path_names_its_id() {
        assert_eq!(session_id("/org/freedesktop/login1/session/_34"), "4");
        assert_eq!(session_id("/org/freedesktop/login1/session/c2"), "c2");
        assert_eq!(session_id("/org/freedesktop/login1/session/_312"), "12");
    }

    /// A wake resumes only on a lock screen known to be down: a failed or
    /// timed-out check keeps access paused.
    #[test]
    fn a_failed_wake_check_stays_locked() {
        for before in [false, true] {
            assert_eq!(locked_after_wake(before, WakeCheck::NoSession), before);
            assert!(locked_after_wake(before, WakeCheck::Failed));
            assert!(locked_after_wake(before, WakeCheck::Hint(true)));
            assert!(!locked_after_wake(before, WakeCheck::Hint(false)));
        }
    }
}
