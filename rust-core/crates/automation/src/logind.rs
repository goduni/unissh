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

/// logind's well-known bus name.
pub const LOGIND: &str = "org.freedesktop.login1";
/// logind's manager object.
pub const MANAGER_PATH: &str = "/org/freedesktop/login1";
/// The manager interface (`PrepareForSleep`, `Inhibit`, `GetSessionByPID`).
pub const MANAGER: &str = "org.freedesktop.login1.Manager";
/// The session interface (`Lock`, `Unlock`, `LockedHint`).
pub const SESSION: &str = "org.freedesktop.login1.Session";
/// The interface of `PropertiesChanged`.
pub const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

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
    use super::{Header, Heard, Logind, MANAGER, MANAGER_PATH, PROPERTIES, SESSION};

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
}
