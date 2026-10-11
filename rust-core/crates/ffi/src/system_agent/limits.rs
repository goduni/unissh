//! The bounds on what a program that can reach the system agent's endpoint may
//! cost the app. Any process of the same user can connect, as often as it
//! likes, so each resource a connection can hold has a ceiling here:
//!
//! * **Connections** — at most [`MAX_CONNECTIONS`] are served at once; one
//!   beyond that is closed unanswered. A connection that sends no complete
//!   request for [`IDLE_TIMEOUT`] is closed, so ones left open do not use the
//!   ceiling up for good.
//! * **Listing** — the identity list is resolved from the vaults once per
//!   change to what it is resolved from ([`Stamped`]), so a loop of
//!   `ssh-add -l` cannot keep the core's lock busy reopening vaults.
//!
//! Signature prompts need no number of their own: a connection has one
//! request in flight, so the connection ceiling is also the most that can wait
//! in the core's line (`crate::approvals`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::lock_recover;

/// Connections served at once. OpenSSH's clients open one per use and close it;
/// this is far above what a busy `git` or `ansible` run holds.
pub(super) const MAX_CONNECTIONS: usize = 64;

/// How long a connection may go without delivering a complete request. Long
/// enough for a tool that keeps one connection for a whole run; a client cut
/// off here reconnects, as it would after the agent restarts at an unlock.
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// One of the connection slots, given back on drop.
pub(super) struct ConnectionSlot<'a>(&'a AtomicUsize);

impl<'a> ConnectionSlot<'a> {
    /// Takes a slot unless `limit` are already taken.
    pub(super) fn take(open: &'a AtomicUsize, limit: usize) -> Option<Self> {
        open.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < limit).then_some(n + 1)
        })
        .ok()
        .map(|_| Self(open))
    }
}

impl Drop for ConnectionSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The last value computed, kept with a stamp of everything it was computed
/// from and reused for as long as that stamp is unchanged.
pub(super) struct Stamped<S, T> {
    slot: Mutex<Option<(S, T)>>,
}

impl<S: PartialEq, T: Clone> Stamped<S, T> {
    pub(super) const fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    /// The value kept for `stamp`; otherwise `fresh()`, which is then kept in
    /// its place.
    pub(super) fn get_or(&self, stamp: S, fresh: impl FnOnce() -> T) -> T {
        let mut slot = lock_recover(&self.slot);
        if let Some((_, value)) = slot.as_ref().filter(|(kept, _)| *kept == stamp) {
            return value.clone();
        }
        let value = fresh();
        *slot = Some((stamp, value.clone()));
        drop(slot);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_beyond_the_limit_gets_no_slot_until_one_is_given_back() {
        let open = AtomicUsize::new(0);
        let first = ConnectionSlot::take(&open, 2).expect("first slot");
        let _second = ConnectionSlot::take(&open, 2).expect("second slot");
        assert!(ConnectionSlot::take(&open, 2).is_none(), "the limit holds");

        drop(first);
        assert!(
            ConnectionSlot::take(&open, 2).is_some(),
            "a freed slot is reused"
        );
    }

    #[test]
    fn a_stamped_value_is_reused_until_its_stamp_changes() {
        let kept = Stamped::new();
        let computed = AtomicUsize::new(0);
        let fresh = || computed.fetch_add(1, Ordering::SeqCst);

        assert_eq!(kept.get_or("a", fresh), 0);
        assert_eq!(kept.get_or("a", fresh), 0, "same stamp, not recomputed");
        assert_eq!(kept.get_or("b", fresh), 1, "new stamp");
        assert_eq!(kept.get_or("a", fresh), 2, "only the last one is kept");
    }
}
