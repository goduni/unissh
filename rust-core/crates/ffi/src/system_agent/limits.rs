//! The bounds on what a program that can reach the system agent's endpoint may
//! cost the app. Any process of the same user can connect, as often as it
//! likes, so each resource a connection can hold has a ceiling here:
//!
//! * **Connections** — at most [`MAX_CONNECTIONS`] are served at once; one
//!   beyond that is closed unanswered. A connection that sends no complete
//!   request for [`IDLE_TIMEOUT`] is closed, so ones left open do not use the
//!   ceiling up for good.
//! * **Listing** — the identity list is resolved from the vaults at most once
//!   per [`IDENTITIES_TTL`] ([`Recent`]), so a loop of `ssh-add -l` cannot keep
//!   the core's lock busy reopening vaults.
//! * **Prompts** — one signature prompt is on screen at a time and at most
//!   [`MAX_QUEUED_PROMPTS`] more wait their turn ([`PromptQueue`]).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::lock_recover;

/// Connections served at once. OpenSSH's clients open one per use and close it;
/// this is far above what a busy `git` or `ansible` run holds.
pub(super) const MAX_CONNECTIONS: usize = 64;

/// How long a connection may go without delivering a complete request. Long
/// enough for a tool that keeps one connection for a whole run; a client cut
/// off here reconnects, as it would after the agent restarts at an unlock.
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// How long a resolved identity list is reused. Changing which keys are shared
/// replaces it at once; a key changed inside a vault (a sync pull) is listed as
/// before for at most this long. Signing never relies on it.
pub(super) const IDENTITIES_TTL: Duration = Duration::from_secs(2);

/// Signature requests that may wait behind the prompt on screen. One more is
/// refused at once: each holds a thread, and a person will not answer a longer
/// line than this anyway.
pub(super) const MAX_QUEUED_PROMPTS: usize = 32;

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

/// The last value computed for a stamp, reused while it is recent and the
/// stamp is unchanged.
pub(super) struct Recent<T> {
    ttl: Duration,
    slot: Mutex<Option<(Vec<u8>, Instant, T)>>,
}

impl<T: Clone> Recent<T> {
    pub(super) const fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slot: Mutex::new(None),
        }
    }

    /// The value kept for `stamp` if it was computed less than the time to
    /// live before `now`; otherwise `fresh()`, which is then kept.
    pub(super) fn get_or(&self, stamp: &[u8], now: Instant, fresh: impl FnOnce() -> T) -> T {
        let mut slot = lock_recover(&self.slot);
        let kept = slot.as_ref().filter(|(kept_stamp, at, _)| {
            kept_stamp.as_slice() == stamp && now.saturating_duration_since(*at) < self.ttl
        });
        if let Some((_, _, value)) = kept {
            return value.clone();
        }
        let value = fresh();
        *slot = Some((stamp.to_vec(), now, value.clone()));
        drop(slot);
        value
    }

    /// Forgets the kept value.
    pub(super) fn clear(&self) {
        *lock_recover(&self.slot) = None;
    }
}

/// Why a signature request never got its prompt.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NoTurn {
    /// The line was full.
    Full,
    /// Its client went away while it waited.
    Gone,
}

/// The line signature requests wait in, so that one prompt is on screen at a
/// time and each is shown for its own full minute.
///
/// The approver's 60-second timeout starts when a prompt is handed to it. Were
/// several handed over at once, the window would still show them one by one,
/// and the ones behind would run out of time unseen. So a request is handed
/// over only when it reaches the front; waiting in line is not timed. The wait
/// is still bounded: everything ahead is answered, withdrawn or timed out
/// within a minute each, and a request whose client hangs up leaves the line.
pub(super) struct PromptQueue {
    /// How many may wait behind the one at the front.
    room: usize,
    line: Mutex<Line>,
    moved: Condvar,
}

#[derive(Default)]
struct Line {
    next: u64,
    /// Front first: the front is the request being shown.
    waiting: VecDeque<u64>,
}

/// A request's place at the front of the line; the next one moves up on drop.
pub(super) struct Turn<'a> {
    queue: &'a PromptQueue,
    ticket: u64,
}

impl PromptQueue {
    pub(super) fn new(room: usize) -> Self {
        Self {
            room,
            line: Mutex::new(Line::default()),
            moved: Condvar::new(),
        }
    }

    /// Joins the line and blocks until this request is at its front. Refused
    /// at once if the line is full, and as soon as `gone()` says its client
    /// left (after a [`PromptQueue::recheck`]).
    pub(super) fn wait_turn(&self, gone: impl Fn() -> bool) -> Result<Turn<'_>, NoTurn> {
        let ticket = {
            let mut line = lock_recover(&self.line);
            if line.waiting.len() > self.room {
                return Err(NoTurn::Full);
            }
            let ticket = line.next;
            line.next = line.next.wrapping_add(1);
            line.waiting.push_back(ticket);
            drop(line);
            ticket
        };
        let mut line = self
            .moved
            .wait_while(lock_recover(&self.line), |line: &mut Line| {
                !gone() && line.waiting.front() != Some(&ticket)
            })
            .unwrap_or_else(PoisonError::into_inner);
        let left = gone();
        if left {
            line.waiting.retain(|waiting| *waiting != ticket);
        }
        drop(line);
        if left {
            // Whoever stood behind it may now be at the front.
            self.moved.notify_all();
            return Err(NoTurn::Gone);
        }
        Ok(Turn {
            queue: self,
            ticket,
        })
    }

    /// Makes every waiting request look at its `gone()` again. Taking the
    /// line's lock first means a waiter is either not yet past its check, or
    /// already waiting for this wake-up.
    pub(super) fn recheck(&self) {
        drop(lock_recover(&self.line));
        self.moved.notify_all();
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut line = lock_recover(&self.queue.line);
        line.waiting.retain(|waiting| *waiting != self.ticket);
        drop(line);
        self.queue.moved.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

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
    fn a_recent_value_is_reused_until_its_stamp_changes_or_it_ages_out() {
        let recent = Recent::new(Duration::from_secs(2));
        let computed = AtomicUsize::new(0);
        let fresh = || computed.fetch_add(1, Ordering::SeqCst);
        let start = Instant::now();
        let later = |ms| start + Duration::from_millis(ms);

        assert_eq!(recent.get_or(b"a", start, fresh), 0);
        assert_eq!(recent.get_or(b"a", later(1_999), fresh), 0, "still recent");
        assert_eq!(recent.get_or(b"b", later(1_999), fresh), 1, "new stamp");
        assert_eq!(recent.get_or(b"b", later(3_999), fresh), 2, "aged out");
    }

    /// Blocks until `queue` holds `len` requests, the front one included.
    fn wait_for_line(queue: &PromptQueue, len: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while lock_recover(&queue.line).waiting.len() != len {
            assert!(Instant::now() < deadline, "the line never reached {len}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_request_beyond_the_room_in_line_is_refused_at_once() {
        let queue = PromptQueue::new(1);
        std::thread::scope(|scope| {
            let shown = queue.wait_turn(|| false).expect("the first is shown");
            let behind = scope.spawn(|| queue.wait_turn(|| false).is_ok());
            wait_for_line(&queue, 2);

            assert_eq!(queue.wait_turn(|| false).err(), Some(NoTurn::Full));

            drop(shown);
            assert!(
                behind.join().expect("the waiter ran"),
                "the one in line moves up"
            );
        });
    }

    #[test]
    fn a_waiting_request_whose_client_left_leaves_the_line_without_a_turn() {
        let queue = PromptQueue::new(4);
        let left = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let shown = queue.wait_turn(|| false).expect("the first is shown");
            let behind = scope.spawn(|| queue.wait_turn(|| left.load(Ordering::SeqCst)).err());
            wait_for_line(&queue, 2);

            left.store(true, Ordering::SeqCst);
            queue.recheck();

            assert_eq!(behind.join().expect("the waiter ran"), Some(NoTurn::Gone));
            wait_for_line(&queue, 1);
            drop(shown);
        });
    }
}
