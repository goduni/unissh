//! The one line every signature approval waits in.
//!
//! Two things ask the registered [`AgentApprover`] whether to sign: a forwarded
//! agent (a program on a remote host, through a session with forwarding on)
//! and the system agent (a program on this machine). The approver's 60-second
//! timeout starts when a request is handed to it, and the window shows one
//! prompt at a time; were several handed over at once, the ones behind would
//! run out of time unseen. So both come through [`Approvals::ask`], and the
//! approver is only ever asked about one request at a time, wherever it came
//! from: a request is handed over when it reaches the front of the line.
//!
//! Waiting in line is not timed. It is still bounded: everything ahead is
//! answered, withdrawn or timed out within a minute each, so a request waits
//! at most a minute per request ahead of it. The line itself is bounded by its
//! callers: the system agent has one request in flight per connection and a
//! ceiling on connections; forwarded requests are counted here
//! ([`MAX_FORWARDED`]).
//!
//! A revoke of the system agent ([`Approvals::revoke_system`]: vault lock,
//! screen lock, sleep, exit, the agent switched off) empties the line of its
//! requests and closes it to every listener that existed until then, so
//! nothing of theirs is handed to the approver afterwards.
//!
//! Lock order: `line`, then the asker's own lock inside [`Asker::System`]'s
//! `gone` (the system agent's per-connection lock), and nothing else. The
//! approver slot is locked only with `line` released, and the approver itself
//! is called with neither held. The core's state lock is never taken here.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use crate::{lock_recover, AgentApprover, AgentSignRequest};

/// Forwarded requests that may be in the line at once; one more is refused.
///
/// Nothing below bounds these: a remote host opens as many agent channels as
/// it likes on a session with forwarding on, and each request holds a blocking
/// thread while it waits. Before there was a line each of them timed out a
/// minute after it arrived, however many there were; in a line they would wait
/// a minute apiece, so an unbounded burst from one host would keep every other
/// request, local ones included, waiting for as long as it cared to make it.
/// The system agent needs no such number: its connection ceiling already is
/// one.
const MAX_FORWARDED: usize = 64;

/// The registered approver and the line its requests wait in. One per core.
pub(crate) struct Approvals {
    approver: Mutex<Option<Arc<dyn AgentApprover>>>,
    line: Mutex<Line>,
    moved: Condvar,
    /// Whether the last forwarded request found the line full, so that a burst
    /// is logged once.
    crowded: AtomicBool,
}

#[derive(Default)]
struct Line {
    /// Front first: the front is the request the approver is being asked about.
    waiting: VecDeque<Waiting>,
    /// Bumped by every revoke of the system agent. A system-agent request
    /// carries the value its listener started under and is let in only while
    /// that is still the current one.
    system_epoch: u64,
}

impl Line {
    /// How many requests are ahead of `id`; `None` if it is not in the line.
    fn place(&self, id: u64) -> Option<usize> {
        self.waiting.iter().position(|waiting| waiting.id == id)
    }
}

struct Waiting {
    /// The request's [`AgentSignRequest::id`].
    id: u64,
    system: bool,
}

/// Where a request put to [`Approvals::ask`] comes from.
pub(crate) enum Asker<'a> {
    /// A forwarded agent.
    Forwarded,
    /// The system agent.
    System {
        /// [`Approvals::system_epoch`] as it was when the listener started.
        epoch: u64,
        /// Whether the request's connection has ended. Called under the line's
        /// lock, once, as the request joins.
        gone: &'a dyn Fn() -> bool,
    },
}

/// A request's place at the front of the line; the next one moves up on drop.
struct Turn<'a> {
    approvals: &'a Approvals,
    id: u64,
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut line = lock_recover(&self.approvals.line);
        line.waiting.retain(|waiting| waiting.id != self.id);
        drop(line);
        self.approvals.moved.notify_all();
    }
}

impl Approvals {
    pub(crate) fn new() -> Self {
        Self {
            approver: Mutex::new(None),
            line: Mutex::new(Line::default()),
            moved: Condvar::new(),
            crowded: AtomicBool::new(false),
        }
    }

    /// Registers (or removes) who is asked.
    pub(crate) fn set(&self, approver: Option<Arc<dyn AgentApprover>>) {
        *lock_recover(&self.approver) = approver;
    }

    /// Whether anyone is registered to be asked.
    pub(crate) fn registered(&self) -> bool {
        lock_recover(&self.approver).is_some()
    }

    fn approver(&self) -> Option<Arc<dyn AgentApprover>> {
        lock_recover(&self.approver).clone()
    }

    /// The system agent's current generation; see [`Asker::System`].
    pub(crate) fn system_epoch(&self) -> u64 {
        lock_recover(&self.line).system_epoch
    }

    /// Puts `request` to the registered approver once it is at the front of
    /// the line, and returns the answer. Blocks for as long as that takes.
    ///
    /// `false` without the approver ever seeing the request when: the system
    /// agent was revoked since its listener started, its connection is gone,
    /// it was withdrawn or revoked while it waited, too many forwarded
    /// requests are waiting already, or no approver is registered.
    ///
    /// The request is handed over with [`AgentSignRequest::waiting`] set to
    /// the number of requests behind it at that moment.
    pub(crate) fn ask(&self, mut request: AgentSignRequest, asker: Asker<'_>) -> bool {
        let id = request.id;
        let system = matches!(asker, Asker::System { .. });
        let admitted = {
            let mut line = lock_recover(&self.line);
            let admitted = match asker {
                Asker::System { epoch, gone } => epoch == line.system_epoch && !gone(),
                Asker::Forwarded => {
                    line.waiting.iter().filter(|w| !w.system).count() < MAX_FORWARDED
                }
            };
            if admitted {
                line.waiting.push_back(Waiting { id, system });
            }
            drop(line);
            admitted
        };
        if !system {
            if admitted {
                self.crowded.store(false, Ordering::Relaxed);
            } else if !self.crowded.swap(true, Ordering::Relaxed) {
                log::warn!(
                    "forwarded agent: too many signature requests waiting; refusing new ones \
                     until the line shortens"
                );
            }
        }
        if !admitted {
            return false;
        }

        // Until it is at the front, or no longer in the line at all (withdrawn
        // or revoked, each of which wakes every waiter).
        let line = self
            .moved
            .wait_while(lock_recover(&self.line), |line: &mut Line| {
                line.place(id).is_some_and(|ahead| ahead > 0)
            })
            .unwrap_or_else(PoisonError::into_inner);
        let behind = line.place(id).map(|_| line.waiting.len().saturating_sub(1));
        drop(line);
        let Some(behind) = behind else {
            return false;
        };
        // Held until the answer: the next request's prompt (and its minute)
        // starts only when this one is over.
        let _turn = Turn {
            approvals: self,
            id,
        };
        request.waiting = u32::try_from(behind).unwrap_or(u32::MAX);
        let Some(approver) = self.approver() else {
            log::info!("agent: no approver registered; signature refused");
            return false;
        };
        approver.approve(request)
    }

    /// The request `id` is no longer wanted (its connection ended). One still
    /// waiting leaves the line and its `ask` returns `false`; the one the
    /// approver is being asked about is cancelled there. Unknown ids are
    /// ignored: a request that has not joined yet is refused at the door by
    /// its own `gone`.
    pub(crate) fn withdraw(&self, id: u64) {
        let shown = {
            let mut line = lock_recover(&self.line);
            let shown = line.place(id) == Some(0);
            if !shown {
                line.waiting.retain(|waiting| waiting.id != id);
            }
            drop(line);
            shown
        };
        self.moved.notify_all();
        if shown {
            self.cancel(id);
        }
    }

    /// Ends every system-agent request there is and closes the line to the
    /// listeners that existed until now: their waiting requests leave it
    /// refused, the one on screen (if it is theirs) is cancelled at the
    /// approver, and a request of theirs arriving later is refused at the
    /// door. A listener started afterwards reads the new epoch and is served.
    /// Forwarded requests are not touched.
    pub(crate) fn revoke_system(&self) {
        let shown = {
            let mut line = lock_recover(&self.line);
            line.system_epoch = line.system_epoch.wrapping_add(1);
            // The front stays where it is: its `Turn` takes it out, so that
            // nothing else is handed over before the approver has let go of it.
            let front = line.waiting.pop_front();
            line.waiting.retain(|waiting| !waiting.system);
            let shown = front
                .as_ref()
                .and_then(|front| front.system.then_some(front.id));
            if let Some(front) = front {
                line.waiting.push_front(front);
            }
            drop(line);
            shown
        };
        self.moved.notify_all();
        if let Some(id) = shown {
            self.cancel(id);
        }
    }

    /// Tells the approver to drop `id`. It copes with an id it has not been
    /// handed yet (it then refuses it on arrival) or is already done with.
    fn cancel(&self, id: u64) {
        let approver = self.approver();
        if let Some(approver) = approver {
            approver.cancel(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentSignOrigin;
    use std::sync::mpsc::{channel, Sender};
    use std::time::{Duration, Instant};

    /// Records what it is handed and answers each request when the test says
    /// so (`answer`), or `false` as soon as that request is cancelled.
    struct Desk {
        handed: Mutex<Vec<AgentSignRequest>>,
        answers: Mutex<Vec<(u64, Sender<bool>)>>,
    }

    impl Desk {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                handed: Mutex::new(Vec::new()),
                answers: Mutex::new(Vec::new()),
            })
        }

        fn handed(&self) -> Vec<u64> {
            self.handed.lock().unwrap().iter().map(|r| r.id).collect()
        }

        /// Blocks until `ids` is exactly what has been handed over so far.
        fn wait_handed(&self, ids: &[u64]) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.handed() != ids {
                assert!(Instant::now() < deadline, "never handed exactly {ids:?}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn answer(&self, id: u64, approved: bool) {
            let mut answers = self.answers.lock().unwrap();
            let at = answers.iter().position(|(open, _)| *open == id).unwrap();
            answers.remove(at).1.send(approved).unwrap();
        }
    }

    impl AgentApprover for Desk {
        fn approve(&self, request: AgentSignRequest) -> bool {
            let (tx, rx) = channel();
            self.answers.lock().unwrap().push((request.id, tx));
            self.handed.lock().unwrap().push(request);
            rx.recv_timeout(Duration::from_secs(10)).unwrap_or(false)
        }

        fn cancel(&self, id: u64) {
            let mut answers = self.answers.lock().unwrap();
            if let Some(at) = answers.iter().position(|(open, _)| *open == id) {
                answers.remove(at).1.send(false).unwrap();
            }
        }
    }

    fn desk() -> (Approvals, Arc<Desk>) {
        let approvals = Approvals::new();
        let desk = Desk::new();
        approvals.set(Some(desk.clone()));
        (approvals, desk)
    }

    fn request(id: u64) -> AgentSignRequest {
        AgentSignRequest {
            id,
            origin: AgentSignOrigin::Forwarded,
            host: String::new(),
            key: String::new(),
            vault: String::new(),
            user: String::new(),
            target: String::new(),
            waiting: 0,
        }
    }

    /// Asks as a system-agent listener started under `epoch` would, for a
    /// connection that stays open.
    fn ask_system(approvals: &Approvals, epoch: u64, id: u64) -> bool {
        approvals.ask(
            request(id),
            Asker::System {
                epoch,
                gone: &|| false,
            },
        )
    }

    /// Blocks until the line holds `len` requests, the front one included.
    fn wait_for_line(approvals: &Approvals, len: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while lock_recover(&approvals.line).waiting.len() != len {
            assert!(Instant::now() < deadline, "the line never reached {len}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_forwarded_and_a_system_request_are_put_to_the_approver_one_after_the_other() {
        let (approvals, desk) = desk();
        std::thread::scope(|scope| {
            let forwarded = scope.spawn(|| approvals.ask(request(1), Asker::Forwarded));
            desk.wait_handed(&[1]);
            let local = scope.spawn(|| ask_system(&approvals, approvals.system_epoch(), 2));
            wait_for_line(&approvals, 2);
            assert_eq!(desk.handed(), [1], "the second waits for the first");

            desk.answer(1, true);
            desk.wait_handed(&[1, 2]);
            desk.answer(2, false);

            assert!(forwarded.join().unwrap(), "the first was approved");
            assert!(!local.join().unwrap(), "the second was refused");
        });
    }

    #[test]
    fn a_request_is_handed_over_with_the_number_waiting_behind_it() {
        let (approvals, desk) = desk();
        std::thread::scope(|scope| {
            let first = scope.spawn(|| approvals.ask(request(1), Asker::Forwarded));
            desk.wait_handed(&[1]);
            let second = scope.spawn(|| approvals.ask(request(2), Asker::Forwarded));
            wait_for_line(&approvals, 2);
            let third = scope.spawn(|| approvals.ask(request(3), Asker::Forwarded));
            wait_for_line(&approvals, 3);

            desk.answer(1, true);
            desk.wait_handed(&[1, 2]);
            desk.answer(2, true);
            desk.wait_handed(&[1, 2, 3]);
            desk.answer(3, true);
            for asked in [first, second, third] {
                assert!(asked.join().unwrap(), "each was approved in its turn");
            }
        });
        let behind: Vec<u32> = desk
            .handed
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.waiting)
            .collect();
        // Nothing had arrived behind the first when it was handed over.
        assert_eq!(behind, [0, 1, 0]);
    }

    #[test]
    fn a_waiting_request_that_is_withdrawn_leaves_the_line_and_is_never_handed_over() {
        let (approvals, desk) = desk();
        std::thread::scope(|scope| {
            let shown = scope.spawn(|| ask_system(&approvals, approvals.system_epoch(), 1));
            desk.wait_handed(&[1]);
            let behind = scope.spawn(|| ask_system(&approvals, approvals.system_epoch(), 2));
            wait_for_line(&approvals, 2);

            approvals.withdraw(2);
            assert!(!behind.join().unwrap(), "the withdrawn request is refused");

            desk.answer(1, true);
            assert!(shown.join().unwrap(), "the one on screen is unaffected");
        });
        assert_eq!(desk.handed(), [1]);
    }

    #[test]
    fn nothing_of_a_revoked_system_agent_reaches_the_approver_until_a_new_listener_starts() {
        let (approvals, desk) = desk();
        let before = approvals.system_epoch();
        std::thread::scope(|scope| {
            let shown = scope.spawn(|| ask_system(&approvals, before, 1));
            desk.wait_handed(&[1]);
            let behind = scope.spawn(|| ask_system(&approvals, before, 2));
            wait_for_line(&approvals, 2);

            approvals.revoke_system();

            assert!(!shown.join().unwrap(), "the prompt on screen is cancelled");
            assert!(!behind.join().unwrap(), "the one in line is refused");
            assert!(
                !ask_system(&approvals, before, 3),
                "a late request of the revoked listener is refused at the door"
            );
        });
        assert_eq!(desk.handed(), [1], "only the first was ever shown");

        std::thread::scope(|scope| {
            let fresh = scope.spawn(|| ask_system(&approvals, approvals.system_epoch(), 4));
            desk.wait_handed(&[1, 4]);
            desk.answer(4, true);
            assert!(
                fresh.join().unwrap(),
                "a listener started afterwards is served"
            );
        });
    }

    #[test]
    fn a_forwarded_request_beyond_the_room_in_line_is_refused_at_once() {
        let (approvals, desk) = desk();
        let approvals = &approvals;
        std::thread::scope(|scope| {
            let waiting: Vec<_> = (1..=MAX_FORWARDED)
                .map(|place| {
                    let id = u64::try_from(place).unwrap();
                    let asked = scope.spawn(move || approvals.ask(request(id), Asker::Forwarded));
                    wait_for_line(approvals, place);
                    asked
                })
                .collect();

            assert!(!approvals.ask(request(0), Asker::Forwarded), "one too many");

            for (id, asked) in (1_u64..).zip(waiting) {
                desk.wait_handed(&(1..=id).collect::<Vec<_>>());
                desk.answer(id, true);
                assert!(asked.join().unwrap(), "the ones in line are still served");
            }
        });
    }
}
