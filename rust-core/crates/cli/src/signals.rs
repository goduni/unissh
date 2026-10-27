//! The stop signals the CLI catches: Ctrl-C (SIGINT), SIGTERM and, where a
//! command asks for it, SIGHUP. Elsewhere than Unix only Ctrl-C exists.
//!
//! Two forms over the same handlers:
//!
//! - async: [`Stop::install`] inside a runtime, then [`Stop::next`], or
//!   [`first`] for both at once (a command that runs its own runtime);
//! - blocking: [`Caught::install`] owns a small runtime of its own;
//!   [`Caught::wait`] blocks for the next signal, [`Caught::note_first`]
//!   writes the first one's number into an `AtomicU8` from a thread, and
//!   [`Caught::quit_on_next`] ends the process at the next one.
//!
//! The contract: once installed, a handler stays installed for the rest of
//! the process (tokio never takes one back), whatever is dropped. A watched
//! signal no longer ends the process by itself from then on; the command
//! decides what it does, and one that arrives after nobody listens any more
//! is lost. So install only once the command will act on the signal to its
//! end, and install before anything the signal should interrupt has started,
//! so that none is missed.

use std::future::poll_fn;
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::thread;

use tokio::runtime::Runtime;

/// A signal that stops a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// Ctrl-C: SIGINT, or Ctrl-C on Windows.
    Interrupt,
    /// SIGTERM. Unix only.
    Terminate,
    /// SIGHUP: the terminal went away. Unix only.
    HangUp,
}

/// Ctrl-C or SIGTERM: what ends a command that should close cleanly.
pub const STOP: &[Signal] = &[Signal::Interrupt, Signal::Terminate];

/// Ctrl-C, SIGTERM or SIGHUP: for a command that must put things back even
/// when its terminal is gone.
pub const STOP_OR_HANG_UP: &[Signal] = &[Signal::Interrupt, Signal::Terminate, Signal::HangUp];

impl Signal {
    /// The signal's number on Unix (also what Ctrl-C counts as elsewhere).
    pub const fn number(self) -> u8 {
        match self {
            Self::Interrupt => 2,
            Self::Terminate => 15,
            Self::HangUp => 1,
        }
    }

    /// The signal [`number`](Self::number) names, if it is one of these.
    pub const fn from_number(number: u8) -> Option<Self> {
        match number {
            2 => Some(Self::Interrupt),
            15 => Some(Self::Terminate),
            1 => Some(Self::HangUp),
            _ => None,
        }
    }

    /// The status a shell reports for a process this signal ended: 128 + its
    /// number, so 130 after Ctrl-C.
    pub const fn exit_status(self) -> u8 {
        128 + self.number()
    }
}

/// One installed handler.
struct Handler {
    signal: Signal,
    #[cfg(unix)]
    stream: tokio::signal::unix::Signal,
    #[cfg(not(unix))]
    stream: tokio::signal::windows::CtrlC,
}

impl Handler {
    #[cfg(unix)]
    fn install(signal: Signal) -> io::Result<Option<Self>> {
        use tokio::signal::unix::SignalKind;
        let kind = match signal {
            Signal::Interrupt => SignalKind::interrupt(),
            Signal::Terminate => SignalKind::terminate(),
            Signal::HangUp => SignalKind::hangup(),
        };
        Ok(Some(Self {
            signal,
            stream: tokio::signal::unix::signal(kind)?,
        }))
    }

    /// Only Ctrl-C is there to catch; the others are no handler at all.
    #[cfg(not(unix))]
    fn install(signal: Signal) -> io::Result<Option<Self>> {
        match signal {
            Signal::Interrupt => Ok(Some(Self {
                signal,
                stream: tokio::signal::windows::ctrl_c()?,
            })),
            Signal::Terminate | Signal::HangUp => Ok(None),
        }
    }
}

/// Handlers for a set of signals, waited on together.
pub struct Stop {
    handlers: Vec<Handler>,
}

impl Stop {
    /// Installs a handler for each of `signals` (see the module's contract).
    /// Needs a tokio runtime's context, with its IO driver enabled.
    pub fn install(signals: &[Signal]) -> io::Result<Self> {
        let mut handlers = Vec::with_capacity(signals.len());
        for &signal in signals {
            handlers.extend(Handler::install(signal)?);
        }
        Ok(Self { handlers })
    }

    /// The next of the signals to arrive. Pending for ever when none of them
    /// can arrive here (SIGTERM alone, on Windows).
    pub async fn next(&mut self) -> Signal {
        poll_fn(|cx| {
            for handler in &mut self.handlers {
                // `Ready(None)` would mean the runtime is going away: taken
                // as the signal, so that nothing waits on a dead handler.
                if handler.stream.poll_recv(cx).is_ready() {
                    return Poll::Ready(handler.signal);
                }
            }
            Poll::Pending
        })
        .await
    }
}

/// Installs handlers for `signals` and waits for the first of them, inside
/// the caller's runtime.
#[expect(dead_code, reason = "for `unissh mcp`'s shutdown, still on its branch")]
pub async fn first(signals: &[Signal]) -> io::Result<Signal> {
    let mut stop = Stop::install(signals)?;
    Ok(stop.next().await)
}

/// Handlers for a set of signals with a runtime of their own, for a command
/// that does not run one.
pub struct Caught {
    runtime: Runtime,
    stop: Stop,
}

impl Caught {
    /// Installs a handler for each of `signals` (see the module's contract).
    pub fn install(signals: &[Signal]) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        let stop = {
            let _context = runtime.enter();
            Stop::install(signals)?
        };
        Ok(Self { runtime, stop })
    }

    /// Blocks until the next of the signals.
    pub fn wait(&mut self) -> Signal {
        self.runtime.block_on(self.stop.next())
    }

    /// From a thread of its own, writes the first signal's
    /// [`number`](Signal::number) into `noted` (left 0 until then). Signals
    /// after that one are caught and dropped.
    pub fn note_first(self, noted: &Arc<AtomicU8>) {
        let noted = Arc::clone(noted);
        let Self { runtime, mut stop } = self;
        thread::spawn(move || {
            let signal = runtime.block_on(stop.next());
            noted.store(signal.number(), Ordering::SeqCst);
        });
    }

    /// From a thread of its own, ends the process with the status a shell
    /// gives a process the next signal ended (130 after Ctrl-C) as soon as
    /// it arrives: for a second Ctrl-C while a command closes, so that a close
    /// that hangs on a dead connection never holds the terminal.
    pub fn quit_on_next(self) {
        let Self { runtime, mut stop } = self;
        thread::spawn(move || {
            let signal = runtime.block_on(stop.next());
            quit(signal.exit_status());
        });
    }
}

/// Starts noting the first of `signals` into `noted`, from now on: the
/// blocking form of a watch, for a command that polls `noted` as it goes.
pub fn watch(signals: &[Signal], noted: &Arc<AtomicU8>) -> io::Result<()> {
    Caught::install(signals)?.note_first(noted);
    Ok(())
}

#[expect(
    clippy::exit,
    reason = "a second signal quits without waiting for the close; the OS closes the sockets"
)]
fn quit(status: u8) {
    std::process::exit(i32::from(status));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_and_statuses_are_the_shells() {
        for signal in [Signal::Interrupt, Signal::Terminate, Signal::HangUp] {
            let number = signal.number();
            assert_eq!(Signal::from_number(number), Some(signal), "signal {number}");
        }
        assert_eq!(Signal::from_number(0), None, "0 is no signal");
        assert_eq!(Signal::Interrupt.exit_status(), 130, "Ctrl-C");
        assert_eq!(Signal::Terminate.exit_status(), 143, "SIGTERM");
        assert_eq!(Signal::HangUp.exit_status(), 129, "SIGHUP");
    }
}
