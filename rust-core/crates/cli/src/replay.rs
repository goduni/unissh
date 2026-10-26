//! Replaying a session recording in this terminal.
//!
//! A recording is the asciicast v2 document the core keeps (see
//! `Core::get_recording`): a header line, then one `[seconds, "o", text]` event
//! per piece of output. Replay writes each event when its time comes, scaled by
//! `--speed` and with long pauses cut to `--idle-limit`, the way
//! `asciinema play` does.
//!
//! The recording drives this terminal as the session drove the app's: it may
//! switch to the alternate screen, hide the cursor or turn on mouse reporting.
//! However playback ends — finished, Ctrl-C, SIGTERM or SIGHUP, an error, a
//! panic — the terminal is put back: those modes off, and the keyboard as it
//! was.

use std::io::{self, IsTerminal as _, Write as _};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::failure::{best_effort, Failure, Res};
use crate::tty::{self, RawMode};

/// How fast to replay.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// 2.0 plays twice as fast.
    pub speed: f64,
    /// The longest pause, in recorded seconds; `None` keeps them all.
    pub idle_limit: Option<f64>,
}

/// One piece of output and when to write it, from the start of playback.
struct Frame {
    at: Duration,
    text: String,
}

/// A recording ready to play.
struct Cast {
    width: u32,
    height: u32,
    frames: Vec<Frame>,
}

/// For `--speed` and `--idle-limit`: a positive, finite number.
pub fn positive(text: &str) -> Result<f64, String> {
    match text.trim().parse::<f64>() {
        Ok(n) if n.is_finite() && n > 0.0 => Ok(n),
        Ok(_) | Err(_) => Err(format!("{text:?} is not a positive number")),
    }
}

impl Cast {
    /// Reads an asciicast v2 document and schedules its output.
    ///
    /// Tolerant past the header, as the app's player is: a recording salvaged
    /// from a session that ended badly can have a broken last line, and the
    /// rest of it is still worth seeing. Events other than output (input,
    /// resize, markers) are skipped; the core records none of them.
    fn parse(text: &str, timing: Timing) -> Res<Self> {
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());
        let header = lines
            .next()
            .and_then(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|h| h.get("version").and_then(Value::as_u64) == Some(2))
            .ok_or_else(|| Failure::msg("this is not an asciicast v2 recording"))?;
        let size = |key: &str, default: u32| {
            header
                .get(key)
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(default)
        };
        let events = lines.filter_map(|line| {
            let event = serde_json::from_str::<Value>(line).ok()?;
            let time = event.get(0)?.as_f64()?;
            if event.get(1)?.as_str()? != "o" {
                return None;
            }
            Some((time, event.get(2)?.as_str()?.to_owned()))
        });
        Ok(Self {
            width: size("width", 80),
            height: size("height", 24),
            frames: schedule(events, timing),
        })
    }
}

/// When each event is written: the recorded gaps, each cut to the idle limit,
/// divided by the speed. A timestamp that goes backwards (a damaged recording)
/// is a gap of nothing.
fn schedule(events: impl Iterator<Item = (f64, String)>, timing: Timing) -> Vec<Frame> {
    let mut previous = 0.0_f64;
    let mut at = 0.0_f64;
    events
        .map(|(time, text)| {
            // `max` also turns a NaN into the other operand.
            let gap = (time - previous).max(0.0);
            previous = time.max(previous);
            let gap = timing.idle_limit.map_or(gap, |limit| gap.min(limit));
            at += gap / timing.speed;
            Frame {
                at: Duration::try_from_secs_f64(at).unwrap_or(Duration::MAX),
                text,
            }
        })
        .collect()
}

/// The sequences that switch to the alternate screen, and back.
const ALT_SCREEN_ON: [&str; 3] = ["\x1b[?1049h", "\x1b[?1047h", "\x1b[?47h"];
const ALT_SCREEN_OFF: [&str; 3] = ["\x1b[?1049l", "\x1b[?1047l", "\x1b[?47l"];

/// Whether the terminal is on the alternate screen after `text`, given whether
/// it was before.
fn alt_screen_after(was: bool, text: &str) -> bool {
    let last = |seqs: &[&str]| seqs.iter().filter_map(|s| text.rfind(s)).max();
    match (last(&ALT_SCREEN_ON), last(&ALT_SCREEN_OFF)) {
        (None, None) => was,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (Some(on), Some(off)) => on > off,
    }
}

/// What puts the terminal back after a replay: the main screen (only when the
/// replay left it — leaving it otherwise restores a stale cursor), plain text,
/// a visible cursor, no mouse reporting, no bracketed paste, normal cursor and
/// keypad keys. The shell that gets the terminal next sets what it wants.
fn reset_sequence(alt_screen: bool) -> String {
    let mut reset = String::new();
    if alt_screen {
        reset.push_str("\x1b[?1049l");
    }
    reset.push_str(
        "\x1b[0m\x1b[?25h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1l\x1b>",
    );
    reset
}

/// Ctrl-C, read as a key: the keyboard is raw during a replay.
const CTRL_C: u8 = 0x03;

/// Exit status of a replay stopped with Ctrl-C (128 + SIGINT, as a shell says).
const STOPPED: u8 = 130;

/// The terminal during a replay, put back when dropped — which also happens
/// when a write fails or the replay panics.
struct Screen {
    /// The keyboard, raw so that keys stop the replay instead of echoing into
    /// it; `None` when stdin is not a terminal.
    keys: Option<RawMode>,
    alt_screen: bool,
}

impl Drop for Screen {
    fn drop(&mut self) {
        let mut out = io::stdout().lock();
        best_effort(
            out.write_all(reset_sequence(self.alt_screen).as_bytes())
                .and_then(|()| out.flush()),
        );
        // `keys` drops after this, so the keyboard comes back last.
    }
}

impl Screen {
    /// Waits until `at` after `start`. `Some(status)` when the replay is to
    /// stop: Ctrl-C on the keyboard, or a signal noted in `signal`.
    fn wait_until(
        &mut self,
        start: Instant,
        at: Duration,
        signal: &AtomicU8,
    ) -> io::Result<Option<u8>> {
        loop {
            match signal.load(Ordering::SeqCst) {
                0 => {}
                signo => return Ok(Some(128_u8.saturating_add(signo))),
            }
            let left = at.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Ok(None);
            }
            let tick = left.min(tty::INPUT_TICK);
            if self.keys.is_none() {
                thread::sleep(tick);
            } else if tty::wait_for_input(tick)? {
                let mut buf = [0_u8; 64];
                match tty::read_stdin(&mut buf)? {
                    // The keyboard went away: play on without it.
                    0 => self.keys = None,
                    n => {
                        if buf.get(..n).is_some_and(|keys| keys.contains(&CTRL_C)) {
                            return Ok(Some(STOPPED));
                        }
                    }
                }
            }
        }
    }
}

/// Replays `cast` on stdout. Returns the exit status: 0 when it played to the
/// end, 130 after Ctrl-C, 128 + the signal after SIGTERM or SIGHUP.
pub fn play(cast: &str, timing: Timing) -> Res<u8> {
    if !io::stdout().is_terminal() {
        return Err(Failure::msg(
            "stdout is not a terminal: `unissh recordings export` saves a recording to a file",
        ));
    }
    let cast = Cast::parse(cast, timing)?;
    if let Some((cols, rows)) = tty::window_size() {
        if cols < cast.width || rows < cast.height {
            eprintln!(
                "unissh: recorded at {}x{}, this terminal is {cols}x{rows}: lines may wrap",
                cast.width, cast.height
            );
        }
    }
    let signal = Arc::new(AtomicU8::new(0));
    signals::watch(&signal)?;
    let keys = if io::stdin().is_terminal() {
        RawMode::for_replay().ok()
    } else {
        None
    };
    let mut screen = Screen {
        keys,
        alt_screen: false,
    };
    let start = Instant::now();
    let mut out = io::stdout().lock();
    let mut frames = cast.frames.iter().peekable();
    while let Some(frame) = frames.next() {
        if let Some(status) = screen.wait_until(start, frame.at, &signal)? {
            return Ok(status);
        }
        out.write_all(frame.text.as_bytes())?;
        screen.alt_screen = alt_screen_after(screen.alt_screen, &frame.text);
        // Everything already due goes out in one write, so a replay that fell
        // behind catches up instead of crawling.
        if frames.peek().is_none_or(|next| next.at > start.elapsed()) {
            out.flush()?;
        }
    }
    out.flush()?;
    Ok(0)
}

/// SIGINT, SIGTERM and SIGHUP during a replay: noted, so that the replay stops
/// and puts the terminal back instead of dying with it raw.
#[cfg(unix)]
mod signals {
    use std::future::poll_fn;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;
    use std::task::Poll;
    use std::thread;

    use tokio::signal::unix::{signal, SignalKind};

    use crate::failure::Res;

    /// Starts watching; the first signal's number lands in `noted`. Watched
    /// from here on, for the rest of the process — a replay is the last thing
    /// the command does.
    pub fn watch(noted: &Arc<AtomicU8>) -> Res<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        // Registered before the replay starts, so none is missed.
        let mut watched = {
            let _context = runtime.enter();
            [
                (signal(SignalKind::interrupt())?, 2_u8),
                (signal(SignalKind::terminate())?, 15),
                (signal(SignalKind::hangup())?, 1),
            ]
        };
        let noted = Arc::clone(noted);
        thread::spawn(move || {
            let signo = runtime.block_on(poll_fn(|cx| {
                for (stream, signo) in &mut watched {
                    if stream.poll_recv(cx).is_ready() {
                        return Poll::Ready(*signo);
                    }
                }
                Poll::Pending
            }));
            noted.store(signo, Ordering::SeqCst);
        });
        Ok(())
    }
}

/// Elsewhere a signal ends the process as usual.
#[cfg(not(unix))]
mod signals {
    use std::sync::atomic::AtomicU8;
    use std::sync::Arc;

    use crate::failure::Res;

    /// Nothing to watch here.
    pub const fn watch(_noted: &Arc<AtomicU8>) -> Res<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_TIME: Timing = Timing {
        speed: 1.0,
        idle_limit: None,
    };

    /// The document the core writes: its size from the header, its output
    /// events in order; input and resize events, and a broken last line, are
    /// passed over.
    #[test]
    fn a_recording_parses_into_its_size_and_output() {
        let text = "{\"version\":2,\"width\":120,\"height\":40,\"timestamp\":1}\n\
                    [0.5,\"o\",\"$ ls\\r\\n\"]\n\
                    [0.7,\"i\",\"q\"]\n\
                    [0.8,\"r\",\"80x24\"]\n\
                    [1.0,\"o\",\"a  b\\r\\n\"]\n\
                    [1.2,\"o\",\"trunc";
        let cast = Cast::parse(text, REAL_TIME).unwrap();
        assert_eq!((cast.width, cast.height), (120, 40));
        let texts: Vec<_> = cast.frames.iter().map(|f| f.text.as_str()).collect();
        assert_eq!(texts, ["$ ls\r\n", "a  b\r\n"]);
    }

    #[test]
    fn a_document_without_a_v2_header_is_refused() {
        assert!(Cast::parse("[0.1,\"o\",\"x\"]\n", REAL_TIME).is_err());
        assert!(Cast::parse("{\"version\":1}\n", REAL_TIME).is_err());
    }

    /// Speed divides every gap; the idle limit cuts each long gap before that,
    /// and a timestamp that goes backwards adds no time.
    #[test]
    fn speed_and_idle_limit_scale_and_cut_the_gaps() {
        let events = || {
            [(1.0, "a"), (31.0, "b"), (32.0, "c"), (20.0, "d")]
                .into_iter()
                .map(|(t, s)| (t, s.to_owned()))
        };
        let at = |timing| {
            schedule(events(), timing)
                .iter()
                .map(|f| f.at.as_secs_f64())
                .collect::<Vec<_>>()
        };
        assert_eq!(at(REAL_TIME), [1.0, 31.0, 32.0, 32.0]);
        let fast_and_cut = Timing {
            speed: 2.0,
            idle_limit: Some(2.0),
        };
        assert_eq!(at(fast_and_cut), [0.5, 1.5, 2.0, 2.0]);
    }

    #[test]
    fn speed_and_idle_limit_must_be_positive_numbers() {
        assert_eq!(positive("1.5"), Ok(1.5));
        for bad in ["0", "-1", "inf", "NaN", "fast"] {
            assert!(positive(bad).is_err(), "{bad} is refused");
        }
    }

    /// The alternate screen is left at the end only if the replay is still on
    /// it: the last switch in a chunk wins, and a chunk without one keeps the
    /// state.
    #[test]
    fn the_reset_leaves_the_alternate_screen_only_when_the_replay_is_on_it() {
        let on = alt_screen_after(false, "\x1b[?1049h\x1b[H");
        assert!(on);
        assert!(alt_screen_after(on, "plain text"));
        assert!(!alt_screen_after(on, "\x1b[?1049h…\x1b[?1049l"));
        assert!(alt_screen_after(false, "\x1b[?47l…\x1b[?47h"));
        assert!(reset_sequence(true).starts_with("\x1b[?1049l"));
        assert!(!reset_sequence(false).contains("\x1b[?1049l"));
    }
}
