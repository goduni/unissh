//! Replaying a session recording in this terminal.
//!
//! A recording is the asciicast v2 document the core keeps (see
//! `Core::get_recording`): a header line, then one `[seconds, "o", text]` event
//! per piece of output. Replay writes each event when its time comes, scaled by
//! `--speed` and with long pauses cut to `--idle-limit`, the way
//! `asciinema play` does.
//!
//! What a recording holds is not trusted: anyone who can write to a shared
//! vault, or a compromised host that was recorded, decides it. So it goes
//! through a [`Filter`] that keeps what draws on the screen and drops what
//! would reach past it — the clipboard (OSC 52), the title and every other OSC
//! string, DCS and the other control strings, and the queries a terminal
//! answers by typing the answer in as input.
//!
//! The recording drives this terminal as the session drove the app's: it may
//! switch to the alternate screen, hide the cursor or turn on mouse reporting.
//! However playback ends — finished, Ctrl-C, SIGTERM or SIGHUP, an error, a
//! panic — the terminal is put back: those modes off, and the keyboard as it
//! was, with nothing the replay provoked left in its input.

use std::io::{self, IsTerminal as _, Write as _};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::failure::{best_effort, Failure, Res};
use crate::tty::{self, ReplayTerminal};

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
    text: Zeroizing<String>,
}

/// A recording ready to play.
struct Cast {
    width: u32,
    height: u32,
    frames: Vec<Frame>,
}

/// What replay reads of the header. The rest of it (an MCP recording's
/// command and output) is skipped over, not copied.
#[derive(Deserialize)]
struct Header {
    version: u64,
    width: Option<u32>,
    height: Option<u32>,
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
            .and_then(|line| serde_json::from_str::<Header>(line).ok())
            .filter(|h| h.version == 2)
            .ok_or_else(|| Failure::msg("this is not an asciicast v2 recording"))?;
        let events = lines.filter_map(|line| {
            let (time, kind, text) = serde_json::from_str::<(f64, String, String)>(line).ok()?;
            let text = Zeroizing::new(text);
            (kind == "o").then_some((time, text))
        });
        Ok(Self {
            width: header.width.unwrap_or(80),
            height: header.height.unwrap_or(24),
            frames: schedule(events, timing),
        })
    }
}

/// When each event is written: the recorded gaps, each cut to the idle limit,
/// divided by the speed. A timestamp that goes backwards (a damaged recording)
/// is a gap of nothing.
fn schedule(events: impl Iterator<Item = (f64, Zeroizing<String>)>, timing: Timing) -> Vec<Frame> {
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

const ESC: char = '\x1b';
const BEL: char = '\x07';
/// ENQ: some terminals (PuTTY) answer it with their answerback string.
const ENQ: char = '\x05';
/// CAN and SUB: cancel a sequence in progress.
const CAN: char = '\x18';
const SUB: char = '\x1a';
/// The 8-bit forms of CSI, ST, DECID and the string introducers (DCS, SOS,
/// OSC, PM, APC): a terminal may act on them as on their `ESC` forms.
const CSI_8BIT: char = '\u{9b}';
const ST_8BIT: char = '\u{9c}';
const DECID_8BIT: char = '\u{9a}';
const STRING_8BIT: [char; 5] = ['\u{90}', '\u{98}', '\u{9d}', '\u{9e}', '\u{9f}'];
/// The 8-bit (C1) controls.
const C1: std::ops::RangeInclusive<char> = '\u{80}'..='\u{9f}';

/// The longest control sequence kept, in bytes; a longer one is dropped.
const SEQUENCE_MAX: usize = 256;

/// Where the [`Filter`] is in the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Text.
    Ground,
    /// After `ESC`, which is held until what follows says what it starts.
    Escape,
    /// In a CSI sequence, held whole until its final byte decides it.
    Csi,
    /// In a CSI sequence too long to keep, dropped up to its final byte.
    CsiDropped,
    /// In an OSC, DCS, SOS, PM or APC string, dropped up to its end.
    String,
    /// After `ESC` in such a string: `\` ends it (ST); anything else ends it
    /// too and starts a new sequence, as a terminal reads it.
    StringEscape,
}

/// What of a recording reaches the terminal: text, and the control sequences
/// that draw — colours, cursor movement, erasing, scrolling, modes. Dropped:
///
/// - every OSC string: the clipboard (52), the title, colours, hyperlinks;
/// - DCS, SOS, PM and APC strings: terminal capability and setting queries
///   (XTGETTCAP, DECRQSS), sixel, and whatever an application puts there;
/// - the CSI queries a terminal answers as if typed: device attributes,
///   status and cursor reports, mode reports, window reports and moves,
///   its version, keyboard flags, and the rest in [`answers`];
/// - DECID (`ESC Z`), which is device attributes again, and ENQ;
/// - the modes that change what the keyboard sends or lock it (see
///   [`keyboard_mode`]).
///
/// An 8-bit control after `ESC` is that control, not `ESC` and a character:
/// `ESC CSI` starts a CSI sequence, as a terminal reads it.
///
/// Sequences are read across frames: one split over two events is held until
/// it is whole. The filter also keeps track of the alternate screen, so the
/// reset at the end knows whether to leave it.
struct Filter {
    state: State,
    /// The CSI sequence being read, introducer included. Never grows past its
    /// first allocation (see [`SEQUENCE_MAX`]), so no copy is left behind.
    sequence: Zeroizing<String>,
    /// Whether the replay has the terminal on the alternate screen.
    alt_screen: bool,
}

impl Filter {
    fn new() -> Self {
        Self {
            state: State::Ground,
            sequence: Zeroizing::new(String::with_capacity(SEQUENCE_MAX + 8)),
            alt_screen: false,
        }
    }

    /// Room in `out` for one frame's worth of `text`: what is kept of it, and
    /// a sequence held over from the frame before.
    const fn room(text: &str) -> usize {
        text.len() + SEQUENCE_MAX + 8
    }

    /// Appends to `out` what of `text` may reach the terminal.
    fn feed(&mut self, text: &str, out: &mut String) {
        for c in text.chars() {
            self.step(c, out);
        }
    }

    fn step(&mut self, c: char, out: &mut String) {
        match self.state {
            State::Ground => self.ground(c, out),
            State::Escape => self.escape(c, out),
            State::Csi => self.csi(c, out),
            State::CsiDropped => match c {
                ESC => self.state = State::Escape,
                CAN | SUB | '\x40'..='\x7e' => self.state = State::Ground,
                c if c.is_ascii_control() => control(c, out),
                c if C1.contains(&c) => {
                    self.state = State::Ground;
                    self.ground(c, out);
                }
                _ => {}
            },
            State::String => match c {
                ESC => self.state = State::StringEscape,
                BEL | ST_8BIT | CAN | SUB => self.state = State::Ground,
                _ => {}
            },
            State::StringEscape => {
                if c == '\\' {
                    self.state = State::Ground;
                } else {
                    self.state = State::Escape;
                    self.escape(c, out);
                }
            }
        }
    }

    fn ground(&mut self, c: char, out: &mut String) {
        match c {
            ESC => self.state = State::Escape,
            CSI_8BIT => self.start_csi(c),
            c if STRING_8BIT.contains(&c) => self.state = State::String,
            DECID_8BIT | ST_8BIT | ENQ => {}
            c => out.push(c),
        }
    }

    fn escape(&mut self, c: char, out: &mut String) {
        match c {
            '[' => self.start_csi(c),
            ']' | 'P' | 'X' | '^' | '_' => self.state = State::String,
            // DECID: a request for the device attributes.
            'Z' => self.state = State::Ground,
            // `ESC ESC`: the second one starts the sequence.
            ESC => {}
            CAN | SUB => self.state = State::Ground,
            // A control in the middle is carried out there, as a terminal does.
            c if c.is_ascii_control() => control(c, out),
            // An 8-bit control replaces the `ESC`: `ESC CSI` is CSI.
            c if C1.contains(&c) => {
                self.state = State::Ground;
                self.ground(c, out);
            }
            c => {
                // RIS, a full reset, also leaves the alternate screen.
                if c == 'c' {
                    self.alt_screen = false;
                }
                out.push(ESC);
                out.push(c);
                self.state = State::Ground;
            }
        }
    }

    fn start_csi(&mut self, c: char) {
        self.sequence.clear();
        if c == '[' {
            self.sequence.push(ESC);
        }
        self.sequence.push(c);
        self.state = State::Csi;
    }

    fn csi(&mut self, c: char, out: &mut String) {
        match c {
            ESC => self.state = State::Escape,
            CAN | SUB => self.state = State::Ground,
            // Parameters and intermediates.
            '\x20'..='\x3f' if self.sequence.len() < SEQUENCE_MAX => self.sequence.push(c),
            '\x20'..='\x3f' => self.state = State::CsiDropped,
            '\x40'..='\x7e' => {
                self.sequence.push(c);
                let body = self
                    .sequence
                    .strip_prefix("\x1b[")
                    .or_else(|| self.sequence.strip_prefix(CSI_8BIT))
                    .unwrap_or_default();
                if !answers(body) && !keyboard_mode(body) {
                    if let Some(on) = alt_screen_switch(body) {
                        self.alt_screen = on;
                    }
                    out.push_str(&self.sequence);
                }
                self.state = State::Ground;
            }
            // DEL is ignored inside a sequence.
            '\x7f' => {}
            c if c.is_ascii_control() => control(c, out),
            // Not part of a sequence: the sequence is broken, and dropped.
            c => {
                self.state = State::Ground;
                self.ground(c, out);
            }
        }
    }
}

/// A C0 control met inside a sequence, carried out there as a terminal does
/// — but ENQ, which a terminal may answer, is dropped.
fn control(c: char, out: &mut String) {
    if c != ENQ {
        out.push(c);
    }
}

/// Whether the CSI sequence `body` (after `CSI`, final byte included) makes
/// the terminal answer as if the user typed it.
fn answers(body: &str) -> bool {
    let Some(last) = body.chars().last() else {
        return false;
    };
    let private = body.chars().next().filter(|c| ('<'..='?').contains(c));
    let between: String = body.chars().filter(|c| (' '..='/').contains(c)).collect();
    match (last, private, between.as_str()) {
        // Device attributes (DA1, DA2, DA3); device status, cursor position
        // and every other `n` report; window reports (XTWINOPS — dropped
        // whole: the rest of it moves and resizes the window).
        ('c' | 'n' | 't', _, _)
        // Mode (DECRQM), presentation state (DECRQPSR) and tab stop
        // (DECRQTSR) reports.
        | ('p' | 'w' | 'u', _, "$")
        // User-preferred supplemental set (DECRQUPSS), checksum (DECRQCRA),
        // locator position (DECRQLP), SGR report (XTREPORTSGR).
        | ('u', _, "&")
        | ('y', _, "*")
        | ('|', _, "'" | "#")
        // Version (XTVERSION), keyboard flags (kitty), key modifiers
        // (XTQMODKEYS), graphics attributes (XTSMGRAPHICS).
        | ('q', Some('>'), _)
        | ('u' | 'm' | 'S', Some('?'), _)
        // Terminal parameters (DECREQTPARM).
        | ('x', None, "") => true,
        _ => false,
    }
}

/// Whether the CSI sequence `body` sets or resets a mode that changes what
/// the keyboard sends or locks it, which the reset could not be trusted to
/// undo: KAM (2, keyboard locked), SRM (12, local echo), LNM (20, Enter sends
/// CR LF), DECANM (`?2`, VT52 — after which no ANSI reset is read). The whole
/// sequence goes, whatever else it sets.
fn keyboard_mode(body: &str) -> bool {
    let Some(params) = body.strip_suffix(['h', 'l']) else {
        return false;
    };
    let (params, dangerous): (&str, &[&str]) = match params.strip_prefix('?') {
        Some(params) => (params, &["2"]),
        None => (params, &["2", "12", "20"]),
    };
    params.split(';').any(|p| dangerous.contains(&p))
}

/// `Some(true)` when the CSI sequence `body` switches to the alternate
/// screen, `Some(false)` when it switches back, `None` otherwise.
fn alt_screen_switch(body: &str) -> Option<bool> {
    let modes = body.strip_prefix('?')?;
    let (modes, on) = if let Some(modes) = modes.strip_suffix('h') {
        (modes, true)
    } else {
        (modes.strip_suffix('l')?, false)
    };
    modes
        .split(';')
        .any(|mode| matches!(mode, "1049" | "1047" | "47"))
        .then_some(on)
}

/// What puts the terminal back after a replay. First out of VT52 mode
/// (`ESC <`, ignored otherwise; the filter drops the switch into it, this is
/// for a terminal left there before) and out of synchronized output, so the
/// rest is read and shown. The main screen, only when the replay left it:
/// leaving it otherwise restores a stale cursor. Then plain text in the ASCII
/// set; a visible, default-shaped cursor; normal video; no mouse or focus
/// reporting, no bracketed paste, no kitty or modifyOtherKeys keyboard
/// modes; normal cursor and keypad keys; line wrap on, insert mode off. Last
/// the left/right margins, the scroll region and origin mode, between a
/// cursor save and restore (`ESC 7`/`ESC 8`, which mean the same with
/// margins on), since they move the cursor home. The shell that gets the
/// terminal next sets what it wants.
fn reset_sequence(alt_screen: bool) -> String {
    let mut reset = String::from("\x1b<\x1b[?2026l");
    if alt_screen {
        reset.push_str("\x1b[?1049l");
    }
    reset.push_str(concat!(
        "\x1b[0m\x0f\x1b(B",
        "\x1b[?25h\x1b[0 q\x1b[?5l",
        "\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l",
        "\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1016l",
        "\x1b[?1004l\x1b[?2004l",
        "\x1b[<99u\x1b[>4m",
        "\x1b[?1l\x1b>",
        "\x1b[?7h\x1b[4l",
        "\x1b7\x1b[?69l\x1b[?6l\x1b[r\x1b8",
    ));
    reset
}

/// Ctrl-C, read as a key: the keyboard is raw during a replay.
const CTRL_C: u8 = 0x03;

/// Exit status of a replay stopped with Ctrl-C (128 + SIGINT, as a shell says).
const STOPPED: u8 = 130;

/// How long a failed write waits to see whether a signal explains it: the
/// hang-up that makes the terminal fail and its SIGHUP arrive apart.
const SIGNAL_GRACE: Duration = Duration::from_millis(100);

/// The terminal during a replay, put back when dropped — which also happens
/// when a write fails or the replay panics.
struct Screen {
    term: ReplayTerminal,
    filter: Filter,
    /// The terminal stopped giving keys (it hung up): play on without them.
    hung_up: bool,
}

impl Drop for Screen {
    fn drop(&mut self) {
        best_effort(
            self.term
                .write_all(reset_sequence(self.filter.alt_screen).as_bytes())
                .and_then(|()| self.term.flush()),
        );
        // `term` drops after this: it drains what the terminal still says,
        // then gives the keyboard back.
    }
}

impl Screen {
    /// Plays `frames`; the exit status as [`play`] gives it.
    fn run(&mut self, frames: &[Frame], signal: &AtomicU8) -> io::Result<u8> {
        let start = Instant::now();
        for frame in frames {
            if let Some(status) = self.wait_until(start, frame.at, signal)? {
                return Ok(status);
            }
            // A frame already due does not wait, so a replay that fell behind
            // catches up instead of crawling.
            let mut out = Zeroizing::new(String::with_capacity(Filter::room(&frame.text)));
            self.filter.feed(&frame.text, &mut out);
            self.term.write_all(out.as_bytes())?;
            self.term.flush()?;
        }
        Ok(0)
    }

    /// Waits until `at` after `start`. `Some(status)` when the replay is to
    /// stop: Ctrl-C on the keyboard, or a signal noted in `signal`.
    fn wait_until(
        &mut self,
        start: Instant,
        at: Duration,
        signal: &AtomicU8,
    ) -> io::Result<Option<u8>> {
        loop {
            if let Some(status) = signalled(signal) {
                return Ok(Some(status));
            }
            let left = at.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Ok(None);
            }
            let tick = left.min(tty::INPUT_TICK);
            if self.hung_up {
                thread::sleep(tick);
                continue;
            }
            let mut keys = [0_u8; 64];
            match self.term.keys(tick, &mut keys)? {
                None => self.hung_up = true,
                Some(n) => {
                    if keys.get(..n).is_some_and(|keys| keys.contains(&CTRL_C)) {
                        return Ok(Some(STOPPED));
                    }
                }
            }
        }
    }
}

/// The exit status for a signal noted in `signal` (128 + its number).
fn signalled(signal: &AtomicU8) -> Option<u8> {
    match signal.load(Ordering::SeqCst) {
        0 => None,
        signo => Some(128_u8.saturating_add(signo)),
    }
}

/// [`signalled`], waiting up to [`SIGNAL_GRACE`] for one: after a failure,
/// so that a hang-up exits 129 even when the failed write came first.
fn signalled_soon(signal: &AtomicU8) -> Option<u8> {
    let start = Instant::now();
    loop {
        if let Some(status) = signalled(signal) {
            return Some(status);
        }
        if start.elapsed() >= SIGNAL_GRACE {
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Replays `cast` on the terminal. Returns the exit status: 0 when it played
/// to the end, 130 after Ctrl-C, 128 + the signal after SIGTERM or SIGHUP.
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
    let term = ReplayTerminal::open()
        .map_err(|e| Failure::msg(format!("a replay needs the controlling terminal: {e}")))?;
    let mut screen = Screen {
        term,
        filter: Filter::new(),
        hung_up: false,
    };
    match screen.run(&cast.frames, &signal) {
        Ok(status) => Ok(status),
        Err(e) => signalled_soon(&signal).ok_or_else(|| e.into()),
    }
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

    /// What reaches the terminal of `frames`, played in order through one
    /// filter.
    fn filtered(frames: &[&str]) -> String {
        let mut filter = Filter::new();
        let mut out = String::new();
        for frame in frames {
            filter.feed(frame, &mut out);
        }
        out
    }

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
                .map(|(t, s)| (t, Zeroizing::new(s.to_owned())))
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

    /// A recording cannot set the clipboard, the title or anything else
    /// through OSC, however the string ends (BEL, ST, 8-bit ST) or is cut
    /// short by the next sequence; the 8-bit OSC introducer counts too.
    #[test]
    fn osc_strings_are_dropped() {
        assert_eq!(
            filtered(&[
                "a\x1b]52;c;cm0gLXJmIH4=\x07b",
                "\x1b]0;title\x1b\\c",
                "\u{9d}8;;https://x\u{9c}d",
                "\x1b]52;c;eA==\x1b[1me",
                "\x1b\u{9d}52;c;QUJD\x07f",
            ]),
            "abcd\x1b[1mef"
        );
    }

    /// DCS (capability and setting queries, XTGETTCAP and DECRQSS among
    /// them), SOS, PM and APC strings never reach the terminal.
    #[test]
    fn dcs_sos_pm_and_apc_strings_are_dropped() {
        assert_eq!(
            filtered(&[
                "a\x1bP+q544e\x1b\\",
                "\x1bP$qm\x1b\\b",
                "\x1bXsos\x1b\\\x1b^pm\x1b\\\x1b_Gapc\x1b\\c",
                "\u{90}+q6b\u{9c}d",
                "\x1b\u{90}$qm\x1b\\e",
            ]),
            "abcde"
        );
    }

    /// Nothing that makes the terminal type an answer gets through: device
    /// attributes, status and cursor reports, mode and window reports, the
    /// version, keyboard flags, DECID, ENQ — in 8-bit form too, also after
    /// an `ESC` (`ESC CSI` is CSI) and one that ends a string.
    #[test]
    fn queries_the_terminal_would_answer_are_dropped() {
        let queries = [
            "\x1b[c",
            "\x1b[0c",
            "\x1b[>c",
            "\x1b[=c",
            "\x1b[5n",
            "\x1b[6n",
            "\x1b[?6n",
            "\x1b[?2026$p",
            "\x1b[4$p",
            "\x1b[14t",
            "\x1b[21t",
            "\x1b[>q",
            "\x1b[?u",
            "\x1b[?4m",
            "\x1b[x",
            "\x1bZ",
            "\u{9b}6n",
            "\u{9a}",
            "\x1b\u{9b}6n",
            "\x1b\u{9a}",
            "\x1b]0;x\x1b\u{9b}6n",
            "\x05",
            "\x1b[\x056n",
        ];
        for query in queries {
            assert_eq!(filtered(&["a", query, "b"]), "ab", "{query:?} is dropped");
        }
    }

    /// What draws passes as it came: text, line ends, colours, cursor moves
    /// and saves, erasing, scroll regions, charsets, screen and mouse modes.
    #[test]
    fn ordinary_output_passes_unchanged() {
        let output = "$ ls\r\n\x1b[1;31mred\x1b[0m \u{e9}\u{1f600}\x1b[2J\x1b[H\x1b[10;5H\
                      \x1b[K\x1b7\x1b8\x1b[2;20r\x1b(0q\x1b(B\x1b[?25l\x1b[?1049h\
                      \x1b[?1000h\x1b[38;2;1;2;3m\x1b[3 q\x1bM\x07\x08\t";
        assert_eq!(filtered(&[output]), output);
    }

    /// The modes that change what the keyboard sends or lock it — KAM, SRM,
    /// LNM, VT52 — never reach the terminal, even among other modes; modes
    /// that only share a digit with them still pass.
    #[test]
    fn modes_that_change_the_keyboard_are_dropped() {
        for mode in [
            "\x1b[2h",
            "\x1b[12l",
            "\x1b[20h",
            "\x1b[4;20h",
            "\x1b[?2l",
            "\x1b[?1;2l",
        ] {
            assert_eq!(filtered(&["a", mode, "b"]), "ab", "{mode:?} is dropped");
        }
        let kept = "\x1b[4h\x1b[?2004h\x1b[?12l\x1b[?20h";
        assert_eq!(filtered(&[kept]), kept);
    }

    /// A sequence split between two events is judged as one: a query is
    /// still dropped, a colour still kept, a string still dropped to its end.
    #[test]
    fn a_sequence_split_across_frames_is_filtered_as_one() {
        assert_eq!(
            filtered(&[
                "a\x1b",
                "[6nb\x1b[3",
                "1mc\x1b]52;c;",
                "eA==",
                "\x1b",
                "\\d"
            ]),
            "ab\x1b[31mcd"
        );
    }

    /// The alternate screen is left at the end only if the replay is still on
    /// it, by the last switch, even one split across events; the reset leaves
    /// VT52 and synchronized output first, and puts back charset, cursor
    /// shape, video, keyboard, mouse, wrap, margin and scroll-region modes.
    #[test]
    fn the_reset_leaves_the_alternate_screen_only_when_the_replay_is_on_it() {
        let mut filter = Filter::new();
        let mut out = String::new();
        filter.feed("\x1b[?10", &mut out);
        assert!(!filter.alt_screen);
        filter.feed("49h\x1b[H", &mut out);
        assert!(filter.alt_screen, "a switch split across events counts");
        filter.feed("plain text", &mut out);
        assert!(filter.alt_screen);
        filter.feed("\x1b[?1049h…\x1b[?1049l", &mut out);
        assert!(!filter.alt_screen);
        filter.feed("\x1b[?47l…\x1b[?1;47h", &mut out);
        assert!(filter.alt_screen);
        filter.feed("\x1bc", &mut out);
        assert!(!filter.alt_screen, "a full reset leaves it");

        assert!(reset_sequence(true).starts_with("\x1b<\x1b[?2026l\x1b[?1049l"));
        let reset = reset_sequence(false);
        assert!(!reset.contains("\x1b[?1049l"));
        assert!(reset.starts_with("\x1b<"), "VT52 is left first");
        for part in [
            "\x0f\x1b(B",
            "\x1b[?25h",
            "\x1b[0 q",
            "\x1b[?5l",
            "\x1b[?9l",
            "\x1b[?1016l",
            "\x1b[?1000l",
            "\x1b[?1003l",
            "\x1b[?1004l",
            "\x1b[?1005l",
            "\x1b[?1006l",
            "\x1b[?1015l",
            "\x1b[?2004l",
            "\x1b[<99u",
            "\x1b[>4m",
            "\x1b[?7h",
            "\x1b[4l",
            "\x1b7\x1b[?69l\x1b[?6l\x1b[r\x1b8",
        ] {
            assert!(reset.contains(part), "the reset has {part:?}");
        }
    }
}
