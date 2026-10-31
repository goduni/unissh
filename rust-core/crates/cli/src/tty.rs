//! The terminal: prompts that do not echo, and raw mode for a session.
//!
//! Prompts talk to the controlling terminal (`/dev/tty` or `CONIN$`/`CONOUT$`), not to stdin and
//! stdout, so `cat file | unissh ssh host -- cmd` can still ask for a password
//! and nothing a prompt prints ends up in a pipe. Every terminal setting this
//! module changes is put back when its guard is dropped.

use std::io;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::failure::{Failure, Res};

pub use imp::{
    read_stdin, stdin_is_foreground, wait_for_input, window_size, RawMode, ReplayTerminal, Tty,
    SUPPORTED,
};

/// `text` without control characters, for one line that came from a server,
/// a vault or a remote host: printed raw, an escape sequence in it could move
/// the cursor, rewrite what is on screen or fake a prompt. Bidi controls and
/// zero-width characters go too: they could reorder or hide part of a name.
pub fn one_line(text: &str) -> String {
    text.chars().filter(|c| shown(*c)).collect()
}

/// [`one_line`] for text that may span lines: line breaks stay.
pub fn lines(text: &str) -> String {
    text.chars().filter(|c| *c == '\n' || shown(*c)).collect()
}

/// Whether a character of untrusted text may reach the terminal: not a C0, DEL
/// or C1 control, not a bidi embedding, override, isolate or mark (U+061C,
/// U+200E/F, U+202A–U+202E, U+2066–U+2069), and not an invisible format
/// character (U+00AD, U+200B–U+200D, U+2060–U+2064, U+FEFF). The same set as
/// the approval notation, `unissh_automation::visible`, escapes.
fn shown(c: char) -> bool {
    !c.is_control()
        && !matches!(
            c,
            '\u{ad}'
                | '\u{61c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

// The quiet-prompt editor is shared by the Unix and Windows terminals.
// It is pure, so its tests run everywhere.

/// What one key does at a quiet prompt.
#[cfg(any(unix, windows, test))]
#[derive(Debug, PartialEq, Eq)]
enum Key {
    /// Keep reading.
    More,
    /// The line is complete.
    Enter,
    /// Ctrl-C: give up.
    Cancel,
    /// Ctrl-D on an empty line: no more input.
    End,
}

#[cfg(any(unix, windows, test))]
const CTRL_C: u8 = 0x03;
#[cfg(any(unix, windows, test))]
const CTRL_D: u8 = 0x04;
#[cfg(any(unix, windows, test))]
const BACKSPACE: u8 = 0x08;
#[cfg(any(unix, windows, test))]
const CTRL_U: u8 = 0x15;
#[cfg(any(unix, windows, test))]
const DELETE: u8 = 0x7f;

/// Line editing for a prompt that echoes nothing. The terminal's own line
/// editing is off there, and so are its signals: a Ctrl-C that killed the
/// process would leave the terminal with echo off. So this does what the
/// terminal would — Backspace and Ctrl-U edit, Enter ends the line (a CR LF
/// pair once), Ctrl-D on an empty line ends input — and Ctrl-C cancels, with
/// the terminal put back by whoever turned echo off.
#[cfg(any(unix, windows, test))]
struct QuietLine {
    text: Zeroizing<Vec<u8>>,
    after_cr: bool,
}

#[cfg(any(unix, windows, test))]
impl QuietLine {
    fn new() -> Self {
        Self {
            // Room up front: a reallocation would leave a copy of the secret
            // behind that is never wiped.
            text: Zeroizing::new(Vec::with_capacity(256)),
            after_cr: false,
        }
    }

    fn key(&mut self, byte: u8) -> Key {
        let after_cr = std::mem::take(&mut self.after_cr);
        match byte {
            b'\n' if after_cr => Key::More,
            b'\r' => {
                self.after_cr = true;
                Key::Enter
            }
            b'\n' => Key::Enter,
            CTRL_C => Key::Cancel,
            CTRL_D if self.text.is_empty() => Key::End,
            BACKSPACE | DELETE => {
                // A whole character, not the last byte of one.
                while let Some(b) = self.text.pop() {
                    if b & 0xC0 != 0x80 {
                        break;
                    }
                }
                Key::More
            }
            CTRL_U => {
                self.text.clear();
                Key::More
            }
            b if b.is_ascii_control() => Key::More,
            b => {
                self.text.push(b);
                Key::More
            }
        }
    }

    /// How many characters the line holds (UTF-8 continuation bytes are part
    /// of the character before them).
    #[cfg(any(unix, windows))]
    fn chars(&self) -> usize {
        self.text.iter().filter(|b| **b & 0xC0 != 0x80).count()
    }

    /// The line so far, leaving an empty one.
    fn take(&mut self) -> Zeroizing<Vec<u8>> {
        std::mem::replace(&mut self.text, Zeroizing::new(Vec::with_capacity(256)))
    }
}

#[cfg(any(unix, windows))]
fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "cancelled")
}

#[cfg(any(unix, windows))]
fn ended() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "cancelled")
}

/// Whether a typed answer means yes.
fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Before a destructive command: shows `warning` and asks to go on, on the
/// terminal. With `yes` it goes on without asking, but the warning is still
/// printed (to stderr): `--yes` skips the question, not what the user is told.
pub fn confirm(yes: bool, warning: &str) -> Res<()> {
    if goes_on(yes, warning)? {
        Ok(())
    } else {
        Err(Failure::msg("nothing changed"))
    }
}

/// [`confirm`]'s question, for a command where no is an answer rather than
/// a failure: whether to go on.
pub fn goes_on(yes: bool, warning: &str) -> Res<bool> {
    if yes {
        eprint!("{warning}");
        return Ok(true);
    }
    let mut tty = Tty::open()
        .map_err(|e| Failure::msg(format!("cannot ask for confirmation ({e}); pass --yes")))?;
    tty.say(warning)?;
    Ok(tty.confirm("Continue? [y/N] ")?)
}

impl Tty {
    /// Prints `prompt` and reads a line, echoed.
    pub fn line(&mut self, prompt: &str) -> io::Result<String> {
        self.say(prompt)?;
        let mut bytes = self.read_line(false)?;
        String::from_utf8(std::mem::take(&mut *bytes))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Prints `prompt` and reads a line without echoing it.
    pub fn secret(&mut self, prompt: &str) -> io::Result<Zeroizing<String>> {
        self.say(prompt)?;
        let bytes = self.read_line(true);
        // The Enter that ended the line was not echoed either.
        self.say("\n")?;
        let bytes = bytes?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Zeroizing::new(text.to_owned()))
    }

    /// Reads a pasted block that echoes nothing, such as a pairing text with a
    /// secret in it: line by line until `complete` accepts the text so far, an
    /// empty line or Ctrl-D. A dot shows for each line received.
    pub fn pasted_secret(
        &mut self,
        mut complete: impl FnMut(&str) -> bool,
    ) -> io::Result<Zeroizing<String>> {
        let bytes =
            self.read_quiet_lines(&mut |text| std::str::from_utf8(text).is_ok_and(&mut complete));
        self.say("\n")?;
        let mut bytes = bytes?;
        String::from_utf8(std::mem::take(&mut *bytes))
            .map(Zeroizing::new)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Prints `prompt` and reads a line a key at a time, echoed when `echo`,
    /// until Enter — or `None` once `deadline` passes or `stop` says so. Works
    /// whatever mode the terminal is in (a full-screen program may hold it
    /// raw), and what was typed before the prompt appeared is discarded, so
    /// keys meant for something else cannot answer it.
    pub fn line_until(
        &mut self,
        prompt: &str,
        echo: bool,
        deadline: Instant,
        stop: &dyn Fn() -> bool,
    ) -> io::Result<Option<Zeroizing<String>>> {
        self.say(prompt)?;
        let bytes = self.read_line_until(echo, deadline, stop);
        self.say("\r\n")?;
        let Some(bytes) = bytes? else {
            return Ok(None);
        };
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Some(Zeroizing::new(text.to_owned())))
    }

    /// Asks a yes/no question; anything but `y`/`yes` is no.
    pub fn confirm(&mut self, prompt: &str) -> io::Result<bool> {
        Ok(is_yes(&self.line(prompt)?))
    }

    /// Asks for a new secret twice, until both match and it is not empty.
    pub fn new_secret(&mut self, prompt: &str) -> io::Result<Zeroizing<String>> {
        loop {
            let first = self.secret(prompt)?;
            if first.is_empty() {
                self.say("It cannot be empty.\n")?;
            } else if *first == *self.secret("Again: ")? {
                return Ok(first);
            } else {
                self.say("They do not match. Once more.\n")?;
            }
        }
    }
}

#[cfg(unix)]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::{AsFd, BorrowedFd};
    use std::time::{Duration, Instant};

    use rustix::event::Timespec;
    #[cfg(not(target_os = "macos"))]
    use rustix::event::{poll, PollFd, PollFlags};
    use rustix::io::Errno;
    use rustix::termios::{
        tcgetattr, tcgetwinsize, tcsetattr, OptionalActions, OutputModes, Termios,
    };

    use super::{cancelled, ended, Key, QuietLine, STOP_TICK};
    use crate::failure::best_effort;
    use zeroize::Zeroizing;

    /// Whether this platform has the terminal an interactive session needs.
    pub const SUPPORTED: bool = true;

    /// The controlling terminal.
    pub struct Tty {
        file: File,
    }

    impl Tty {
        /// Opens the controlling terminal; fails when there is none (cron, a
        /// pipeline without a terminal).
        pub fn open() -> io::Result<Self> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .map(|file| Self { file })
        }

        /// Prints `text` as is.
        pub fn say(&mut self, text: &str) -> io::Result<()> {
            self.file.write_all(text.as_bytes())?;
            self.file.flush()
        }

        /// Waits up to `timeout` for the user to type something; `false` when
        /// the time ran out.
        pub fn wait(&self, timeout: Duration) -> io::Result<bool> {
            ready(self.file.as_fd(), timeout)
        }

        /// Reads one line, without its line ending. End of input before any
        /// character is an `UnexpectedEof` — the user pressed Ctrl-D; Ctrl-C
        /// at a quiet prompt is an `Interrupted`.
        pub(super) fn read_line(&self, quiet: bool) -> io::Result<Zeroizing<Vec<u8>>> {
            if quiet {
                let _quiet = Quiet::on(&self.file)?;
                return self.read_quiet_line(&mut QuietLine::new());
            }
            let mut line = Zeroizing::new(Vec::with_capacity(256));
            let mut byte = [0_u8; 1];
            loop {
                if (&self.file).read(&mut byte)? == 0 {
                    if line.is_empty() {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "cancelled"));
                    }
                    return Ok(line);
                }
                match byte {
                    [b'\n'] => return Ok(line),
                    [b'\r'] => {}
                    [b] => line.push(b),
                }
            }
        }

        /// Lines with nothing echoed, in one quiet stretch so a pasted block
        /// keeps its later lines, until `complete` accepts the text, an empty
        /// line or end of input.
        pub(super) fn read_quiet_lines(
            &self,
            complete: &mut dyn FnMut(&[u8]) -> bool,
        ) -> io::Result<Zeroizing<Vec<u8>>> {
            let _quiet = Quiet::on(&self.file)?;
            let mut editor = QuietLine::new();
            let mut text = Zeroizing::new(Vec::with_capacity(1024));
            loop {
                let line = match self.read_quiet_line(&mut editor) {
                    Ok(line) => line,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(text),
                    Err(e) => return Err(e),
                };
                if line.is_empty() {
                    if text.is_empty() {
                        continue;
                    }
                    return Ok(text);
                }
                text.extend_from_slice(&line);
                text.push(b'\n');
                (&self.file).write_all(b".")?;
                if complete(&text) {
                    return Ok(text);
                }
            }
        }

        /// One line a key at a time ([`QuietLine`]) with the terminal's own
        /// echo, editing and signals off, echoing what the editor keeps when
        /// `echo`; `None` at `deadline` or once `stop` turns true.
        pub(super) fn read_line_until(
            &self,
            echo: bool,
            deadline: Instant,
            stop: &dyn Fn() -> bool,
        ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
            let _quiet = Quiet::on(&self.file)?;
            let mut editor = QuietLine::new();
            let mut byte = [0_u8; 1];
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if stop() || left.is_zero() {
                    return Ok(None);
                }
                if !ready(self.file.as_fd(), left.min(STOP_TICK))? {
                    continue;
                }
                if (&self.file).read(&mut byte)? == 0 {
                    return Err(ended());
                }
                let [key] = byte;
                let (bytes, chars) = (editor.text.len(), editor.chars());
                match editor.key(key) {
                    Key::More if echo => {
                        if editor.text.len() > bytes {
                            (&self.file).write_all(&byte)?;
                        }
                        for _ in editor.chars()..chars {
                            (&self.file).write_all(b"\x08 \x08")?;
                        }
                    }
                    Key::More => {}
                    Key::Enter => return Ok(Some(editor.take())),
                    Key::Cancel => return Err(cancelled()),
                    Key::End => return Err(ended()),
                }
            }
        }

        /// One line at a quiet prompt, a key at a time ([`QuietLine`]).
        fn read_quiet_line(&self, editor: &mut QuietLine) -> io::Result<Zeroizing<Vec<u8>>> {
            let mut byte = [0_u8; 1];
            loop {
                if (&self.file).read(&mut byte)? == 0 {
                    let line = editor.take();
                    return if line.is_empty() {
                        Err(ended())
                    } else {
                        Ok(line)
                    };
                }
                let [key] = byte;
                match editor.key(key) {
                    Key::More => {}
                    Key::Enter => return Ok(editor.take()),
                    Key::Cancel => return Err(cancelled()),
                    Key::End => return Err(ended()),
                }
            }
        }
    }

    /// A terminal that echoes nothing and does no line editing or signals of
    /// its own, until dropped ([`QuietLine`] does the editing).
    struct Quiet<'fd> {
        fd: BorrowedFd<'fd>,
        saved: Termios,
    }

    impl<'fd> Quiet<'fd> {
        fn on(file: &'fd File) -> io::Result<Self> {
            let fd = file.as_fd();
            let saved = tcgetattr(fd)?;
            let mut quiet = saved.clone();
            // Raw: no echo, no ICANON editing, no ISIG — a key at a time.
            quiet.make_raw();
            // TCSAFLUSH, as `ssh` does for a passphrase: what was typed ahead
            // of the prompt is not taken as the beginning of the secret.
            tcsetattr(fd, OptionalActions::Flush, &quiet)?;
            Ok(Self { fd, saved })
        }
    }

    impl Drop for Quiet<'_> {
        fn drop(&mut self) {
            best_effort(tcsetattr(self.fd, OptionalActions::Flush, &self.saved));
        }
    }

    /// stdin in raw mode until dropped: every key goes to the remote as typed,
    /// Ctrl-C included.
    pub struct RawMode {
        saved: Termios,
    }

    impl RawMode {
        /// Switches stdin to raw mode.
        pub fn enter() -> io::Result<Self> {
            let stdin = io::stdin();
            let saved = tcgetattr(stdin.as_fd())?;
            let mut raw = saved.clone();
            raw.make_raw();
            tcsetattr(stdin.as_fd(), OptionalActions::Now, &raw)?;
            Ok(Self { saved })
        }
    }

    impl Drop for RawMode {
        fn drop(&mut self) {
            best_effort(tcsetattr(
                io::stdin().as_fd(),
                OptionalActions::Now,
                &self.saved,
            ));
        }
    }

    /// The controlling terminal during a replay, written to and read from
    /// directly — not stdin — so that whatever the terminal says back is read
    /// here and never waits in a queue for the shell.
    ///
    /// Keys are raw: one typed meanwhile neither echoes into the replay nor
    /// raises a signal. Output is still processed, so output that is not from
    /// a terminal (a recorded command's bare `\n`) starts its lines at the left
    /// edge. Dropped, it reads and discards input for [`DRAIN`], then puts the
    /// settings back discarding what is still pending (TCSAFLUSH): nothing
    /// from the replay reaches the shell as typed input.
    pub struct ReplayTerminal {
        file: File,
        saved: Termios,
    }

    /// How long a replay goes on reading input after its last write: answers
    /// already on their way from the terminal arrive within it.
    const DRAIN: Duration = Duration::from_millis(150);

    impl ReplayTerminal {
        /// Opens the controlling terminal and makes its keys raw.
        pub fn open() -> io::Result<Self> {
            let file = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
            let saved = tcgetattr(file.as_fd())?;
            let mut raw = saved.clone();
            raw.make_raw();
            raw.output_modes.insert(OutputModes::OPOST);
            tcsetattr(file.as_fd(), OptionalActions::Now, &raw)?;
            Ok(Self { file, saved })
        }

        /// Waits up to `timeout` for keys and reads them into `buf`:
        /// `Some(0)` when none came, `None` when the terminal hung up.
        pub fn keys(&self, timeout: Duration, buf: &mut [u8]) -> io::Result<Option<usize>> {
            if !ready(self.file.as_fd(), timeout)? {
                return Ok(Some(0));
            }
            Ok(match read_fd(self.file.as_fd(), buf)? {
                0 => None,
                n => Some(n),
            })
        }
    }

    impl Write for ReplayTerminal {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            (&self.file).write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            (&self.file).flush()
        }
    }

    impl Drop for ReplayTerminal {
        fn drop(&mut self) {
            let fd = self.file.as_fd();
            let start = Instant::now();
            let mut discarded = [0_u8; 256];
            loop {
                let left = DRAIN.saturating_sub(start.elapsed());
                // Nothing more, the time is up, or the terminal is gone.
                if !matches!(ready(fd, left), Ok(true))
                    || !matches!(read_fd(fd, &mut discarded), Ok(n) if n > 0)
                {
                    break;
                }
            }
            best_effort(tcsetattr(fd, OptionalActions::Flush, &self.saved));
        }
    }

    /// The terminal's size as `(columns, rows)`, when stdin or stdout is one.
    pub fn window_size() -> Option<(u32, u32)> {
        let size = tcgetwinsize(io::stdout().as_fd())
            .or_else(|_| tcgetwinsize(io::stdin().as_fd()))
            .ok()?;
        (size.ws_col > 0 && size.ws_row > 0)
            .then_some((u32::from(size.ws_col), u32::from(size.ws_row)))
    }

    /// Waits up to `timeout` for stdin to become readable.
    pub fn wait_for_input(timeout: Duration) -> io::Result<bool> {
        ready(io::stdin().as_fd(), timeout)
    }

    /// Whether stdin is this process's controlling terminal (not a pipe, not
    /// some other terminal: `tcgetpgrp` answers only for the controlling one)
    /// and this process is in its foreground: not started with `&`, not
    /// suspended and sent on with `bg`.
    /// (A background process that reads the terminal is stopped, and the one
    /// in the foreground is someone else, who must not answer for it.)
    pub fn stdin_is_foreground() -> bool {
        rustix::termios::tcgetpgrp(io::stdin().as_fd())
            .is_ok_and(|group| group == rustix::process::getpgrp())
    }

    /// Waits up to `timeout` for `fd` to become readable. A signal arriving
    /// meanwhile does not end the wait early: it goes on for the time left.
    fn ready(fd: BorrowedFd<'_>, timeout: Duration) -> io::Result<bool> {
        let start = Instant::now();
        loop {
            let left = timeout.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Ok(false);
            }
            let left = Timespec::try_from(left)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            match read_ready_once(fd, &left) {
                Ok(ready) => return Ok(ready),
                Err(e) if e == Errno::INTR => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn read_ready_once(fd: BorrowedFd<'_>, timeout: &Timespec) -> rustix::io::Result<bool> {
        let mut fds = [PollFd::new(&fd, PollFlags::IN)];
        poll(&mut fds, Some(timeout)).map(|count| count > 0)
    }

    // Darwin poll can report /dev/tty ready when a read would still block.
    // select works for that controlling-terminal alias, preserving deadlines
    // and the SSH input worker's bounded cancellation waits.
    #[cfg(target_os = "macos")]
    #[expect(
        unsafe_code,
        reason = "select receives only a live borrowed descriptor in a correctly sized set"
    )]
    fn read_ready_once(fd: BorrowedFd<'_>, timeout: &Timespec) -> rustix::io::Result<bool> {
        use rustix::event::{fd_set_insert, fd_set_num_elements, select, FdSetElement};
        use std::os::fd::AsRawFd;
        let raw = fd.as_raw_fd();
        let bound = raw.checked_add(1).ok_or(Errno::INVAL)?;
        let mut readable = vec![FdSetElement::default(); fd_set_num_elements(1, bound)];
        fd_set_insert(&mut readable, raw);
        // SAFETY: fd stays borrowed for this call. The initialized set has the
        // exact capacity requested by rustix, contains only fd, and no other
        // descriptor sets are supplied. rustix supports Darwin's unlimited select.
        unsafe { select(bound, Some(&mut readable), None, None, Some(timeout)) }
            .map(|count| count > 0)
    }

    /// Reads what is available on stdin, unbuffered: `0` is end of input.
    pub fn read_stdin(buf: &mut [u8]) -> io::Result<usize> {
        read_fd(io::stdin().as_fd(), buf)
    }

    /// Reads what is available on `fd`, retrying when a signal interrupts.
    fn read_fd(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match rustix::io::read(fd, &mut *buf) {
                Ok(n) => return Ok(n),
                Err(e) if e == Errno::INTR => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
}

#[cfg(windows)]
#[path = "tty/windows.rs"]
mod imp;

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::io::{self, Read, Write};
    use std::time::{Duration, Instant};

    use zeroize::Zeroizing;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "interactive use of the UniSSH CLI needs a Unix terminal",
        )
    }

    /// Whether this platform has the terminal an interactive session needs.
    pub const SUPPORTED: bool = false;

    /// The controlling terminal: none here, so no value of this type exists.
    pub enum Tty {}

    impl Tty {
        /// Always fails here.
        pub fn open() -> io::Result<Self> {
            Err(unsupported())
        }

        /// Never called: there is no `Tty` to call it on.
        pub const fn say(&mut self, _text: &str) -> io::Result<()> {
            match *self {}
        }

        /// Never called: there is no `Tty` to call it on.
        pub const fn wait(&self, _timeout: Duration) -> io::Result<bool> {
            match *self {}
        }

        pub(super) const fn read_line(&self, _quiet: bool) -> io::Result<Zeroizing<Vec<u8>>> {
            match *self {}
        }

        pub(super) const fn read_quiet_lines(
            &self,
            _complete: &mut dyn FnMut(&[u8]) -> bool,
        ) -> io::Result<Zeroizing<Vec<u8>>> {
            match *self {}
        }

        pub(super) const fn read_line_until(
            &self,
            _echo: bool,
            _deadline: Instant,
            _stop: &dyn Fn() -> bool,
        ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
            match *self {}
        }
    }

    /// Raw mode: none here, so no value of this type exists.
    pub enum RawMode {}

    impl RawMode {
        /// Always fails here.
        pub fn enter() -> io::Result<Self> {
            Err(unsupported())
        }
    }

    /// The terminal during a replay: stdout here, and no keys — Ctrl-C ends
    /// the process as usual.
    pub struct ReplayTerminal {
        out: io::Stdout,
    }

    impl ReplayTerminal {
        /// stdout.
        pub fn open() -> io::Result<Self> {
            Ok(Self { out: io::stdout() })
        }

        /// Shows what was written, then waits `timeout`; no key ever comes.
        pub fn keys(&self, timeout: Duration, _buf: &mut [u8]) -> io::Result<Option<usize>> {
            (&self.out).flush()?;
            std::thread::sleep(timeout);
            Ok(Some(0))
        }
    }

    impl Write for ReplayTerminal {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.out.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.out.flush()
        }
    }

    /// Unknown here.
    pub const fn window_size() -> Option<(u32, u32)> {
        None
    }

    /// No terminal to be in the foreground of.
    pub const fn stdin_is_foreground() -> bool {
        false
    }

    /// Always "ready": the read that follows blocks instead.
    pub const fn wait_for_input(_timeout: Duration) -> io::Result<bool> {
        Ok(true)
    }

    /// Reads stdin.
    pub fn read_stdin(buf: &mut [u8]) -> io::Result<usize> {
        io::stdin().read(buf)
    }
}

/// How long the session input loop waits for a key before it looks at the
/// window size again.
pub const INPUT_TICK: Duration = Duration::from_millis(100);

/// How often a timed prompt looks whether it is still wanted.
#[cfg(any(unix, windows))]
const STOP_TICK: Duration = Duration::from_millis(200);

#[cfg(test)]
mod tests {
    use super::{is_yes, lines, one_line, Key, QuietLine, CTRL_C, CTRL_D, CTRL_U, DELETE};

    fn typed(keys: &[u8]) -> (Vec<Key>, Vec<u8>) {
        let mut editor = QuietLine::new();
        let keys = keys.iter().map(|&k| editor.key(k)).collect();
        (keys, editor.take().to_vec())
    }

    /// With the terminal's line editing off, the prompt edits: a Backspace
    /// takes a whole character, Ctrl-U the line, control keys type nothing.
    #[test]
    fn a_quiet_prompt_edits_the_line_itself() {
        let (_, line) = typed("pä".as_bytes());
        assert_eq!(line, "pä".as_bytes());
        let mut keys = "pä".as_bytes().to_vec();
        keys.push(DELETE);
        assert_eq!(typed(&keys).1, b"p", "the two bytes of ä go together");
        assert_eq!(typed(&[b'x', CTRL_U, b'y', 0x1b]).1, b"y");
    }

    /// Ctrl-C cancels instead of killing the process with echo off; Ctrl-D
    /// ends input only on an empty line; CR LF is one Enter.
    #[test]
    fn a_quiet_prompt_cancels_ends_and_enters() {
        assert_eq!(typed(&[b'a', CTRL_C]).0.last(), Some(&Key::Cancel));
        assert_eq!(typed(&[CTRL_D]).0, [Key::End]);
        assert_eq!(typed(&[b'a', CTRL_D]).0, [Key::More, Key::More]);
        assert_eq!(
            typed(b"a\r\nb\n").0,
            [Key::More, Key::Enter, Key::More, Key::More, Key::Enter]
        );
    }

    /// What a hostile server or host name could try: clear the screen, move
    /// the cursor (also via the 8-bit CSI), ring the bell, add a fake line.
    #[test]
    fn untrusted_text_loses_its_control_characters() {
        let hostile = "web\x1b[2J\x1b[1;1H\u{9b}31m\x07\nMaster password: ";
        assert_eq!(one_line(hostile), "web[2J[1;1H31mMaster password: ");
        assert_eq!(lines(hostile), "web[2J[1;1H31m\nMaster password: ");
    }

    /// A label that reverses or hides part of itself: `exe.txt` shown as
    /// `txt.exe`, a zero-width space splitting a word, a byte-order mark.
    #[test]
    fn untrusted_text_loses_its_bidi_and_zero_width_characters() {
        let hostile = "\u{202e}txt.exe\u{202c} pro\u{200b}d\u{2066}\u{200f}\u{feff}";
        assert_eq!(one_line(hostile), "txt.exe prod");
        assert_eq!(lines(hostile), "txt.exe prod");
        let invisible = "a\u{ad}b\u{61c}c\u{2060}d\u{2064}e";
        assert_eq!(one_line(invisible), "abcde");
        assert_eq!(lines(invisible), "abcde");
    }

    #[test]
    fn only_y_or_yes_confirms() {
        for yes in ["y", "Y", "yes", " YES \n"] {
            assert!(is_yes(yes), "{yes:?} confirms");
        }
        for no in ["", "n", "no", "yep", "sure"] {
            assert!(!is_yes(no), "{no:?} does not confirm");
        }
    }
}

#[cfg(test)]
#[path = "tty/console_tests.rs"]
mod console_tests;
