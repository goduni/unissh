//! The terminal: prompts that do not echo, and raw mode for a session.
//!
//! Prompts talk to the controlling terminal (`/dev/tty`), not to stdin and
//! stdout, so `cat file | unissh ssh host -- cmd` can still ask for a password
//! and nothing a prompt prints ends up in a pipe. Every terminal setting this
//! module changes is put back when its guard is dropped.

use std::io;
use std::time::Duration;

use zeroize::Zeroizing;

pub use imp::{read_stdin, wait_for_input, window_size, RawMode, Tty, SUPPORTED};

/// `text` without control characters, for one line that came from a server,
/// a vault or a remote host: printed raw, an escape sequence in it could move
/// the cursor, rewrite what is on screen or fake a prompt.
pub fn one_line(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// [`one_line`] for text that may span lines: line breaks stay.
pub fn lines(text: &str) -> String {
    text.chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .collect()
}

// The quiet-prompt line editor is the Unix terminal's (Windows has no `Tty`);
// it is pure, so its tests run everywhere.

/// What one key does at a quiet prompt.
#[cfg(any(unix, test))]
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

#[cfg(any(unix, test))]
const CTRL_C: u8 = 0x03;
#[cfg(any(unix, test))]
const CTRL_D: u8 = 0x04;
#[cfg(any(unix, test))]
const BACKSPACE: u8 = 0x08;
#[cfg(any(unix, test))]
const CTRL_U: u8 = 0x15;
#[cfg(any(unix, test))]
const DELETE: u8 = 0x7f;

/// Line editing for a prompt that echoes nothing. The terminal's own line
/// editing is off there, and so are its signals: a Ctrl-C that killed the
/// process would leave the terminal with echo off. So this does what the
/// terminal would — Backspace and Ctrl-U edit, Enter ends the line (a CR LF
/// pair once), Ctrl-D on an empty line ends input — and Ctrl-C cancels, with
/// the terminal put back by whoever turned echo off.
#[cfg(any(unix, test))]
struct QuietLine {
    text: Zeroizing<Vec<u8>>,
    after_cr: bool,
}

#[cfg(any(unix, test))]
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

    /// The line so far, leaving an empty one.
    fn take(&mut self) -> Zeroizing<Vec<u8>> {
        std::mem::replace(&mut self.text, Zeroizing::new(Vec::with_capacity(256)))
    }
}

#[cfg(unix)]
fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "cancelled")
}

#[cfg(unix)]
fn ended() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "cancelled")
}

/// Whether a typed answer means yes.
fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
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

    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    use rustix::io::Errno;
    use rustix::termios::{
        tcgetattr, tcgetwinsize, tcsetattr, OptionalActions, OutputModes, Termios,
    };

    use super::{cancelled, ended, Key, QuietLine};
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

        /// Raw keys, but output still processed, for replaying a recording:
        /// a key typed meanwhile neither echoes into the replay nor raises a
        /// signal, and output that is not from a terminal (a recorded command's
        /// bare `\n`) still starts its lines at the left edge.
        pub fn for_replay() -> io::Result<Self> {
            let stdin = io::stdin();
            let saved = tcgetattr(stdin.as_fd())?;
            let mut raw = saved.clone();
            raw.make_raw();
            raw.output_modes.insert(OutputModes::OPOST);
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
            let mut fds = [PollFd::new(&fd, PollFlags::IN)];
            match poll(&mut fds, Some(&left)) {
                Ok(ready) => return Ok(ready > 0),
                Err(e) if e == Errno::INTR => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Reads what is available on stdin, unbuffered: `0` is end of input.
    pub fn read_stdin(buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match rustix::io::read(io::stdin().as_fd(), &mut *buf) {
                Ok(n) => return Ok(n),
                Err(e) if e == Errno::INTR => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use std::io::{self, Read};
    use std::time::Duration;

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
    }

    /// Raw mode: none here, so no value of this type exists.
    pub enum RawMode {}

    impl RawMode {
        /// Always fails here.
        pub fn enter() -> io::Result<Self> {
            Err(unsupported())
        }

        /// Always fails here.
        pub fn for_replay() -> io::Result<Self> {
            Err(unsupported())
        }
    }

    /// Unknown here.
    pub const fn window_size() -> Option<(u32, u32)> {
        None
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
