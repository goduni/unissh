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
        tcgetattr, tcgetwinsize, tcsetattr, LocalModes, OptionalActions, Termios,
    };

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
        /// character is an `UnexpectedEof` — the user pressed Ctrl-D.
        pub(super) fn read_line(&self, quiet: bool) -> io::Result<Zeroizing<Vec<u8>>> {
            let _echo = quiet.then(|| NoEcho::on(&self.file)).transpose()?;
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
    }

    /// Echo off on a terminal until dropped.
    struct NoEcho<'fd> {
        fd: BorrowedFd<'fd>,
        saved: Termios,
    }

    impl<'fd> NoEcho<'fd> {
        fn on(file: &'fd File) -> io::Result<Self> {
            let fd = file.as_fd();
            let saved = tcgetattr(fd)?;
            let mut quiet = saved.clone();
            quiet.local_modes.remove(LocalModes::ECHO);
            // TCSAFLUSH, as `ssh` does for a passphrase: what was typed ahead
            // of the prompt is not taken as the beginning of the secret.
            tcsetattr(fd, OptionalActions::Flush, &quiet)?;
            Ok(Self { fd, saved })
        }
    }

    impl Drop for NoEcho<'_> {
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
    }

    /// Raw mode: none here, so no value of this type exists.
    pub enum RawMode {}

    impl RawMode {
        /// Always fails here.
        pub fn enter() -> io::Result<Self> {
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
    use super::{is_yes, lines, one_line};

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
