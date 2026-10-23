//! `~` escapes in a session, the way `ssh` has them.
//!
//! Typed at the start of a line, `~.` ends the session — the way out of a
//! remote that stopped answering — `~?` lists the escapes and `~~` sends one
//! `~`. A `~` followed by anything else, or typed mid-line, is sent as typed.

/// An escape the user typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escape {
    /// `~.`: end the session.
    Disconnect,
    /// `~?`: list the escapes.
    Help,
}

/// What `~?` prints. Raw mode is on, so lines end in `\r\n`.
pub const HELP: &str = "\r\nSupported escapes (after a newline):\r\n  \
                        ~.  end the session\r\n  \
                        ~?  this list\r\n  \
                        ~~  send a single ~\r\n";

/// Watches typed input for escapes across reads.
pub struct Escapes {
    at_line_start: bool,
    tilde_pending: bool,
}

impl Escapes {
    /// A fresh session counts as the start of a line.
    pub const fn new() -> Self {
        Self {
            at_line_start: true,
            tilde_pending: false,
        }
    }

    /// Splits typed `input` into what goes to the remote and the escape typed,
    /// if any. After a [`Escape::Disconnect`] the rest of `input` is dropped.
    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Option<Escape>) {
        let mut send = Vec::with_capacity(input.len());
        let mut escape = None;
        for &byte in input {
            if self.tilde_pending {
                self.tilde_pending = false;
                match byte {
                    b'.' => return (send, Some(Escape::Disconnect)),
                    b'?' => {
                        escape = Some(Escape::Help);
                        self.at_line_start = false;
                    }
                    b'~' => {
                        send.push(b'~');
                        self.at_line_start = false;
                    }
                    other => {
                        send.extend_from_slice(&[b'~', other]);
                        self.at_line_start = is_line_end(other);
                    }
                }
            } else if self.at_line_start && byte == b'~' {
                self.tilde_pending = true;
            } else {
                send.push(byte);
                self.at_line_start = is_line_end(byte);
            }
        }
        (send, escape)
    }
}

impl Default for Escapes {
    fn default() -> Self {
        Self::new()
    }
}

const fn is_line_end(byte: u8) -> bool {
    matches!(byte, b'\r' | b'\n')
}

#[cfg(test)]
mod tests {
    use super::{Escape, Escapes};

    #[test]
    fn tilde_dot_after_enter_disconnects_and_keeps_what_came_before() {
        let mut e = Escapes::new();
        assert_eq!(
            e.feed(b"ls\r~.rm -rf /\r"),
            (b"ls\r".to_vec(), Some(Escape::Disconnect)),
            "the line before goes out; nothing after the escape does"
        );
    }

    #[test]
    fn tilde_mid_line_is_just_a_character() {
        let mut e = Escapes::new();
        assert_eq!(e.feed(b"cd ~.ssh"), (b"cd ~.ssh".to_vec(), None));
    }

    #[test]
    fn double_tilde_sends_one_and_an_unknown_escape_is_sent_as_typed() {
        let mut e = Escapes::new();
        assert_eq!(e.feed(b"~~x\r~a"), (b"~x\r~a".to_vec(), None));
    }

    /// Keys arrive one read at a time when typed by hand.
    #[test]
    fn an_escape_split_across_reads_is_still_recognised() {
        let mut e = Escapes::new();
        assert_eq!(e.feed(b"\r~"), (b"\r".to_vec(), None));
        assert_eq!(e.feed(b"?"), (Vec::new(), Some(Escape::Help)));
    }
}
