//! What a command failure prints, and the exit code it leaves.
//!
//! One type for everything a command can fail with, so `main` prints a single
//! line and exits with a code that scripts can branch on: the remote command's
//! own status passes through untouched, a connection that never got that far is
//! 255 (as with `ssh`), and anything else is 1.

use std::fmt;

use unissh_cloud::CloudError;
use unissh_ffi::FfiError;

use crate::tty::lines;

/// Exit code of a failure that is not about a connection.
pub const EXIT_FAILURE: u8 = 1;
/// Exit code of a connection that failed before a remote command could run.
pub const EXIT_CONNECT: u8 = 255;

/// A command failure: the message for the terminal and the exit code.
#[derive(Debug)]
pub struct Failure {
    /// What to print (without the `unissh:` prefix).
    pub message: String,
    /// Exit code of the process.
    pub exit: u8,
    /// The server's code, when the server refused.
    code: Option<String>,
    /// The person at the terminal ended a prompt (Ctrl-C or Ctrl-D).
    cancelled: bool,
}

impl Failure {
    /// A failure with exit code 1.
    pub fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit: EXIT_FAILURE,
            code: None,
            cancelled: false,
        }
    }

    /// Whether this is a cancel at a prompt rather than something that failed:
    /// a retry loop must stop on it, not ask again.
    pub const fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// The same failure, reported as a connection failure (exit 255).
    pub const fn connecting(mut self) -> Self {
        self.exit = EXIT_CONNECT;
        self
    }

    /// The server's refusal `code`, with `hint` added; any other failure as is.
    /// For the call sites that know what a code means there.
    pub fn hint_for(self, code: &str, hint: &str) -> Self {
        if self.code.as_deref() == Some(code) {
            Self {
                message: format!("{} — {hint}", self.message),
                ..self
            }
        } else {
            self
        }
    }
}

/// Printed without control characters: a message can quote a server or a
/// remote host, and nothing they say may drive the terminal.
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&lines(&self.message))
    }
}

impl From<FfiError> for Failure {
    fn from(e: FfiError) -> Self {
        let message = match e {
            FfiError::InvalidCredentials => "wrong master password or Secret Key".to_owned(),
            FfiError::HostKeyMismatch {
                host,
                port,
                fingerprint,
            } => {
                return Self {
                    message: host_key_warning(&host, port, &fingerprint),
                    exit: EXIT_CONNECT,
                    code: None,
                    cancelled: false,
                }
            }
            FfiError::HostUntrusted
            | FfiError::Locked
            | FfiError::NotFound
            | FfiError::AlreadyExists
            | FfiError::AlreadyCloud
            | FfiError::NoServer
            | FfiError::PayloadTooLarge { .. }
            | FfiError::RotationInProgress { .. }
            | FfiError::RotationPartlyFinished { .. }
            | FfiError::PublickeyOnlyNeedsKey
            | FfiError::KeyRefused
            | FfiError::KeyAcceptedMoreAuthRequired
            | FfiError::Ssh { .. }
            | FfiError::Other { .. } => e.to_string(),
        };
        Self::msg(message)
    }
}

impl From<CloudError> for Failure {
    fn from(e: CloudError) -> Self {
        match e {
            CloudError::Core(e) => e.into(),
            CloudError::Server { code, message } => Self {
                code: Some(code.clone()),
                ..Self::msg(server_message(&code, &message))
            },
            CloudError::Other { msg } => Self::msg(msg),
        }
    }
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Self {
            cancelled: matches!(
                e.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::UnexpectedEof
            ),
            ..Self::msg(e.to_string())
        }
    }
}

/// The server's refusal in words a person can act on.
fn server_message(code: &str, message: &str) -> String {
    let hint = match code {
        "network" => "is the server reachable from this machine?",
        "unauthenticated" => {
            "if this device was revoked, `unissh logout --local` clears it so you can sign in again"
        }
        _ => "",
    };
    let detail = if message.is_empty() { code } else { message };
    if hint.is_empty() {
        format!("server: {detail}")
    } else {
        format!("server: {detail} — {hint}")
    }
}

/// The warning for a host whose key changed, with what to do about it.
pub fn host_key_warning(host: &str, port: u16, fingerprint: &str) -> String {
    format!(
        "THE HOST KEY OF {host}:{port} HAS CHANGED.\n\
         Someone could be intercepting this connection, or the host was reinstalled.\n\
         It now presents {fingerprint}.\n\
         Check that fingerprint with the host's administrator. If it is right, trust it with:\n  \
         unissh known-hosts trust {host}:{port} {fingerprint}\n\
         (for a host behind a jump host: unissh known-hosts forget {host}:{port}, then connect again)"
    )
}

/// Result of a command step.
pub type Res<T> = Result<T, Failure>;

/// Discards the outcome of a step whose failure has no remedy: a write to a
/// terminal that went away, closing a session being abandoned anyway, a
/// logout from a server that cannot be reached.
pub fn best_effort<T, E>(result: Result<T, E>) {
    if result.is_err() {
        // Deliberately ignored; see the doc comment.
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use super::Failure;

    /// Ctrl-C or Ctrl-D at a prompt stays a cancel on its way up, so a retry
    /// loop can stop on it; anything else is a plain failure.
    #[test]
    fn a_cancelled_prompt_stays_a_cancel() {
        assert!(Failure::from(Error::new(ErrorKind::Interrupted, "cancelled")).is_cancelled());
        assert!(Failure::from(Error::new(ErrorKind::UnexpectedEof, "cancelled")).is_cancelled());
        assert!(!Failure::from(Error::new(ErrorKind::NotFound, "no such file")).is_cancelled());
        assert!(!Failure::msg("wrong master password or Secret Key").is_cancelled());
    }
}
