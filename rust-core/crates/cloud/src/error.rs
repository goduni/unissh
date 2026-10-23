//! The one error type of the server client.
//!
//! Three buckets, mirroring how the callers react: the server (or the transport
//! to it) said no, the core said no, or something local failed. The desktop maps
//! each one onto its own IPC error without losing anything; the CLI prints them.

use unissh_ffi::FfiError;

/// An error from talking to a UniSSH server.
#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    /// The server refused the call, or the request never got an answer.
    ///
    /// `code` is the server's snake_case code (`unauthenticated`, `forbidden`,
    /// `conflict`, `gone`, `rate_limited`, `malformed`, …) or one of the
    /// client-side pseudo-codes: `network` for a request that got no answer,
    /// `http_<status>` for an answer that was not the server's error envelope.
    #[error("{message} ({code})")]
    Server {
        /// Machine-readable code to branch on.
        code: String,
        /// Human-readable detail, as the server (or the transport) phrased it.
        message: String,
    },
    /// The core refused: wrong credentials, a locked instance, a keyset that is
    /// already installed, …
    #[error(transparent)]
    Core(#[from] FfiError),
    /// Anything else (a malformed local argument, an unreadable file, …).
    #[error("{msg}")]
    Other {
        /// What went wrong.
        msg: String,
    },
}

impl CloudError {
    /// An [`CloudError::Other`] from anything printable.
    pub fn other(msg: impl std::fmt::Display) -> Self {
        Self::Other {
            msg: msg.to_string(),
        }
    }
}

/// Result of a server-client call.
pub type CloudResult<T> = Result<T, CloudError>;
