//! SSH transport errors.

use thiserror::Error;

/// Transport errors. Also used as `Handler::Error` for russh
/// (requires `From<russh::Error> + Send + Debug`).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransportError {
    /// SSH protocol error (russh).
    #[error("ssh protocol error: {0}")]
    Russh(#[from] russh::Error),

    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Embedded agent error.
    #[error("agent error: {0}")]
    Agent(#[from] unissh_ssh_agent::AgentError),

    /// Storage error (known_hosts).
    #[error("storage error: {0}")]
    Storage(#[from] unissh_storage::StorageError),

    /// The host key did not match the pinned one — possible MITM (spec 5.4).
    /// `fingerprint` is the fingerprint of the key ACTUALLY presented by the server
    /// (SHA256), so it can be shown to the user to let them consciously "trust the new one".
    #[error("host key mismatch for {host}:{port} (possible MITM); presented {fingerprint}")]
    HostKeyMismatch {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// SHA256 fingerprint of the presented key.
        fingerprint: String,
    },

    /// SFTP subsystem error.
    #[error("sftp error: {0}")]
    Sftp(String),

    /// The bind address of a dynamic (SOCKS5) forward is not loopback — rejected
    /// (SOCKS5 runs without authentication, so it must not be exposed to the network).
    #[error("dynamic forward bind address must be loopback, got {0}")]
    NonLoopbackBind(String),

    /// The host key presented during re-pinning did not match the fingerprint
    /// confirmed by the user (possible MITM at the moment of "trust the new one").
    /// `expected` is deliberately not printed in the message so it does not leak into
    /// general logs via `Display` (both values are public fingerprints, but we play safe).
    #[error("presented host key fingerprint {got} does not match the confirmed one")]
    FingerprintMismatch {
        /// The fingerprint confirmed by the user.
        expected: String,
        /// The fingerprint of the key actually presented.
        got: String,
    },

    /// The SSH handshake/authentication did not complete within the timeout (a
    /// malicious/hung server: the SFTP per-packet timeout does not cover the session
    /// establishment phase).
    #[error("ssh handshake timed out")]
    HandshakeTimeout,

    /// Authentication failed.
    #[error("authentication failed")]
    AuthFailed,

    /// The server asked something only the user can answer — a one-time code, a
    /// push confirmation — and no prompter was attached to the connection.
    /// Distinct from [`AuthFailed`](Self::AuthFailed) on purpose: the credentials
    /// may be perfectly correct, the client simply had no way to ask.
    #[error("server requires interactive input (e.g. a one-time code), but no prompt handler is attached")]
    InteractiveAuthUnsupported,

    /// The user dismissed the interactive prompt, or answered it with the wrong
    /// number of fields.
    #[error("authentication cancelled")]
    AuthCancelled,

    /// Key encoding/decoding error.
    #[error("key encoding error: {0}")]
    KeyEncoding(String),

    /// ssh-config parse error.
    #[error("ssh config error: {0}")]
    Config(String),

    /// SOCKS protocol error (dynamic forward).
    #[error("socks protocol error")]
    Socks,
}

// Required for russh::auth::Signer (type Error: From<russh::SendError>).
impl From<russh::SendError> for TransportError {
    fn from(_e: russh::SendError) -> Self {
        TransportError::Russh(russh::Error::SendError)
    }
}
