//! Serializable error surfaced to the frontend. Mirrors `unissh_ffi::FfiError`,
//! preserving the structured `HostKeyMismatch` so the TOFU flow can react.

use serde::Serialize;
use unissh_ffi::FfiError;

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ApiError {
    /// Core is not unlocked yet.
    Locked,
    /// Bad master password / Secret Key / backup passphrase.
    InvalidCredentials,
    /// Object not found.
    NotFound,
    /// Instance / vault / item id collision.
    AlreadyExists,
    /// Pinned host key changed — possible MITM. The UI must warn and offer trust.
    #[serde(rename_all = "camelCase")]
    HostKeyMismatch {
        host: String,
        port: u16,
        fingerprint: String,
    },
    /// Generic SSH / transport error (string bucket from the core).
    Ssh { msg: String },
    /// Cloud server error. `code` is the server's snake_case code
    /// (`unauthenticated`, `forbidden`, `conflict`, `gone`, `rate_limited`,
    /// `tenant_suspended`, `rollback_detected`, `malformed`, …) plus client-side
    /// pseudo-codes (`network`, `not_connected`, `http_<status>`). The frontend
    /// switches on `code` to react (e.g. re-auth on `unauthenticated`).
    #[serde(rename_all = "camelCase")]
    Server { code: String, message: String },
    /// Everything else (incl. wrapper-level failures: missing session id, join errors…).
    Other { msg: String },
}

impl ApiError {
    pub fn other(msg: impl std::fmt::Display) -> Self {
        ApiError::Other {
            msg: msg.to_string(),
        }
    }
    pub fn not_found(what: impl std::fmt::Display) -> Self {
        ApiError::Other {
            msg: format!("not found: {what}"),
        }
    }
}

impl From<FfiError> for ApiError {
    fn from(e: FfiError) -> Self {
        match e {
            FfiError::HostUntrusted => ApiError::other("Verify the SSH host key in UniSSH first."),
            FfiError::Locked => ApiError::Locked,
            FfiError::InvalidCredentials => ApiError::InvalidCredentials,
            FfiError::NotFound => ApiError::NotFound,
            FfiError::AlreadyExists => ApiError::AlreadyExists,
            FfiError::HostKeyMismatch {
                host,
                port,
                fingerprint,
            } => ApiError::HostKeyMismatch {
                host,
                port,
                fingerprint,
            },
            FfiError::Ssh { msg } => ApiError::Ssh { msg },
            FfiError::Other { msg } => ApiError::Other { msg },
        }
    }
}

/// A `JoinError` from `spawn_blocking` (task panicked / cancelled).
impl From<tauri::Error> for ApiError {
    fn from(e: tauri::Error) -> Self {
        ApiError::other(e)
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
