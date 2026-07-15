//! Canonical error envelope (spec §5.0).
//!
//! ```json
//! { "error": { "code": "snake_case_code", "message": "human readable", "retry_after": 0 } }
//! ```
//!
//! An invariant violation = **refusal (HTTP 4xx/5xx), NOT a panic** (spec §3).

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Canonical error codes (spec §5.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Unauthenticated,
    Forbidden,
    NotFound,
    Conflict,
    Gone,
    RateLimited,
    PayloadTooLarge,
    Malformed,
    RollbackDetected,
    Internal,
}

impl ErrorCode {
    pub fn status(self) -> StatusCode {
        match self {
            ErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::Gone => StatusCode::GONE,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::Malformed => StatusCode::BAD_REQUEST,
            ErrorCode::RollbackDetected => StatusCode::CONFLICT,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Unauthenticated => "unauthenticated",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Conflict => "conflict",
            ErrorCode::Gone => "gone",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::PayloadTooLarge => "payload_too_large",
            ErrorCode::Malformed => "malformed",
            ErrorCode::RollbackDetected => "rollback_detected",
            ErrorCode::Internal => "internal",
        }
    }
}

/// Application error, serialized into the canonical §5.0 envelope.
#[derive(Debug)]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retry_after: None,
        }
    }
    pub fn with_retry_after(mut self, secs: u64) -> Self {
        self.retry_after = Some(secs);
        self
    }

    pub fn unauthenticated(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthenticated, m)
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, m)
    }
    pub fn gone(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Gone, m)
    }
    pub fn rate_limited(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::RateLimited, m)
    }
    pub fn payload_too_large(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::PayloadTooLarge, m)
    }
    pub fn malformed(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Malformed, m)
    }
    pub fn rollback_detected(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::RollbackDetected, m)
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, m)
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorEnvelope<'a>,
}
#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    code: &'a str,
    message: &'a str,
    retry_after: u64,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // We log internal errors server-side, but return ONLY a generic
        // message to the client — otherwise SQL fragments/table names/DB details leak (§13).
        let client_message = if self.code == ErrorCode::Internal {
            tracing::error!(message = %self.message, "internal error");
            "internal error"
        } else {
            self.message.as_str()
        };
        let body = ErrorBody {
            error: ErrorEnvelope {
                code: self.code.as_str(),
                message: client_message,
                retry_after: self.retry_after.unwrap_or(0),
            },
        };
        let mut resp = (self.code.status(), Json(body)).into_response();
        if let Some(ra) = self.retry_after {
            if let Ok(v) = header::HeaderValue::from_str(&ra.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for AppError {}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::internal(format!("db error: {e}"))
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::internal(format!("{e}"))
    }
}

pub type AppResult<T> = Result<T, AppError>;
