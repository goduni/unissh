//! Low-level HTTP plumbing for the UniSSH server `/v1` API: a process-global
//! blocking client, header/auth wiring, base64 STANDARD helpers, JSON send, and
//! the server error-envelope mapping.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use once_cell::sync::Lazy;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::StatusCode;
use serde_json::Value;

use crate::error::{ApiError, ApiResult};

/// How many times to retry a `429 Too Many Requests` (honoring `Retry-After`).
const MAX_429_RETRIES: u32 = 2;
/// Cap a server-suggested `Retry-After` so a hostile/buggy value can't hang the UI.
const MAX_RETRY_AFTER_SECS: u64 = 5;

/// Process-global blocking HTTP client (connection pool reuse). Initialised lazily
/// on first use — which always happens inside `spawn_blocking`, so the inner
/// current-thread runtime is never created from within Tauri's async runtime.
static HTTP: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .user_agent(concat!("unissh-client/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_else(|_| Client::new())
});

/// The shared blocking client. MUST be called from a blocking context.
pub fn http() -> &'static Client {
    &HTTP
}

/// base64 STANDARD (padded) — the server's wire encoding for every blob/id.
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn unb64(s: &str) -> ApiResult<Vec<u8>> {
    STANDARD.decode(s.trim()).map_err(|_| ApiError::Server {
        code: "malformed".into(),
        message: "invalid base64 from server".into(),
    })
}

/// Lowercase hex encode. The core's membership API takes pubkeys as hex, whereas
/// the server returns them base64 — this bridges `/v1/accounts` → `add_member`.
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Percent-encode a query-string value (RFC 3986 unreserved set kept verbatim).
/// Needed because base64 STANDARD contains `+`/`/`/`=`, which corrupt a raw query.
pub fn enc_query(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Join base_url + path, tolerating a trailing slash on base_url.
pub fn url(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}

/// Reject a server base URL that would carry traffic in cleartext. The threat
/// model assumes TLS 1.3 on the wire; an `http://` link to a non-loopback host
/// exposes the Bearer access/refresh tokens (and every ciphertext blob) to any
/// on-path attacker, who can then mint access to the (server-trusted) account.
/// `http://` is permitted ONLY for loopback hosts (localhost / 127.x / [::1]),
/// which the integration tests and the local-eval stack use.
pub fn validate_base_url(base_url: &str) -> ApiResult<()> {
    let s = base_url.trim();
    if let Some(rest) = s.strip_prefix("https://") {
        return if rest.is_empty() {
            Err(ApiError::other("server URL is missing a host"))
        } else {
            Ok(())
        };
    }
    if let Some(rest) = s.strip_prefix("http://") {
        let host = rest.split('/').next().unwrap_or("").to_ascii_lowercase();
        let is_loopback = host.starts_with("localhost")
            || host.starts_with("127.")
            || host.starts_with("[::1]")
            || host.starts_with("::1");
        return if is_loopback {
            Ok(())
        } else {
            Err(ApiError::other(format!(
                "refusing plaintext http:// to non-loopback host \"{host}\": \
                 use https:// so tokens and data are encrypted in transit"
            )))
        };
    }
    Err(ApiError::other(
        "server URL must start with https:// (http:// allowed for localhost only)",
    ))
}

/// Attach an optional Bearer to a request builder. The instance is addressed by
/// its base URL alone — there is no tenant header any more.
pub fn headers(rb: RequestBuilder, bearer: Option<&str>) -> RequestBuilder {
    match bearer {
        Some(tok) => rb.header(reqwest::header::AUTHORIZATION, format!("Bearer {tok}")),
        None => rb,
    }
}

/// Send a built request, mapping transport errors and the server error envelope.
/// Returns the parsed JSON body on 2xx (`Value::Null` for empty/204 bodies).
/// Retries `429` up to `MAX_429_RETRIES`, honoring (and capping) `Retry-After`.
pub fn send_json(rb: RequestBuilder) -> ApiResult<Value> {
    let mut attempt: u32 = 0;
    loop {
        // Clone for a possible retry; our bodies (JSON/empty) are always cloneable.
        match rb.try_clone() {
            Some(c) => {
                let resp = c.send().map_err(transport_err)?;
                if resp.status() == StatusCode::TOO_MANY_REQUESTS && attempt < MAX_429_RETRIES {
                    attempt += 1;
                    std::thread::sleep(Duration::from_secs(retry_after_secs(&resp)));
                    continue;
                }
                return finish(resp);
            }
            None => return finish(rb.send().map_err(transport_err)?),
        }
    }
}

fn finish(resp: Response) -> ApiResult<Value> {
    let status = resp.status();
    let bytes = resp.bytes().map_err(transport_err)?;
    if status.is_success() {
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).map_err(|e| ApiError::other(format!("bad server JSON: {e}")))
    } else {
        Err(envelope_err(status, &bytes))
    }
}

fn retry_after_secs(resp: &Response) -> u64 {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(1)
        .clamp(1, MAX_RETRY_AFTER_SECS)
}

fn transport_err(e: reqwest::Error) -> ApiError {
    ApiError::Server {
        code: "network".into(),
        message: e.to_string(),
    }
}

/// Map `{error:{code,message,retry_after}}` → `ApiError::Server`. Falls back to the
/// HTTP status if the body isn't the expected envelope.
fn envelope_err(status: StatusCode, body: &[u8]) -> ApiError {
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        if let Some(err) = v.get("error") {
            let code = err
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("internal")
                .to_string();
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            return ApiError::Server { code, message };
        }
    }
    ApiError::Server {
        code: format!("http_{}", status.as_u16()),
        message: status.to_string(),
    }
}

// ---- typed extraction from a JSON response (server contract is fixed) ----

fn missing(key: &str) -> ApiError {
    ApiError::Server {
        code: "malformed".into(),
        message: format!("server response missing '{key}'"),
    }
}

pub fn jstr(v: &Value, key: &str) -> ApiResult<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| missing(key))
}

pub fn ju64(v: &Value, key: &str) -> ApiResult<u64> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| missing(key))
}

pub fn ji64(v: &Value, key: &str) -> ApiResult<i64> {
    v.get(key)
        .and_then(|x| x.as_i64())
        .ok_or_else(|| missing(key))
}

#[cfg(test)]
mod base_url_tests {
    use super::validate_base_url;

    #[test]
    fn https_ok_http_loopback_ok_http_remote_rejected() {
        assert!(validate_base_url("https://cloud.example.com").is_ok());
        assert!(validate_base_url("https://cloud.example.com:8443/").is_ok());
        assert!(validate_base_url("http://127.0.0.1:8443").is_ok());
        assert!(validate_base_url("http://localhost").is_ok());
        assert!(validate_base_url("http://[::1]:8443").is_ok());
        // the dangerous cases: plaintext to a real host / non-http schemes
        assert!(validate_base_url("http://cloud.example.com").is_err());
        assert!(validate_base_url("ftp://cloud.example.com").is_err());
        assert!(validate_base_url("cloud.example.com").is_err());
        assert!(validate_base_url("https://").is_err());
    }
}
