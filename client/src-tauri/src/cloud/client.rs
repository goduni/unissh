//! Low-level HTTP plumbing for the UniSSH server `/v1` API: a process-global
//! blocking client, header/auth wiring, base64 STANDARD helpers, JSON send, and
//! the server error-envelope mapping.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use once_cell::sync::Lazy;
use reqwest::blocking::{Client, Request, RequestBuilder, Response};
use reqwest::header::{HeaderValue, AUTHORIZATION};
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
///
/// Preparing the platform verifier here, ahead of the `HTTP` deref that builds
/// the client, is the fix for #34. On Android the certificate trust store is
/// reached over JNI, and a verifier that was never handed the JVM panics — on
/// reqwest's own internal thread, where the message is thrown away and replaced
/// by reqwest's secondary "event loop thread panicked". Every cloud call on
/// Android died there.
///
/// It sits in this function rather than in `HTTP`'s initialiser or in `setup()`
/// for two reasons: the Android activity is not guaranteed to exist before the
/// first cloud command, and running once per call means a transient failure is
/// retried instead of being cached with the client for the life of the process.
/// After the first success it is one atomic load. See `crate::platform_tls`.
///
/// The error is logged, not returned: this hands out a `&'static Client` to ~45
/// call sites, several of which implement infallible core traits and have
/// nowhere to put one. A failure still ends in a panic further down — but with a
/// log line naming the real cause, which is exactly what #34 lacked. Making the
/// whole path fallible is a separate change.
pub fn http() -> &'static Client {
    if let Err(e) = crate::platform_tls::init() {
        log::error!("cloud: platform certificate verifier unavailable — {e}");
    }
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

/// Exchanges a rejected bearer for a fresh one. Installed once at startup by the
/// app, which is what owns the refresh token; this layer only knows that a call
/// came back 401 and which bearer it sent.
type Reauth = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;
static REAUTH: OnceLock<Reauth> = OnceLock::new();

/// Wire up token rotation. Called once during setup; later calls are ignored.
pub fn set_reauth(f: Reauth) {
    let _ = REAUTH.set(f);
}

/// The fresh bearer for a request whose token the server has rejected, or None
/// when there is no bearer, no refresher, or nothing to rotate to.
fn reauth_header(req: &Request, reauth: &Reauth) -> Option<HeaderValue> {
    let stale = req
        .headers()
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?
        .to_string();
    let fresh = reauth(&stale)?;
    HeaderValue::from_str(&format!("Bearer {fresh}")).ok()
}

/// Send a built request, mapping transport errors and the server error envelope.
/// Returns the parsed JSON body on 2xx (`Value::Null` for empty/204 bodies).
/// Retries `429` up to `MAX_429_RETRIES`, honoring (and capping) `Retry-After`.
///
/// Also retries ONCE on `401`, after rotating the access token. An access token
/// is short-lived by design, so meeting an expired one is routine rather than
/// exceptional — and until this existed the routine case surfaced as "access
/// token expired" and left the user to press Refresh session by hand, then
/// repeat whatever they were doing. Retrying here rather than per command covers
/// the sync transport too, which talks to the server without passing through the
/// command layer at all.
///
/// Safe to replay: the server authenticates in its extractor, before any handler
/// runs, so a request rejected with 401 had no effect to repeat. Once only — a
/// second 401 is a real authentication problem and must reach the user.
pub fn send_json(rb: RequestBuilder) -> ApiResult<Value> {
    send_json_reauth(rb, REAUTH.get().cloned())
}

/// The body of [`send_json`], with the refresher passed in rather than read from
/// the process-global — so the retry can be tested without installing one.
fn send_json_reauth(rb: RequestBuilder, reauth: Option<Reauth>) -> ApiResult<Value> {
    let (http, built) = rb.build_split();
    let mut req = built.map_err(transport_err)?;
    let mut attempt: u32 = 0;
    let mut rotated = false;
    loop {
        // Clone for a possible retry; our bodies (JSON/empty) are always cloneable.
        let Some(copy) = req.try_clone() else {
            return finish(http.execute(req).map_err(transport_err)?);
        };
        let resp = http.execute(copy).map_err(transport_err)?;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS && attempt < MAX_429_RETRIES {
            attempt += 1;
            std::thread::sleep(Duration::from_secs(retry_after_secs(&resp)));
            continue;
        }
        if resp.status() == StatusCode::UNAUTHORIZED && !rotated {
            if let Some(fresh) = reauth.as_ref().and_then(|f| reauth_header(&req, f)) {
                rotated = true;
                req.headers_mut().insert(AUTHORIZATION, fresh);
                continue;
            }
        }
        return finish(resp);
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
    let mut message = e.to_string();
    if let Some(hint) = tls_hint(&error_chain(&e)) {
        message.push_str(" — ");
        message.push_str(hint);
    }
    ApiError::Server {
        code: "network".into(),
        message,
    }
}

/// Flatten an error and its `source()` chain into one lowercase haystack. The
/// outer Display of a failed request is only "error sending request for url
/// (...)"; the reason (rustls' certificate verdict) lives several sources down.
fn error_chain(e: &dyn std::error::Error) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let mut cur = Some(e);
    while let Some(err) = cur {
        let _ = write!(out, "{err}; ");
        cur = err.source();
    }
    out.to_ascii_lowercase()
}

/// Turn a TLS verification failure into an instruction. Self-hosting behind a
/// private CA is a supported deployment, and it is the one case where the raw
/// message ("invalid peer certificate: unknownissuer") names the symptom and
/// nothing else — the operator has to already know that the fix is a trust-store
/// install. The client verifies against the OS trust store (rustls
/// platform-verifier), so that is where the CA root has to go.
fn tls_hint(chain: &str) -> Option<&'static str> {
    if !chain.contains("certificate") {
        return None;
    }
    if chain.contains("unknownissuer") || chain.contains("unknown issuer") {
        return Some(
            "the server's TLS certificate is not trusted by this machine. \
             If it is self-signed or issued by an internal CA (e.g. Caddy's \
             \"tls internal\"), install that CA's root certificate into this \
             machine's system trust store: https://unissh.dev/operations/deploy-scenarios/",
        );
    }
    if chain.contains("notvalidforname") {
        return Some(
            "the server's TLS certificate is not valid for this hostname — \
             use the exact hostname the certificate was issued for",
        );
    }
    if chain.contains("expired") {
        return Some("the server's TLS certificate has expired (or this machine's clock is wrong)");
    }
    None
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

#[cfg(test)]
mod tls_hint_tests {
    use super::tls_hint;

    /// The strings are what rustls actually produces, lowercased by
    /// `error_chain`: a private-CA server is the case the hint exists for.
    #[test]
    fn untrusted_issuer_gets_the_trust_store_instruction() {
        let chain = "error sending request for url (https://unissh.local/v1/health); \
                     invalid peer certificate: unknownissuer; ";
        assert!(tls_hint(chain).unwrap().contains("system trust store"));
    }

    #[test]
    fn hostname_mismatch_and_expiry_are_distinguished() {
        assert!(tls_hint("invalid peer certificate: notvalidforname; ")
            .unwrap()
            .contains("hostname"));
        assert!(tls_hint("invalid peer certificate: expired; ")
            .unwrap()
            .contains("expired"));
    }

    #[test]
    fn ordinary_transport_failures_get_no_hint() {
        assert!(tls_hint("error sending request; connection refused; ").is_none());
        assert!(tls_hint("operation timed out; ").is_none());
    }
}

#[cfg(test)]
mod reauth_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A throwaway HTTP server that answers each connection from a canned script
    /// and records the Authorization header it was given.
    ///
    /// `replies` are (status line, JSON body) — the Content-Length is COMPUTED.
    /// It was hand-written first, was wrong by two bytes, and reqwest then failed
    /// to read the body: three tests failed asserting on the error code because
    /// the envelope never parsed. A fixture that can lie about its own length is
    /// a fixture that tests the fixture.
    fn serve(replies: Vec<(&'static str, &'static str)>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen2 = Arc::clone(&seen);
        std::thread::spawn(move || {
            for (status, body) in replies {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let mut reader = BufReader::new(&stream);
                let mut auth = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("authorization:") {
                        auth = v.trim().to_string();
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                seen2.lock().unwrap().push(auth);
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let mut w = &stream;
                let _ = w.write_all(reply.as_bytes());
                let _ = w.flush();
            }
        });
        (format!("http://127.0.0.1:{port}"), seen)
    }

    const UNAUTH: (&str, &str) = (
        "401 Unauthorized",
        r#"{"error":{"code":"unauthenticated","message":"access token expired"}}"#,
    );
    const OK: (&str, &str) = ("200 OK", r#"{"ok":true}"#);

    fn get(base: &str, bearer: &str, reauth: Option<Reauth>) -> ApiResult<Value> {
        send_json_reauth(
            headers(http().get(url(base, "/v1/thing")), Some(bearer)),
            reauth,
        )
    }

    /// The whole point: an expired access token is rotated and the call is made
    /// again with the new one, so what the caller sees is a success rather than
    /// "access token expired" plus a manual Refresh session.
    #[test]
    fn an_expired_token_is_rotated_and_the_call_retried() {
        let (base, seen) = serve(vec![UNAUTH, OK]);
        let asked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let asked2 = Arc::clone(&asked);
        let reauth: Reauth = Arc::new(move |stale: &str| {
            asked2.lock().unwrap().push(stale.to_string());
            Some("fresh-token".to_string())
        });

        let out = get(&base, "stale-token", Some(reauth)).expect("the retry must succeed");
        assert_eq!(out["ok"], true);

        assert_eq!(
            asked.lock().unwrap().as_slice(),
            ["stale-token"],
            "the refresher is handed the token that was rejected, and asked once"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "exactly one retry");
        assert_eq!(seen[0], "bearer stale-token");
        assert_eq!(
            seen[1], "bearer fresh-token",
            "the retry must carry the NEW token — replacing the header, not appending to it"
        );
    }

    /// A token that is still refused after rotation is a real authentication
    /// problem. It has to reach the user instead of looping.
    #[test]
    fn a_second_rejection_is_not_retried_again() {
        let (base, seen) = serve(vec![UNAUTH, UNAUTH]);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let reauth: Reauth = Arc::new(move |_| {
            calls2.fetch_add(1, Ordering::SeqCst);
            Some("fresh-token".to_string())
        });

        let err = get(&base, "stale-token", Some(reauth)).expect_err("must surface the 401");
        assert!(
            matches!(&err, ApiError::Server { code, .. } if code == "unauthenticated"),
            "the caller sees the server's own error, not a rotation failure: {err:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "rotation attempted once");
        assert_eq!(seen.lock().unwrap().len(), 2, "two requests, then stop");
    }

    /// Nothing to rotate to (no session, no refresh token) must behave exactly as
    /// it did before rotation existed.
    #[test]
    fn without_a_refresher_the_401_surfaces_untouched() {
        let (base, seen) = serve(vec![UNAUTH]);
        let err = get(&base, "stale-token", None).expect_err("must surface the 401");
        assert!(matches!(&err, ApiError::Server { code, .. } if code == "unauthenticated"));
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "no retry without a refresher"
        );
    }

    /// A refresher that fails (expired refresh token, no keychain entry) returns
    /// None, and that must not turn into a retry with the same stale token.
    #[test]
    fn a_failed_rotation_does_not_retry() {
        let (base, seen) = serve(vec![UNAUTH]);
        let reauth: Reauth = Arc::new(|_| None);
        let err = get(&base, "stale-token", Some(reauth)).expect_err("must surface the 401");
        assert!(matches!(&err, ApiError::Server { code, .. } if code == "unauthenticated"));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}
