//! Desktop OIDC "Sign in with SSO" browser-flow plumbing (Phase 5).
//!
//! The server proves the SSO credential at `POST /v1/oidc/callback` (see
//! `identity::oidc_callback`); this module is the *client* half of the Authorization
//! Code + PKCE dance that obtains the IdP-signed `id_token` to feed it:
//!
//!   1. resolve the IdP endpoints from the issuer's discovery document,
//!   2. open the SYSTEM browser to the authorize URL (PKCE + the keyset `nonce`),
//!   3. catch the `?code=…` redirect on a localhost loopback listener,
//!   4. exchange the code for an `id_token` at the IdP token endpoint.
//!
//! No new plugin dependency: the redirect is caught by a tiny `std::net` loopback
//! HTTP listener (bound to an ephemeral 127.0.0.1 port), and the browser is opened
//! through the already-present `tauri-plugin-opener`. Every network hop here is to
//! the IdP (discovery / token), NOT to the UniSSH server.
//!
//! MANUAL-TEST NOTE: the browser↔IdP round-trip cannot be exercised in CI (there is
//! no real IdP + browser). The code is written to the OIDC/OAuth2 spec and build-
//! verified; the click-through must be tested against a real IdP.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use reqwest::blocking::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::cloud::client;
use crate::error::{ApiError, ApiResult};

/// How long to wait for the user to complete the browser sign-in before giving up.
const REDIRECT_TIMEOUT: Duration = Duration::from_secs(300);
/// Per-connection read timeout while parsing an inbound redirect request line.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The IdP endpoints resolved from the issuer's discovery document.
pub struct OidcEndpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

/// 32 bytes of randomness as URL-safe base64 (no padding). Sourced from two v4
/// UUIDs (getrandom-backed) — used for the PKCE verifier and the CSRF `state`.
fn random_token() -> String {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(Uuid::new_v4().as_bytes());
    buf.extend_from_slice(Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(buf)
}

/// A CSRF `state` value (opaque, unguessable). Echoed by the IdP on the redirect and
/// checked verbatim to reject a forged/replayed callback.
pub fn random_state() -> String {
    random_token()
}

/// Build a PKCE pair: `(code_verifier, code_challenge)` where the challenge is
/// `base64url(sha256(verifier))` (S256). The verifier is kept client-side and sent
/// only on the token exchange, so intercepting the redirect `code` alone is useless.
pub fn pkce() -> (String, String) {
    let verifier = random_token();
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    (verifier, challenge)
}

/// Fetch + parse the issuer's OIDC discovery document
/// (`{issuer}/.well-known/openid-configuration`) and return the authorization + token
/// endpoints. This is the REAL OIDC discovery endpoint — not a fabricated one — so any
/// standards-compliant IdP (Okta/Auth0/Keycloak/Azure AD/Google/…) resolves correctly
/// regardless of its endpoint paths.
pub fn discover(http: &Client, issuer: &str) -> ApiResult<OidcEndpoints> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        .send()
        .map_err(|e| ApiError::other(format!("OIDC discovery request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::other(format!(
            "OIDC discovery returned HTTP {}",
            resp.status().as_u16()
        )));
    }
    let doc: Value = resp
        .json()
        .map_err(|e| ApiError::other(format!("OIDC discovery is not valid JSON: {e}")))?;
    let authorization_endpoint = doc
        .get("authorization_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::other("OIDC discovery is missing authorization_endpoint"))?
        .to_string();
    let token_endpoint = doc
        .get("token_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::other("OIDC discovery is missing token_endpoint"))?
        .to_string();
    Ok(OidcEndpoints {
        authorization_endpoint,
        token_endpoint,
    })
}

/// Compose the IdP authorize URL for the Authorization Code + PKCE flow. `nonce` is
/// the keyset key-binding (`Core::oidc_nonce`) the server's callback verifies against
/// the presented registration — it is what stops a stolen id_token being re-bound to
/// another keyset. Scope requests `openid profile groups` (name + group→space mapping);
/// whether `groups` is honoured depends on IdP configuration.
pub fn build_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> String {
    let q = |v: &str| client::enc_query(v);
    format!(
        "{authorization_endpoint}?response_type=code\
         &client_id={}&redirect_uri={}&scope={}&state={}&nonce={}\
         &code_challenge={}&code_challenge_method=S256",
        q(client_id),
        q(redirect_uri),
        q("openid profile groups"),
        q(state),
        q(nonce),
        q(code_challenge),
    )
}

/// Exchange the authorization `code` for tokens at the IdP token endpoint (public
/// client + PKCE: no client secret). Returns the `id_token` (the credential the
/// UniSSH callback verifies). An OAuth2 error body (`error`/`error_description`) is
/// surfaced verbatim.
pub fn exchange_code(
    http: &Client,
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> ApiResult<String> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];
    let resp = http
        .post(token_endpoint)
        .form(&form)
        .send()
        .map_err(|e| ApiError::other(format!("OIDC token exchange request failed: {e}")))?;
    let status = resp.status();
    let body: Value = resp
        .json()
        .map_err(|e| ApiError::other(format!("OIDC token response is not valid JSON: {e}")))?;
    if !status.is_success() {
        let code = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("token_exchange_failed");
        let desc = body
            .get("error_description")
            .and_then(Value::as_str)
            .unwrap_or("");
        return Err(ApiError::other(format!(
            "OIDC token exchange rejected ({code}): {desc}"
        )));
    }
    body.get("id_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ApiError::other("OIDC token response is missing id_token"))
}

/// Bind an ephemeral loopback listener for the redirect. Returns the listener and the
/// `http://127.0.0.1:PORT/callback` redirect URI to register in the authorize request.
pub fn bind_loopback() -> ApiResult<(TcpListener, String)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| ApiError::other(format!("could not open a loopback listener: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| ApiError::other(format!("loopback listener has no address: {e}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    Ok((listener, redirect_uri))
}

/// Block until the browser redirects back to the loopback listener, then return the
/// authorization `code`. Verifies the echoed `state` matches (CSRF) and surfaces an
/// IdP `error=` redirect. Times out after `REDIRECT_TIMEOUT` so a cancelled sign-in
/// never hangs the calling blocking task forever. Connections that are not the
/// callback (favicon probes, etc.) get a 404 and the wait continues.
pub fn wait_for_redirect(listener: TcpListener, expected_state: &str) -> ApiResult<String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| ApiError::other(format!("loopback listener setup failed: {e}")))?;
    let deadline = Instant::now() + REDIRECT_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(result) = handle_connection(stream, expected_state) {
                    return result;
                }
                // Not the callback (or a benign probe) — keep waiting.
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(ApiError::other(
                        "timed out waiting for the SSO sign-in to complete in the browser",
                    ));
                }
                std::thread::sleep(Duration::from_millis(120));
            }
            Err(e) => return Err(ApiError::other(format!("loopback accept failed: {e}"))),
        }
    }
}

/// Parse one inbound HTTP request. Returns `Some(Ok(code))` on a valid callback,
/// `Some(Err(..))` on an IdP error / state mismatch, and `None` for a request that is
/// not the callback (so the caller keeps waiting). Always writes a short HTML reply so
/// the browser tab shows a friendly "you can close this" page.
fn handle_connection(
    mut stream: TcpStream,
    expected_state: &str,
) -> Option<ApiResult<String>> {
    // The listener runs non-blocking (for the accept-timeout loop); force the accepted
    // stream blocking so the read below honours the timeout instead of erroring EAGAIN.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| ApiError::other(format!("loopback stream clone failed: {e}")))
            .ok()?,
    );
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        respond(&mut stream, "Waiting for sign-in…");
        return None;
    }

    // "GET /callback?code=…&state=… HTTP/1.1"
    let target = request_line.split_whitespace().nth(1).unwrap_or("");
    let query = match target.split_once('?') {
        Some((path, q)) if path.starts_with("/callback") => q,
        // Not the callback path (e.g. a favicon probe) — ignore and keep listening.
        _ => {
            respond(&mut stream, "Waiting for sign-in…");
            return None;
        }
    };

    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    let mut err: Option<String> = None;
    for (k, v) in parse_query(query) {
        match k.as_str() {
            "code" => code = Some(v),
            "state" => state = Some(v),
            "error" => err = Some(v),
            _ => {}
        }
    }

    if let Some(e) = err {
        respond(&mut stream, "Sign-in failed. You can close this window.");
        return Some(Err(ApiError::other(format!(
            "the identity provider returned an error: {e}"
        ))));
    }
    // CSRF: the state must round-trip byte-for-byte.
    if state.as_deref() != Some(expected_state) {
        respond(&mut stream, "Sign-in state mismatch. You can close this window.");
        return Some(Err(ApiError::other(
            "SSO redirect state mismatch (possible CSRF) — sign-in aborted",
        )));
    }
    match code {
        Some(c) => {
            respond(&mut stream, "Signed in. You can close this window and return to UniSSH.");
            Some(Ok(c))
        }
        None => {
            respond(&mut stream, "Sign-in incomplete. You can close this window.");
            Some(Err(ApiError::other(
                "SSO redirect carried no authorization code",
            )))
        }
    }
}

/// Write a minimal `text/html` 200 response and flush. Best-effort — a failed write
/// only means the browser tab lacks the courtesy page; the flow already has its code.
fn respond(stream: &mut TcpStream, message: &str) {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>UniSSH</title></head>\
         <body style=\"font-family:system-ui;padding:3rem;text-align:center\">\
         <h2>UniSSH</h2><p>{message}</p></body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    // Drop closes the socket (Connection: close) — no need to drain the request body,
    // which could otherwise block up to the read timeout after we already have the code.
}

/// Parse an `application/x-www-form-urlencoded` query string into (key, value) pairs,
/// percent- and `+`-decoding each component.
fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (url_decode(k), url_decode(v))
        })
        .collect()
}

/// Percent-decode (`%XX`) with `+` → space, tolerating malformed escapes verbatim.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let (verifier, challenge) = pkce();
        let expect = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, expect);
        // Verifier length is within the PKCE-permitted 43..=128 range.
        assert!((43..=128).contains(&verifier.len()));
    }

    #[test]
    fn parse_query_decodes_pairs() {
        let pairs = parse_query("code=ab%2Fc&state=x+y&error=");
        assert_eq!(pairs[0], ("code".into(), "ab/c".into()));
        assert_eq!(pairs[1], ("state".into(), "x y".into()));
        assert_eq!(pairs[2], ("error".into(), String::new()));
    }

    #[test]
    fn authorize_url_encodes_params() {
        let u = build_authorize_url(
            "https://idp.example/authorize",
            "unissh",
            "http://127.0.0.1:5000/callback",
            "st8",
            "nonce+val/=",
            "chal",
        );
        assert!(u.starts_with("https://idp.example/authorize?response_type=code"));
        assert!(u.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback"));
        assert!(u.contains("scope=openid%20profile%20groups"));
        assert!(u.contains("code_challenge_method=S256"));
        // base64 chars in the nonce are percent-encoded, not raw.
        assert!(u.contains("nonce=nonce%2Bval%2F%3D"));
    }
}
