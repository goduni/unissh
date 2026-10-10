//! Rate-limit (spec §13): per-IP token-bucket, deterministic via `Clock`
//! (testable). Per-instance (sufficient for multi-instance — the public
//! endpoints are thus protected from abuse). 429 + Retry-After.

use crate::error::AppError;
use crate::state::AppState;
use crate::time::SharedClock;
use axum::extract::{ConnectInfo, State};
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

struct Bucket {
    tokens: f64,
    last: i64,
}

/// A bucket untouched for longer than this window is considered idle and may be
/// removed (it is recreated full — losing the state is safe). Protection against
/// memory-exhaustion under a flood of unique IPs.
const IDLE_TTL_SECS: i64 = 3600;
/// Minimum interval between map sweeps (amortizes the O(n) cleanup).
const SWEEP_INTERVAL_SECS: i64 = 60;

struct Inner {
    buckets: HashMap<IpAddr, Bucket>,
    last_sweep: i64,
}

/// Per-IP token-bucket: `burst` capacity, refill of `rps` tokens/sec.
pub struct RateLimiter {
    inner: Mutex<Inner>,
    rps: f64,
    burst: f64,
    clock: SharedClock,
}

impl RateLimiter {
    pub fn new(rps: u32, burst: u32, clock: SharedClock) -> Self {
        Self {
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                last_sweep: i64::MIN,
            }),
            rps: f64::from(rps.max(1)),
            burst: f64::from(burst.max(1)),
            clock,
        }
    }

    /// Debit 1 token. `Ok(())` if allowed, `Err(retry_after_secs)` otherwise.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let now = self.clock.now_unix();
        // A panic mid-update leaves at worst one stale bucket; keep limiting.
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Periodically evict idle buckets so the map doesn't grow
        // unboundedly (especially with a forgeable key under trust_proxy).
        if now.saturating_sub(inner.last_sweep) >= SWEEP_INTERVAL_SECS {
            inner
                .buckets
                .retain(|_, b| now.saturating_sub(b.last) < IDLE_TTL_SECS);
            inner.last_sweep = now;
        }
        let b = inner.buckets.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = (now - b.last).max(0) as f64;
        b.tokens = (b.tokens + elapsed * self.rps).min(self.burst);
        b.last = now;
        let verdict = if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            // time until the next token
            let need = (1.0 - b.tokens) / self.rps;
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "the value is at least 1.0 and float-to-int `as` saturates; whole seconds are the intent"
            )]
            let secs = need.ceil().max(1.0) as u64;
            Err(secs)
        };
        drop(inner);
        verdict
    }
}

/// Extract the client IP honoring trust_proxy. Behind a trusted reverse-proxy we take
/// the **last** (rightmost) element of `X-Forwarded-For` — the one added by our
/// immediate proxy (= the real peer it saw). The left elements are
/// client-controlled and forgeable, so we can't take the first (otherwise the
/// per-IP rate-limit is bypassed by XFF spoofing). Exactly one
/// trusted hop is assumed (the documented topology: a single Caddy/nginx in front of the server).
fn client_ip(state: &AppState, peer: SocketAddr, headers: &http::HeaderMap) -> IpAddr {
    if state.config.server.trust_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(last) = xff.rsplit(',').next() {
                if let Ok(ip) = last.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    peer.ip()
}

/// Rate-limit middleware for /v1 (applied in build_router).
pub async fn rate_limit_mw(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
    let ip = client_ip(&state, peer, req.headers());
    match state.rate.check(ip) {
        Ok(()) => next.run(req).await,
        Err(retry) => {
            metrics::counter!("unissh_rate_limited_total").increment(1);
            AppError::rate_limited("rate limit exceeded")
                .with_retry_after(retry)
                .into_response()
        }
    }
}
