//! Shared application state (axum `State`). All state lives in the DB;
//! `AppState` holds the pool, config, clock, metrics-handle and rate-limiter.

use crate::config::Config;
use crate::http::ratelimit::RateLimiter;
use crate::obs::MetricsHistory;
use crate::store::Store;
use crate::time::SharedClock;
use metrics_exporter_prometheus::PrometheusHandle;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

/// Hot-reloadable runtime knobs (edited via `PUT /v1/admin/config` without a
/// restart). Only values safe for atomic replacement on the hot path.
pub struct RuntimeConfig {
    pub validate_signatures: AtomicBool,
    /// Cap on the size of a single object (bytes), enforced in `sync/push`.
    pub max_object_bytes: AtomicUsize,
    /// Cap on the number of objects in a single `sync/push`.
    pub max_objects_per_push: AtomicUsize,
}

pub struct AppStateInner {
    pub store: Store,
    pub config: Config,
    /// This server's instance identity (random 16B), stashed at boot from the
    /// singleton `instance` row. Used as the auth-challenge host binding.
    pub instance_id: Vec<u8>,
    /// Server-PRIVATE secret (32B) keying the enumeration-resistant decoy salt in
    /// `GET /v1/escrow/params`. Loaded at boot from the singleton `instance` row.
    /// Unlike `instance_id` this is NEVER returned by any endpoint — that is the
    /// whole point: a public value (like `instance_id`) would let an attacker
    /// recompute the decoy and distinguish enrolled from unenrolled handles.
    pub escrow_decoy_secret: Vec<u8>,
    pub runtime: RuntimeConfig,
    pub clock: SharedClock,
    pub metrics: Option<PrometheusHandle>,
    /// Ring-buffer of samples for `/v1/admin/metrics/summary` (Some when metrics
    /// are enabled). Provides a time axis on top of the instantaneous `/metrics`.
    pub metrics_history: Option<Arc<MetricsHistory>>,
    pub rate: Arc<RateLimiter>,
    /// Unix time of process start (for `uptime_seconds` in `/v1/admin/health`).
    pub started_at_unix: i64,
    /// Unix time of the last successful janitor run (0 = not yet).
    pub last_janitor_run: AtomicI64,
}

/// A cloneable state handle (axum requires `Clone` for `State`).
pub type AppState = Arc<AppStateInner>;

impl AppStateInner {
    pub fn new(
        store: Store,
        config: Config,
        instance_id: Vec<u8>,
        escrow_decoy_secret: Vec<u8>,
        clock: SharedClock,
        metrics: Option<PrometheusHandle>,
    ) -> AppState {
        let rate = Arc::new(RateLimiter::new(
            config.limits.rate_limit_per_ip_rps,
            config.limits.rate_limit_burst,
            clock.clone(),
        ));
        let runtime = RuntimeConfig {
            validate_signatures: AtomicBool::new(config.sync.validate_signatures),
            max_object_bytes: AtomicUsize::new(config.limits.max_object_bytes),
            max_objects_per_push: AtomicUsize::new(config.limits.max_objects_per_push),
        };
        // The history-ring exists only when metrics are enabled (otherwise there's nothing to sample).
        let metrics_history = metrics.as_ref().map(|_| {
            Arc::new(MetricsHistory::new(
                crate::obs::METRICS_SUMMARY_CAP,
                crate::obs::METRICS_SUMMARY_MIN_INTERVAL_S,
            ))
        });
        let started_at_unix = clock.now_unix();
        Arc::new(Self {
            store,
            config,
            instance_id,
            escrow_decoy_secret,
            runtime,
            clock,
            metrics,
            metrics_history,
            rate,
            started_at_unix,
            last_janitor_run: AtomicI64::new(0),
        })
    }

    pub fn now(&self) -> i64 {
        self.clock.now_unix()
    }

    /// Best-effort server-observed audit append. The caller owns the emitted
    /// JSON shape (`ev`, including its own `"ts"` field); this only deduplicates
    /// the `append_audit_server_observed(..).await` tail. Errors are swallowed
    /// (audit is best-effort and must never fail a request).
    pub async fn audit_event(&self, ev: &serde_json::Value, vault_id: Option<&[u8]>) {
        let _ = self
            .store
            .append_audit_server_observed(ev, vault_id, self.now())
            .await;
    }

    /// Live value of the defense-in-depth signature check (§2.4), hot-reloadable.
    pub fn validate_signatures(&self) -> bool {
        self.runtime.validate_signatures.load(Ordering::Relaxed)
    }

    pub fn set_validate_signatures(&self, v: bool) {
        self.runtime.validate_signatures.store(v, Ordering::Relaxed);
    }

    /// Live cap on object size (hot-reloadable, enforced in `sync/push`).
    pub fn max_object_bytes(&self) -> usize {
        self.runtime.max_object_bytes.load(Ordering::Relaxed)
    }

    pub fn set_max_object_bytes(&self, v: usize) {
        self.runtime.max_object_bytes.store(v, Ordering::Relaxed);
    }

    /// Live cap on the number of objects in a push (hot-reloadable).
    pub fn max_objects_per_push(&self) -> usize {
        self.runtime.max_objects_per_push.load(Ordering::Relaxed)
    }

    pub fn set_max_objects_per_push(&self, v: usize) {
        self.runtime
            .max_objects_per_push
            .store(v, Ordering::Relaxed);
    }
}
