//! Observability: structured tracing (JSON) + Prometheus metrics + health.
//! Logs without blobs/tokens/full pubkeys (spec §13).

use crate::config::ObsConfig;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

/// How many points the summary-ring holds (≈1 hour at a 15-sec UI poll).
pub const METRICS_SUMMARY_CAP: usize = 240;
/// Minimum step between samples — debounce for several concurrent
/// pollers (multiple panel tabs).
pub const METRICS_SUMMARY_MIN_INTERVAL_S: i64 = 10;

/// Initialize the tracing-subscriber (json|text), idempotent-safe for tests.
pub fn init_tracing(cfg: &ObsConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,unissh_server=debug,tower_http=info"));
    let registry = tracing_subscriber::registry().with(filter);
    let result = if cfg.log_format.eq_ignore_ascii_case("json") {
        registry
            .with(tracing_subscriber::fmt::layer().json().flatten_event(true))
            .try_init()
    } else {
        registry.with(tracing_subscriber::fmt::layer()).try_init()
    };
    // try_init returns Err if a subscriber is already installed (a repeat call in tests) — fine.
    let _ = result;
    // OTLP export is not compiled in (§13 seam) — don't stay silent if the operator set it.
    if !cfg.otel_endpoint.is_empty() {
        tracing::warn!(
            endpoint = %cfg.otel_endpoint,
            "otel_endpoint is configured but OTLP export is not built into this binary; \
             use the Prometheus /metrics endpoint + structured logs, or run a collector/sidecar"
        );
    }
}

/// Install the Prometheus recorder and return a handle for rendering `/metrics`.
pub fn init_metrics() -> Option<PrometheusHandle> {
    PrometheusBuilder::new().install_recorder().ok()
}

/// In-memory ring-buffer of Prometheus-counter samples for
/// `GET /v1/admin/metrics/summary`. Provides a **time axis** that raw
/// `/metrics` lacks (instantaneous cumulative counters). Filled lazily — on each
/// poll of the summary endpoint, but no more often than `min_interval` sec (debounce). Holds
/// the last `cap` points. The state is per-process and is reset on restart — it's
/// a "live" graph for the duration of viewing, not a long-term TSDB store.
pub struct MetricsHistory {
    buf: Mutex<VecDeque<MetricSample>>,
    cap: usize,
    min_interval: i64,
}

struct MetricSample {
    t: i64,
    values: BTreeMap<String, f64>,
}

impl MetricsHistory {
    pub fn new(cap: usize, min_interval_seconds: i64) -> Self {
        Self {
            buf: Mutex::new(VecDeque::new()),
            cap: cap.max(1),
            min_interval: min_interval_seconds.max(0),
        }
    }

    pub fn min_interval(&self) -> i64 {
        self.min_interval
    }
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Take a sample from the current Prometheus render if ≥ `min_interval` sec have
    /// passed since the last point. The value of each `unissh_*` counter is summed over
    /// all label sets.
    pub fn observe(&self, prometheus_text: &str, now: i64) {
        let values = parse_unissh_metrics(prometheus_text);
        let mut buf = self.buf.lock().unwrap();
        let due = buf.back().is_none_or(|s| now - s.t >= self.min_interval);
        if !due {
            return;
        }
        buf.push_back(MetricSample { t: now, values });
        while buf.len() > self.cap {
            buf.pop_front();
        }
    }

    /// Projection into series: `{ "<metric>": [ {"t":<unix>,"v":<f64>}, ... ] }` over
    /// the union of all encountered metrics, in chronological order.
    pub fn series(&self) -> serde_json::Value {
        let buf = self.buf.lock().unwrap();
        let mut names: BTreeSet<&str> = BTreeSet::new();
        for s in buf.iter() {
            names.extend(s.values.keys().map(String::as_str));
        }
        let mut series = serde_json::Map::new();
        for name in names {
            let points: Vec<serde_json::Value> = buf
                .iter()
                .filter_map(|s| {
                    s.values
                        .get(name)
                        .map(|v| serde_json::json!({ "t": s.t, "v": v }))
                })
                .collect();
            series.insert(name.to_string(), serde_json::Value::Array(points));
        }
        serde_json::Value::Object(series)
    }
}

/// Parse `unissh_*` metric values from Prometheus text, summing over
/// label sets. Skips `# HELP`/`# TYPE` and foreign metrics. Assumption:
/// our own metrics carry no label values containing spaces.
fn parse_unissh_metrics(text: &str) -> BTreeMap<String, f64> {
    let mut out: BTreeMap<String, f64> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = line.rsplit_once(' ') else {
            continue;
        };
        let Ok(v) = rhs.trim().parse::<f64>() else {
            continue;
        };
        let base = lhs.split('{').next().unwrap_or(lhs).trim();
        if !base.starts_with("unissh_") {
            continue;
        }
        *out.entry(base.to_string()).or_insert(0.0) += v;
    }
    out
}

#[cfg(test)]
mod metrics_history_tests {
    use super::*;

    const SAMPLE: &str = "# HELP unissh_admin_requests_total reqs\n\
        # TYPE unissh_admin_requests_total counter\n\
        unissh_admin_requests_total 5\n\
        unissh_push_objects_total{space=\"x\"} 3\n\
        other_metric 99\n";

    #[test]
    fn parses_only_unissh_and_sums_labels() {
        let m = parse_unissh_metrics(SAMPLE);
        assert_eq!(m.get("unissh_admin_requests_total"), Some(&5.0));
        assert_eq!(m.get("unissh_push_objects_total"), Some(&3.0));
        assert!(!m.contains_key("other_metric"));
    }

    #[test]
    fn min_interval_debounces_samples() {
        let h = MetricsHistory::new(10, 10);
        h.observe(SAMPLE, 100);
        h.observe(SAMPLE, 105); // < min_interval → dropped
        h.observe(SAMPLE, 115); // ≥ min_interval → kept
        let series = h.series();
        let pts = series["unissh_admin_requests_total"].as_array().unwrap();
        assert_eq!(pts.len(), 2);
        assert_eq!(pts[0]["t"], 100);
        assert_eq!(pts[1]["t"], 115);
    }

    #[test]
    fn ring_buffer_caps_retention() {
        let h = MetricsHistory::new(3, 0);
        for t in 0..10 {
            h.observe(SAMPLE, t);
        }
        let series = h.series();
        let pts = series["unissh_admin_requests_total"].as_array().unwrap();
        assert_eq!(pts.len(), 3);
        assert_eq!(pts[0]["t"], 7);
        assert_eq!(pts[2]["t"], 9);
    }
}
