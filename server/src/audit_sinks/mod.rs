//! Audit export sinks: deliver the audit log, in seq order, to a destination the
//! owner configured (`[audit.*]`), with a persisted cursor.
//!
//! Contract (every sink):
//! - One background task per configured sink ([`spawn_configured`]), started
//!   with the server and stopped on shutdown.
//! - [`Delivery::step`] reads up to `batch_size` entries after the sink's cursor,
//!   hands them to [`Sink::deliver`], and advances the cursor
//!   (`audit_sink_cursor`) only after the sink acknowledges.
//! - A failure (sink error, or the cursor write after an ack) keeps the SAME
//!   batch and retries it after an exponential backoff (1 s doubling to 5 min,
//!   with jitter), reset by the next success.
//! - At-least-once: a crash or cursor-write failure after an ack re-sends that
//!   batch. Receivers dedupe on `seq`.
//! - Failures are logged with the sink name, seq range and an error code only,
//!   never entry contents (the server log must not duplicate the audit log).

pub mod webhook;

use crate::error::AppResult;
use crate::state::AppState;
use crate::store::Store;
use crate::store::models::AuditExportRow;
use crate::time::SharedClock;
use futures_util::future::BoxFuture;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// First retry delay after a failure.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Ceiling of the retry delay (jitter included).
pub const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// How long a caught-up sink waits before looking for new entries.
pub const IDLE_POLL: Duration = Duration::from_secs(2);

/// A non-empty run of consecutive audit entries, seq ascending.
pub struct Batch {
    rows: Vec<AuditExportRow>,
}

impl Batch {
    pub fn rows(&self) -> &[AuditExportRow] {
        &self.rows
    }
    pub fn first_seq(&self) -> i64 {
        self.rows[0].seq
    }
    pub fn last_seq(&self) -> i64 {
        self.rows[self.rows.len() - 1].seq
    }
}

/// Why a delivery failed: a short code (`http_500`, `timeout`, `connect`), safe
/// to log. It must never carry entry contents, URLs or secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkError(pub String);

impl std::fmt::Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A destination for audit entries. `Ok(())` is the acknowledgement that lets
/// the cursor advance past the batch; any `Err` retries the same batch.
pub trait Sink: Send + Sync {
    /// Stable name: the `audit_sink_cursor.sink` key and the log/metric label.
    fn name(&self) -> &str;
    fn deliver<'a>(&'a self, batch: &'a Batch) -> BoxFuture<'a, Result<(), SinkError>>;
}

/// Where a sink's acknowledged position is persisted. A trait so tests can fail
/// the write that follows an ack.
pub trait CursorStore: Send + Sync {
    fn load<'a>(&'a self, sink: &'a str) -> BoxFuture<'a, AppResult<i64>>;
    fn save<'a>(&'a self, sink: &'a str, last_seq: i64, now: i64) -> BoxFuture<'a, AppResult<()>>;
}

impl CursorStore for Store {
    fn load<'a>(&'a self, sink: &'a str) -> BoxFuture<'a, AppResult<i64>> {
        Box::pin(self.audit_sink_cursor(sink))
    }
    fn save<'a>(&'a self, sink: &'a str, last_seq: i64, now: i64) -> BoxFuture<'a, AppResult<()>> {
        Box::pin(self.set_audit_sink_cursor(sink, last_seq, now))
    }
}

/// Outcome of one [`Delivery::step`]. Status and metrics (per-sink last seq,
/// last error, failure count) hook in where [`Delivery::run`] observes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The sink acknowledged `first..=last` and the cursor now stands at `last`.
    Delivered { first: i64, last: i64 },
    /// Nothing after the cursor.
    Idle,
    /// The batch (or the log read) failed; retry after `delay`.
    Failed { delay: Duration },
}

impl Step {
    /// How long the loop waits before the next step.
    pub fn wait(&self) -> Duration {
        match self {
            Step::Delivered { .. } => Duration::ZERO,
            Step::Idle => IDLE_POLL,
            Step::Failed { delay } => *delay,
        }
    }
}

/// The transport-independent delivery loop for one sink.
pub struct Delivery {
    sink: Arc<dyn Sink>,
    entries: Store,
    cursor: Arc<dyn CursorStore>,
    clock: SharedClock,
    batch_size: i64,
    /// Spreads retries of many servers hitting one receiver. Injected so tests
    /// see the bare backoff sequence.
    jitter: fn(Duration) -> Duration,
    failures: u32,
    /// The batch being retried. Kept in memory so a retry sends exactly the same
    /// entries even if more were appended meanwhile.
    pending: Option<Batch>,
}

impl Delivery {
    pub fn new(
        sink: Arc<dyn Sink>,
        entries: Store,
        cursor: Arc<dyn CursorStore>,
        clock: SharedClock,
        batch_size: u32,
    ) -> Self {
        Self {
            sink,
            entries,
            cursor,
            clock,
            batch_size: i64::from(batch_size.max(1)),
            jitter: random_jitter,
            failures: 0,
            pending: None,
        }
    }

    /// One delivery attempt. Never sleeps: the caller waits [`Step::wait`].
    pub async fn step(&mut self) -> Step {
        let batch = match self.pending.take() {
            Some(b) => b,
            None => match self.next_batch().await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    self.failures = 0;
                    return Step::Idle;
                }
                Err(e) => {
                    let delay = self.fail();
                    tracing::warn!(
                        sink = self.sink.name(),
                        error = e.code.as_str(),
                        retry_in_ms = delay.as_millis() as u64,
                        "audit sink could not read the log"
                    );
                    return Step::Failed { delay };
                }
            },
        };
        let (first, last) = (batch.first_seq(), batch.last_seq());
        let error = match self.sink.deliver(&batch).await {
            Ok(()) => match self
                .cursor
                .save(self.sink.name(), last, self.clock.now_unix())
                .await
            {
                Ok(()) => {
                    self.failures = 0;
                    return Step::Delivered { first, last };
                }
                // Acked but not recorded: the batch goes out again (at-least-once).
                Err(e) => format!("cursor_write_{}", e.code.as_str()),
            },
            Err(e) => e.0,
        };
        self.pending = Some(batch);
        let delay = self.fail();
        tracing::warn!(
            sink = self.sink.name(),
            first_seq = first,
            last_seq = last,
            error = %error,
            retry_in_ms = delay.as_millis() as u64,
            "audit sink delivery failed; the same batch will be retried"
        );
        Step::Failed { delay }
    }

    async fn next_batch(&self) -> AppResult<Option<Batch>> {
        let after = self.cursor.load(self.sink.name()).await?;
        let rows = self
            .entries
            .export_audit_page(after + 1, i64::MAX, self.batch_size)
            .await?;
        Ok((!rows.is_empty()).then_some(Batch { rows }))
    }

    /// Record a failure and return the delay before the retry.
    fn fail(&mut self) -> Duration {
        let base = BACKOFF_MIN
            .saturating_mul(1u32 << self.failures.min(16))
            .min(BACKOFF_MAX);
        self.failures = self.failures.saturating_add(1);
        (self.jitter)(base).min(BACKOFF_MAX)
    }

    /// Step until `shutdown` turns true (or its sender is dropped).
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let name = self.sink.name().to_string();
        tracing::info!(sink = %name, "audit sink started");
        loop {
            if *shutdown.borrow() {
                break;
            }
            let step = tokio::select! {
                s = self.step() => s,
                _ = shutdown.changed() => break,
            };
            let wait = step.wait();
            if wait.is_zero() {
                continue;
            }
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => break,
            }
        }
        tracing::info!(sink = %name, "audit sink stopped");
    }
}

/// Up to +25 % of `base`, so retries from a fleet do not arrive in lockstep.
fn random_jitter(base: Duration) -> Duration {
    let mut b = [0u8; 8];
    crate::ids::fill_random(&mut b);
    let quarter = (base.as_millis() / 4) as u64;
    let extra = if quarter == 0 {
        0
    } else {
        u64::from_le_bytes(b) % (quarter + 1)
    };
    base + Duration::from_millis(extra)
}

/// Start one delivery task per sink configured in `[audit]`. Errors (a secret
/// that cannot be read, a client that cannot be built) stop the boot.
pub fn spawn_configured(
    state: &AppState,
    shutdown: watch::Receiver<bool>,
) -> Result<Vec<JoinHandle<()>>, String> {
    let mut tasks = Vec::new();
    if let Some(cfg) = &state.config.audit.webhook {
        let sink = webhook::WebhookSink::from_config(cfg, crate::ids::b64(&state.instance_id))?;
        let delivery = Delivery::new(
            Arc::new(sink),
            state.store.clone(),
            Arc::new(state.store.clone()),
            state.clock.clone(),
            cfg.batch_size,
        );
        tasks.push(tokio::spawn(delivery.run(shutdown.clone())));
    }
    Ok(tasks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;
    use crate::time::TestClock;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Records the seqs of every attempted batch; acks unless `fail` is set.
    #[derive(Default)]
    struct FakeSink {
        fail: AtomicBool,
        attempts: Mutex<Vec<Vec<i64>>>,
    }

    impl FakeSink {
        fn attempts(&self) -> Vec<Vec<i64>> {
            self.attempts.lock().unwrap().clone()
        }
    }

    impl Sink for FakeSink {
        fn name(&self) -> &str {
            "fake"
        }
        fn deliver<'a>(&'a self, batch: &'a Batch) -> BoxFuture<'a, Result<(), SinkError>> {
            let seqs = batch.rows().iter().map(|r| r.seq).collect();
            self.attempts.lock().unwrap().push(seqs);
            let fail = self.fail.load(Ordering::SeqCst);
            Box::pin(async move {
                if fail {
                    Err(SinkError("http_500".into()))
                } else {
                    Ok(())
                }
            })
        }
    }

    /// The real cursor table, with a switch that fails the write after an ack.
    struct FlakyCursor {
        store: Store,
        fail_save: AtomicBool,
    }

    impl CursorStore for FlakyCursor {
        fn load<'a>(&'a self, sink: &'a str) -> BoxFuture<'a, AppResult<i64>> {
            self.store.load(sink)
        }
        fn save<'a>(&'a self, sink: &'a str, seq: i64, now: i64) -> BoxFuture<'a, AppResult<()>> {
            if self.fail_save.load(Ordering::SeqCst) {
                return Box::pin(async { Err(AppError::internal("db down")) });
            }
            self.store.save(sink, seq, now)
        }
    }

    async fn store_with(n: usize) -> Store {
        let store = Store::connect_sqlite(":memory:", 1).await.unwrap();
        store.migrate().await.unwrap();
        store.ensure_instance(1).await.unwrap();
        for _ in 0..n {
            append(&store).await;
        }
        store
    }

    async fn append(store: &Store) {
        store
            .append_audit_server_observed(&serde_json::json!({"ev": "login"}), None, 1)
            .await
            .unwrap();
    }

    fn delivery(sink: &Arc<FakeSink>, store: &Store, cursor: Arc<dyn CursorStore>) -> Delivery {
        let clock: SharedClock = Arc::new(TestClock::new(1));
        Delivery {
            jitter: |d| d,
            ..Delivery::new(sink.clone(), store.clone(), cursor, clock, 2)
        }
    }

    #[tokio::test]
    async fn delivers_in_seq_order() {
        let store = store_with(5).await;
        let sink = Arc::new(FakeSink::default());
        let mut d = delivery(&sink, &store, Arc::new(store.clone()));
        while d.step().await != Step::Idle {}
        assert_eq!(sink.attempts(), vec![vec![1, 2], vec![3, 4], vec![5]]);
    }

    #[tokio::test]
    async fn cursor_advances_only_on_ack() {
        let store = store_with(2).await;
        let sink = Arc::new(FakeSink::default());
        let mut d = delivery(&sink, &store, Arc::new(store.clone()));
        sink.fail.store(true, Ordering::SeqCst);
        d.step().await;
        assert_eq!(store.audit_sink_cursor("fake").await.unwrap(), 0);
        sink.fail.store(false, Ordering::SeqCst);
        d.step().await;
        assert_eq!(store.audit_sink_cursor("fake").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn failing_sink_retries_the_same_batch() {
        // Batch size 2 with one entry: the entry appended during the outage would
        // fit, but the retry must still be exactly the batch that failed.
        let store = store_with(1).await;
        let sink = Arc::new(FakeSink::default());
        let mut d = delivery(&sink, &store, Arc::new(store.clone()));
        sink.fail.store(true, Ordering::SeqCst);
        d.step().await;
        append(&store).await;
        d.step().await;
        sink.fail.store(false, Ordering::SeqCst);
        d.step().await;
        assert_eq!(sink.attempts(), vec![vec![1], vec![1], vec![1]]);
    }

    #[tokio::test]
    async fn restart_resumes_from_the_cursor() {
        let store = store_with(4).await;
        let sink = Arc::new(FakeSink::default());
        delivery(&sink, &store, Arc::new(store.clone()))
            .step()
            .await;
        // A fresh loop (new process) knows only what the cursor table says.
        let mut restarted = delivery(&sink, &store, Arc::new(store.clone()));
        restarted.step().await;
        assert_eq!(sink.attempts(), vec![vec![1, 2], vec![3, 4]]);
    }

    #[tokio::test]
    async fn acked_batch_whose_cursor_write_failed_is_sent_again() {
        let store = store_with(2).await;
        let sink = Arc::new(FakeSink::default());
        let cursor = Arc::new(FlakyCursor {
            store: store.clone(),
            fail_save: AtomicBool::new(true),
        });
        let mut d = delivery(&sink, &store, cursor.clone());
        assert!(matches!(d.step().await, Step::Failed { .. }));
        cursor.fail_save.store(false, Ordering::SeqCst);
        assert_eq!(d.step().await, Step::Delivered { first: 1, last: 2 });
        assert_eq!(sink.attempts(), vec![vec![1, 2], vec![1, 2]]);
    }

    #[tokio::test]
    async fn backoff_doubles_to_the_cap_and_resets_on_success() {
        let store = store_with(4).await;
        let sink = Arc::new(FakeSink::default());
        let mut d = delivery(&sink, &store, Arc::new(store.clone()));
        let mut waits = Vec::new();
        sink.fail.store(true, Ordering::SeqCst);
        for _ in 0..11 {
            waits.push(d.step().await.wait().as_secs());
        }
        sink.fail.store(false, Ordering::SeqCst);
        waits.push(d.step().await.wait().as_secs());
        sink.fail.store(true, Ordering::SeqCst);
        waits.push(d.step().await.wait().as_secs());
        assert_eq!(
            waits,
            vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 0, 1]
        );
    }
}
