//! Clock abstraction — for deterministic TTL tests (nonce/invite/session/
//! idempotency). The server stores unix seconds (i64) in all `*_at`/`expires_at`.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Source of the "current time" in unix seconds.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now_unix(&self) -> i64;
}

/// Production system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

/// Controllable clock for tests.
#[derive(Debug)]
pub struct TestClock {
    now: AtomicI64,
}

impl TestClock {
    pub const fn new(start: i64) -> Self {
        Self {
            now: AtomicI64::new(start),
        }
    }
    pub fn advance(&self, secs: i64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }
    pub fn set(&self, secs: i64) {
        self.now.store(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_unix(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

pub type SharedClock = Arc<dyn Clock>;

pub fn system_clock() -> SharedClock {
    Arc::new(SystemClock)
}
