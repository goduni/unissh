//! User-configurable resource ceilings and the eviction that keeps history
//! within them. A record ceiling never turns into a permanent `busy`: past it,
//! the oldest finished command or closed session is dropped; only a ceiling
//! filled by work still in flight refuses a request.
use super::*;

/// Resource ceilings of one grant, chosen with it in the native access editor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GrantLimits {
    /// Simultaneous SSH connections, explicit sessions and one-shot commands together.
    pub max_connections: u32,
    /// Commands awaiting approval, queued or running at the same time.
    pub max_active_commands: u32,
    /// Command records kept for status, output and request-key deduplication.
    pub retained_commands: u32,
    /// Session records kept, open and closed.
    pub retained_sessions: u32,
    /// Output kept per command; the rest is discarded and marked truncated.
    pub output_per_run_bytes: u32,
}
impl Default for GrantLimits {
    fn default() -> Self {
        Self {
            max_connections: 4,
            max_active_commands: 8,
            retained_commands: 128,
            retained_sessions: 32,
            output_per_run_bytes: 1024 * 1024,
        }
    }
}
impl GrantLimits {
    /// Whether every value is within the range the native editor offers. History
    /// must hold at least the work that can be in flight at once, so that only
    /// finished records ever need to make room.
    pub fn is_valid(&self) -> bool {
        (1..=64).contains(&self.max_connections)
            && (1..=256).contains(&self.max_active_commands)
            && (self.max_active_commands..=10_000).contains(&self.retained_commands)
            && (self.max_connections..=1_000).contains(&self.retained_sessions)
            && (1024 * 1024..=64 * 1024 * 1024).contains(&self.output_per_run_bytes)
            && self.output_per_run_bytes.is_multiple_of(1024 * 1024)
    }
    /// Lets saved consent with default limits keep its previous serialized form.
    pub(super) fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Application-wide ceilings shared by every integration, set in MCP settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrokerLimits {
    /// Simultaneous SSH connections across all integrations.
    pub max_connections: u32,
    /// Command records kept across all integrations.
    pub retained_commands: u32,
    /// Output kept across all commands.
    pub output_total_bytes: u64,
}
impl Default for BrokerLimits {
    fn default() -> Self {
        Self {
            max_connections: 8,
            retained_commands: 256,
            output_total_bytes: 8 * 1024 * 1024,
        }
    }
}
impl BrokerLimits {
    /// Whether every value is within the range the native settings offer.
    pub fn is_valid(&self) -> bool {
        (1..=256).contains(&self.max_connections)
            && (16..=100_000).contains(&self.retained_commands)
            && (1024 * 1024..=1024 * 1024 * 1024).contains(&self.output_total_bytes)
            && self.output_total_bytes.is_multiple_of(1024 * 1024)
    }
}

/// Saved application-wide limits at `path` (the `mcp-limits.json` beside an
/// application's MCP configuration), or `None` — the defaults — when the file is
/// absent, unreadable or invalid. Kept outside the versioned credential file so
/// that file stays readable by releases without configurable limits.
pub fn load_limits(path: &std::path::Path) -> Option<BrokerLimits> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            log::warn!("mcp: reading saved limits failed: {e}");
            return None;
        }
    };
    serde_json::from_slice(&bytes)
        .inspect_err(|e| log::warn!("mcp: saved limits are invalid ({e}); using the defaults"))
        .ok()
}

/// Saves application-wide limits to `path`: written beside it and renamed over
/// it, so a crash leaves either the old or the new limits, never a torn file.
pub fn save_limits(path: &std::path::Path, limits: &BrokerLimits) -> std::io::Result<()> {
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec(limits)?)?;
    std::fs::rename(&temp, path)
}

/// A counting limiter whose capacity can change while slots are held; a lowered
/// capacity only refuses new slots, held ones stay valid until released.
pub(super) struct Limiter {
    capacity: AtomicUsize,
    used: AtomicUsize,
}
/// A held limiter slot, released on drop.
pub(super) struct Slot(Arc<Limiter>);
impl Limiter {
    pub(super) fn new(capacity: u32) -> Arc<Self> {
        Arc::new(Self {
            capacity: AtomicUsize::new(count(capacity)),
            used: AtomicUsize::new(0),
        })
    }
    pub(super) fn set_capacity(&self, capacity: u32) {
        self.capacity.store(count(capacity), Ordering::SeqCst);
    }
    pub(super) fn try_acquire(self: &Arc<Self>) -> Option<Slot> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                (used < self.capacity.load(Ordering::SeqCst)).then_some(used + 1)
            })
            .ok()
            .map(|_| Slot(self.clone()))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A configured count as a collection size.
fn count(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

impl State {
    /// Finished command records a sealed worker no longer needs, oldest first:
    /// those of `owner` before everyone else's, only ones holding output when
    /// `with_output`.
    fn evictable(&self, owner: Option<&str>, with_output: bool) -> Vec<String> {
        let mut found: Vec<_> = self
            .runs
            .iter()
            .filter(|(_, r)| !r.worker && (!with_output || r.bytes > 0))
            .filter_map(|(id, r)| {
                r.finished_at
                    .map(|at| (owner.is_some_and(|o| r.owner != o), at, id.clone()))
            })
            .collect();
        found.sort();
        found.into_iter().map(|(_, _, id)| id).collect()
    }
    fn remove_run(&mut self, id: &str) {
        if let Some(run) = self.runs.remove(id) {
            self.retained_bytes = self.retained_bytes.saturating_sub(run.bytes);
        }
    }
    /// Makes room for one more command record of `owner`, dropping the oldest
    /// finished records, its own first; false, with nothing dropped, when the
    /// records filling a ceiling are still in flight.
    pub(super) fn admit_run(&mut self, owner: &str, per_grant: u32, total: u32) -> bool {
        let any = self.evictable(Some(owner), false);
        let own = any
            .iter()
            .take_while(|id| self.runs.get(*id).is_some_and(|r| r.owner == owner))
            .count();
        let own_excess = (self.runs.values().filter(|r| r.owner == owner).count() + 1)
            .saturating_sub(count(per_grant));
        let total_excess = (self.runs.len() + 1).saturating_sub(count(total));
        // Own records come first in `any`, so dropping `own_excess` of them also
        // counts toward the application-wide excess.
        let dropped = own_excess.max(total_excess);
        if own < own_excess || any.len() < dropped {
            return false;
        }
        for id in any.iter().take(dropped) {
            self.remove_run(id);
        }
        true
    }
    /// Makes room for one more session record of `owner` by dropping its oldest
    /// closed sessions; false, with nothing dropped, when too few are closed.
    pub(super) fn admit_session(&mut self, owner: &str, retained: u32) -> bool {
        let excess = (self.sessions.values().filter(|s| s.owner == owner).count() + 1)
            .saturating_sub(count(retained));
        let mut closed: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.owner == owner && s.state == "closed")
            .map(|(id, s)| (s.created_unix_ms, id.clone()))
            .collect();
        if closed.len() < excess {
            return false;
        }
        closed.sort();
        for (_, id) in closed.into_iter().take(excess) {
            self.sessions.remove(&id);
        }
        true
    }
    /// Brings existing history within lowered application-wide ceilings.
    pub(super) fn trim(&mut self, limits: &BrokerLimits) {
        let excess = self
            .runs
            .len()
            .saturating_sub(count(limits.retained_commands));
        for id in self.evictable(None, false).into_iter().take(excess) {
            self.remove_run(&id);
        }
        let total = usize::try_from(limits.output_total_bytes).unwrap_or(usize::MAX);
        for id in self.evictable(None, true) {
            if self.retained_bytes <= total {
                break;
            }
            self.remove_run(&id);
        }
    }
    /// Frees retained output for `needed` more bytes of `owner`'s run by dropping
    /// the oldest finished records holding output, its own first; returns how
    /// many bytes may now be kept.
    pub(super) fn output_room(&mut self, owner: &str, needed: usize, total: u64) -> usize {
        let total = usize::try_from(total).unwrap_or(usize::MAX);
        if total.saturating_sub(self.retained_bytes) < needed {
            for id in self.evictable(Some(owner), true) {
                self.remove_run(&id);
                if total.saturating_sub(self.retained_bytes) >= needed {
                    break;
                }
            }
        }
        total.saturating_sub(self.retained_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{load_limits, save_limits, BrokerLimits};

    #[test]
    fn saved_limits_read_back_as_saved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-limits.json");
        assert_eq!(load_limits(&path), None, "nothing saved yet");
        let limits = BrokerLimits {
            max_connections: 3,
            retained_commands: 64,
            output_total_bytes: 2 * 1024 * 1024,
        };
        save_limits(&path, &limits).unwrap();
        assert_eq!(load_limits(&path), Some(limits), "the saved limits");
        assert!(
            !path.with_extension("json.tmp").exists(),
            "no temporary file is left"
        );
    }

    #[test]
    fn a_damaged_limits_file_means_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-limits.json");
        std::fs::write(&path, br#"{"max_connections":3,"surprise":1}"#).unwrap();
        assert_eq!(load_limits(&path), None, "unknown fields are refused");
    }
}
