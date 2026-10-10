//! Sync transport: the [`SyncTransport`] trait + the in-memory mock [`InMemoryTransport`].
//!
//! There is no real server/network in this repository. The trait is the narrow
//! boundary of a "dumb box of versioned blobs" (server-tz §3.1): accept
//! versions (`push_objects`), hand off "what is after the cursor" (`delta_since`), report
//! the maximum (`report_version`). The mock is an **untrusted** server stand-in: it
//! can be made to lie (hand off objects below the cursor, understate
//! report_version, hand off forged/stale objects) for the engine's negative
//! tests.

use crate::error::SyncError;
use crate::object::SyncObject;

/// The narrow contract of an untrusted sync server. The engine does NOT trust ordering, nor
/// `server_seq`, nor content — it only verifies on receipt.
pub trait SyncTransport {
    /// Sends objects to the server. The server assigns each a monotonic
    /// `server_seq` (the client does not choose). Returns the assigned seq in the order of
    /// the input objects.
    fn push_objects(&mut self, objects: &[SyncObject]) -> Result<Vec<u64>, SyncError>;

    /// Hands off everything with `server_seq > cursor`, in `seq` ASC order. (The mock may
    /// violate order/values — the engine re-sorts and verifies.)
    fn delta_since(&self, cursor: u64) -> Vec<(u64, SyncObject)>;

    /// Reports the maximum assigned `server_seq` (informational; the engine
    /// uses it for the anti-rollback check but does NOT trust it as an authority).
    fn report_version(&self) -> u64;
}

/// In-memory server mock. Stores `(seq, SyncObject)` in receipt order.
/// **Untrusted**: the `force_*` levers force it to lie for negative tests.
#[derive(Debug, Default)]
pub struct InMemoryTransport {
    objects: Vec<(u64, SyncObject)>,
    next_seq: u64,
    /// If `Some(f)` — all handed-off seq are replaced with `f` (simulates
    /// handing off objects below the cursor).
    forced_seq_floor: Option<u64>,
    /// If `Some(v)` — `report_version` returns `v` instead of the real max.
    forced_report_version: Option<u64>,
    /// Substituted objects added to the `delta_since` output on top of the real ones
    /// (simulates the server injecting forged objects).
    injected: Vec<(u64, SyncObject)>,
}

impl InMemoryTransport {
    /// A new empty mock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Force it to hand off all objects with a fixed seq (misbehave).
    pub fn force_seq_floor(&mut self, seq: u64) {
        self.forced_seq_floor = Some(seq);
    }

    /// Force `report_version` to return the given value (misbehave).
    pub fn force_report_version(&mut self, v: u64) {
        self.forced_report_version = Some(v);
    }

    /// Inject an object at the given seq (misbehave: forged/stale).
    pub fn inject(&mut self, seq: u64, obj: SyncObject) {
        self.injected.push((seq, obj));
    }

    /// Direct access for tests: the real max seq.
    pub fn real_max_seq(&self) -> u64 {
        self.next_seq
    }
}

impl SyncTransport for InMemoryTransport {
    fn push_objects(&mut self, objects: &[SyncObject]) -> Result<Vec<u64>, SyncError> {
        let mut assigned = Vec::with_capacity(objects.len());
        for o in objects {
            self.next_seq += 1;
            self.objects.push((self.next_seq, o.clone()));
            assigned.push(self.next_seq);
        }
        Ok(assigned)
    }

    fn delta_since(&self, cursor: u64) -> Vec<(u64, SyncObject)> {
        // Honest behavior: hand off everything with a real `server_seq > cursor`.
        // **Misbehave** (`forced_seq_floor`): the untrusted server lies — it hands off
        // ALL stored objects, re-stamping their seq to `floor` (including <= cursor),
        // ignoring the real filter. Thus the engine must itself discard the
        // below-cursor ones (D-CURSOR) instead of trusting the transport's seq.
        let mut out: Vec<(u64, SyncObject)> = match self.forced_seq_floor {
            Some(floor) => self
                .objects
                .iter()
                .map(|(_, o)| (floor, o.clone()))
                .collect(),
            None => self
                .objects
                .iter()
                .filter(|(s, _)| *s > cursor)
                .map(|(s, o)| (*s, o.clone()))
                .collect(),
        };
        for (s, o) in &self.injected {
            out.push((*s, o.clone()));
        }
        out
    }

    fn report_version(&self) -> u64 {
        self.forced_report_version.unwrap_or(self.next_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{AuditObject, SyncObject};

    fn audit(tag: u8) -> SyncObject {
        SyncObject::Audit(AuditObject {
            vault_id: vec![tag],
            entry_blob: vec![tag],
            signature: vec![1_u8; 67],
            author_pubkey: vec![2_u8; 32],
        })
    }

    #[test]
    fn push_assigns_monotonic_seq_and_delta_orders() {
        let mut t = InMemoryTransport::new();
        t.push_objects(&[audit(1), audit(2)]).unwrap();
        t.push_objects(&[audit(3)]).unwrap();
        assert_eq!(t.report_version(), 3);
        let d = t.delta_since(0);
        let seqs: Vec<u64> = d.iter().map(|(s, _)| *s).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
        let d2 = t.delta_since(2);
        assert_eq!(d2.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![3]);
    }

    #[test]
    fn misbehave_below_cursor_and_stale_version() {
        let mut t = InMemoryTransport::new();
        t.push_objects(&[audit(1)]).unwrap();
        // force it to hand off objects with seq=0 (below any cursor)
        t.force_seq_floor(0);
        let d = t.delta_since(5); // even above the real one — the mock lies
        assert!(d.iter().all(|(s, _)| *s == 0));
        // force report_version to return an understated value
        t.force_report_version(0);
        assert_eq!(t.report_version(), 0);
    }
}
