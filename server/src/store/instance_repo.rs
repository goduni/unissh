//! Singleton `instance` row: identity of this server, claim state, setup code,
//! instance-wide next_seq.

use super::{Store, Tx, Val};
use crate::error::AppResult;
use crate::ids;
use crate::store::models::InstanceRow;

const SEL: &str = "SELECT instance_id, name, claimed, owner_account_id, setup_code_hash, \
                   next_seq, created_at FROM instance WHERE id = 1";

impl Store {
    /// Create the singleton on first boot (race-safe via ON CONFLICT DO NOTHING).
    pub async fn ensure_instance(&self, now: i64) -> AppResult<InstanceRow> {
        let iid = ids::random_id16().to_vec();
        self.exec(
            "INSERT INTO instance (id, instance_id, claimed, next_seq, created_at) \
             VALUES (1, ?, 0, 0, ?) ON CONFLICT (id) DO NOTHING",
            vec![Val::B(iid), Val::I(now)],
        )
        .await?;
        self.instance().await
    }

    pub async fn instance(&self) -> AppResult<InstanceRow> {
        Ok(self
            .fetch_optional_as::<InstanceRow>(SEL, vec![])
            .await?
            .expect("instance row exists after ensure_instance"))
    }

    pub async fn set_setup_code_hash(&self, hash: &[u8]) -> AppResult<()> {
        self.exec(
            "UPDATE instance SET setup_code_hash = ? WHERE id = 1 AND claimed = 0",
            vec![Val::b(hash)],
        )
        .await?;
        Ok(())
    }

    /// Single-winner claim; clears the setup code. Runs inside the caller's tx
    /// (atomic with owner account + first space creation).
    pub async fn claim_instance_cas(
        &self,
        tx: &mut Tx<'_>,
        owner_account_id: &[u8],
        name: Option<&str>,
    ) -> AppResult<bool> {
        let n = tx
            .exec(
                "UPDATE instance SET claimed = 1, owner_account_id = ?, \
                 name = COALESCE(?, name), setup_code_hash = NULL \
                 WHERE id = 1 AND claimed = 0",
                vec![Val::b(owner_account_id), Val::OptT(name.map(String::from))],
            )
            .await?;
        Ok(n == 1)
    }

    /// Raise `next_seq` to the floor `to`, if it is above the current value
    /// (NEVER lowers). Returns (old, new).
    ///
    /// Cross-dialect note: SQLite's `MAX(a, b)` (two args) is a scalar function,
    /// but Postgres's `MAX` is an aggregate-only — the two-arg form does not
    /// exist there (`GREATEST` would be the Postgres equivalent, but the two
    /// dialects don't share one spelling). A `CASE` expression is standard SQL
    /// and works identically on both.
    pub async fn bump_instance_seq_to(&self, to: i64) -> AppResult<(i64, i64)> {
        let old = self.instance().await?.next_seq;
        self.exec(
            "UPDATE instance SET next_seq = CASE WHEN next_seq < ? THEN ? ELSE next_seq END \
             WHERE id = 1",
            vec![Val::I(to), Val::I(to)],
        )
        .await?;
        Ok((old, self.instance().await?.next_seq))
    }

    pub async fn bump_instance_seq_by(&self, by: i64) -> AppResult<(i64, i64)> {
        let old = self.instance().await?.next_seq;
        self.exec(
            "UPDATE instance SET next_seq = next_seq + ? WHERE id = 1",
            vec![Val::I(by.max(0))],
        )
        .await?;
        Ok((old, self.instance().await?.next_seq))
    }

    /// Instance-wide monotonic generation for whole-DB anti-rollback (§16):
    /// `instance.next_seq` (next_seq only grows; seq-bump only raises). A decrease
    /// = an old snapshot was restored.
    pub async fn instance_generation(&self) -> AppResult<i64> {
        Ok(self.instance().await?.next_seq)
    }

    /// An account's canonical ed25519 keyset (for owner_account_id → ed resolution,
    /// e.g. the audit-author gate). Nonexistent → None.
    pub async fn account_ed(&self, account_id: &[u8]) -> AppResult<Option<Vec<u8>>> {
        use super::models::EdOnly;
        Ok(self
            .fetch_optional_as::<EdOnly>(
                "SELECT ed25519_pub FROM accounts WHERE account_id = ?",
                vec![Val::b(account_id)],
            )
            .await?
            .map(|r| r.ed25519_pub))
    }

    /// Background TTL cleanup (§13): stale nonce/relay/sessions are deleted, pending
    /// invites are marked expired, old idempotency keys (older than `idem_cutoff`)
    /// are deleted. Expiry is also enforced at use-time — this is hygiene.
    pub async fn cleanup_expired(&self, now: i64, idem_cutoff: i64) -> AppResult<()> {
        self.exec(
            "DELETE FROM auth_nonces WHERE expires_at < ?",
            vec![Val::I(now)],
        )
        .await?;
        self.exec(
            "DELETE FROM pake_relay WHERE expires_at < ?",
            vec![Val::I(now)],
        )
        .await?;
        self.exec(
            "UPDATE invites SET state = 'expired' WHERE state = 'pending' AND expires_at < ?",
            vec![Val::I(now)],
        )
        .await?;
        self.exec(
            "DELETE FROM sessions WHERE refresh_expires < ?",
            vec![Val::I(now)],
        )
        .await?;
        self.exec(
            "DELETE FROM idempotency_keys WHERE created_at < ?",
            vec![Val::I(idem_cutoff)],
        )
        .await?;
        Ok(())
    }

    /// ZK diagnostics (§15.3): concatenation of all opaque blobs. The test verifies
    /// that plaintext markers are absent (the server stores only ciphertext + open
    /// metadata).
    pub async fn dump_blobs(&self) -> AppResult<Vec<u8>> {
        use super::models::BlobRow;
        let mut out = Vec::new();
        for sql in [
            "SELECT object_bytes AS b FROM objects",
            "SELECT keyset_bytes AS b FROM keyset_blobs",
            "SELECT manifest_blob AS b FROM membership_manifests",
            "SELECT wrapped_vk AS b FROM membership_grants",
            "SELECT entry_blob AS b FROM audit_log",
        ] {
            for r in self.fetch_all_as::<BlobRow>(sql, vec![]).await? {
                out.extend_from_slice(&r.b);
            }
        }
        Ok(out)
    }
}
