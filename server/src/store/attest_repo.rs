//! Key-binding attestations (Task 10). A space admin publishes a signed statement
//! binding a target account's keys; the server stores `blob` + `signature` VERBATIM
//! (opaque) and never verifies them — clients verify signatures themselves (ZK
//! discipline). Dual-dialect: the UPSERT uses `ON CONFLICT .. DO UPDATE`, supported
//! identically by SQLite and Postgres.

use super::{Store, Val};
use crate::error::AppResult;
use crate::store::models::AttestationRow;

const SEL: &str = "SELECT account_id, attestor_pubkey, blob, signature, created_at \
                   FROM key_attestations";

impl Store {
    /// Insert-or-replace an attestation on its PK `(account_id, attestor_pubkey)`.
    /// A re-attestation by the same attestor over the same target overwrites the
    /// previous `blob`/`signature`/`created_at` (one row per attestor per target).
    pub async fn attest_put(
        &self,
        account_id: &[u8],
        attestor_pubkey: &[u8],
        blob: &[u8],
        signature: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO key_attestations \
             (account_id, attestor_pubkey, blob, signature, created_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (account_id, attestor_pubkey) \
             DO UPDATE SET blob = ?, signature = ?, created_at = ?",
            vec![
                Val::b(account_id),
                Val::b(attestor_pubkey),
                Val::b(blob),
                Val::b(signature),
                Val::I(now),
                Val::b(blob),
                Val::b(signature),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    /// Every attestation about `account_id`, oldest first.
    pub async fn attest_list(&self, account_id: &[u8]) -> AppResult<Vec<AttestationRow>> {
        self.fetch_all_as(
            &format!("{SEL} WHERE account_id = ? ORDER BY created_at, attestor_pubkey"),
            vec![Val::b(account_id)],
        )
        .await
    }

    /// Attestation guard: does `caller_account_id` hold an `admin` role in at least
    /// one space that `target_account_id` is also a member of? (a = caller, b =
    /// target, joined on the shared space.)
    pub async fn shares_admin_space(
        &self,
        caller_account_id: &[u8],
        target_account_id: &[u8],
    ) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM space_members a \
                 JOIN space_members b ON a.space_id = b.space_id \
                 WHERE a.account_id = ? AND a.role = 'admin' AND b.account_id = ?",
                vec![Val::b(caller_account_id), Val::b(target_account_id)],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }
}
