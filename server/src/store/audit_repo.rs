//! Audit repository (§4.7/§11): append-only, instance-wide monotonic seq,
//! admin-query. Two categories: client-signed (author==owner) and server-observed.

use super::models::{AuditChainRow, AuditRow, BlobRow};
use super::{Dialect, Store, Val};
use crate::error::AppResult;

// ---- tamper-evident hash-chain (§11.2/§16) ----
//
// Each record stores the running chain-head in `prev_hash`:
//   chain[n] = SHA-256( chain[n-1] ‖ record_bytes(n) ),  chain[-1] = 32 zeros.
// Verify recomputes the chain and catches any edit to the body/order/deletion.

fn put_lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

fn put_opt(buf: &mut Vec<u8>, b: Option<&[u8]>) {
    match b {
        Some(x) => {
            buf.push(1);
            put_lp(buf, x);
        }
        None => buf.push(0),
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_record_bytes(
    seq: i64,
    source: &str,
    entry_blob: &[u8],
    signature: Option<&[u8]>,
    author: Option<&[u8]>,
    vault_id: Option<&[u8]>,
    recorded_at: i64,
    server_seq: Option<i64>,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"unissh-audit-chain-v2");
    b.extend_from_slice(&seq.to_be_bytes());
    put_lp(&mut b, source.as_bytes());
    put_lp(&mut b, entry_blob);
    put_opt(&mut b, signature);
    put_opt(&mut b, author);
    put_opt(&mut b, vault_id);
    b.extend_from_slice(&recorded_at.to_be_bytes());
    b.extend_from_slice(&server_seq.unwrap_or(-1).to_be_bytes());
    b
}

fn chain_hash(prev: &[u8], record: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(prev.len() + record.len());
    input.extend_from_slice(prev);
    input.extend_from_slice(record);
    crate::ids::sha256(&input)
}

impl Store {
    /// Server-observed event (login/logout/device/session): without a client
    /// signature/author (§4.7). Returns the assigned seq.
    pub async fn append_audit_server_observed(
        &self,
        event: &serde_json::Value,
        vault_id: Option<&[u8]>,
        now: i64,
    ) -> AppResult<i64> {
        let blob = serde_json::to_vec(event).unwrap_or_default();
        self.append_audit_row("server-observed", &blob, None, None, vault_id, None, now)
            .await
    }

    /// Client-signed audit record (via push tag 5 or /v1/audit). author and
    /// signature are mandatory (the author==owner check is at the endpoint level).
    #[allow(clippy::too_many_arguments)]
    pub async fn append_audit_client_signed(
        &self,
        entry_blob: &[u8],
        signature: &[u8],
        author_pubkey: &[u8],
        vault_id: Option<&[u8]>,
        server_seq: Option<i64>,
        now: i64,
    ) -> AppResult<i64> {
        self.append_audit_row(
            "client-signed",
            entry_blob,
            Some(signature),
            Some(author_pubkey),
            vault_id,
            server_seq,
            now,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn append_audit_row(
        &self,
        source: &str,
        entry_blob: &[u8],
        signature: Option<&[u8]>,
        author_pubkey: Option<&[u8]>,
        vault_id: Option<&[u8]>,
        server_seq: Option<i64>,
        now: i64,
    ) -> AppResult<i64> {
        let mut tx = self.begin().await?;
        // Serialize appends by taking a write-lock on the singleton instance row
        // BEFORE reading MAX(seq) — otherwise a deferred-read yields a seq collision
        // under concurrency. PG: SELECT ... FOR UPDATE; SQLite: a no-op UPDATE takes
        // the RESERVED-lock immediately (the BEGIN IMMEDIATE equivalent for this tx).
        match tx.dialect() {
            Dialect::Postgres => {
                tx.fetch_scalar_i64(
                    "SELECT next_seq FROM instance WHERE id = 1 FOR UPDATE",
                    vec![],
                )
                .await?;
            }
            Dialect::Sqlite => {
                tx.exec(
                    "UPDATE instance SET next_seq = next_seq WHERE id = 1",
                    vec![],
                )
                .await?;
            }
        }
        let seq = tx
            .fetch_scalar_i64("SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_log", vec![])
            .await?
            .unwrap_or(1);
        // Chain-head of the previous record (under the same instance write-lock).
        let prev = tx
            .fetch_optional_as::<BlobRow>(
                "SELECT prev_hash AS b FROM audit_log \
                 WHERE prev_hash IS NOT NULL ORDER BY seq DESC LIMIT 1",
                vec![],
            )
            .await?
            .map(|r| r.b)
            .unwrap_or_else(|| vec![0u8; 32]);
        let record = audit_record_bytes(
            seq,
            source,
            entry_blob,
            signature,
            author_pubkey,
            vault_id,
            now,
            server_seq,
        );
        let chain = chain_hash(&prev, &record).to_vec();
        tx.exec(
            "INSERT INTO audit_log \
             (seq, source, entry_blob, signature, author_pubkey, vault_id, \
              recorded_at, server_seq, prev_hash) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                Val::I(seq),
                Val::t(source),
                Val::b(entry_blob),
                Val::OptB(signature.map(|s| s.to_vec())),
                Val::OptB(author_pubkey.map(|a| a.to_vec())),
                Val::OptB(vault_id.map(|v| v.to_vec())),
                Val::I(now),
                Val::OptI(server_seq),
                Val::B(chain),
            ],
        )
        .await?;
        tx.commit().await?;
        Ok(seq)
    }

    /// Admin-query: records with seq >= since_seq, ASC, a page up to limit (§5.6).
    pub async fn query_audit(&self, since_seq: i64, limit: i64) -> AppResult<Vec<AuditRow>> {
        self.fetch_all_as::<AuditRow>(
            "SELECT seq, source, entry_blob, signature, author_pubkey, recorded_at \
             FROM audit_log WHERE seq >= ? ORDER BY seq ASC LIMIT ?",
            vec![Val::I(since_seq), Val::I(limit)],
        )
        .await
    }

    /// Verify the audit hash-chain (§11.2). Returns
    /// `(ok, count, broken_at_seq, head_hash)`.
    pub async fn verify_audit_chain(&self) -> AppResult<(bool, i64, Option<i64>, Option<Vec<u8>>)> {
        let rows = self
            .fetch_all_as::<AuditChainRow>(
                "SELECT seq, source, entry_blob, signature, author_pubkey, vault_id, \
                 recorded_at, server_seq, prev_hash \
                 FROM audit_log ORDER BY seq ASC",
                vec![],
            )
            .await?;
        let mut expected = vec![0u8; 32];
        let mut count = 0i64;
        let mut head: Option<Vec<u8>> = None;
        for r in &rows {
            count += 1;
            let record = audit_record_bytes(
                r.seq,
                &r.source,
                &r.entry_blob,
                r.signature.as_deref(),
                r.author_pubkey.as_deref(),
                r.vault_id.as_deref(),
                r.recorded_at,
                r.server_seq,
            );
            let computed = chain_hash(&expected, &record).to_vec();
            match &r.prev_hash {
                Some(stored) if *stored == computed => {
                    expected = computed.clone();
                    head = Some(computed);
                }
                _ => return Ok((false, count, Some(r.seq), head)),
            }
        }
        Ok((true, count, None, head))
    }
}
