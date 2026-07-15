//! pending_actions: crypto to-do queue for vault-admin clients. The server marks
//! rows done ITSELF by observing published manifests/grants — clients never self-report.

use super::{Store, Tx, Val};
use crate::error::AppResult;
use crate::store::models::PendingActionRow;

const SEL: &str = "SELECT action_id, kind, vault_id, account_id, crypto_role, source, proof, \
                   state, created_at, done_at, done_epoch FROM pending_actions";

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub async fn pending_enqueue(
        &self,
        tx: &mut Tx<'_>,
        action_id: &[u8],
        kind: &str,
        vault_id: &[u8],
        account_id: &[u8],
        crypto_role: Option<i64>,
        source: &str,
        proof: Option<&[u8]>,
        now: i64,
    ) -> AppResult<()> {
        tx.exec(
            "INSERT INTO pending_actions (action_id, kind, vault_id, account_id, crypto_role, \
             source, proof, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
            vec![
                Val::b(action_id),
                Val::t(kind),
                Val::b(vault_id),
                Val::b(account_id),
                Val::OptI(crypto_role),
                Val::t(source),
                Val::OptB(proof.map(|b| b.to_vec())),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    /// Pending work visible to a vault-admin keyset: vaults where it holds a live
    /// Admin(2) grant at the vault's latest epoch.
    pub async fn pending_for_admin(
        &self,
        admin_ed25519: &[u8],
    ) -> AppResult<Vec<PendingActionRow>> {
        self.fetch_all_as(
            &format!(
                "{SEL} WHERE state = 'pending' AND vault_id IN ( \
                   SELECT g.vault_id FROM membership_grants g \
                   JOIN vaults v ON v.vault_id = g.vault_id \
                   WHERE g.member_pubkey = ? AND g.role = 2 AND g.revoked = 0 \
                     AND g.key_epoch = v.latest_epoch) \
                 ORDER BY created_at"
            ),
            vec![Val::b(admin_ed25519)],
        )
        .await
    }

    /// After a manifest publish: grant-actions for members INCLUDED in the new
    /// grant set are done.
    pub async fn pending_mark_grants_done(
        &self,
        tx: &mut Tx<'_>,
        vault_id: &[u8],
        member_eds: &[Vec<u8>],
        epoch: i64,
        now: i64,
    ) -> AppResult<u64> {
        let mut total = 0u64;
        for ed in member_eds {
            total += tx
                .exec(
                    "UPDATE pending_actions SET state = 'done', done_at = ?, done_epoch = ? \
                     WHERE vault_id = ? AND kind = 'grant' AND state = 'pending' AND account_id IN \
                       (SELECT account_id FROM accounts WHERE ed25519_pub = ?)",
                    vec![
                        Val::I(now),
                        Val::I(epoch),
                        Val::b(vault_id),
                        Val::B(ed.clone()),
                    ],
                )
                .await?;
        }
        Ok(total)
    }

    /// After a rotation: revoke-actions for accounts ABSENT from the new grant set are done.
    pub async fn pending_mark_revokes_done(
        &self,
        tx: &mut Tx<'_>,
        vault_id: &[u8],
        still_member_eds: &[Vec<u8>],
        epoch: i64,
        now: i64,
    ) -> AppResult<u64> {
        let rows: Vec<PendingActionRow> = tx
            .fetch_all_as(
                &format!("{SEL} WHERE vault_id = ? AND kind = 'revoke' AND state = 'pending'"),
                vec![Val::b(vault_id)],
            )
            .await?;
        let mut total = 0u64;
        for r in rows {
            let ed: Option<Vec<u8>> = tx
                .fetch_optional_as::<crate::store::models::EdOnly>(
                    "SELECT ed25519_pub FROM accounts WHERE account_id = ?",
                    vec![Val::B(r.account_id.clone())],
                )
                .await?
                .map(|e| e.ed25519_pub);
            let still_in = ed
                .as_ref()
                .map(|e| still_member_eds.contains(e))
                .unwrap_or(false);
            if !still_in {
                total += tx
                    .exec(
                        "UPDATE pending_actions SET state = 'done', done_at = ?, done_epoch = ? \
                         WHERE action_id = ?",
                        vec![Val::I(now), Val::I(epoch), Val::B(r.action_id)],
                    )
                    .await?;
            }
        }
        Ok(total)
    }
}
