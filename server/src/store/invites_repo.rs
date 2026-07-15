//! v2 invites: one join mechanism; intents (spaces + selective vaults) ride inside.

use super::{Store, Tx, Val};
use crate::error::AppResult;
use crate::store::models::InviteV2Row;

const SEL: &str = "SELECT invite_id, token_hash, space_intents, vault_intents, expires_at, \
                   state, redeemed_by, redeemed_at, created_by, created_at FROM invites";

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub async fn create_invite_v2(
        &self,
        invite_id: &[u8],
        token_hash: &[u8],
        space_intents_json: &str,
        vault_intents_json: &str,
        expires_at: i64,
        created_by: Option<&[u8]>,
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO invites (invite_id, token_hash, space_intents, vault_intents, \
             expires_at, state, created_by, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
            vec![
                Val::b(invite_id),
                Val::b(token_hash),
                Val::t(space_intents_json),
                Val::t(vault_intents_json),
                Val::I(expires_at),
                Val::OptB(created_by.map(|b| b.to_vec())),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn get_invite_v2_by_hash(&self, token_hash: &[u8]) -> AppResult<Option<InviteV2Row>> {
        self.fetch_optional_as(
            &format!("{SEL} WHERE token_hash = ?"),
            vec![Val::b(token_hash)],
        )
        .await
    }

    /// Fetch an invite by its (non-secret) id — the revoke path authorizes the caller
    /// against the invite's intents, so it looks the invite up by id, not by token.
    pub async fn get_invite_v2_by_id(&self, invite_id: &[u8]) -> AppResult<Option<InviteV2Row>> {
        self.fetch_optional_as(
            &format!("{SEL} WHERE invite_id = ?"),
            vec![Val::b(invite_id)],
        )
        .await
    }

    /// CAS pending→redeemed; expired or already-redeemed → None (loser must rollback).
    pub async fn redeem_invite_v2_cas(
        &self,
        tx: &mut Tx<'_>,
        token_hash: &[u8],
        redeemed_by: &[u8],
        now: i64,
    ) -> AppResult<Option<InviteV2Row>> {
        let n = tx
            .exec(
                "UPDATE invites SET state = 'redeemed', redeemed_by = ?, redeemed_at = ? \
                 WHERE token_hash = ? AND state = 'pending' AND expires_at > ?",
                vec![
                    Val::b(redeemed_by),
                    Val::I(now),
                    Val::b(token_hash),
                    Val::I(now),
                ],
            )
            .await?;
        if n != 1 {
            return Ok(None);
        }
        tx.fetch_optional_as(
            &format!("{SEL} WHERE token_hash = ?"),
            vec![Val::b(token_hash)],
        )
        .await
    }

    pub async fn revoke_invite_v2(&self, invite_id: &[u8]) -> AppResult<u64> {
        self.exec(
            "UPDATE invites SET state = 'revoked' WHERE invite_id = ? AND state = 'pending'",
            vec![Val::b(invite_id)],
        )
        .await
    }
}
