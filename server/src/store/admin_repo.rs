//! Admin/ops repository: read-projections (public metadata) + account
//! lifecycle. Instance-scoped (v2). NEVER selects object_bytes / keyset_bytes /
//! relay messages — the ZK boundary (ARCH §5.4).

use super::models::*;
use super::{Store, Val};
use crate::error::{AppError, AppResult};

/// Dashboard aggregates (public counters for the instance).
#[derive(Debug, Clone, Default)]
pub struct OverviewCounts {
    pub accounts: i64,
    pub owners: i64,
    pub devices: i64,
    pub active_sessions: i64,
    pub vaults: i64,
    pub objects: i64,
    pub pending_invites: i64,
}

impl Store {
    async fn count_scalar(&self, sql: &str) -> AppResult<i64> {
        Ok(self.fetch_scalar_i64(sql, vec![]).await?.unwrap_or(0))
    }

    pub async fn admin_overview(&self) -> AppResult<OverviewCounts> {
        Ok(OverviewCounts {
            accounts: self.count_scalar("SELECT COUNT(*) FROM accounts").await?,
            owners: self
                .count_scalar("SELECT COUNT(*) FROM accounts WHERE is_owner = 1")
                .await?,
            devices: self.count_scalar("SELECT COUNT(*) FROM devices").await?,
            active_sessions: self
                .count_scalar("SELECT COUNT(*) FROM sessions WHERE revoked = 0")
                .await?,
            vaults: self.count_scalar("SELECT COUNT(*) FROM vaults").await?,
            objects: self.count_scalar("SELECT COUNT(*) FROM objects").await?,
            pending_invites: self
                .count_scalar("SELECT COUNT(*) FROM invites WHERE state = 'pending'")
                .await?,
        })
    }

    // ---- account lifecycle ----

    pub async fn set_account_status(&self, account_id: &[u8], status: &str) -> AppResult<()> {
        let n = self
            .exec(
                "UPDATE accounts SET status = ? WHERE account_id = ?",
                vec![Val::t(status), Val::b(account_id)],
            )
            .await?;
        if n == 0 {
            return Err(AppError::not_found("account"));
        }
        Ok(())
    }

    /// Whether the account is active (status='active'). Nonexistent → false.
    pub async fn account_is_active(&self, account_id: &[u8]) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM accounts WHERE account_id = ? AND status = 'active'",
                vec![Val::b(account_id)],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }

    // ---- devices / sessions ----

    pub async fn admin_list_devices(&self, account_id: &[u8]) -> AppResult<Vec<AdminDeviceRow>> {
        self.fetch_all_as::<AdminDeviceRow>(
            "SELECT d.device_id, d.kind, d.label, d.status, d.registered_at, \
             (SELECT COUNT(*) FROM sessions s WHERE s.device_id = d.device_id AND s.revoked = 0) \
                AS session_count \
             FROM devices d WHERE d.account_id = ? ORDER BY d.registered_at ASC",
            vec![Val::b(account_id)],
        )
        .await
    }

    /// Active (revoked=0) sessions; optional filter by account_id.
    pub async fn admin_list_sessions(
        &self,
        account_id: Option<&[u8]>,
    ) -> AppResult<Vec<AdminSessionRow>> {
        match account_id {
            Some(a) => {
                self.fetch_all_as::<AdminSessionRow>(
                    "SELECT session_id, account_id, device_id, access_expires, refresh_expires, \
                     revoked, created_at FROM sessions \
                     WHERE account_id = ? AND revoked = 0 ORDER BY created_at DESC",
                    vec![Val::b(a)],
                )
                .await
            }
            None => {
                self.fetch_all_as::<AdminSessionRow>(
                    "SELECT session_id, account_id, device_id, access_expires, refresh_expires, \
                     revoked, created_at FROM sessions \
                     WHERE revoked = 0 ORDER BY created_at DESC",
                    vec![],
                )
                .await
            }
        }
    }

    pub async fn admin_revoke_session(&self, session_id: &[u8]) -> AppResult<()> {
        let n = self
            .exec(
                "UPDATE sessions SET revoked = 1 WHERE session_id = ?",
                vec![Val::b(session_id)],
            )
            .await?;
        if n == 0 {
            return Err(AppError::not_found("session"));
        }
        Ok(())
    }

    // ---- invites (v2 shape) ----

    pub async fn admin_list_invites(&self) -> AppResult<Vec<AdminInviteRow>> {
        self.fetch_all_as::<AdminInviteRow>(
            "SELECT invite_id, state, expires_at, created_at, redeemed_at \
             FROM invites ORDER BY created_at DESC",
            vec![],
        )
        .await
    }

    // ---- vaults ----

    pub async fn admin_list_vaults(&self) -> AppResult<Vec<VaultRow>> {
        self.fetch_all_as::<VaultRow>(
            "SELECT vault_id, owner_pubkey, latest_version, latest_epoch, sync_target, \
             cache_policy, tombstone FROM vaults ORDER BY created_at ASC",
            vec![],
        )
        .await
    }

    pub async fn admin_get_vault(&self, vault_id: &[u8]) -> AppResult<Option<VaultRow>> {
        self.fetch_optional_as::<VaultRow>(
            "SELECT vault_id, owner_pubkey, latest_version, latest_epoch, sync_target, \
             cache_policy, tombstone FROM vaults WHERE vault_id = ?",
            vec![Val::b(vault_id)],
        )
        .await
    }

    // ---- objects metadata (ZK: only public columns + blob size) ----

    pub async fn admin_list_objects(
        &self,
        tag: Option<i64>,
        vault_id: Option<&[u8]>,
        cursor: i64,
        limit: i64,
    ) -> AppResult<Vec<ObjectMetaRow>> {
        // WHERE is built only from trusted constants + bind parameters (`?`).
        let mut sql = String::from(
            "SELECT server_seq, object_tag, vault_id, item_id, obj_version, key_epoch, tombstone, \
             author_pubkey, received_at, LENGTH(object_bytes) AS blob_len \
             FROM objects WHERE server_seq > ?",
        );
        let mut vals = vec![Val::I(cursor)];
        if let Some(t) = tag {
            sql.push_str(" AND object_tag = ?");
            vals.push(Val::I(t));
        }
        if let Some(v) = vault_id {
            sql.push_str(" AND vault_id = ?");
            vals.push(Val::b(v));
        }
        sql.push_str(" ORDER BY server_seq ASC LIMIT ?");
        vals.push(Val::I(limit));
        self.fetch_all_as::<ObjectMetaRow>(&sql, vals).await
    }

    // ---- relay / keysets observation ----

    pub async fn admin_list_relay(&self) -> AppResult<Vec<AdminRelayRow>> {
        self.fetch_all_as::<AdminRelayRow>(
            "SELECT channel_id, state, expires_at, created_at FROM pake_relay \
             ORDER BY created_at DESC",
            vec![],
        )
        .await
    }

    pub async fn admin_list_keysets(&self, account_id: &[u8]) -> AppResult<Vec<AdminKeysetRow>> {
        self.fetch_all_as::<AdminKeysetRow>(
            "SELECT generation, uploaded_at FROM keyset_blobs \
             WHERE account_id = ? ORDER BY generation DESC",
            vec![Val::b(account_id)],
        )
        .await
    }

    // ---- migrations (instance-global) ----

    pub async fn admin_list_migrations(&self) -> AppResult<Vec<MigrationRow>> {
        self.fetch_all_as::<MigrationRow>(
            "SELECT version, description FROM _sqlx_migrations ORDER BY version ASC",
            vec![],
        )
        .await
    }

    // ---- ops aggregates (instance-wide) ----

    /// Instance-wide aggregates for the ops dashboard: (accounts, objects).
    pub async fn ops_counts(&self) -> AppResult<(i64, i64)> {
        let accounts = self.count_scalar("SELECT COUNT(*) FROM accounts").await?;
        let objects = self.count_scalar("SELECT COUNT(*) FROM objects").await?;
        Ok((accounts, objects))
    }
}
