//! Admin/ops repository: read-projections (public metadata) + account
//! lifecycle. Tenant-scoped. NEVER selects object_bytes / keyset_bytes /
//! relay messages — the ZK boundary (ARCH §5.4). `set_tenant_status` and seq-bump live
//! in `tenants.rs`; here — everything else for `/v1/admin/*`.

use super::models::*;
use super::{Store, Val};
use crate::error::{AppError, AppResult};

/// Dashboard aggregates (public counters for a single tenant).
#[derive(Debug, Clone, Default)]
pub struct OverviewCounts {
    pub accounts: i64,
    pub admins: i64,
    pub devices: i64,
    pub active_sessions: i64,
    pub vaults: i64,
    pub objects: i64,
    pub pending_invites: i64,
}

impl Store {
    async fn admin_count_scalar(&self, sql: &str, tid: &[u8]) -> AppResult<i64> {
        Ok(self
            .fetch_scalar_i64(sql, vec![Val::b(tid)])
            .await?
            .unwrap_or(0))
    }

    pub async fn admin_overview(&self, tid: &[u8]) -> AppResult<OverviewCounts> {
        Ok(OverviewCounts {
            accounts: self
                .admin_count_scalar("SELECT COUNT(*) FROM accounts WHERE tenant_id = ?", tid)
                .await?,
            admins: self
                .admin_count_scalar(
                    "SELECT COUNT(*) FROM accounts WHERE tenant_id = ? AND is_admin = 1",
                    tid,
                )
                .await?,
            devices: self
                .admin_count_scalar(
                    "SELECT COUNT(*) FROM device_pubkeys WHERE tenant_id = ?",
                    tid,
                )
                .await?,
            active_sessions: self
                .admin_count_scalar(
                    "SELECT COUNT(*) FROM sessions WHERE tenant_id = ? AND revoked = 0",
                    tid,
                )
                .await?,
            vaults: self
                .admin_count_scalar("SELECT COUNT(*) FROM vaults WHERE tenant_id = ?", tid)
                .await?,
            objects: self
                .admin_count_scalar("SELECT COUNT(*) FROM objects WHERE tenant_id = ?", tid)
                .await?,
            pending_invites: self
                .admin_count_scalar(
                    "SELECT COUNT(*) FROM invites WHERE tenant_id = ? AND state = 'pending'",
                    tid,
                )
                .await?,
        })
    }

    // ---- account lifecycle ----

    pub async fn set_account_status(
        &self,
        tid: &[u8],
        account_id: &[u8],
        status: &str,
    ) -> AppResult<()> {
        let n = self
            .exec(
                "UPDATE accounts SET status = ? WHERE tenant_id = ? AND account_id = ?",
                vec![Val::t(status), Val::b(tid), Val::b(account_id)],
            )
            .await?;
        if n == 0 {
            return Err(AppError::not_found("account"));
        }
        Ok(())
    }

    /// Whether the account is active (status='active'). Nonexistent → false.
    pub async fn account_is_active(&self, tid: &[u8], account_id: &[u8]) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM accounts \
                 WHERE tenant_id = ? AND account_id = ? AND status = 'active'",
                vec![Val::b(tid), Val::b(account_id)],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }

    // ---- devices / sessions ----

    pub async fn admin_list_devices(
        &self,
        tid: &[u8],
        account_id: &[u8],
    ) -> AppResult<Vec<AdminDeviceRow>> {
        self.fetch_all_as::<AdminDeviceRow>(
            "SELECT d.device_id, d.status, d.registered_at, \
             (SELECT COUNT(*) FROM sessions s WHERE s.tenant_id = d.tenant_id \
                AND s.device_id = d.device_id AND s.revoked = 0) AS session_count \
             FROM device_pubkeys d WHERE d.tenant_id = ? AND d.account_id = ? \
             ORDER BY d.registered_at ASC",
            vec![Val::b(tid), Val::b(account_id)],
        )
        .await
    }

    /// Active (revoked=0) sessions of the tenant; optional filter by account_id.
    pub async fn admin_list_sessions(
        &self,
        tid: &[u8],
        account_id: Option<&[u8]>,
    ) -> AppResult<Vec<AdminSessionRow>> {
        match account_id {
            Some(a) => {
                self.fetch_all_as::<AdminSessionRow>(
                    "SELECT session_id, account_id, device_id, access_expires, refresh_expires, \
                     revoked, created_at FROM sessions \
                     WHERE tenant_id = ? AND account_id = ? AND revoked = 0 ORDER BY created_at DESC",
                    vec![Val::b(tid), Val::b(a)],
                )
                .await
            }
            None => {
                self.fetch_all_as::<AdminSessionRow>(
                    "SELECT session_id, account_id, device_id, access_expires, refresh_expires, \
                     revoked, created_at FROM sessions \
                     WHERE tenant_id = ? AND revoked = 0 ORDER BY created_at DESC",
                    vec![Val::b(tid)],
                )
                .await
            }
        }
    }

    pub async fn admin_revoke_session(&self, tid: &[u8], session_id: &[u8]) -> AppResult<()> {
        let n = self
            .exec(
                "UPDATE sessions SET revoked = 1 WHERE tenant_id = ? AND session_id = ?",
                vec![Val::b(tid), Val::b(session_id)],
            )
            .await?;
        if n == 0 {
            return Err(AppError::not_found("session"));
        }
        Ok(())
    }

    // ---- invites ----

    pub async fn admin_list_invites(&self, tid: &[u8]) -> AppResult<Vec<AdminInviteRow>> {
        self.fetch_all_as::<AdminInviteRow>(
            "SELECT invite_id, role, scope, state, expires_at, created_at, redeemed_at \
             FROM invites WHERE tenant_id = ? ORDER BY created_at DESC",
            vec![Val::b(tid)],
        )
        .await
    }

    /// Revoke a pending invite. Non-pending → conflict; missing → not_found.
    pub async fn admin_revoke_invite(&self, tid: &[u8], invite_id: &[u8]) -> AppResult<()> {
        let n = self
            .exec(
                "UPDATE invites SET state = 'revoked' \
                 WHERE tenant_id = ? AND invite_id = ? AND state = 'pending'",
                vec![Val::b(tid), Val::b(invite_id)],
            )
            .await?;
        if n == 0 {
            let exists = self
                .fetch_scalar_i64(
                    "SELECT COUNT(*) FROM invites WHERE tenant_id = ? AND invite_id = ?",
                    vec![Val::b(tid), Val::b(invite_id)],
                )
                .await?
                .unwrap_or(0)
                > 0;
            return Err(if exists {
                AppError::conflict("invite not pending")
            } else {
                AppError::not_found("invite")
            });
        }
        Ok(())
    }

    // ---- vaults ----

    pub async fn admin_list_vaults(&self, tid: &[u8]) -> AppResult<Vec<VaultRow>> {
        self.fetch_all_as::<VaultRow>(
            "SELECT vault_id, owner_pubkey, latest_version, latest_epoch, sync_target, \
             cache_policy, tombstone FROM vaults WHERE tenant_id = ? ORDER BY created_at ASC",
            vec![Val::b(tid)],
        )
        .await
    }

    pub async fn admin_get_vault(
        &self,
        tid: &[u8],
        vault_id: &[u8],
    ) -> AppResult<Option<VaultRow>> {
        self.fetch_optional_as::<VaultRow>(
            "SELECT vault_id, owner_pubkey, latest_version, latest_epoch, sync_target, \
             cache_policy, tombstone FROM vaults WHERE tenant_id = ? AND vault_id = ?",
            vec![Val::b(tid), Val::b(vault_id)],
        )
        .await
    }

    // ---- objects metadata (ZK: only public columns + blob size) ----

    pub async fn admin_list_objects(
        &self,
        tid: &[u8],
        tag: Option<i64>,
        vault_id: Option<&[u8]>,
        cursor: i64,
        limit: i64,
    ) -> AppResult<Vec<ObjectMetaRow>> {
        // WHERE is built only from trusted constants + bind parameters (`?`).
        let mut sql = String::from(
            "SELECT server_seq, object_tag, vault_id, item_id, obj_version, key_epoch, tombstone, \
             author_pubkey, received_at, LENGTH(object_bytes) AS blob_len \
             FROM objects WHERE tenant_id = ? AND server_seq > ?",
        );
        let mut vals = vec![Val::b(tid), Val::I(cursor)];
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

    pub async fn admin_list_relay(&self, tid: &[u8]) -> AppResult<Vec<AdminRelayRow>> {
        self.fetch_all_as::<AdminRelayRow>(
            "SELECT channel_id, state, expires_at, created_at FROM pake_relay \
             WHERE tenant_id = ? ORDER BY created_at DESC",
            vec![Val::b(tid)],
        )
        .await
    }

    pub async fn admin_list_keysets(
        &self,
        tid: &[u8],
        account_id: &[u8],
    ) -> AppResult<Vec<AdminKeysetRow>> {
        self.fetch_all_as::<AdminKeysetRow>(
            "SELECT generation, uploaded_at FROM keyset_blobs \
             WHERE tenant_id = ? AND account_id = ? ORDER BY generation DESC",
            vec![Val::b(tid), Val::b(account_id)],
        )
        .await
    }

    // ---- migrations (instance-global, not tenant-scoped) ----

    pub async fn admin_list_migrations(&self) -> AppResult<Vec<MigrationRow>> {
        self.fetch_all_as::<MigrationRow>(
            "SELECT version, description FROM _sqlx_migrations ORDER BY version ASC",
            vec![],
        )
        .await
    }

    // ---- cross-tenant ops (instance-global) ----

    pub async fn ops_list_tenants(&self) -> AppResult<Vec<OpsTenantRow>> {
        self.fetch_all_as::<OpsTenantRow>(
            "SELECT t.tenant_id, t.tier, t.display_name, t.status, t.next_seq, t.created_at, \
             t.genesis_owner_pubkey, \
             (SELECT COUNT(*) FROM accounts a WHERE a.tenant_id = t.tenant_id) AS account_count \
             FROM tenants t ORDER BY t.created_at ASC",
            vec![],
        )
        .await
    }

    /// Cross-tenant discoverability by handle (§ chicken/egg — the operator has
    /// nowhere to get an account_id before Bearer). `handle` is unique WITHIN a tenant, not
    /// globally → we return ALL matches across tenants.
    pub async fn ops_find_accounts_by_handle(&self, handle: &str) -> AppResult<Vec<OpsAccountRow>> {
        self.fetch_all_as::<OpsAccountRow>(
            "SELECT tenant_id, account_id, display_name, handle, is_admin, status \
             FROM accounts WHERE handle = ? ORDER BY tenant_id ASC",
            vec![Val::t(handle)],
        )
        .await
    }

    /// Account's devices (ops-discoverability; without pubkey bytes).
    pub async fn ops_account_devices(
        &self,
        tenant_id: &[u8],
        account_id: &[u8],
    ) -> AppResult<Vec<OpsDeviceRow>> {
        self.fetch_all_as::<OpsDeviceRow>(
            "SELECT device_id, status, registered_at FROM device_pubkeys \
             WHERE tenant_id = ? AND account_id = ? ORDER BY registered_at ASC",
            vec![Val::b(tenant_id), Val::b(account_id)],
        )
        .await
    }

    /// Instance-wide aggregates for the ops dashboard.
    pub async fn ops_counts(&self) -> AppResult<(i64, i64, i64)> {
        let tenants = self
            .fetch_scalar_i64("SELECT COUNT(*) FROM tenants", vec![])
            .await?
            .unwrap_or(0);
        let accounts = self
            .fetch_scalar_i64("SELECT COUNT(*) FROM accounts", vec![])
            .await?
            .unwrap_or(0);
        let objects = self
            .fetch_scalar_i64("SELECT COUNT(*) FROM objects", vec![])
            .await?
            .unwrap_or(0);
        Ok((tenants, accounts, objects))
    }

    /// Number of personal spaces (for the personal/org breakdown on Overview).
    pub async fn count_personal_tenants(&self) -> AppResult<i64> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM tenants WHERE tier = 'personal'",
                vec![],
            )
            .await?
            .unwrap_or(0))
    }
}
