//! Auth/session/device lookups (§4.2/§4.10) used by the bearer extractor and
//! instance-admin resolution.

use super::models::{DeviceRow, SessionRow};
use super::{Store, Val};
use crate::error::AppResult;

const SESSION_COLS: &str = "session_id, account_id, device_id, access_hash, refresh_hash, \
                            access_expires, refresh_expires, revoked";
const DEVICE_COLS: &str = "tenant_id, account_id, device_id, ed25519_pub, x25519_pub, \
                           registered_at, status";

impl Store {
    pub async fn find_session_by_access_hash(
        &self,
        tenant_id: &[u8],
        access_hash: &[u8],
    ) -> AppResult<Option<SessionRow>> {
        self.fetch_optional_as::<SessionRow>(
            &format!("SELECT {SESSION_COLS} FROM sessions WHERE tenant_id = ? AND access_hash = ?"),
            vec![Val::b(tenant_id), Val::b(access_hash)],
        )
        .await
    }

    /// Lookup by session_id — the refresh flow resolves the session from the id
    /// embedded in the refresh token, then compares hashes itself (reuse detection
    /// across ALL past generations, not just the immediately-previous token).
    pub async fn find_session_by_id(
        &self,
        tenant_id: &[u8],
        session_id: &[u8],
    ) -> AppResult<Option<SessionRow>> {
        self.fetch_optional_as::<SessionRow>(
            &format!("SELECT {SESSION_COLS} FROM sessions WHERE tenant_id = ? AND session_id = ?"),
            vec![Val::b(tenant_id), Val::b(session_id)],
        )
        .await
    }

    pub async fn get_device(
        &self,
        tenant_id: &[u8],
        device_id: &[u8],
    ) -> AppResult<Option<DeviceRow>> {
        self.fetch_optional_as::<DeviceRow>(
            &format!(
                "SELECT {DEVICE_COLS} FROM device_pubkeys WHERE tenant_id = ? AND device_id = ?"
            ),
            vec![Val::b(tenant_id), Val::b(device_id)],
        )
        .await
    }

    pub async fn get_device_by_ed(
        &self,
        tenant_id: &[u8],
        ed25519_pub: &[u8],
    ) -> AppResult<Option<DeviceRow>> {
        self.fetch_optional_as::<DeviceRow>(
            &format!(
                "SELECT {DEVICE_COLS} FROM device_pubkeys WHERE tenant_id = ? AND ed25519_pub = ?"
            ),
            vec![Val::b(tenant_id), Val::b(ed25519_pub)],
        )
        .await
    }

    /// Instance-admin (server-trusted, for invite/audit-query/grants-publish/
    /// device-revoke): device-keyset == genesis_owner (bootstrap admin) OR
    /// the account of this keyset is flagged `is_admin`. Decoupled from vault grants — this is
    /// enforcement authority, not decryption cryptography (§10).
    pub async fn is_instance_admin(&self, tenant_id: &[u8], ed25519_pub: &[u8]) -> AppResult<bool> {
        let genesis = self
            .fetch_optional_as::<GenesisRow>(
                "SELECT genesis_owner_pubkey FROM tenants WHERE tenant_id = ?",
                vec![Val::b(tenant_id)],
            )
            .await?;
        if let Some(GenesisRow {
            genesis_owner_pubkey: Some(g),
        }) = genesis
        {
            if g == ed25519_pub {
                return Ok(true);
            }
        }
        let flag = self
            .fetch_scalar_i64(
                "SELECT is_admin FROM accounts WHERE tenant_id = ? AND ed25519_pub = ?",
                vec![Val::b(tenant_id), Val::b(ed25519_pub)],
            )
            .await?
            .unwrap_or(0);
        Ok(flag == 1)
    }

    /// Space owner (the genesis_owner of this tenant) — strictly the keyset that
    /// bootstrapped it. Narrower than (§10) [`is_instance_admin`]: an is_admin
    /// member administers but does NOT own the space. By this flag the client decides whether
    /// a personal vault can be assigned here (personal — only in one's own space).
    pub async fn is_genesis_owner(&self, tenant_id: &[u8], ed25519_pub: &[u8]) -> AppResult<bool> {
        let genesis = self
            .fetch_optional_as::<GenesisRow>(
                "SELECT genesis_owner_pubkey FROM tenants WHERE tenant_id = ?",
                vec![Val::b(tenant_id)],
            )
            .await?;
        Ok(matches!(
            genesis,
            Some(GenesisRow { genesis_owner_pubkey: Some(g) }) if g == ed25519_pub
        ))
    }
}

#[derive(sqlx::FromRow)]
struct GenesisRow {
    genesis_owner_pubkey: Option<Vec<u8>>,
}
