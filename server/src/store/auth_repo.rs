//! Auth/session/device lookups (§4.2/§4.10) used by the bearer extractor.
//! Instance-scoped (v2): sessions/devices are global to this instance.

use super::models::{DeviceRow, SessionRow};
use super::{Store, Val};
use crate::error::AppResult;

const SESSION_COLS: &str = "session_id, account_id, device_id, access_hash, refresh_hash, \
                            access_expires, refresh_expires, auth_source, reassert_expires, revoked";
const DEVICE_COLS: &str = "account_id, device_id, ed25519_pub, x25519_pub, \
                           registered_at, status, expires_at";

impl Store {
    pub async fn find_session_by_access_hash(
        &self,
        access_hash: &[u8],
    ) -> AppResult<Option<SessionRow>> {
        self.fetch_optional_as::<SessionRow>(
            &format!("SELECT {SESSION_COLS} FROM sessions WHERE access_hash = ?"),
            vec![Val::b(access_hash)],
        )
        .await
    }

    /// Lookup by session_id — the refresh flow resolves the session from the id
    /// embedded in the refresh token, then compares hashes itself (reuse detection
    /// across ALL past generations, not just the immediately-previous token).
    pub async fn find_session_by_id(&self, session_id: &[u8]) -> AppResult<Option<SessionRow>> {
        self.fetch_optional_as::<SessionRow>(
            &format!("SELECT {SESSION_COLS} FROM sessions WHERE session_id = ?"),
            vec![Val::b(session_id)],
        )
        .await
    }

    pub async fn get_device(&self, device_id: &[u8]) -> AppResult<Option<DeviceRow>> {
        self.fetch_optional_as::<DeviceRow>(
            &format!("SELECT {DEVICE_COLS} FROM devices WHERE device_id = ?"),
            vec![Val::b(device_id)],
        )
        .await
    }

    pub async fn get_device_by_ed(&self, ed25519_pub: &[u8]) -> AppResult<Option<DeviceRow>> {
        self.fetch_optional_as::<DeviceRow>(
            &format!("SELECT {DEVICE_COLS} FROM devices WHERE ed25519_pub = ?"),
            vec![Val::b(ed25519_pub)],
        )
        .await
    }
}
