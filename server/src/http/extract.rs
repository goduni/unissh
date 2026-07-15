//! Typed extractors (v2, instance-scoped): bearer authentication (§5.0/§12) and
//! the owner/ops gates. All private endpoints go through `AuthCtx`; `/v1/admin/*`
//! through `OwnerCtx`; `/v1/ops/*` through `OpsCtx`.

use crate::error::{AppError, AppResult};
use crate::ids;
use crate::state::AppState;
use crate::store::Store;
use crate::store::models::{DeviceRow, SessionRow};
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

/// Authenticated context: a valid session + an active device (instance-scoped).
pub struct AuthCtx {
    pub session: SessionRow,
    pub device: DeviceRow,
}

impl AuthCtx {
    pub fn device_ed25519(&self) -> &[u8] {
        &self.device.ed25519_pub
    }
    pub fn account_id(&self) -> &[u8] {
        &self.session.account_id
    }

    /// Require the instance owner (server-trusted) — otherwise 403.
    pub async fn require_owner(&self, store: &Store) -> AppResult<()> {
        if store.account_is_owner(self.account_id()).await? {
            Ok(())
        } else {
            Err(AppError::forbidden("owner role required"))
        }
    }
}

impl FromRequestParts<AppState> for AuthCtx {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let (session, device) = resolve_bearer(parts, state).await?;
        Ok(AuthCtx { session, device })
    }
}

/// Owner context for /v1/admin/* (bearer + accounts.is_owner).
pub struct OwnerCtx {
    pub session: SessionRow,
    pub device: DeviceRow,
}

impl OwnerCtx {
    pub fn account_id(&self) -> &[u8] {
        &self.session.account_id
    }
}

impl FromRequestParts<AppState> for OwnerCtx {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let (session, device) = resolve_bearer(parts, state).await?;
        if !state.store.account_is_owner(&session.account_id).await? {
            return Err(AppError::forbidden("owner role required"));
        }
        metrics::counter!("unissh_admin_requests_total").increment(1);
        Ok(OwnerCtx { session, device })
    }
}

/// Shared Bearer-token resolution (§5.0/§12): strip `Bearer ` → base64-decode →
/// sha256 → `find_session_by_access_hash` → revoked/expiry → active (non-expired)
/// device → active account. Instance-scoped: no per-space load. Returns the validated
/// `(SessionRow, DeviceRow)`.
async fn resolve_bearer(parts: &mut Parts, state: &AppState) -> AppResult<(SessionRow, DeviceRow)> {
    let auth = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or_else(|| AppError::unauthenticated("missing Authorization header"))?;
    let s = auth
        .to_str()
        .map_err(|_| AppError::unauthenticated("bad Authorization header"))?;
    let token = s
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthenticated("expected Bearer token"))?
        .trim();
    // An unparseable token is an authentication error (401), not a generic 400.
    let raw = ids::unb64(token).map_err(|_| AppError::unauthenticated("malformed access token"))?;
    let access_hash = ids::sha256(&raw);
    let session = state
        .store
        .find_session_by_access_hash(&access_hash)
        .await?
        .ok_or_else(|| AppError::unauthenticated("invalid access token"))?;
    if session.revoked != 0 {
        return Err(AppError::unauthenticated("session revoked"));
    }
    if session.access_expires <= state.now() {
        return Err(AppError::unauthenticated("access token expired"));
    }
    let device = state
        .store
        .get_device(&session.device_id)
        .await?
        .ok_or_else(|| AppError::unauthenticated("device not found"))?;
    if device.status != "active" {
        return Err(AppError::unauthenticated("device not active"));
    }
    if let Some(exp) = device.expires_at {
        if exp <= state.now() {
            return Err(AppError::unauthenticated("device expired"));
        }
    }
    if !state.store.account_is_active(&session.account_id).await? {
        return Err(AppError::unauthenticated("account disabled"));
    }
    Ok((session, device))
}

/// Constant-time byte equality (for comparing secret tokens: ops, setup code).
/// The length is not a secret — an early return on differing length is fine.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Ops context: a server-trusted operator for break-glass `/v1/ops/*`. Authentication —
/// the `X-UniSSH-Ops-Token` header == `[ops] token` (constant-time). An empty config
/// token → the surface is disabled (403). This is infrastructure access, NOT a keyset —
/// it does not grant decryption.
pub struct OpsCtx;

impl FromRequestParts<AppState> for OpsCtx {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let want = state.config.ops.token.as_bytes();
        if want.is_empty() {
            return Err(AppError::forbidden("ops surface disabled"));
        }
        let got = parts
            .headers
            .get("x-unissh-ops-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct_eq(got.as_bytes(), want) {
            Ok(OpsCtx)
        } else {
            Err(AppError::unauthenticated("invalid ops token"))
        }
    }
}
