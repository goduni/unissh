//! Typed extractors: tenant-routing (`UniSSH-Tenant`), suspended-check,
//! bearer authentication (§5.0/§12). All private endpoints go through `AuthCtx`.

use crate::error::{AppError, AppResult};
use crate::ids;
use crate::state::AppState;
use crate::store::Store;
use crate::store::models::{DeviceRow, SessionRow, TenantRow};
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

/// Just the raw tenant_id from the `UniSSH-Tenant` header (for /v1/bootstrap, where
/// the tenant may not exist yet).
pub struct RawTenantId(pub Vec<u8>);

impl FromRequestParts<AppState> for RawTenantId {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, _state: &AppState) -> AppResult<Self> {
        let h = parts
            .headers
            .get("unissh-tenant")
            .ok_or_else(|| AppError::malformed("missing UniSSH-Tenant header"))?;
        let s = h
            .to_str()
            .map_err(|_| AppError::malformed("bad UniSSH-Tenant header"))?;
        let id = ids::unb64(s)?;
        if id.is_empty() || id.len() > 64 {
            return Err(AppError::malformed("invalid tenant id length"));
        }
        Ok(RawTenantId(id))
    }
}

/// The loaded tenant + suspended-check (for all /v1 except bootstrap/health).
pub struct TenantCtx {
    pub tenant: TenantRow,
}

impl TenantCtx {
    pub fn id(&self) -> &[u8] {
        &self.tenant.tenant_id
    }
    pub fn is_org(&self) -> bool {
        self.tenant.tier.eq_ignore_ascii_case("org")
    }
}

impl FromRequestParts<AppState> for TenantCtx {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let RawTenantId(tid) = RawTenantId::from_request_parts(parts, state).await?;
        let tenant = state
            .store
            .get_tenant(&tid)
            .await?
            .ok_or_else(|| AppError::not_found("tenant"))?;
        if tenant.status == "suspended" {
            return Err(AppError::tenant_suspended());
        }
        Ok(TenantCtx { tenant })
    }
}

/// Authenticated context: tenant + a valid session + an active device.
pub struct AuthCtx {
    pub tenant: TenantRow,
    pub session: SessionRow,
    pub device: DeviceRow,
}

impl AuthCtx {
    pub fn tenant_id(&self) -> &[u8] {
        &self.tenant.tenant_id
    }
    pub fn device_ed25519(&self) -> &[u8] {
        &self.device.ed25519_pub
    }
    pub fn account_id(&self) -> &[u8] {
        &self.session.account_id
    }
    pub fn is_org(&self) -> bool {
        self.tenant.tier.eq_ignore_ascii_case("org")
    }

    /// Require instance-admin (§10) — otherwise 403.
    pub async fn require_admin(&self, store: &Store) -> AppResult<()> {
        if store
            .is_instance_admin(&self.tenant.tenant_id, &self.device.ed25519_pub)
            .await?
        {
            Ok(())
        } else {
            Err(AppError::forbidden("admin role required"))
        }
    }
}

/// Shared Bearer-token resolution for `AuthCtx` and `AdminCtx` (§5.0/§12): strip
/// `Bearer ` → base64-decode → sha256 → `find_session_by_access_hash` →
/// revoked/expiry → active device → active account. Returns the validated
/// `(SessionRow, DeviceRow)`. The tenant is loaded by the caller — that is the ONLY
/// difference between the two extractors: `AuthCtx` goes through `TenantCtx`
/// (suspended-gated), `AdminCtx` loads the tenant WITHOUT the suspended-gate and
/// then layers the extra instance-admin check on top of this shared resolution.
async fn resolve_bearer(
    parts: &mut Parts,
    state: &AppState,
    tenant_id: &[u8],
) -> AppResult<(SessionRow, DeviceRow)> {
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
        .find_session_by_access_hash(tenant_id, &access_hash)
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
        .get_device(tenant_id, &session.device_id)
        .await?
        .ok_or_else(|| AppError::unauthenticated("device not found"))?;
    if device.status != "active" {
        return Err(AppError::unauthenticated("device not active"));
    }
    if !state
        .store
        .account_is_active(tenant_id, &session.account_id)
        .await?
    {
        return Err(AppError::unauthenticated("account disabled"));
    }
    Ok((session, device))
}

impl FromRequestParts<AppState> for AuthCtx {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let TenantCtx { tenant } = TenantCtx::from_request_parts(parts, state).await?;
        let (session, device) = resolve_bearer(parts, state, &tenant.tenant_id).await?;
        Ok(AuthCtx {
            tenant,
            session,
            device,
        })
    }
}

/// Constant-time byte equality (for comparing secret tokens: ops,
/// bootstrap). The length is not a secret — an early return on differing length is fine.
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

/// Ops context: a server-trusted operator for cross-tenant `/v1/ops/*`. Does NOT require
/// `UniSSH-Tenant`. Authentication — the `X-UniSSH-Ops-Token` header == `[ops] token`
/// (constant-time). An empty config token → the surface is disabled (403). This is
/// infrastructure access, NOT a keyset — it does not grant decryption.
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

/// Admin/ops context: the tenant is loaded WITHOUT the suspended-gate (the operator must be
/// able to administer/restore a suspended tenant), the Bearer session is valid,
/// the device is active, the account is active and is an instance-admin. All `/v1/admin/*`
/// go through this extractor.
pub struct AdminCtx {
    pub tenant: TenantRow,
    pub session: SessionRow,
    pub device: DeviceRow,
}

impl AdminCtx {
    pub fn tenant_id(&self) -> &[u8] {
        &self.tenant.tenant_id
    }
    pub fn account_id(&self) -> &[u8] {
        &self.session.account_id
    }
}

impl FromRequestParts<AppState> for AdminCtx {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        // tenant WITHOUT the suspended-gate (unlike TenantCtx).
        let RawTenantId(tid) = RawTenantId::from_request_parts(parts, state).await?;
        let tenant = state
            .store
            .get_tenant(&tid)
            .await?
            .ok_or_else(|| AppError::not_found("tenant"))?;
        // bearer → session → device → account (the same logic as in AuthCtx).
        let (session, device) = resolve_bearer(parts, state, &tenant.tenant_id).await?;
        if !state
            .store
            .is_instance_admin(&tenant.tenant_id, &device.ed25519_pub)
            .await?
        {
            return Err(AppError::forbidden("admin role required"));
        }
        metrics::counter!("unissh_admin_requests_total").increment(1);
        Ok(AdminCtx {
            tenant,
            session,
            device,
        })
    }
}
