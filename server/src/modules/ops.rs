//! Ops surface (`/v1/ops/*`): cross-tenant, server-trusted operator console.
//! Auth — `X-UniSSH-Ops-Token` (`OpsCtx`), NOT keyset and NOT per-tenant. Only
//! infrastructure: tenant list/lifecycle, instance aggregates, seq-bump.
//! Zero-knowledge preserved — no content, only open metadata.

use crate::error::{AppError, AppResult};
use crate::http::extract::OpsCtx;
use crate::ids;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/ops/tenants", get(tenants_list))
        .route("/v1/ops/account", get(ops_account_lookup))
        .route("/v1/ops/overview", get(ops_overview))
        .route("/v1/ops/instance", get(ops_instance))
        .route("/v1/ops/tenant/status", post(ops_tenant_status))
        .route("/v1/ops/tenant/profile", post(ops_tenant_profile))
        .route("/v1/ops/seq-bump", post(ops_seq_bump))
        .route("/v1/ops/enroll", get(enroll_list))
        .route("/v1/ops/enroll/create", post(enroll_create))
        .route("/v1/ops/enroll/revoke", post(enroll_revoke))
}

async fn tenants_list(_ops: OpsCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = state.store.ops_list_tenants().await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|t| {
            json!({
                "tenant_id": ids::b64(&t.tenant_id),
                "tier": t.tier,
                "display_name": t.display_name,
                "status": t.status,
                "next_seq": t.next_seq,
                "created_at": t.created_at,
                "accounts": t.account_count,
                "genesis_owner": t.genesis_owner_pubkey.as_deref().map(ids::b64),
            })
        })
        .collect();
    Ok(Json(json!({ "tenants": out })))
}

#[derive(Deserialize)]
struct OpsAccountQuery {
    handle: String,
}

/// `GET /v1/ops/account?handle=` — cross-tenant discoverability. Solves the
/// chicken/egg problem: the operator has nowhere to get an `account_id`/`device_id`
/// before a keyset-Bearer. A `handle` is unique only WITHIN a tenant → we return a
/// `matches` array across all tenants. Only open metadata (ZK preserved) — no
/// pubkey bytes, no content.
async fn ops_account_lookup(
    _ops: OpsCtx,
    State(state): State<AppState>,
    Query(q): Query<OpsAccountQuery>,
) -> AppResult<Json<Value>> {
    let handle = q.handle.trim();
    if handle.is_empty() {
        return Err(AppError::malformed("handle query parameter is required"));
    }
    let accounts = state.store.ops_find_accounts_by_handle(handle).await?;
    let mut matches = Vec::with_capacity(accounts.len());
    for a in accounts {
        let devices = state
            .store
            .ops_account_devices(&a.tenant_id, &a.account_id)
            .await?;
        let devices: Vec<Value> = devices
            .into_iter()
            .map(|d| {
                json!({
                    "device_id": ids::b64(&d.device_id),
                    "status": d.status,
                    "registered_at": d.registered_at,
                })
            })
            .collect();
        matches.push(json!({
            "tenant_id": ids::b64(&a.tenant_id),
            "account_id": ids::b64(&a.account_id),
            "display_name": a.display_name,
            "handle": a.handle,
            "is_admin": a.is_admin == 1,
            "status": a.status,
            "devices": devices,
        }));
    }
    Ok(Json(json!({ "matches": matches })))
}

async fn ops_overview(_ops: OpsCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let (tenants, accounts, objects) = state.store.ops_counts().await?;
    let personal = state.store.count_personal_tenants().await?;
    let generation = state.store.instance_generation().await?;
    Ok(Json(json!({
        "tenants": tenants,
        "tenants_personal": personal,
        "accounts": accounts,
        "objects": objects,
        "instance_generation": generation,
    })))
}

async fn ops_instance(_ops: OpsCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let generation = state.store.instance_generation().await?;
    Ok(Json(json!({
        "generation": generation,
        "min_floor": state.config.sync.min_instance_generation,
    })))
}

#[derive(Deserialize)]
struct OpsTenantStatusReq {
    tenant_id: String,
    suspended: bool,
}

async fn ops_tenant_status(
    _ops: OpsCtx,
    State(state): State<AppState>,
    Json(req): Json<OpsTenantStatusReq>,
) -> AppResult<StatusCode> {
    let tid = ids::unb64(&req.tenant_id)?;
    let status = if req.suspended { "suspended" } else { "active" };
    state.store.set_tenant_status(&tid, status).await?;
    let ev = json!({
        "event": if req.suspended { "tenant_suspend" } else { "tenant_activate" },
        "by": "ops", "ts": state.now(),
    });
    let _ = state
        .store
        .append_audit_server_observed(&tid, &ev, None, state.now())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct OpsTenantProfileReq {
    tenant_id: String,
    /// New name; an empty string clears the label (→ NULL).
    display_name: String,
}

/// `POST /v1/ops/tenant/profile` — set/rename the human-readable tenant name
/// for the ops switcher (open metadata, ZK preserved). An empty string clears it.
/// This is the only path that populates `tenants.display_name`.
async fn ops_tenant_profile(
    _ops: OpsCtx,
    State(state): State<AppState>,
    Json(req): Json<OpsTenantProfileReq>,
) -> AppResult<StatusCode> {
    let tid = ids::unb64(&req.tenant_id)?;
    let name = req.display_name.trim();
    if name.chars().count() > 200 {
        return Err(AppError::malformed("display_name too long (max 200 chars)"));
    }
    let dn = if name.is_empty() { None } else { Some(name) };
    state.store.set_tenant_display_name(&tid, dn).await?;
    let ev = json!({
        "event": "tenant_rename", "by": "ops", "display_name": dn, "ts": state.now(),
    });
    let _ = state
        .store
        .append_audit_server_observed(&tid, &ev, None, state.now())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct OpsSeqBumpReq {
    /// Optional specific tenant (base64). Absent → all tenants.
    tenant_id: Option<String>,
    by: Option<i64>,
    to: Option<i64>,
}

async fn ops_seq_bump(
    _ops: OpsCtx,
    State(state): State<AppState>,
    Json(req): Json<OpsSeqBumpReq>,
) -> AppResult<Json<Value>> {
    let tenants: Vec<Vec<u8>> = match &req.tenant_id {
        Some(t) => vec![ids::unb64(t)?],
        None => state.store.list_tenant_ids().await?,
    };
    let mut results = Vec::new();
    for tid in &tenants {
        let (old, new) = if let Some(to) = req.to {
            state.store.bump_next_seq_to(tid, to).await?
        } else if let Some(by) = req.by {
            state.store.bump_next_seq_by(tid, by).await?
        } else {
            return Err(AppError::malformed("seq-bump requires `by` or `to`"));
        };
        results.push(json!({ "tenant_id": ids::b64(tid), "old": old, "new": new }));
    }
    Ok(Json(json!({ "bumped": results })))
}

// ---- enrollment grants (per-engineer single-use bootstrap creds) ----

#[derive(Deserialize)]
struct EnrollCreateReq {
    label: String,
    tier: Option<String>,
    ttl_seconds: Option<i64>,
}

/// Issue a grant. The secret is returned ONCE (only its hash is stored).
async fn enroll_create(
    _ops: OpsCtx,
    State(state): State<AppState>,
    Json(req): Json<EnrollCreateReq>,
) -> AppResult<Json<Value>> {
    let label = req.label.trim();
    if label.is_empty() {
        return Err(AppError::malformed("label required"));
    }
    if let Some(t) = req.tier.as_deref() {
        if t != "personal" && t != "org" {
            return Err(AppError::malformed("invalid tier"));
        }
    }
    let now = state.now();
    let expires_at = req.ttl_seconds.filter(|s| *s > 0).map(|s| now + s);
    let grant_id = ids::random_id16().to_vec();
    let token = ids::random_bytes32();
    let token_hash = ids::sha256(&token);
    state
        .store
        .create_enrollment_grant(
            &grant_id,
            &token_hash,
            label,
            req.tier.as_deref(),
            expires_at,
            now,
        )
        .await?;
    Ok(Json(json!({
        "grant_id": ids::b64(&grant_id),
        "token": ids::b64(&token),
        "expires_at": expires_at,
    })))
}

#[derive(Deserialize)]
struct EnrollRevokeReq {
    grant_id: String,
}

/// Revoke a grant before it is used.
async fn enroll_revoke(
    _ops: OpsCtx,
    State(state): State<AppState>,
    Json(req): Json<EnrollRevokeReq>,
) -> AppResult<StatusCode> {
    let gid = ids::unb64(&req.grant_id)?;
    state.store.revoke_enrollment_grant(&gid).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// List grants (without secrets).
async fn enroll_list(_ops: OpsCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = state.store.list_enrollment_grants().await?;
    let grants: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "grant_id": ids::b64(&r.grant_id),
                "label": r.label,
                "tier": r.tier,
                "state": r.state,
                "expires_at": r.expires_at,
                "redeemed_tenant": r.redeemed_tenant.as_ref().map(|t| ids::b64(t)),
                "redeemed_at": r.redeemed_at,
                "created_at": r.created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "grants": grants })))
}
