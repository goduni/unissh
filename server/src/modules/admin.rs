//! Admin/ops surface (`/v1/admin/*`): read-projections + lifecycle controls for
//! the self-host administration panel. Everything under `AdminCtx` (instance-admin,
//! per-tenant, WITHOUT suspended-gate). The server stays zero-knowledge: we return
//! only open metadata — NEVER object_bytes / keyset_bytes / relay messages.

use crate::error::{AppError, AppResult};
use crate::http::extract::AdminCtx;
use crate::ids;
use crate::state::AppState;
use crate::store::models::VaultRow;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/overview", get(overview))
        .route("/v1/admin/tenant/status", post(tenant_status))
        .route("/v1/admin/account/status", post(account_status))
        .route("/v1/admin/devices", get(devices_list))
        .route("/v1/admin/sessions", get(sessions_list))
        .route("/v1/admin/session/revoke", post(session_revoke))
        .route("/v1/admin/invites", get(invites_list))
        .route("/v1/admin/invite/revoke", post(invite_revoke))
        .route("/v1/admin/vaults", get(vaults_list))
        .route("/v1/admin/vault", get(vault_get))
        .route("/v1/admin/objects", get(objects_list))
        .route("/v1/admin/relay", get(relay_list))
        .route("/v1/admin/keysets", get(keysets_list))
        .route("/v1/admin/config", get(config_get).put(config_put))
        .route("/v1/admin/metrics", get(metrics_raw))
        .route("/v1/admin/metrics/summary", get(metrics_summary))
        .route("/v1/admin/health", get(health))
        .route("/v1/admin/seq-bump", post(seq_bump))
        .route("/v1/admin/migrations", get(migrations_list))
        .route("/v1/admin/audit/verify", get(audit_verify))
        .route("/v1/admin/instance", get(instance_info))
}

// ---- helpers ----

fn role_label(role: i64) -> &'static str {
    match role {
        2 => "admin",
        1 => "editor",
        _ => "viewer",
    }
}

#[derive(Deserialize)]
struct AccountQuery {
    account_id: Option<String>,
}

// ---- overview ----

async fn overview(admin: AdminCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let c = state.store.admin_overview(admin.tenant_id()).await?;
    let instance_generation = state.store.instance_generation().await?;
    Ok(Json(json!({
        "tenant_id": ids::b64(admin.tenant_id()),
        "tier": admin.tenant.tier,
        "status": admin.tenant.status,
        "next_seq": admin.tenant.next_seq,
        "accounts": c.accounts,
        "admins": c.admins,
        "devices": c.devices,
        "active_sessions": c.active_sessions,
        "vaults": c.vaults,
        "objects": c.objects,
        "pending_invites": c.pending_invites,
        "instance_generation": instance_generation,
    })))
}

/// Instance-wide anti-rollback generation (§16) + current floor from config.
async fn instance_info(admin: AdminCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let _ = &admin;
    let generation = state.store.instance_generation().await?;
    Ok(Json(json!({
        "generation": generation,
        "min_floor": state.config.sync.min_instance_generation,
    })))
}

// ---- tenant lifecycle ----

#[derive(Deserialize)]
struct TenantStatusReq {
    suspended: bool,
}

async fn tenant_status(
    admin: AdminCtx,
    State(state): State<AppState>,
    Json(req): Json<TenantStatusReq>,
) -> AppResult<StatusCode> {
    let status = if req.suspended { "suspended" } else { "active" };
    state
        .store
        .set_tenant_status(admin.tenant_id(), status)
        .await?;
    let ev = json!({
        "event": if req.suspended { "tenant_suspend" } else { "tenant_activate" },
        "ts": state.now(),
    });
    let _ = state
        .store
        .append_audit_server_observed(admin.tenant_id(), &ev, None, state.now())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---- account lifecycle ----

#[derive(Deserialize)]
struct AccountStatusReq {
    account_id: String,
    disabled: bool,
}

async fn account_status(
    admin: AdminCtx,
    State(state): State<AppState>,
    Json(req): Json<AccountStatusReq>,
) -> AppResult<StatusCode> {
    let target = ids::unb64(&req.account_id)?;
    let acct = state
        .store
        .get_account_by_id(admin.tenant_id(), &target)
        .await?
        .ok_or_else(|| AppError::not_found("account"))?;
    if req.disabled {
        // anti-lockout: cannot disable the genesis owner or the last admin.
        let t = state
            .store
            .get_tenant(admin.tenant_id())
            .await?
            .ok_or_else(|| AppError::not_found("tenant"))?;
        if t.genesis_owner_pubkey.is_some()
            && t.genesis_owner_pubkey.as_deref() == acct.ed25519_pub.as_deref()
        {
            return Err(AppError::forbidden("cannot disable the genesis owner"));
        }
        if acct.is_admin == 1 && state.store.admin_count(admin.tenant_id()).await? <= 1 {
            return Err(AppError::forbidden("cannot disable the last admin"));
        }
    }
    let status = if req.disabled { "disabled" } else { "active" };
    state
        .store
        .set_account_status(admin.tenant_id(), &target, status)
        .await?;
    let ev = json!({
        "event": if req.disabled { "account_disable" } else { "account_enable" },
        "account_id": ids::b64(&target), "ts": state.now(),
    });
    let _ = state
        .store
        .append_audit_server_observed(admin.tenant_id(), &ev, None, state.now())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---- devices / sessions ----

async fn devices_list(
    admin: AdminCtx,
    State(state): State<AppState>,
    Query(q): Query<AccountQuery>,
) -> AppResult<Json<Value>> {
    let acc = match q.account_id {
        Some(a) => ids::unb64(&a)?,
        None => admin.account_id().to_vec(),
    };
    let rows = state
        .store
        .admin_list_devices(admin.tenant_id(), &acc)
        .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|d| {
            json!({
                "device_id": ids::b64(&d.device_id),
                "status": d.status,
                "registered_at": d.registered_at,
                "active_sessions": d.session_count,
            })
        })
        .collect();
    Ok(Json(json!({ "devices": out })))
}

async fn sessions_list(
    admin: AdminCtx,
    State(state): State<AppState>,
    Query(q): Query<AccountQuery>,
) -> AppResult<Json<Value>> {
    let acc = match &q.account_id {
        Some(a) => Some(ids::unb64(a)?),
        None => None,
    };
    let rows = state
        .store
        .admin_list_sessions(admin.tenant_id(), acc.as_deref())
        .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|s| {
            json!({
                "session_id": ids::b64(&s.session_id),
                "account_id": ids::b64(&s.account_id),
                "device_id": ids::b64(&s.device_id),
                "access_expires": s.access_expires,
                "refresh_expires": s.refresh_expires,
                "created_at": s.created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": out })))
}

#[derive(Deserialize)]
struct SessionRevokeReq {
    session_id: String,
}

async fn session_revoke(
    admin: AdminCtx,
    State(state): State<AppState>,
    Json(req): Json<SessionRevokeReq>,
) -> AppResult<StatusCode> {
    let sid = ids::unb64(&req.session_id)?;
    state
        .store
        .admin_revoke_session(admin.tenant_id(), &sid)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- invites ----

async fn invites_list(admin: AdminCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = state.store.admin_list_invites(admin.tenant_id()).await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|i| {
            json!({
                "invite_id": ids::b64(&i.invite_id),
                "role": role_label(i.role),
                "scope": i.scope,
                "state": i.state,
                "expires_at": i.expires_at,
                "created_at": i.created_at,
                "redeemed_at": i.redeemed_at,
            })
        })
        .collect();
    Ok(Json(json!({ "invites": out })))
}

#[derive(Deserialize)]
struct InviteRevokeReq {
    invite_id: String,
}

async fn invite_revoke(
    admin: AdminCtx,
    State(state): State<AppState>,
    Json(req): Json<InviteRevokeReq>,
) -> AppResult<StatusCode> {
    let id = ids::unb64(&req.invite_id)?;
    state
        .store
        .admin_revoke_invite(admin.tenant_id(), &id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- vaults ----

fn vault_json(v: &VaultRow) -> Value {
    json!({
        "vault_id": ids::b64(&v.vault_id),
        "owner_pubkey": ids::b64(&v.owner_pubkey),
        "latest_version": v.latest_version,
        "latest_epoch": v.latest_epoch,
        "sync_target": v.sync_target,
        "cache_policy": v.cache_policy,
        "tombstone": v.tombstone != 0,
    })
}

async fn vaults_list(admin: AdminCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = state.store.admin_list_vaults(admin.tenant_id()).await?;
    let out: Vec<Value> = rows.iter().map(vault_json).collect();
    Ok(Json(json!({ "vaults": out })))
}

#[derive(Deserialize)]
struct VaultQuery {
    vault_id: String,
}

async fn vault_get(
    admin: AdminCtx,
    State(state): State<AppState>,
    Query(q): Query<VaultQuery>,
) -> AppResult<Json<Value>> {
    let id = ids::unb64(&q.vault_id)?;
    let v = state
        .store
        .admin_get_vault(admin.tenant_id(), &id)
        .await?
        .ok_or_else(|| AppError::not_found("vault"))?;
    Ok(Json(vault_json(&v)))
}

// ---- objects metadata (ZK-safe, cursor paginated) ----

#[derive(Deserialize)]
struct ObjectsQuery {
    tag: Option<i64>,
    vault_id: Option<String>,
    cursor: Option<i64>,
    limit: Option<i64>,
}

async fn objects_list(
    admin: AdminCtx,
    State(state): State<AppState>,
    Query(q): Query<ObjectsQuery>,
) -> AppResult<Json<Value>> {
    let cursor = q.cursor.unwrap_or(0);
    let max = state.config.limits.delta_max_page_size as i64;
    let limit = q
        .limit
        .unwrap_or(state.config.limits.delta_page_size as i64)
        .clamp(1, max);
    let vault = match &q.vault_id {
        Some(v) => Some(ids::unb64(v)?),
        None => None,
    };
    let rows = state
        .store
        .admin_list_objects(admin.tenant_id(), q.tag, vault.as_deref(), cursor, limit)
        .await?;
    let (has_more, next_cursor) =
        crate::http::page(&rows, limit as usize, cursor, |r| r.server_seq);
    let out: Vec<Value> = rows
        .into_iter()
        .map(|o| {
            json!({
                "server_seq": o.server_seq,
                "object_tag": o.object_tag,
                "vault_id": o.vault_id.as_deref().map(ids::b64),
                "item_id": o.item_id.as_deref().map(ids::b64),
                "obj_version": o.obj_version,
                "key_epoch": o.key_epoch,
                "tombstone": o.tombstone.map(|t| t != 0),
                "author_pubkey": o.author_pubkey.as_deref().map(ids::b64),
                "received_at": o.received_at,
                "blob_len": o.blob_len,
            })
        })
        .collect();
    Ok(Json(
        json!({ "items": out, "has_more": has_more, "next_cursor": next_cursor }),
    ))
}

// ---- relay / keysets observation ----

async fn relay_list(admin: AdminCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = state.store.admin_list_relay(admin.tenant_id()).await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "channel_id": ids::b64(&r.channel_id),
                "state": r.state,
                "expires_at": r.expires_at,
                "created_at": r.created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "channels": out })))
}

async fn keysets_list(
    admin: AdminCtx,
    State(state): State<AppState>,
    Query(q): Query<AccountQuery>,
) -> AppResult<Json<Value>> {
    let acc = match q.account_id {
        Some(a) => ids::unb64(&a)?,
        None => admin.account_id().to_vec(),
    };
    let rows = state
        .store
        .admin_list_keysets(admin.tenant_id(), &acc)
        .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|k| json!({ "generation": k.generation, "uploaded_at": k.uploaded_at }))
        .collect();
    Ok(Json(json!({ "keysets": out })))
}

// ---- config (read-only, secrets masked) ----

fn mask(s: &str) -> Value {
    if s.is_empty() {
        json!("")
    } else {
        json!("***")
    }
}

async fn config_get(_admin: AdminCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let c = &state.config;
    Ok(Json(json!({
        "server": {
            "bind": c.server.bind,
            "tls_cert": mask(&c.server.tls_cert),
            "tls_key": mask(&c.server.tls_key),
            "trust_proxy": c.server.trust_proxy,
            "acme": c.server.acme,
            "cors_allowed_origins": c.server.cors_allowed_origins,
        },
        "db": {
            "backend": c.db.backend,
            "url": mask(&c.db.url),
            "max_connections": c.db.max_connections,
        },
        "limits": {
            "max_body_bytes": c.limits.max_body_bytes,
            "max_object_bytes": state.max_object_bytes(),
            "max_objects_per_push": state.max_objects_per_push(),
            "delta_page_size": c.limits.delta_page_size,
            "delta_max_page_size": c.limits.delta_max_page_size,
            "rate_limit_per_ip_rps": c.limits.rate_limit_per_ip_rps,
            "rate_limit_burst": c.limits.rate_limit_burst,
        },
        "sync": {
            "freshness_window_seconds": c.sync.freshness_window_seconds,
            "validate_signatures": state.validate_signatures(),
            "min_instance_generation": c.sync.min_instance_generation,
        },
        "session": {
            "access_ttl_seconds": c.session.access_ttl_seconds,
            "refresh_ttl_seconds": c.session.refresh_ttl_seconds,
            "nonce_ttl_seconds": c.session.nonce_ttl_seconds,
            "invite_default_ttl_seconds": c.session.invite_default_ttl_seconds,
            "relay_ttl_seconds": c.session.relay_ttl_seconds,
            "janitor_interval_seconds": c.session.janitor_interval_seconds,
            "idempotency_ttl_seconds": c.session.idempotency_ttl_seconds,
        },
        "obs": {
            "log_format": c.obs.log_format,
            "otel_endpoint": c.obs.otel_endpoint,
            "metrics_bind": c.obs.metrics_bind,
        },
        "bootstrap": {
            "token": mask(&c.bootstrap.token),
            "allow_open": c.bootstrap.allow_open,
            "default_tier": c.bootstrap.default_tier,
        },
        "ops": { "token": mask(&c.ops.token) },
    })))
}

/// `PUT /v1/admin/config` — hot-reload of a safe subset of runtime settings
/// (without a restart). Allowlist: `validate_signatures`, `max_object_bytes`,
/// `max_objects_per_push` — all atomically-swappable and enforced on the hot path.
/// The remaining keys are edited in the file/env + restart (figment load-only).
/// Returns live runtime values.
#[derive(Deserialize)]
struct ConfigPutReq {
    validate_signatures: Option<bool>,
    max_object_bytes: Option<usize>,
    max_objects_per_push: Option<usize>,
}

async fn config_put(
    _admin: AdminCtx,
    State(state): State<AppState>,
    Json(req): Json<ConfigPutReq>,
) -> AppResult<Json<Value>> {
    if let Some(v) = req.validate_signatures {
        state.set_validate_signatures(v);
    }
    if let Some(v) = req.max_object_bytes {
        if v == 0 {
            return Err(AppError::malformed("max_object_bytes must be > 0"));
        }
        state.set_max_object_bytes(v);
    }
    if let Some(v) = req.max_objects_per_push {
        if v == 0 {
            return Err(AppError::malformed("max_objects_per_push must be > 0"));
        }
        state.set_max_objects_per_push(v);
    }
    Ok(Json(json!({
        "validate_signatures": state.validate_signatures(),
        "max_object_bytes": state.max_object_bytes(),
        "max_objects_per_push": state.max_objects_per_push(),
        "note": "hot-reloaded; other keys require file/env + restart",
    })))
}

// ---- metrics ----

/// `GET /v1/admin/metrics` — raw Prometheus render (instant snapshot).
async fn metrics_raw(_admin: AdminCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    match &state.metrics {
        Some(h) => Ok(Json(json!({ "enabled": true, "prometheus": h.render() }))),
        None => Ok(Json(json!({ "enabled": false, "prometheus": Value::Null }))),
    }
}

/// `GET /v1/admin/metrics/summary` — ready-made series with a **time axis** for
/// charts. Each poll takes a sample of the `unissh_*` counters into an in-memory ring
/// (see `obs::MetricsHistory`); the UI draws the curves without parsing raw text.
/// History is per-process (a live chart for the viewing session), reset on restart.
async fn metrics_summary(
    _admin: AdminCtx,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    match (&state.metrics, &state.metrics_history) {
        (Some(h), Some(hist)) => {
            hist.observe(&h.render(), state.now());
            Ok(Json(json!({
                "enabled": true,
                "sample_interval_seconds": hist.min_interval(),
                "retained_samples": hist.cap(),
                "series": hist.series(),
            })))
        }
        _ => Ok(Json(json!({ "enabled": false, "series": Value::Null }))),
    }
}

// ---- health ----

/// `GET /v1/admin/health` — operational health of the instance: uptime, reachability
/// and DB pool, the last janitor run, TLS mode. Open metadata (not ZK).
async fn health(_admin: AdminCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let db_ok = state.store.ping().await.is_ok();
    let (size, idle) = state.store.pool_stats();
    let in_use = (size as i64 - idle as i64).max(0);
    let now = state.now();
    let uptime = (now - state.started_at_unix).max(0);

    let last_jan = state
        .last_janitor_run
        .load(std::sync::atomic::Ordering::Relaxed);
    let (last_run, last_run_age) = if last_jan > 0 {
        (json!(last_jan), json!((now - last_jan).max(0)))
    } else {
        (Value::Null, Value::Null)
    };

    // acme=true is rejected at startup; at runtime TLS is either in-process rustls,
    // or terminated upstream (reverse-proxy) — in which case in-process plain HTTP.
    let tls = if !state.config.server.tls_cert.is_empty() && !state.config.server.tls_key.is_empty()
    {
        "rustls"
    } else {
        "proxy"
    };

    Ok(Json(json!({
        "status": if db_ok { "ok" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime,
        "db": {
            "backend": state.config.db.backend,
            "reachable": db_ok,
            "pool": {
                "in_use": in_use,
                "idle": idle,
                "size": size,
                "max": state.config.db.max_connections,
            },
        },
        "janitor": {
            "interval_seconds": state.config.session.janitor_interval_seconds,
            "last_run": last_run,
            "last_run_age_seconds": last_run_age,
        },
        "tls": tls,
        "trust_proxy": state.config.server.trust_proxy,
    })))
}

// ---- seq-bump over HTTP (caller tenant; only raises) ----

#[derive(Deserialize)]
struct SeqBumpReq {
    by: Option<i64>,
    to: Option<i64>,
}

async fn seq_bump(
    admin: AdminCtx,
    State(state): State<AppState>,
    Json(req): Json<SeqBumpReq>,
) -> AppResult<Json<Value>> {
    let tid = admin.tenant_id();
    let (old, new) = if let Some(to) = req.to {
        state.store.bump_next_seq_to(tid, to).await?
    } else if let Some(by) = req.by {
        state.store.bump_next_seq_by(tid, by).await?
    } else {
        return Err(AppError::malformed("seq-bump requires `by` or `to`"));
    };
    Ok(Json(json!({ "old": old, "new": new })))
}

// ---- migrations status ----

async fn migrations_list(
    _admin: AdminCtx,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let rows = state.store.admin_list_migrations().await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|m| json!({ "version": m.version, "description": m.description }))
        .collect();
    Ok(Json(json!({ "migrations": out })))
}

// ---- audit tamper-evidence (§11.2 hash-chain) ----

async fn audit_verify(admin: AdminCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let (ok, count, broken_at, head) = state.store.verify_audit_chain(admin.tenant_id()).await?;
    Ok(Json(json!({
        "ok": ok,
        "count": count,
        "broken_at": broken_at,
        "head_hash": head.as_deref().map(ids::b64),
    })))
}
