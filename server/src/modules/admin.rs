//! Admin surface (`/v1/admin/*`): read-projections + lifecycle controls for the
//! self-host administration panel. Everything under `OwnerCtx` (instance owner).
//! The server stays zero-knowledge: we return only open metadata — NEVER
//! object_bytes / keyset_bytes / relay messages.

use crate::error::{AppError, AppResult};
use crate::http::extract::OwnerCtx;
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
        .route("/v1/admin/account/status", post(account_status))
        .route("/v1/admin/devices", get(devices_list))
        .route("/v1/admin/sessions", get(sessions_list))
        .route("/v1/admin/session/revoke", post(session_revoke))
        .route("/v1/admin/invites", get(invites_list))
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

#[derive(Deserialize)]
struct AccountQuery {
    account_id: Option<String>,
}

// ---- overview ----

async fn overview(_owner: OwnerCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let c = state.store.admin_overview().await?;
    let inst = state.store.instance().await?;
    Ok(Json(json!({
        "instance_id": ids::b64(&inst.instance_id),
        "name": inst.name,
        "claimed": inst.claimed != 0,
        "next_seq": inst.next_seq,
        "accounts": c.accounts,
        "owners": c.owners,
        "devices": c.devices,
        "active_sessions": c.active_sessions,
        "vaults": c.vaults,
        "objects": c.objects,
        "pending_invites": c.pending_invites,
        "instance_generation": inst.next_seq,
    })))
}

/// Instance-wide anti-rollback generation (§16) + current floor from config.
async fn instance_info(_owner: OwnerCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let generation = state.store.instance_generation().await?;
    Ok(Json(json!({
        "generation": generation,
        "min_floor": state.config.sync.min_instance_generation,
    })))
}

// ---- account lifecycle ----

#[derive(Deserialize)]
struct AccountStatusReq {
    account_id: String,
    disabled: bool,
}

async fn account_status(
    _owner: OwnerCtx,
    State(state): State<AppState>,
    Json(req): Json<AccountStatusReq>,
) -> AppResult<StatusCode> {
    let target = ids::unb64(&req.account_id)?;
    let acct = state
        .store
        .get_account_by_id(&target)
        .await?
        .ok_or_else(|| AppError::not_found("account"))?;
    if req.disabled {
        // anti-lockout: cannot disable the claim owner or the last owner.
        let inst = state.store.instance().await?;
        if inst.owner_account_id.as_deref() == Some(target.as_slice()) {
            return Err(AppError::forbidden("cannot disable the claim owner"));
        }
        if acct.is_owner == 1 && state.store.owner_count().await? <= 1 {
            return Err(AppError::forbidden("cannot disable the last owner"));
        }
    }
    let status = if req.disabled { "disabled" } else { "active" };
    state.store.set_account_status(&target, status).await?;

    // On disable, enqueue a crypto `revoke` (Task 9) across ALL vaults where the
    // account still holds a live grant at the latest epoch — a vault-admin fulfils
    // each by rotating that vault's key. Mirrors the space member-remove path, minus
    // the space filter (a disable is instance-wide).
    if req.disabled {
        if let Some(member_ed) = state.store.account_ed(&target).await? {
            let vaults = state.store.vaults_with_live_grant(&member_ed).await?;
            if !vaults.is_empty() {
                let now = state.now();
                let mut tx = state.store.begin().await?;
                for vault_id in &vaults {
                    let action_id = ids::random_id16().to_vec();
                    state
                        .store
                        .pending_enqueue(
                            &mut tx,
                            &action_id,
                            "revoke",
                            vault_id,
                            &target,
                            None,
                            "directory",
                            None,
                            now,
                        )
                        .await?;
                }
                tx.commit().await?;
            }
        }
    }

    let ev = json!({
        "event": if req.disabled { "account_disable" } else { "account_enable" },
        "account_id": ids::b64(&target), "ts": state.now(),
    });
    state.audit_event(&ev, None).await;
    Ok(StatusCode::NO_CONTENT)
}

// ---- devices / sessions ----

async fn devices_list(
    owner: OwnerCtx,
    State(state): State<AppState>,
    Query(q): Query<AccountQuery>,
) -> AppResult<Json<Value>> {
    let acc = match q.account_id {
        Some(a) => ids::unb64(&a)?,
        None => owner.account_id().to_vec(),
    };
    let rows = state.store.admin_list_devices(&acc).await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|d| {
            json!({
                "device_id": ids::b64(&d.device_id),
                "kind": d.kind,
                "label": d.label,
                "status": d.status,
                "registered_at": d.registered_at,
                "active_sessions": d.session_count,
            })
        })
        .collect();
    Ok(Json(json!({ "devices": out })))
}

async fn sessions_list(
    _owner: OwnerCtx,
    State(state): State<AppState>,
    Query(q): Query<AccountQuery>,
) -> AppResult<Json<Value>> {
    let acc = match &q.account_id {
        Some(a) => Some(ids::unb64(a)?),
        None => None,
    };
    let rows = state.store.admin_list_sessions(acc.as_deref()).await?;
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
    _owner: OwnerCtx,
    State(state): State<AppState>,
    Json(req): Json<SessionRevokeReq>,
) -> AppResult<StatusCode> {
    let sid = ids::unb64(&req.session_id)?;
    state.store.admin_revoke_session(&sid).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- invites (read-only listing; v2 create/revoke arrive in Task 8) ----

async fn invites_list(_owner: OwnerCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = state.store.admin_list_invites().await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|i| {
            json!({
                "invite_id": ids::b64(&i.invite_id),
                "state": i.state,
                "expires_at": i.expires_at,
                "created_at": i.created_at,
                "redeemed_at": i.redeemed_at,
            })
        })
        .collect();
    Ok(Json(json!({ "invites": out })))
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

async fn vaults_list(_owner: OwnerCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = state.store.admin_list_vaults().await?;
    let out: Vec<Value> = rows.iter().map(vault_json).collect();
    Ok(Json(json!({ "vaults": out })))
}

#[derive(Deserialize)]
struct VaultQuery {
    vault_id: String,
}

async fn vault_get(
    _owner: OwnerCtx,
    State(state): State<AppState>,
    Query(q): Query<VaultQuery>,
) -> AppResult<Json<Value>> {
    let id = ids::unb64(&q.vault_id)?;
    let v = state
        .store
        .admin_get_vault(&id)
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
    _owner: OwnerCtx,
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
        .admin_list_objects(q.tag, vault.as_deref(), cursor, limit)
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

async fn relay_list(_owner: OwnerCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = state.store.admin_list_relay().await?;
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
    owner: OwnerCtx,
    State(state): State<AppState>,
    Query(q): Query<AccountQuery>,
) -> AppResult<Json<Value>> {
    let acc = match q.account_id {
        Some(a) => ids::unb64(&a)?,
        None => owner.account_id().to_vec(),
    };
    let rows = state.store.admin_list_keysets(&acc).await?;
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

async fn config_get(_owner: OwnerCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let c = &state.config;
    Ok(Json(json!({
        "server": {
            "bind": c.server.bind,
            "tls_cert": mask(&c.server.tls_cert),
            "tls_key": mask(&c.server.tls_key),
            "trust_proxy": c.server.trust_proxy,
            "acme": c.server.acme,
            "cors_allowed_origins": c.server.cors_allowed_origins,
            "public_url": c.server.public_url,
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
        "setup": { "code": mask(&c.setup.code) },
        "oidc": {
            "enabled": c.oidc.enabled,
            "issuer": c.oidc.issuer,
            "client_id": c.oidc.client_id,
            "audience": c.oidc.audience,
            "jwks_url": c.oidc.jwks_url,
            "groups_claim": c.oidc.groups_claim,
            "group_map_len": c.oidc.group_map.len(),
            "max_reassertion_age_seconds": c.oidc.max_reassertion_age_seconds,
        },
        "ops": { "token": mask(&c.ops.token) },
    })))
}

/// `PUT /v1/admin/config` — hot-reload of a safe subset of runtime settings.
#[derive(Deserialize)]
struct ConfigPutReq {
    validate_signatures: Option<bool>,
    max_object_bytes: Option<usize>,
    max_objects_per_push: Option<usize>,
}

async fn config_put(
    _owner: OwnerCtx,
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

async fn metrics_raw(_owner: OwnerCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    match &state.metrics {
        Some(h) => Ok(Json(json!({ "enabled": true, "prometheus": h.render() }))),
        None => Ok(Json(json!({ "enabled": false, "prometheus": Value::Null }))),
    }
}

async fn metrics_summary(
    _owner: OwnerCtx,
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

async fn health(_owner: OwnerCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
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

// ---- seq-bump over HTTP (instance-wide; only raises) ----

#[derive(Deserialize)]
struct SeqBumpReq {
    by: Option<i64>,
    to: Option<i64>,
}

async fn seq_bump(
    _owner: OwnerCtx,
    State(state): State<AppState>,
    Json(req): Json<SeqBumpReq>,
) -> AppResult<Json<Value>> {
    let (old, new) = if let Some(to) = req.to {
        state.store.bump_instance_seq_to(to).await?
    } else if let Some(by) = req.by {
        state.store.bump_instance_seq_by(by).await?
    } else {
        return Err(AppError::malformed("seq-bump requires `by` or `to`"));
    };
    Ok(Json(json!({ "old": old, "new": new })))
}

// ---- migrations status ----

async fn migrations_list(
    _owner: OwnerCtx,
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

async fn audit_verify(_owner: OwnerCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let (ok, count, broken_at, head) = state.store.verify_audit_chain().await?;
    Ok(Json(json!({
        "ok": ok,
        "count": count,
        "broken_at": broken_at,
        "head_hash": head.as_deref().map(ids::b64),
    })))
}
