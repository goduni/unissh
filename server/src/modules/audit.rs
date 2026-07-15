//! backend-audit (spec §5.6/§11): append-only audit_log, monotonic seq,
//! admin-view. Client-signed (author==genesis) + server-observed (unsigned).

use crate::codec::{ObjectTag, parse_open};
use crate::error::{AppError, AppResult};
use crate::http::extract::AuthCtx;
use crate::ids;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/audit", post(audit_append).get(audit_query))
}

#[derive(Deserialize)]
struct AppendReq {
    audit_object: String,
}

#[derive(Serialize)]
struct AppendResp {
    seq: i64,
}

/// `POST /v1/audit` (§5.6): direct ingest of a client-signed audit object.
/// author_pubkey MUST == the instance owner's keyset (§11.3), otherwise reject.
async fn audit_append(
    _auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<AppendReq>,
) -> AppResult<(StatusCode, Json<AppendResp>)> {
    let bytes = ids::unb64(&req.audit_object)?;
    let p = parse_open(&bytes)?;
    if p.tag() != Some(ObjectTag::Audit) {
        return Err(AppError::malformed("audit object expected"));
    }
    let entry_blob = p
        .entry_blob
        .ok_or_else(|| AppError::malformed("missing entry_blob"))?;
    let signature = p
        .signature
        .ok_or_else(|| AppError::malformed("missing signature"))?;
    let author = p
        .author_pubkey
        .ok_or_else(|| AppError::malformed("missing author"))?;

    let owner_ed = match state.store.instance().await?.owner_account_id {
        Some(aid) => state.store.account_ed(&aid).await?,
        None => None,
    };
    let owner_ed = owner_ed.ok_or_else(|| AppError::forbidden("instance not claimed"))?;
    if author != owner_ed {
        return Err(AppError::forbidden("audit author must be instance owner"));
    }

    let vault_id = p.vault_id.filter(|v| !v.is_empty());
    let seq = state
        .store
        .append_audit_client_signed(
            &entry_blob,
            &signature,
            &author,
            vault_id.as_deref(),
            None,
            state.now(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(AppendResp { seq })))
}

#[derive(Deserialize)]
struct AuditQuery {
    since_seq: Option<i64>,
    limit: Option<i64>,
}

#[derive(Serialize)]
struct AuditEntry {
    seq: i64,
    entry_blob: String,
    signature: Option<String>,
    author_pubkey: Option<String>,
    recorded_at: i64,
    source: String,
}

#[derive(Serialize)]
struct AuditQueryResp {
    entries: Vec<AuditEntry>,
    has_more: bool,
    next_since: i64,
}

/// `GET /v1/audit` (§5.6): admin-only, paginated by seq ASC.
async fn audit_query(
    auth: AuthCtx,
    State(state): State<AppState>,
    Query(q): Query<AuditQuery>,
) -> AppResult<Json<AuditQueryResp>> {
    auth.require_owner(&state.store).await?;
    let since = q.since_seq.unwrap_or(0).max(0);
    let max = state.config.limits.delta_max_page_size as i64;
    let def = state.config.limits.delta_page_size as i64;
    let limit = q.limit.unwrap_or(def).clamp(1, max);

    let rows = state.store.query_audit(since, limit).await?;
    let has_more = rows.len() as i64 == limit;
    let next_since = rows.last().map(|r| r.seq + 1).unwrap_or(since);
    let entries = rows
        .into_iter()
        .map(|r| AuditEntry {
            seq: r.seq,
            entry_blob: ids::b64(&r.entry_blob),
            signature: r.signature.as_deref().map(ids::b64),
            author_pubkey: r.author_pubkey.as_deref().map(ids::b64),
            recorded_at: r.recorded_at,
            source: r.source,
        })
        .collect();
    Ok(Json(AuditQueryResp {
        entries,
        has_more,
        next_since,
    }))
}
