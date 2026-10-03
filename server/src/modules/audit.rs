//! backend-audit (spec §5.6/§11): append-only audit_log, monotonic seq,
//! admin-view. Client-signed (author==genesis) + server-observed (unsigned).

use crate::codec::{ObjectTag, parse_open};
use crate::error::{AppError, AppResult};
use crate::http::extract::{AuthCtx, OwnerCtx};
use crate::ids;
use crate::state::AppState;
use crate::store::models::AuditExportRow;
use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/audit", post(audit_append).get(audit_query))
        .route("/v1/audit/export", get(audit_export))
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

// ---- JSON Lines export ----

#[derive(Deserialize)]
struct ExportQuery {
    from_seq: Option<i64>,
    to_seq: Option<i64>,
}

/// One exported line: every chained column (so the file verifies offline with
/// the `unissh-audit-chain-v2` recipe) plus a readable `entry`. Also the entry
/// object of a webhook batch (`crate::audit_sinks::webhook`).
#[derive(Serialize)]
pub(crate) struct ExportLine {
    seq: i64,
    server_seq: Option<i64>,
    source: String,
    recorded_at: i64,
    author_pubkey: Option<String>,
    vault_id: Option<String>,
    space_id: Option<String>,
    prev_hash: Option<String>,
    signature: Option<String>,
    /// Decoded JSON for a server-observed entry; base64 for a client-signed
    /// (opaque) one, or for a server-observed blob that is not JSON.
    entry: serde_json::Value,
    /// The exact chained bytes, base64. A re-serialised `entry` is not
    /// guaranteed byte-identical, so offline verification hashes these.
    entry_blob: String,
}

/// The readable form of an entry: decoded JSON for a server-observed entry;
/// base64 (a JSON string) for a client-signed one, or for a server-observed
/// blob that is not JSON. Shared by the export, the webhook and syslog.
pub(crate) fn entry_value(r: &AuditExportRow) -> serde_json::Value {
    if r.source == "server-observed" {
        serde_json::from_slice(&r.entry_blob).ok()
    } else {
        None
    }
    .unwrap_or_else(|| serde_json::Value::String(ids::b64(&r.entry_blob)))
}

impl From<&AuditExportRow> for ExportLine {
    fn from(r: &AuditExportRow) -> Self {
        let entry = entry_value(r);
        ExportLine {
            seq: r.seq,
            server_seq: r.server_seq,
            source: r.source.clone(),
            recorded_at: r.recorded_at,
            author_pubkey: r.author_pubkey.as_deref().map(ids::b64),
            vault_id: r.vault_id.as_deref().map(ids::b64),
            space_id: r.space_id.as_deref().map(ids::b64),
            prev_hash: r.prev_hash.as_deref().map(ids::b64),
            signature: r.signature.as_deref().map(ids::b64),
            entry,
            entry_blob: ids::b64(&r.entry_blob),
        }
    }
}

/// `GET /v1/audit/export?from_seq&to_seq`: the audit log (or the inclusive seq
/// range) as JSON Lines, owner only. Streamed page by page; the upper bound is
/// pinned to the head at request time, so the file is a consistent slice even
/// while new entries are appended.
async fn audit_export(
    _owner: OwnerCtx,
    State(state): State<AppState>,
    Query(q): Query<ExportQuery>,
) -> AppResult<Response> {
    let from = q.from_seq.unwrap_or(1);
    if from < 1 {
        return Err(AppError::malformed("from_seq must be >= 1"));
    }
    if q.to_seq.is_some_and(|to| to < from) {
        return Err(AppError::malformed("to_seq must be >= from_seq"));
    }
    let head = state.store.max_audit_seq().await?;
    let to = q.to_seq.map_or(head, |t| t.min(head));

    // Rows per round-trip: the same page size as the `/v1/audit` listing.
    let page = (state.config.limits.delta_page_size as i64).max(1);
    let store = state.store.clone();
    let pages = futures_util::stream::try_unfold(from, move |next| {
        let store = store.clone();
        async move {
            if next > to {
                return Ok(None);
            }
            let rows = store.export_audit_page(next, to, page).await?;
            let Some(last) = rows.last().map(|r| r.seq) else {
                return Ok(None);
            };
            let mut buf = Vec::new();
            for r in &rows {
                serde_json::to_writer(&mut buf, &ExportLine::from(r))
                    .map_err(|_| AppError::internal("audit export serialisation"))?;
                buf.push(b'\n');
            }
            Ok::<_, AppError>(Some((Bytes::from(buf), last + 1)))
        }
    });
    // Headers are already sent once the body streams: a failure can only cut
    // the download short. Log the error code, never row contents.
    let body = futures_util::TryStreamExt::map_err(pages, |e: AppError| {
        tracing::warn!(code = e.code.as_str(), "audit export aborted mid-stream");
        std::io::Error::other("audit export aborted")
    });

    let filename = format!("attachment; filename=\"unissh-audit-{from}-{to}.jsonl\"");
    Ok((
        [
            (header::CONTENT_TYPE, "application/jsonl".to_string()),
            (header::CONTENT_DISPOSITION, filename),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Body::from_stream(body),
    )
        .into_response())
}
