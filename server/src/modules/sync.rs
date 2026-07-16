//! backend-sync (spec §5.1/§7): push_objects, delta_since, report_version.
//! Byte-compatible with the core `SyncTransport`. Semantics are load-bearing.

use crate::codec::parse_open;
use crate::error::{AppError, AppResult};
use crate::http::extract::AuthCtx;
use crate::ids;
use crate::state::AppState;
use crate::store::sync_repo::PushObj;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/sync/push", post(push))
        .route("/v1/sync/delta", get(delta))
        .route("/v1/sync/version", get(version))
}

#[derive(Deserialize)]
struct PushReq {
    objects: Vec<String>,
}

#[derive(Serialize)]
struct PushResp {
    server_seq: Vec<i64>,
}

/// `POST /v1/sync/push` → push_objects (§5.1). Atomically assigns a monotonic
/// instance-wide server_seq; idempotent by `Idempotency-Key`.
async fn push(
    auth: AuthCtx,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: Bytes,
) -> AppResult<Json<PushResp>> {
    let req: PushReq =
        serde_json::from_slice(&body).map_err(|_| AppError::malformed("invalid JSON body"))?;

    if req.objects.len() > state.max_objects_per_push() {
        return Err(AppError::payload_too_large("too many objects per push"));
    }

    // Instance owner's keyset (for the unconditional audit-author check, §11.3):
    // instance.owner_account_id → its account ed25519. None until claimed.
    let genesis = match state.store.instance().await?.owner_account_id {
        Some(aid) => state.store.account_ed(&aid).await?,
        None => None,
    };

    let mut items = Vec::with_capacity(req.objects.len());
    for o in &req.objects {
        let bytes = ids::unb64(o)?;
        if bytes.len() > state.max_object_bytes() {
            return Err(AppError::payload_too_large(
                "object exceeds max_object_bytes",
            ));
        }
        // Strict parse of the open columns (reject corrupt objects early, §2.4).
        let parsed = parse_open(&bytes)?;

        // --- Unconditional structural invariants (regardless of tier/validate) ---
        // Only Cloud vaults reach the server; Local(0) is rejected (§4.3/§5.4).
        if parsed.tag() == Some(crate::codec::ObjectTag::Vault) && parsed.sync_target != Some(1) {
            return Err(AppError::malformed(
                "vault sync_target must be Cloud; Local objects never reach the server",
            ));
        }
        // Audit record via push: author MUST == the instance owner (§11.3), if the
        // instance is claimed. (The client re-verifies on read anyway.)
        if parsed.tag() == Some(crate::codec::ObjectTag::Audit) {
            if let Some(g) = genesis.as_deref() {
                if parsed.author_pubkey.as_deref() != Some(g) {
                    return Err(AppError::forbidden("audit author must be instance owner"));
                }
            }
        }
        // A3: account-state MUST be self-authored by the pushing device (== the
        // account's keyset). Unconditional (not under validate_signatures): otherwise
        // a member could write someone else's account-state, and delta
        // addresses tag-7 by author_pubkey.
        if parsed.tag() == Some(crate::codec::ObjectTag::AccountState)
            && parsed.author_pubkey.as_deref() != Some(auth.device_ed25519())
        {
            return Err(AppError::forbidden("account state must be self-authored"));
        }

        items.push(PushObj { bytes, parsed });
    }

    // Record-sig verification (§2.4 defense-in-depth): discards forged/garbage
    // objects early. The client re-verifies on read anyway. The gate is
    // validate_signatures, BUT ACL objects (manifest/grant, tag 3/4) are ALWAYS
    // verified (S5): their integrity is not a client read concern but a server
    // authorization decision (the delta visibility filter trusts materialized
    // manifests/grants); otherwise, with validate_signatures=off, a space member
    // could push a forged grant and gain delta visibility of someone else's vault.
    let validate = state.validate_signatures();
    for it in &items {
        let is_acl = matches!(
            it.parsed.tag(),
            Some(crate::codec::ObjectTag::MembershipManifest)
                | Some(crate::codec::ObjectTag::MembershipGrant)
        );
        if is_acl || validate {
            crate::crypto::verify_record_sig(&it.bytes)?;
        }
    }

    // Write-accept (RBAC + author∈members@epoch, §9.3/§9.4/§10). S5: authorship
    // of ACL objects (author==Admin@epoch) is ALWAYS checked; full RBAC for
    // Item/Vault/Audit is under validate_signatures (`acl_only = !validate`). On
    // single-owner personal vaults the author resolves to the owner's Admin → no-op.
    crate::modules::policy::write_accept(&state, auth.device_ed25519(), &items, !validate).await?;

    let idem = match headers.get("idempotency-key") {
        // Cap the client-chosen key so it can't write oversize idempotency rows
        // (bounds the client-chosen key like the other id guards); 128 bytes covers any UUID/hash.
        Some(v) if v.as_bytes().len() > 128 => {
            return Err(AppError::malformed(
                "idempotency-key too long (max 128 bytes)",
            ));
        }
        Some(v) => Some(v.as_bytes().to_vec()),
        None => None,
    };
    // Bind the idempotency request hash to the authenticated principal (device
    // pubkey): the idem lookup is key-only, so without this a key collision across
    // accounts/devices could replay ANOTHER principal's stored response. Same
    // principal+body still hashes stable → legitimate retries stay idempotent.
    let mut hin = Vec::with_capacity(auth.device_ed25519().len() + body.len());
    hin.extend_from_slice(auth.device_ed25519());
    hin.extend_from_slice(&body);
    let req_hash = ids::sha256(&hin);
    let res = state
        .store
        .push_objects(idem.as_deref(), &req_hash, items, state.now())
        .await?;

    metrics::counter!("unissh_push_objects_total").increment(res.server_seq.len() as u64);
    Ok(Json(PushResp {
        server_seq: res.server_seq,
    }))
}

#[derive(Deserialize)]
struct DeltaQuery {
    cursor: Option<i64>,
    limit: Option<i64>,
    /// Optional hex `vault_id`: restrict the delta to a SINGLE vault (targeted "pull
    /// this vault"). Membership is still enforced for that vault. The client applies
    /// the result without advancing its per-tenant cursor.
    vault: Option<String>,
}

#[derive(Serialize)]
struct DeltaItem {
    server_seq: i64,
    object: String,
}

#[derive(Serialize)]
struct DeltaResp {
    items: Vec<DeltaItem>,
    has_more: bool,
    next_cursor: i64,
}

/// `GET /v1/sync/delta` → delta_since (§5.1): seq>cursor, ASC, pagination.
async fn delta(
    auth: AuthCtx,
    State(state): State<AppState>,
    Query(q): Query<DeltaQuery>,
) -> AppResult<Json<DeltaResp>> {
    let cursor = q.cursor.unwrap_or(0).max(0);
    let max = state.config.limits.delta_max_page_size as i64;
    let def = state.config.limits.delta_page_size as i64;
    let limit = q.limit.unwrap_or(def).clamp(1, max);

    // A1: membership-scoped — a device sees only vaults where it is owner/member.
    // Instance-admin is NOT a bypass (delta does not consult is_instance_admin).
    // With `?vault=<hex>`, the same scope is applied but restricted to one vault.
    let rows = match q.vault.as_deref() {
        Some(vhex) => {
            let vid = hex::decode(vhex.trim())
                .map_err(|_| AppError::malformed("invalid vault id (expected hex)"))?;
            state
                .store
                .delta_since_vault(cursor, limit, auth.device_ed25519(), state.now(), &vid)
                .await?
        }
        None => {
            state
                .store
                .delta_since(cursor, limit, auth.device_ed25519(), state.now())
                .await?
        }
    };
    let (has_more, next_cursor) =
        crate::http::page(&rows, limit as usize, cursor, |r| r.server_seq);
    let items = rows
        .into_iter()
        .map(|r| DeltaItem {
            server_seq: r.server_seq,
            object: ids::b64(&r.object_bytes),
        })
        .collect();
    metrics::counter!("unissh_delta_requests_total").increment(1);
    Ok(Json(DeltaResp {
        items,
        has_more,
        next_cursor,
    }))
}

#[derive(Serialize)]
struct VersionResp {
    report_version: i64,
}

/// `GET /v1/sync/version` → report_version (§5.1): the max assigned server_seq.
async fn version(_auth: AuthCtx, State(state): State<AppState>) -> AppResult<Json<VersionResp>> {
    let v = state.store.report_version().await?;
    Ok(Json(VersionResp { report_version: v }))
}
