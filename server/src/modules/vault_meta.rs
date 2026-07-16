//! backend-vault-metadata (spec §5.4/§8.2): claim vault_id namespace.
//! Vault/Item objects flow through /v1/sync/push (there are no separate endpoints).

use crate::error::{AppError, AppResult};
use crate::http::extract::AuthCtx;
use crate::ids;
use crate::state::AppState;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/vaults", get(list_vaults))
        .route("/v1/vaults/claim", post(claim))
}

#[derive(Serialize)]
struct CatalogVault {
    /// hex vault_id — the client works in hex vault ids (bind / `?vault=` / local rows).
    vault_id: String,
    latest_version: i64,
    latest_epoch: i64,
    tombstone: bool,
    /// base64 of the latest Vault (tag-1) record (opaque bytes) — reserved for name
    /// preview. Absent only for the degenerate vault-with-no-record case.
    record: Option<String>,
}

#[derive(Serialize)]
struct CatalogResp {
    vaults: Vec<CatalogVault>,
}

/// `GET /v1/vaults` — the member-facing catalog: every vault this caller can access
/// (owned + granted), independent of any sync cursor. Membership-scoped exactly like
/// `/v1/sync/delta` (owner OR active grant on the latest epoch); instance-admin is NOT
/// a bypass. Lets the client show "vaults available on this server" and pull a specific
/// one, instead of blindly re-walking the whole delta.
async fn list_vaults(auth: AuthCtx, State(state): State<AppState>) -> AppResult<Json<CatalogResp>> {
    let rows = state
        .store
        .list_accessible_vaults(auth.device_ed25519(), state.now())
        .await?;
    let vaults = rows
        .into_iter()
        .map(|v| CatalogVault {
            vault_id: hex::encode(&v.vault_id),
            latest_version: v.latest_version,
            latest_epoch: v.latest_epoch,
            tombstone: v.tombstone != 0,
            record: v.record_bytes.as_deref().map(ids::b64),
        })
        .collect();
    metrics::counter!("unissh_vault_catalog_requests_total").increment(1);
    Ok(Json(CatalogResp { vaults }))
}

#[derive(Deserialize)]
struct ClaimReq {
    vault_id: String,
    /// Space vault: base64 space_id. Absent → personal vault (owner = caller account).
    #[serde(default)]
    space_id: Option<String>,
    /// "selective" (default) | "space_wide".
    #[serde(default)]
    access_policy: Option<String>,
    /// Crypto role (0|1|2) applied space-wide when `access_policy = "space_wide"`.
    #[serde(default)]
    space_wide_role: Option<i64>,
    #[serde(default)]
    manual_approve: Option<bool>,
}

#[derive(Serialize)]
struct ClaimResp {
    claimed: bool,
}

/// `POST /v1/vaults/claim` (§5.4): fixes owner=author on the first claim; rejects if
/// vault_id already belongs to another owner (claim-rule §8.2). A personal claim binds
/// the vault to the caller's account; a space claim requires the caller to be a member.
async fn claim(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<ClaimReq>,
) -> AppResult<Json<ClaimResp>> {
    let vault_id = ids::unb64(&req.vault_id)?;
    if vault_id.is_empty() {
        return Err(AppError::malformed("empty vault_id"));
    }
    let access_policy = req.access_policy.as_deref().unwrap_or("selective");
    if access_policy != "selective" && access_policy != "space_wide" {
        return Err(AppError::malformed("invalid access_policy"));
    }

    let (space_id, owner_account_id): (Option<Vec<u8>>, Option<Vec<u8>>) = match &req.space_id {
        Some(s) => {
            let sid = ids::unb64(s)?;
            if !state.store.is_space_member(&sid, auth.account_id()).await? {
                return Err(AppError::forbidden("not a member of this space"));
            }
            (Some(sid), None)
        }
        None => (None, Some(auth.account_id().to_vec())),
    };

    let claimed = state
        .store
        .claim_vault(
            &vault_id,
            auth.device_ed25519(),
            owner_account_id.as_deref(),
            space_id.as_deref(),
            access_policy,
            req.space_wide_role,
            req.manual_approve.unwrap_or(false),
            state.now(),
        )
        .await?;
    Ok(Json(ClaimResp { claimed }))
}
