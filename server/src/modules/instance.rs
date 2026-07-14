//! Instance identity + claim (v2 §5.1): GET /v1/instance, POST /v1/claim.

use crate::crypto::{self, RegistrationPayload};
use crate::error::{AppError, AppResult};
use crate::http::extract::ct_eq;
use crate::ids;
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/instance", get(instance_info))
        .route("/v1/claim", post(claim))
}

/// The public OIDC hints a browser-flow client needs to build the IdP authorize
/// URL: the `issuer` (from which it resolves the authorization/token endpoints via
/// `{issuer}/.well-known/openid-configuration`) and the public `client_id`. Both are
/// non-secret — they already travel in the browser's redirect to the IdP. The
/// `audience`, `jwks_url`, `group_map` and reassertion window stay server-side.
#[derive(Serialize)]
struct OidcInfo {
    issuer: String,
    client_id: String,
}

#[derive(Serialize)]
struct InstanceInfo {
    claimed: bool,
    name: Option<String>,
    version: String,
    instance_id: String,
    auth: Vec<&'static str>,
    /// Present only when OIDC is enabled — the browser-flow clients read the issuer
    /// + client_id from here to start the SSO dance. Omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc: Option<OidcInfo>,
}

async fn instance_info(State(state): State<AppState>) -> AppResult<Json<InstanceInfo>> {
    let row = state.store.instance().await?;
    let mut auth = vec!["password"];
    let mut oidc = None;
    if state.config.oidc.enabled {
        auth.push("oidc");
        oidc = Some(OidcInfo {
            issuer: state.config.oidc.issuer.clone(),
            client_id: state.config.oidc.client_id.clone(),
        });
    }
    Ok(Json(InstanceInfo {
        claimed: row.claimed != 0,
        name: row.name,
        version: env!("CARGO_PKG_VERSION").to_string(),
        instance_id: ids::b64(&row.instance_id),
        auth,
        oidc,
    }))
}

#[derive(Deserialize)]
struct ClaimReq {
    setup_code: String,
    registration_payload: String,
    registration_signature: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    space_name: Option<String>,
}

#[derive(Serialize)]
struct ClaimResp {
    account_id: String,
    device_id: String,
    space_id: String,
    instance_id: String,
}

/// Single-winner claim: setup code → owner account + device + first space.
async fn claim(
    State(state): State<AppState>,
    Json(req): Json<ClaimReq>,
) -> AppResult<(StatusCode, Json<ClaimResp>)> {
    let row = state.store.instance().await?;
    if row.claimed != 0 {
        return Err(AppError::conflict("instance already claimed"));
    }
    let want = row
        .setup_code_hash
        .as_deref()
        .ok_or_else(|| AppError::forbidden("setup closed"))?;
    let got = ids::sha256(req.setup_code.trim().as_bytes());
    if !ct_eq(&got, want) {
        return Err(AppError::forbidden("invalid setup code"));
    }

    let payload_bytes = ids::unb64(&req.registration_payload)?;
    let payload = RegistrationPayload::parse_canonical(&payload_bytes)?;
    let sig = ids::unb64(&req.registration_signature)?;
    crypto::verify_registration(&payload, &sig)?;

    let now = state.now();
    let account_id = ids::random_id16().to_vec();
    let device_id = ids::random_id16().to_vec();
    let space_id = ids::random_id16().to_vec();
    let space_name = req.space_name.as_deref().unwrap_or("Main");

    let mut tx = state.store.begin().await?;
    if !state
        .store
        .claim_instance_cas(&mut tx, &account_id, None)
        .await?
    {
        return Err(AppError::conflict("instance already claimed"));
    }
    tx.create_account(
        &account_id,
        &payload.ed25519_pub,
        &payload.x25519_pub,
        req.display_name.as_deref(),
        req.handle.as_deref(),
        true, // is_owner
        &payload_bytes,
        &sig,
        None, // external_issuer (keyset account)
        None, // external_subject
        now,
    )
    .await?;
    tx.create_device(
        &account_id,
        &device_id,
        &payload.ed25519_pub,
        &payload.x25519_pub,
        now,
    )
    .await?;
    state
        .store
        .create_space(&mut tx, &space_id, space_name, Some(&account_id), now)
        .await?;
    state
        .store
        .space_member_add(&mut tx, &space_id, &account_id, "admin", None, now)
        .await?;
    tx.commit().await?;

    tracing::info!("instance claimed");
    Ok((
        StatusCode::CREATED,
        Json(ClaimResp {
            account_id: ids::b64(&account_id),
            device_id: ids::b64(&device_id),
            space_id: ids::b64(&space_id),
            instance_id: ids::b64(&state.instance_id),
        }),
    ))
}
