//! backend-identity-auth (spec §5.3/§6): auth challenge/verify, sessions,
//! keyset (Path A), PAKE-relay (Path B), account profile, owner management,
//! device add/list. Instance-scoped (v2); claim/invite live in `instance`/Task 8.
//! The server verifies self-attested registration + server-auth signatures, and
//! enforces single-use nonce + expiry itself; it does not decrypt the payload.

use crate::crypto::{self, ServerAuthChallenge};
use crate::error::{AppError, AppResult};
use crate::http::extract::AuthCtx;
use crate::ids;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/challenge", post(auth_challenge))
        .route("/v1/auth/verify", post(auth_verify))
        .route("/v1/session/refresh", post(session_refresh))
        .route("/v1/session/logout", post(session_logout))
        .route("/v1/session/device-revoke", post(device_revoke))
        .route("/v1/keyset", get(keyset_get).put(keyset_put))
        .route("/v1/relay/open", post(relay_open))
        .route("/v1/relay/msg1", post(relay_msg1))
        .route("/v1/relay/msg2", post(relay_msg2))
        .route("/v1/relay/msg3", post(relay_msg3))
        .route("/v1/relay/poll", get(relay_poll))
        .route("/v1/account/profile", post(account_profile))
        .route("/v1/accounts", get(accounts_list))
        .route("/v1/owner/set", post(owner_set))
        .route("/v1/devices/add", post(device_add))
        .route("/v1/devices", get(devices_list_self))
}

// ---- helpers ----

#[derive(Serialize)]
struct SessionTokens {
    access_token: String,
    refresh_token: String,
    access_expires: i64,
    refresh_expires: i64,
    session_id: String,
}

/// Refresh token = `session_id(16) || secret(32)`. Embedding the (non-secret)
/// session_id lets `session_refresh` locate the session directly, so a presented
/// token whose hash matches NEITHER the live row can still be attributed to its
/// session and recognized as reuse of a past generation (F9).
fn build_refresh_token(session_id: &[u8], secret: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(session_id.len() + 32);
    t.extend_from_slice(session_id);
    t.extend_from_slice(secret);
    t
}

async fn mint_session(
    state: &AppState,
    account_id: &[u8],
    device_id: &[u8],
) -> AppResult<SessionTokens> {
    let now = state.now();
    let access = ids::random_bytes32();
    let session_id = ids::random_id16();
    let refresh = build_refresh_token(&session_id, &ids::random_bytes32());
    let access_expires = now + state.config.session.access_ttl_seconds;
    let refresh_expires = now + state.config.session.refresh_ttl_seconds;
    state
        .store
        .create_session(
            &session_id,
            account_id,
            device_id,
            &ids::sha256(&access),
            &ids::sha256(&refresh),
            access_expires,
            refresh_expires,
            now,
        )
        .await?;
    Ok(SessionTokens {
        access_token: ids::b64(&access),
        refresh_token: ids::b64(&refresh),
        access_expires,
        refresh_expires,
        session_id: ids::b64(&session_id),
    })
}

async fn audit_observed(state: &AppState, event: &str, account_id: &[u8], device_id: &[u8]) {
    let ev = serde_json::json!({
        "event": event,
        "account_id": ids::b64(account_id),
        "device_id": ids::b64(device_id),
        "ts": state.now(),
    });
    state.audit_event(&ev, None).await;
}

// ---- auth challenge / verify ----

#[derive(Deserialize)]
struct ChallengeReq {
    account_id: String,
    device_id: String,
    key_id: String,
}

#[derive(Serialize, Deserialize)]
struct ChallengeJson {
    host: String,
    account_id: String,
    device_id: String,
    key_id: String,
    nonce: String,
    expiry: u64,
}

async fn auth_challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeReq>,
) -> AppResult<Json<ChallengeJson>> {
    let device_id = ids::unb64(&req.device_id)?;
    // The device must exist (the challenge is addressed).
    let _device = state
        .store
        .get_device(&device_id)
        .await?
        .ok_or_else(|| AppError::not_found("device"))?;

    let nonce = ids::random_bytes32();
    let now = state.now();
    let expiry = (now + state.config.session.nonce_ttl_seconds) as u64;
    state
        .store
        .insert_nonce(&nonce, Some(&device_id), expiry as i64)
        .await?;

    Ok(Json(ChallengeJson {
        host: ids::b64(&state.instance_id),
        account_id: req.account_id,
        device_id: req.device_id,
        key_id: req.key_id,
        nonce: ids::b64(&nonce),
        expiry,
    }))
}

#[derive(Deserialize)]
struct VerifyReq {
    challenge: ChallengeJson,
    signature: String,
}

async fn auth_verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyReq>,
) -> AppResult<Json<SessionTokens>> {
    let c = &req.challenge;
    let now = state.now();

    if c.expiry <= now as u64 {
        return Err(AppError::unauthenticated("challenge expired"));
    }
    let account_id = ids::unb64(&c.account_id)?;
    let device_id = ids::unb64(&c.device_id)?;
    let nonce = ids::unb64(&c.nonce)?;

    // host must match the server-issued one (= base64(instance_id)) — the challenge
    // is bound to this instance (§5.3 step 3).
    if ids::unb64(&c.host)? != state.instance_id {
        return Err(AppError::unauthenticated("challenge host mismatch"));
    }

    // The device is active and belongs to the claimed account.
    let device = state
        .store
        .get_device(&device_id)
        .await?
        .ok_or_else(|| AppError::unauthenticated("device not found"))?;
    if device.status != "active" {
        return Err(AppError::unauthenticated("device not active"));
    }
    if device.account_id != account_id {
        return Err(AppError::unauthenticated("device/account mismatch"));
    }
    if !state.store.account_is_active(&account_id).await? {
        return Err(AppError::unauthenticated("account disabled"));
    }

    // Verify the challenge signature under the device ed25519 (verify_strict).
    let challenge = ServerAuthChallenge {
        host: ids::unb64(&c.host)?,
        account_id: account_id.clone(),
        device_id: device_id.clone(),
        key_id: ids::unb64(&c.key_id)?,
        nonce: nonce.clone(),
        expiry: c.expiry,
    };
    let sig = ids::unb64(&req.signature)?;
    crypto::verify_server_auth(&device.ed25519_pub, &challenge, &sig)?;

    // The server ITSELF enforces single-use nonce + expiry + device-binding (CAS).
    if !state.store.consume_nonce(&nonce, &device_id, now).await? {
        return Err(AppError::unauthenticated(
            "nonce already used, expired, or not issued for this device",
        ));
    }

    let tokens = mint_session(&state, &account_id, &device_id).await?;
    metrics::counter!("unissh_auth_verify_total").increment(1);
    audit_observed(&state, "login", &account_id, &device_id).await;
    Ok(Json(tokens))
}

// ---- sessions ----

#[derive(Deserialize)]
struct RefreshReq {
    refresh_token: String,
}

async fn session_refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshReq>,
) -> AppResult<Json<SessionTokens>> {
    let raw = ids::unb64(&req.refresh_token)?;
    // Token layout: session_id(16) || secret(32).
    if raw.len() != 16 + 32 {
        return Err(AppError::unauthenticated("invalid refresh token"));
    }
    let session_id = &raw[..16];
    let refresh_hash = ids::sha256(&raw);
    let session = match state.store.find_session_by_id(session_id).await? {
        Some(s) if s.revoked == 0 => s,
        _ => return Err(AppError::unauthenticated("invalid refresh token")),
    };
    let now = state.now();

    // A LIVE session whose current refresh hash is NOT the presented one means the
    // caller holds a superseded token from an earlier generation — revoke the whole
    // session so the theft dies with it (F9).
    if session.refresh_hash != refresh_hash {
        state.store.revoke_session(&session.session_id).await?;
        return Err(AppError::unauthenticated(
            "refresh token reuse detected; session revoked",
        ));
    }
    if session.refresh_expires <= now {
        return Err(AppError::unauthenticated(
            "refresh token expired or revoked",
        ));
    }
    if !state.store.account_is_active(&session.account_id).await? {
        return Err(AppError::unauthenticated("account is not active"));
    }
    // Rotate access + refresh (new secret under the same session_id).
    let access = ids::random_bytes32();
    let refresh = build_refresh_token(&session.session_id, &ids::random_bytes32());
    let access_expires = now + state.config.session.access_ttl_seconds;
    let refresh_expires = now + state.config.session.refresh_ttl_seconds;
    let rotated = state
        .store
        .rotate_session(
            &session.session_id,
            &refresh_hash,
            &ids::sha256(&access),
            &ids::sha256(&refresh),
            access_expires,
            refresh_expires,
        )
        .await?;
    if rotated != 1 {
        return Err(AppError::unauthenticated(
            "refresh token already used (concurrent or replayed refresh)",
        ));
    }
    Ok(Json(SessionTokens {
        access_token: ids::b64(&access),
        refresh_token: ids::b64(&refresh),
        access_expires,
        refresh_expires,
        session_id: ids::b64(&session.session_id),
    }))
}

async fn session_logout(auth: AuthCtx, State(state): State<AppState>) -> AppResult<StatusCode> {
    state.store.revoke_session(&auth.session.session_id).await?;
    audit_observed(&state, "logout", auth.account_id(), &auth.device.device_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct DeviceRevokeReq {
    device_id: String,
}

async fn device_revoke(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<DeviceRevokeReq>,
) -> AppResult<StatusCode> {
    let target = ids::unb64(&req.device_id)?;
    let dev = state
        .store
        .get_device(&target)
        .await?
        .ok_or_else(|| AppError::not_found("device"))?;
    // owner OR the device owner (§5.3).
    if dev.account_id != auth.account_id() {
        auth.require_owner(&state.store).await?;
    }
    state.store.set_device_status(&target, "revoked").await?;
    state.store.revoke_device_sessions(&target).await?;
    audit_observed(&state, "device_remove", &dev.account_id, &target).await;
    Ok(StatusCode::NO_CONTENT)
}

// ---- keyset (Path A) ----

#[derive(Serialize)]
struct KeysetGetResp {
    keyset_blob: String,
    generation: i64,
}

async fn keyset_get(
    auth: AuthCtx,
    State(state): State<AppState>,
) -> AppResult<Json<KeysetGetResp>> {
    let row = state
        .store
        .get_latest_keyset(auth.account_id())
        .await?
        .ok_or_else(|| AppError::not_found("keyset"))?;
    Ok(Json(KeysetGetResp {
        keyset_blob: ids::b64(&row.keyset_bytes),
        generation: row.generation,
    }))
}

#[derive(Deserialize)]
struct KeysetPutReq {
    keyset_blob: String,
}

#[derive(Serialize)]
struct KeysetPutResp {
    generation: i64,
}

async fn keyset_put(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<KeysetPutReq>,
) -> AppResult<Json<KeysetPutResp>> {
    let blob = ids::unb64(&req.keyset_blob)?;
    let header = crypto::parse_keyset_header(&blob)?;
    let generation = header.generation as i64;
    let acc = auth.account_id();
    // No-downgrade: generation > max of the existing one (§6.4).
    if let Some(maxg) = state.store.keyset_max_generation(acc).await? {
        if generation <= maxg {
            return Err(AppError::conflict(
                "keyset generation must be greater than current",
            ));
        }
    }
    state
        .store
        .put_keyset(
            acc,
            generation,
            &blob,
            &header.ed25519_pub,
            &header.x25519_pub,
            state.now(),
        )
        .await?;
    audit_observed(&state, "keyset_publish", acc, &auth.device.device_id).await;
    Ok(Json(KeysetPutResp { generation }))
}

// ---- PAKE relay (Path B) ----

#[derive(Serialize)]
struct RelayOpenResp {
    channel_id: String,
    expires_at: i64,
}

async fn relay_open(
    auth: AuthCtx,
    State(state): State<AppState>,
) -> AppResult<Json<RelayOpenResp>> {
    let _ = &auth;
    let now = state.now();
    let expires_at = now + state.config.session.relay_ttl_seconds;
    let channel_id = ids::random_id16().to_vec();
    state.store.relay_open(&channel_id, expires_at, now).await?;
    Ok(Json(RelayOpenResp {
        channel_id: ids::b64(&channel_id),
        expires_at,
    }))
}

#[derive(Deserialize)]
struct RelayMsgReq {
    channel_id: String,
    #[serde(default)]
    msg1: Option<String>,
    #[serde(default)]
    msg2: Option<String>,
    #[serde(default)]
    msg3: Option<String>,
}

async fn relay_put_slot(
    state: &AppState,
    req: &RelayMsgReq,
    slot: &str,
    msg_b64: &Option<String>,
) -> AppResult<StatusCode> {
    let channel_id = ids::unb64(&req.channel_id)?;
    let row = state
        .store
        .relay_get(&channel_id)
        .await?
        .ok_or_else(|| AppError::not_found("relay channel"))?;
    if row.expires_at <= state.now() {
        return Err(AppError::gone("relay channel expired"));
    }
    let msg = ids::unb64(
        msg_b64
            .as_deref()
            .ok_or_else(|| AppError::malformed("missing message"))?,
    )?;
    state.store.relay_put(&channel_id, slot, &msg).await?;
    Ok(StatusCode::OK)
}

async fn relay_msg1(
    State(state): State<AppState>,
    Json(req): Json<RelayMsgReq>,
) -> AppResult<StatusCode> {
    relay_put_slot(&state, &req, "msg1", &req.msg1).await
}
async fn relay_msg2(
    State(state): State<AppState>,
    Json(req): Json<RelayMsgReq>,
) -> AppResult<StatusCode> {
    relay_put_slot(&state, &req, "msg2", &req.msg2).await
}
async fn relay_msg3(
    State(state): State<AppState>,
    Json(req): Json<RelayMsgReq>,
) -> AppResult<StatusCode> {
    relay_put_slot(&state, &req, "msg3", &req.msg3).await
}

#[derive(Deserialize)]
struct PollQuery {
    channel_id: String,
    want: String,
}

async fn relay_poll(
    State(state): State<AppState>,
    Query(q): Query<PollQuery>,
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let channel_id = ids::unb64(&q.channel_id)?;
    let row = state
        .store
        .relay_get(&channel_id)
        .await?
        .ok_or_else(|| AppError::not_found("relay channel"))?;
    if row.expires_at <= state.now() {
        return Err(AppError::gone("relay channel expired"));
    }
    let msg = match q.want.as_str() {
        "msg1" => row.msg1,
        "msg2" => row.msg2,
        "msg3" => row.msg3,
        _ => return Err(AppError::malformed("bad want")),
    };
    match msg {
        Some(m) => Ok(Json(serde_json::json!({ q.want.clone(): ids::b64(&m) })).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

// ---- account profile / owner management / device-add (human identifiers, §6.1) ----

#[derive(Deserialize)]
struct ProfileReq {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    handle: Option<String>,
}

/// `POST /v1/account/profile` (Bearer, own account): set display_name/handle.
async fn account_profile(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<ProfileReq>,
) -> AppResult<StatusCode> {
    if let Some(h) = req.handle.as_deref() {
        if state
            .store
            .handle_taken_by_other(h, auth.account_id())
            .await?
        {
            return Err(AppError::conflict("handle already taken"));
        }
    }
    state
        .store
        .update_account_profile(
            auth.account_id(),
            req.display_name.as_deref(),
            req.handle.as_deref(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct AccountInfo {
    account_id: String,
    display_name: Option<String>,
    handle: Option<String>,
    is_owner: bool,
    /// Canonical member-id (Ed25519 keyset) — what grants are issued against.
    member_pubkey: Option<String>,
    /// The member's X25519 key (open metadata) — recipient of the HPKE-wrapped VK.
    x25519_pub: Option<String>,
    status: String,
    device_count: i64,
    /// Self-attested registration (M14): canonical payload + signature (base64).
    reg_payload: Option<String>,
    reg_signature: Option<String>,
}

/// `GET /v1/accounts` (Bearer-owner): list of accounts with human labels, role,
/// member-id and device count.
async fn accounts_list(
    auth: AuthCtx,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    auth.require_owner(&state.store).await?;
    let rows = state.store.list_accounts().await?;
    let accounts: Vec<AccountInfo> = rows
        .into_iter()
        .map(|r| AccountInfo {
            account_id: ids::b64(&r.account_id),
            display_name: r.display_name,
            handle: r.handle,
            is_owner: r.is_owner == 1,
            member_pubkey: r.ed25519_pub.as_deref().map(ids::b64),
            x25519_pub: r.x25519_pub.as_deref().map(ids::b64),
            status: r.status,
            device_count: r.device_count,
            reg_payload: r.reg_payload.as_deref().map(ids::b64),
            reg_signature: r.reg_signature.as_deref().map(ids::b64),
        })
        .collect();
    Ok(Json(serde_json::json!({ "accounts": accounts })))
}

#[derive(Deserialize)]
struct OwnerSetReq {
    account_id: String,
    is_owner: bool,
}

/// `POST /v1/owner/set` (Bearer-owner): grant/revoke instance-owner on an account.
/// A server-trusted authority; does NOT grant decryption. Cannot demote the claim
/// owner or remove the last owner (anti-lockout).
async fn owner_set(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<OwnerSetReq>,
) -> AppResult<StatusCode> {
    auth.require_owner(&state.store).await?;
    let target = ids::unb64(&req.account_id)?;
    let acct = state
        .store
        .get_account_by_id(&target)
        .await?
        .ok_or_else(|| AppError::not_found("account"))?;

    if !req.is_owner {
        // The claim owner is always an owner (anti-lockout, keyed by account_id).
        let inst = state.store.instance().await?;
        if inst.owner_account_id.as_deref() == Some(target.as_slice()) {
            return Err(AppError::forbidden("cannot demote the claim owner"));
        }
        if acct.is_owner == 1 && state.store.owner_count().await? <= 1 {
            return Err(AppError::forbidden("cannot remove the last owner"));
        }
    }

    state.store.set_account_owner(&target, req.is_owner).await?;
    let ev = serde_json::json!({
        "event": if req.is_owner { "owner_grant" } else { "owner_revoke" },
        "account_id": ids::b64(&target), "ts": state.now(),
    });
    state.audit_event(&ev, None).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct DeviceAddResp {
    device_id: String,
}

/// `POST /v1/devices/add` (Bearer, existing device): register another device under
/// the SAME account — it shares the canonical keyset (member-id).
async fn device_add(
    auth: AuthCtx,
    State(state): State<AppState>,
) -> AppResult<(StatusCode, Json<DeviceAddResp>)> {
    let acct = state
        .store
        .get_account_by_id(auth.account_id())
        .await?
        .ok_or_else(|| AppError::not_found("account"))?;
    let ed = acct
        .ed25519_pub
        .ok_or_else(|| AppError::internal("account missing canonical keyset"))?;
    let x = acct
        .x25519_pub
        .ok_or_else(|| AppError::internal("account missing canonical keyset"))?;
    let device_id = ids::random_id16().to_vec();
    state
        .store
        .create_device(auth.account_id(), &device_id, &ed, &x, state.now())
        .await?;
    audit_observed(&state, "device_add", auth.account_id(), &device_id).await;
    Ok((
        StatusCode::CREATED,
        Json(DeviceAddResp {
            device_id: ids::b64(&device_id),
        }),
    ))
}

/// `GET /v1/devices` (Bearer): list the CALLER'S OWN account devices.
async fn devices_list_self(
    auth: AuthCtx,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let rows = state.store.admin_list_devices(auth.account_id()).await?;
    let out: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "device_id": ids::b64(&d.device_id),
                "status": d.status,
                "registered_at": d.registered_at,
                "active_sessions": d.session_count,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "devices": out })))
}
