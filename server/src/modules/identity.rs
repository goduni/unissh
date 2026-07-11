//! backend-identity-auth (spec §5.3/§6): bootstrap, register, invite,
//! invite/redeem, auth challenge/verify, sessions, keyset (Path A), PAKE-relay
//! (Path B). The server verifies self-attested registration + server-auth signatures,
//! and enforces single-use nonce + expiry itself; it does not decrypt the payload.

use crate::crypto::{self, RegistrationPayload, ServerAuthChallenge};
use crate::domain::rbac::Role;
use crate::error::{AppError, AppResult};
use crate::http::extract::{AuthCtx, RawTenantId, TenantCtx};
use crate::ids;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/bootstrap", post(bootstrap))
        .route("/v1/register", post(register))
        .route("/v1/invite", post(invite_issue))
        .route("/v1/invite/redeem", post(invite_redeem))
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
        .route("/v1/admin/set", post(admin_set))
        .route("/v1/devices/add", post(device_add))
        .route("/v1/devices", get(devices_list_self))
}

// ---- helpers ----

fn role_str(role: i64) -> &'static str {
    Role::from_u8(role.clamp(0, 2) as u8)
        .unwrap_or(Role::Viewer)
        .as_str()
}

fn parse_role(s: &str) -> AppResult<i64> {
    match s {
        "viewer" => Ok(0),
        "editor" => Ok(1),
        "admin" => Ok(2),
        _ => Err(AppError::malformed("invalid role")),
    }
}

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
/// session and recognized as reuse of a past generation (F9) — not just the
/// immediately-previous one. The 32-byte secret is what makes the token unguessable.
fn build_refresh_token(session_id: &[u8], secret: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(session_id.len() + 32);
    t.extend_from_slice(session_id);
    t.extend_from_slice(secret);
    t
}

async fn mint_session(
    state: &AppState,
    tid: &[u8],
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
            tid,
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

async fn audit_observed(
    state: &AppState,
    tid: &[u8],
    event: &str,
    account_id: &[u8],
    device_id: &[u8],
) {
    let ev = serde_json::json!({
        "event": event,
        "account_id": ids::b64(account_id),
        "device_id": ids::b64(device_id),
        "ts": state.now(),
    });
    let _ = state
        .store
        .append_audit_server_observed(tid, &ev, None, state.now())
        .await;
}

// ---- bootstrap / register ----

#[derive(Deserialize)]
struct BootstrapReq {
    tenant_bootstrap_token: Option<String>,
    registration_payload: String,
    registration_signature: String,
    tier: Option<String>,
    /// Human identifiers (server-visible metadata): label + unique handle.
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    handle: Option<String>,
}

#[derive(Serialize)]
struct RegisterResp {
    account_id: String,
    device_id: String,
    role: String,
    /// Owns this space (genesis-owner)? Lets a re-attaching client restore the
    /// correct `owned` flag; a new member joining via invite is never the owner.
    owned: bool,
}

async fn bootstrap(
    RawTenantId(tid): RawTenantId,
    State(state): State<AppState>,
    Json(req): Json<BootstrapReq>,
) -> AppResult<(StatusCode, Json<RegisterResp>)> {
    // Three bootstrap authorization paths: (1) global config token, (2) personal
    // enrollment grant (redeemed INSIDE the transaction below — atomically with tenant
    // creation), (3) open registration. Any non-empty secret that does not match the
    // global token is treated as a candidate grant; an invalid one is rejected at
    // CAS-redeem.
    let cfg = &state.config.bootstrap;
    let secret = req.tenant_bootstrap_token.as_deref().unwrap_or("");
    // Constant-time comparison of the global token — no timing oracle.
    let global_match = !cfg.token.is_empty()
        && crate::http::extract::ct_eq(secret.as_bytes(), cfg.token.as_bytes());
    let grant_hash: Option<[u8; 32]> = if global_match {
        None
    } else if !secret.is_empty() {
        // The grant secret is base64(32 random bytes) (like an invite token): decode it,
        // then hash the raw bytes. Invalid base64 → it is not a grant → reject.
        let raw = ids::unb64(secret).map_err(|_| AppError::forbidden("invalid bootstrap token"))?;
        Some(ids::sha256(&raw))
    } else if cfg.allow_open {
        None
    } else {
        return Err(AppError::forbidden(
            "bootstrap disabled (no token configured)",
        ));
    };

    let payload_bytes = ids::unb64(&req.registration_payload)?;
    let payload = RegistrationPayload::parse_canonical(&payload_bytes)?;
    let sig = ids::unb64(&req.registration_signature)?;
    crypto::verify_registration(&payload, &sig)?;

    // Validate the client-requested tier up front; the grant may override it.
    if let Some(t) = req.tier.as_deref() {
        if t != "personal" && t != "org" {
            return Err(AppError::malformed("invalid tier"));
        }
    }

    let now = state.now();
    let account_id = ids::random_id16().to_vec();
    let device_id = ids::random_id16().to_vec();

    // All tenant creation happens in one transaction so that redeeming the grant is
    // atomic with the genesis-CAS: a lost race (or any error) rolls back the grant
    // redeem too.
    let mut tx = state.store.begin().await?;

    // 1. Redeem the grant (if this is the grant path) — before the INSERT, so we know the pinned tier.
    let pinned_tier = match &grant_hash {
        Some(h) => tx.redeem_enrollment_grant_cas(h, &tid, now).await?,
        None => None,
    };
    let tier = pinned_tier
        .as_deref()
        .or(req.tier.as_deref())
        .unwrap_or(&cfg.default_tier);

    // 2. Create the tenant (idempotent) + pin genesis_owner (single winner).
    tx.exec(
        "INSERT INTO tenants (tenant_id, tier, next_seq, created_at, status) \
         VALUES (?, ?, 0, ?, 'active') ON CONFLICT (tenant_id) DO NOTHING",
        vec![
            crate::store::Val::b(&tid[..]),
            crate::store::Val::t(tier),
            crate::store::Val::I(now),
        ],
    )
    .await?;
    let won = tx
        .exec(
            "UPDATE tenants SET genesis_owner_pubkey = ? \
             WHERE tenant_id = ? AND genesis_owner_pubkey IS NULL",
            vec![
                crate::store::Val::B(payload.ed25519_pub.to_vec()),
                crate::store::Val::b(&tid[..]),
            ],
        )
        .await?
        == 1;
    if !won {
        // tx leaves scope without commit → rollback (the grant redeem is undone).
        return Err(AppError::conflict("tenant already bootstrapped"));
    }

    // 3. genesis = the first instance-admin: account (is_admin=1) + device in the same tx.
    tx.create_account(
        &tid,
        &account_id,
        &payload.ed25519_pub,
        &payload.x25519_pub,
        req.display_name.as_deref(),
        req.handle.as_deref(),
        true,
        &payload_bytes,
        &sig,
        now,
    )
    .await?;
    tx.create_device(
        &tid,
        &account_id,
        &device_id,
        &payload.ed25519_pub,
        &payload.x25519_pub,
        now,
    )
    .await?;
    tx.commit().await?;
    audit_observed(&state, &tid, "bootstrap_admin", &account_id, &device_id).await;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResp {
            account_id: ids::b64(&account_id),
            device_id: ids::b64(&device_id),
            role: "admin".into(),
            owned: true, // genesis-owner of the space you just bootstrapped
        }),
    ))
}

#[derive(Deserialize)]
struct RegisterReq {
    invite_token: String,
    registration_payload: String,
    registration_signature: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    handle: Option<String>,
}

async fn register(
    tenant: TenantCtx,
    State(state): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> AppResult<(StatusCode, Json<RegisterResp>)> {
    let tid = tenant.id();
    let payload_bytes = ids::unb64(&req.registration_payload)?;
    let payload = RegistrationPayload::parse_canonical(&payload_bytes)?;
    let sig = ids::unb64(&req.registration_signature)?;
    crypto::verify_registration(&payload, &sig)?;
    let now = state.now();

    // Re-attach path. This keyset (ed25519_pub) already owns an account in this
    // space — a returning member reconnecting a device whose link was removed (or
    // that lost every session). The registration signature we just verified proves
    // possession of the account's ed25519 private key; that IS the credential, so
    // no invite is required. Requiring one would be a lockout trap: a member with
    // no live session anywhere cannot mint an invite. We add a fresh device to the
    // existing account and return ITS id — never a second account (accounts carries
    // a UNIQUE(tenant_id, ed25519_pub), and devices deliberately share the keyset).
    //
    // Replay of a captured (public) registration blob only ever adds an inert
    // device row: authenticating it still needs the ed25519 private key to sign a
    // fresh login challenge, which a replayer does not hold.
    if let Some(acct) = state
        .store
        .get_account_by_ed(tid, &payload.ed25519_pub)
        .await?
    {
        if acct.status != "active" {
            return Err(AppError::forbidden(
                "this identity's account is disabled in this space — ask an admin to re-enable it",
            ));
        }
        let device_id = ids::random_id16().to_vec();
        state
            .store
            .create_device(
                tid,
                &acct.account_id,
                &device_id,
                &payload.ed25519_pub,
                &payload.x25519_pub,
                now,
            )
            .await?;
        audit_observed(&state, tid, "reattach_device", &acct.account_id, &device_id).await;
        // The account row only records instance-admin; the (cosmetic) role echo the
        // client ignores. Admin → admin, otherwise editor.
        let role = if acct.is_admin != 0 { 2 } else { 1 };
        let owned = state
            .store
            .is_genesis_owner(tid, &payload.ed25519_pub)
            .await?;
        return Ok((
            StatusCode::OK,
            Json(RegisterResp {
                account_id: ids::b64(&acct.account_id),
                device_id: ids::b64(&device_id),
                role: role_str(role).into(),
                owned,
            }),
        ));
    }

    // New-member path: joining a space you're NOT part of requires an invite.
    if req.invite_token.is_empty() {
        return Err(AppError::not_found(
            "no account for your identity in this space — joining as a new member needs an invite",
        ));
    }
    let token_raw = ids::unb64(&req.invite_token)?;
    let token_hash = ids::sha256(&token_raw);

    if let Some(h) = req.handle.as_deref() {
        if state.store.handle_taken(tid, h).await? {
            return Err(AppError::conflict("handle already taken"));
        }
    }
    // Atomic: CAS-redeem of the invite (binding the invitee-pubkey) + account/device creation.
    // invite role==Admin(2) → instance-admin immediately (§10).
    let account_id = ids::random_id16().to_vec();
    let device_id = ids::random_id16().to_vec();
    let mut tx = state.store.begin().await?;
    let (role, _scope) = tx
        .redeem_invite_cas(tid, &token_hash, &payload.ed25519_pub, now)
        .await?;
    let is_admin = role == 2;
    // M14: store the self-attested registration verbatim for panel binding check.
    tx.create_account(
        tid,
        &account_id,
        &payload.ed25519_pub,
        &payload.x25519_pub,
        req.display_name.as_deref(),
        req.handle.as_deref(),
        is_admin,
        &payload_bytes,
        &sig,
        now,
    )
    .await?;
    tx.create_device(
        tid,
        &account_id,
        &device_id,
        &payload.ed25519_pub,
        &payload.x25519_pub,
        now,
    )
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResp {
            account_id: ids::b64(&account_id),
            device_id: ids::b64(&device_id),
            role: role_str(role).into(),
            owned: false, // joined via invite — a member, never the space owner
        }),
    ))
}

// ---- invites ----

#[derive(Deserialize)]
struct InviteReq {
    role: String,
    scope: Option<String>,
    ttl_seconds: Option<i64>,
}

#[derive(Serialize)]
struct InviteResp {
    invite_id: String,
    token: String,
    expires_at: i64,
}

async fn invite_issue(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<InviteReq>,
) -> AppResult<(StatusCode, Json<InviteResp>)> {
    auth.require_admin(&state.store).await?;
    let role = parse_role(&req.role)?;
    let now = state.now();
    let ttl = req
        .ttl_seconds
        .unwrap_or(state.config.session.invite_default_ttl_seconds);
    let expires_at = now + ttl;
    let invite_id = ids::random_id16().to_vec();
    let token = ids::random_bytes32();
    let token_hash = ids::sha256(&token);
    state
        .store
        .create_invite(
            auth.tenant_id(),
            &invite_id,
            &token_hash,
            role,
            req.scope.as_deref(),
            expires_at,
            Some(auth.device_ed25519()),
            now,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(InviteResp {
            invite_id: ids::b64(&invite_id),
            token: ids::b64(&token),
            expires_at,
        }),
    ))
}

#[derive(Deserialize)]
struct RedeemReq {
    invite_token: String,
}

#[derive(Serialize)]
struct RedeemResp {
    role: String,
    scope: Option<String>,
}

/// Read-only preview (does NOT consume the slot, §6.2).
async fn invite_redeem(
    tenant: TenantCtx,
    State(state): State<AppState>,
    Json(req): Json<RedeemReq>,
) -> AppResult<Json<RedeemResp>> {
    let token_raw = ids::unb64(&req.invite_token)?;
    let token_hash = ids::sha256(&token_raw);
    let inv = state
        .store
        .get_invite_by_token_hash(tenant.id(), &token_hash)
        .await?
        .ok_or_else(|| AppError::not_found("invite"))?;
    if inv.state != "pending" {
        return Err(AppError::gone("invite already redeemed or revoked"));
    }
    if inv.expires_at <= state.now() {
        return Err(AppError::gone("invite expired"));
    }
    Ok(Json(RedeemResp {
        role: role_str(inv.role).into(),
        scope: inv.scope,
    }))
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
    tenant: TenantCtx,
    State(state): State<AppState>,
    Json(req): Json<ChallengeReq>,
) -> AppResult<Json<ChallengeJson>> {
    let tid = tenant.id().to_vec();
    let device_id = ids::unb64(&req.device_id)?;
    // The device must exist (the challenge is addressed).
    let _device = state
        .store
        .get_device(&tid, &device_id)
        .await?
        .ok_or_else(|| AppError::not_found("device"))?;

    let nonce = ids::random_bytes32();
    let now = state.now();
    let expiry = (now + state.config.session.nonce_ttl_seconds) as u64;
    state
        .store
        .insert_nonce(&tid, &nonce, Some(&device_id), expiry as i64)
        .await?;

    Ok(Json(ChallengeJson {
        host: ids::b64(&tid),
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
    tenant: TenantCtx,
    State(state): State<AppState>,
    Json(req): Json<VerifyReq>,
) -> AppResult<Json<SessionTokens>> {
    let tid = tenant.id().to_vec();
    let c = &req.challenge;
    let now = state.now();

    if c.expiry <= now as u64 {
        return Err(AppError::unauthenticated("challenge expired"));
    }
    let account_id = ids::unb64(&c.account_id)?;
    let device_id = ids::unb64(&c.device_id)?;
    let nonce = ids::unb64(&c.nonce)?;

    // host must match the server-issued one (= base64(tenant_id)) — the challenge
    // is bound to this instance/tenant (§5.3 step 3).
    if ids::unb64(&c.host)? != tid {
        return Err(AppError::unauthenticated("challenge host mismatch"));
    }

    // The device is active and belongs to the claimed account.
    let device = state
        .store
        .get_device(&tid, &device_id)
        .await?
        .ok_or_else(|| AppError::unauthenticated("device not found"))?;
    if device.status != "active" {
        return Err(AppError::unauthenticated("device not active"));
    }
    if device.account_id != account_id {
        return Err(AppError::unauthenticated("device/account mismatch"));
    }
    if !state.store.account_is_active(&tid, &account_id).await? {
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
    if !state
        .store
        .consume_nonce(&tid, &nonce, &device_id, now)
        .await?
    {
        return Err(AppError::unauthenticated(
            "nonce already used, expired, or not issued for this device",
        ));
    }

    let tokens = mint_session(&state, &tid, &account_id, &device_id).await?;
    metrics::counter!("unissh_auth_verify_total").increment(1);
    audit_observed(&state, &tid, "login", &account_id, &device_id).await;
    Ok(Json(tokens))
}

// ---- sessions ----

#[derive(Deserialize)]
struct RefreshReq {
    refresh_token: String,
}

async fn session_refresh(
    tenant: TenantCtx,
    State(state): State<AppState>,
    Json(req): Json<RefreshReq>,
) -> AppResult<Json<SessionTokens>> {
    let tid = tenant.id();
    let raw = ids::unb64(&req.refresh_token)?;
    // Token layout: session_id(16) || secret(32). We look the session up by its
    // embedded id (not by hash) so a token whose hash matches no live row can STILL
    // be attributed to its session and recognized as reuse of a past generation.
    if raw.len() != 16 + 32 {
        return Err(AppError::unauthenticated("invalid refresh token"));
    }
    let session_id = &raw[..16];
    let refresh_hash = ids::sha256(&raw);
    let session = match state.store.find_session_by_id(tid, session_id).await? {
        Some(s) if s.revoked == 0 => s,
        // Unknown session, or one already revoked (e.g. by an earlier reuse): nothing
        // to rotate.
        _ => return Err(AppError::unauthenticated("invalid refresh token")),
    };
    let now = state.now();

    // A LIVE session whose current refresh hash is NOT the presented one means the
    // caller holds a superseded token from an earlier generation — only a stolen
    // lineage does that. Revoke the whole session so the theft dies with it (F9:
    // catches ANY past generation, not just the immediately-previous token). The
    // benign concurrent/replay race — two requests carrying the SAME still-live
    // token — is handled by the rotate CAS below, which fails the loser WITHOUT
    // revoking, so a legit double-submit cannot trip this.
    if session.refresh_hash != refresh_hash {
        state.store.revoke_session(tid, &session.session_id).await?;
        return Err(AppError::unauthenticated(
            "refresh token reuse detected; session revoked",
        ));
    }
    if session.refresh_expires <= now {
        return Err(AppError::unauthenticated(
            "refresh token expired or revoked",
        ));
    }
    // Do not extend access for a disabled account: AuthCtx blocks it on every
    // request, but without this check a disabled account could rotate tokens
    // indefinitely (needless persistence for a compromised device).
    if !state
        .store
        .account_is_active(tid, &session.account_id)
        .await?
    {
        return Err(AppError::unauthenticated("account is not active"));
    }
    // Rotate access + refresh (new secret under the same session_id).
    let access = ids::random_bytes32();
    let refresh = build_refresh_token(&session.session_id, &ids::random_bytes32());
    let access_expires = now + state.config.session.access_ttl_seconds;
    let refresh_expires = now + state.config.session.refresh_ttl_seconds;
    // CAS on the old refresh-hash: exactly one of the concurrent/repeated rotations
    // with the same token will change the row; 0 rows ⇒ the token was already rotated
    // (race/replay) — reject WITHOUT revoking (a legitimate double-submit must not kill
    // the session).
    let rotated = state
        .store
        .rotate_session(
            tid,
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
    state
        .store
        .revoke_session(auth.tenant_id(), &auth.session.session_id)
        .await?;
    audit_observed(
        &state,
        auth.tenant_id(),
        "logout",
        auth.account_id(),
        &auth.device.device_id,
    )
    .await;
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
    let tid = auth.tenant_id();
    let target = ids::unb64(&req.device_id)?;
    let dev = state
        .store
        .get_device(tid, &target)
        .await?
        .ok_or_else(|| AppError::not_found("device"))?;
    // admin OR the device owner (§5.3).
    if dev.account_id != auth.account_id() {
        auth.require_admin(&state.store).await?;
    }
    state
        .store
        .set_device_status(tid, &target, "revoked")
        .await?;
    state.store.revoke_device_sessions(tid, &target).await?;
    audit_observed(&state, tid, "device_remove", &dev.account_id, &target).await;
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
        .get_latest_keyset(auth.tenant_id(), auth.account_id())
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
    let tid = auth.tenant_id();
    let acc = auth.account_id();
    // No-downgrade: generation > max of the existing one (§6.4).
    if let Some(maxg) = state.store.keyset_max_generation(tid, acc).await? {
        if generation <= maxg {
            return Err(AppError::conflict(
                "keyset generation must be greater than current",
            ));
        }
    }
    state
        .store
        .put_keyset(
            tid,
            acc,
            generation,
            &blob,
            &header.ed25519_pub,
            &header.x25519_pub,
            state.now(),
        )
        .await?;
    audit_observed(&state, tid, "keyset_publish", acc, &auth.device.device_id).await;
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
    let now = state.now();
    let expires_at = now + state.config.session.relay_ttl_seconds;
    let channel_id = ids::random_id16().to_vec();
    state
        .store
        .relay_open(auth.tenant_id(), &channel_id, expires_at, now)
        .await?;
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
    tid: &[u8],
    req: &RelayMsgReq,
    slot: &str,
    msg_b64: &Option<String>,
) -> AppResult<StatusCode> {
    let channel_id = ids::unb64(&req.channel_id)?;
    let row = state
        .store
        .relay_get(tid, &channel_id)
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
    state.store.relay_put(tid, &channel_id, slot, &msg).await?;
    Ok(StatusCode::OK)
}

async fn relay_msg1(
    tenant: TenantCtx,
    State(state): State<AppState>,
    Json(req): Json<RelayMsgReq>,
) -> AppResult<StatusCode> {
    relay_put_slot(&state, tenant.id(), &req, "msg1", &req.msg1).await
}
async fn relay_msg2(
    tenant: TenantCtx,
    State(state): State<AppState>,
    Json(req): Json<RelayMsgReq>,
) -> AppResult<StatusCode> {
    relay_put_slot(&state, tenant.id(), &req, "msg2", &req.msg2).await
}
async fn relay_msg3(
    tenant: TenantCtx,
    State(state): State<AppState>,
    Json(req): Json<RelayMsgReq>,
) -> AppResult<StatusCode> {
    let r = relay_put_slot(&state, tenant.id(), &req, "msg3", &req.msg3).await?;
    Ok(r)
}

#[derive(Deserialize)]
struct PollQuery {
    channel_id: String,
    want: String,
}

async fn relay_poll(
    tenant: TenantCtx,
    State(state): State<AppState>,
    Query(q): Query<PollQuery>,
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let channel_id = ids::unb64(&q.channel_id)?;
    let row = state
        .store
        .relay_get(tenant.id(), &channel_id)
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

// ---- account profile / admin management / device-add (human identifiers, §6.1) ----

#[derive(Deserialize)]
struct ProfileReq {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    handle: Option<String>,
}

/// `POST /v1/account/profile` (Bearer, own account): set display_name/handle.
/// This is SERVER-VISIBLE metadata (like the member-set) — a private deployment puts a pseudonym.
async fn account_profile(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<ProfileReq>,
) -> AppResult<StatusCode> {
    if let Some(h) = req.handle.as_deref() {
        if state
            .store
            .handle_taken_by_other(auth.tenant_id(), h, auth.account_id())
            .await?
        {
            return Err(AppError::conflict("handle already taken"));
        }
    }
    state
        .store
        .update_account_profile(
            auth.tenant_id(),
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
    is_admin: bool,
    /// Canonical member-id (Ed25519 keyset) — what grants are issued against.
    member_pubkey: Option<String>,
    /// The member's X25519 key (open metadata) — the recipient of the HPKE-wrapped VK
    /// during grant rotation (`/v1/grants/publish`). The ZK boundary is not violated.
    x25519_pub: Option<String>,
    status: String,
    device_count: i64,
    /// Self-attested registration (M14): canonical payload + signature (base64).
    /// The panel verifies x25519<->ed25519 binding with these; NULL for pre-M14
    /// accounts (treated as unverifiable/legacy, not failed).
    reg_payload: Option<String>,
    reg_signature: Option<String>,
}

/// `GET /v1/accounts` (Bearer-admin): list of accounts with human labels,
/// role, member-id and device count. This is exactly "recognizing Vasya/John/Igor".
async fn accounts_list(
    auth: AuthCtx,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    auth.require_admin(&state.store).await?;
    let rows = state.store.list_accounts(auth.tenant_id()).await?;
    let accounts: Vec<AccountInfo> = rows
        .into_iter()
        .map(|r| AccountInfo {
            account_id: ids::b64(&r.account_id),
            display_name: r.display_name,
            handle: r.handle,
            is_admin: r.is_admin == 1,
            member_pubkey: r.ed25519_pub.as_deref().map(ids::b64),
            x25519_pub: r.x25519_pub.as_deref().map(ids::b64),
            status: r.status,
            device_count: r.device_count,
            reg_payload: r.reg_payload.as_deref().map(ids::b64),
            reg_signature: r.reg_signature.as_deref().map(ids::b64),
        })
        .collect();
    // Expose the pinned genesis owner so the admin panel can TOFU-pin it and verify
    // a /v1/grants manifest's signature against it before trusting its member set
    // for rotation (defends the panel against an injected, unverified member set).
    let genesis_owner = state
        .store
        .get_tenant(auth.tenant_id())
        .await?
        .and_then(|t| t.genesis_owner_pubkey)
        .map(|p| ids::b64(&p));
    Ok(Json(serde_json::json!({
        "accounts": accounts,
        "genesis_owner": genesis_owner,
    })))
}

#[derive(Deserialize)]
struct AdminSetReq {
    account_id: String,
    is_admin: bool,
}

/// `POST /v1/admin/set` (Bearer-admin): grant/revoke instance-admin on an account.
/// A server-trusted authority (invite/audit/device-revoke/grants-publish), it does NOT
/// grant decryption. Cannot be removed from genesis or from the last admin (anti-lockout).
async fn admin_set(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<AdminSetReq>,
) -> AppResult<StatusCode> {
    auth.require_admin(&state.store).await?;
    let target = ids::unb64(&req.account_id)?;
    let acct = state
        .store
        .get_account_by_id(auth.tenant_id(), &target)
        .await?
        .ok_or_else(|| AppError::not_found("account"))?;

    if !req.is_admin {
        // genesis is always admin
        let tenant = state
            .store
            .get_tenant(auth.tenant_id())
            .await?
            .ok_or_else(|| AppError::not_found("tenant"))?;
        if tenant.genesis_owner_pubkey.is_some()
            && tenant.genesis_owner_pubkey.as_deref() == acct.ed25519_pub.as_deref()
        {
            return Err(AppError::forbidden("cannot demote the genesis admin"));
        }
        if acct.is_admin == 1 && state.store.admin_count(auth.tenant_id()).await? <= 1 {
            return Err(AppError::forbidden("cannot remove the last admin"));
        }
    }

    state
        .store
        .set_account_admin(auth.tenant_id(), &target, req.is_admin)
        .await?;
    let ev = serde_json::json!({
        "event": if req.is_admin { "admin_grant" } else { "admin_revoke" },
        "account_id": ids::b64(&target), "ts": state.now(),
    });
    let _ = state
        .store
        .append_audit_server_observed(auth.tenant_id(), &ev, None, state.now())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct DeviceAddResp {
    device_id: String,
}

/// `POST /v1/devices/add` (Bearer, existing device): register another
/// device under the SAME account — it shares the canonical keyset (member-id).
/// Authorizes an already-authenticated device; the new device then
/// authenticates with this device_id by signing the challenge with the keyset key (which it
/// has after Path A/B). A grant on the account automatically covers the new device.
async fn device_add(
    auth: AuthCtx,
    State(state): State<AppState>,
) -> AppResult<(StatusCode, Json<DeviceAddResp>)> {
    let acct = state
        .store
        .get_account_by_id(auth.tenant_id(), auth.account_id())
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
        .create_device(
            auth.tenant_id(),
            auth.account_id(),
            &device_id,
            &ed,
            &x,
            state.now(),
        )
        .await?;
    audit_observed(
        &state,
        auth.tenant_id(),
        "device_add",
        auth.account_id(),
        &device_id,
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(DeviceAddResp {
            device_id: ids::b64(&device_id),
        }),
    ))
}

/// `GET /v1/devices` (Bearer): list the CALLER'S OWN account devices. Self-service
/// equivalent of the admin-only `/v1/admin/devices` (same row shape) so a user can
/// see and revoke their own siblings without being an instance-admin.
async fn devices_list_self(
    auth: AuthCtx,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let rows = state
        .store
        .admin_list_devices(auth.tenant_id(), auth.account_id())
        .await?;
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
