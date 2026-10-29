//! Tauri commands for cloud server integration: identity, session, devices.
//!
//! An instance may be linked to MULTIPLE cloud servers. Every command takes an
//! optional `server_id`; when omitted it resolves to the *active* server, so the
//! single-server call sites keep working unchanged. State (config sidecar,
//! in-memory access token, keychain refresh token) is keyed per server.
//!
//! Every command offloads the blocking HTTP + core-signing work onto a blocking
//! thread (`spawn_blocking`); state mutations happen on the async side after the
//! call returns.

use std::sync::Arc;

use tauri::State;
use tauri_plugin_opener::OpenerExt;
use uuid::Uuid;

use crate::cloud::config::{new_server_id, ServerConfig, SpaceEntry};
use crate::cloud::transport::HttpSyncTransport;
use crate::cloud::{client, identity, oidc, onboard, shared, tokens, ServerList, ServerStatus};
use crate::dto;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Run a blocking closure that itself returns `ApiResult` off the async runtime.
async fn blocking_api<T, F>(f: F) -> ApiResult<T>
where
    F: FnOnce() -> ApiResult<T> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f).await?
}

/// Persist the (rotated) refresh token for a server, surfacing a keychain failure
/// to the log instead of silently dropping it — losing it forces a later re-login.
/// Only the error kind and server id are logged, never the token itself.
fn persist_refresh(server_id: &str, token: &str) {
    if let Err(e) = tokens::save_refresh(server_id, token) {
        log::warn!("cloud: failed to persist refresh token in keychain (server {server_id}): {e}");
    }
}

/// Resolve the target server's config (defaults to the active server).
fn require_config(state: &AppState, server_id: Option<&str>) -> ApiResult<ServerConfig> {
    state
        .cloud
        .config_for(server_id)?
        .ok_or_else(|| ApiError::Server {
            code: "not_connected".into(),
            message: "no server is linked".into(),
        })
}

/// Resolve the target server's in-memory access token (defaults to active).
fn require_access(state: &AppState, server_id: Option<&str>) -> ApiResult<String> {
    state
        .cloud
        .access_token_for(server_id)?
        .ok_or_else(|| ApiError::Server {
            code: "unauthenticated".into(),
            message: "no active session — sign in to the server".into(),
        })
}

/// Best-effort refresh of a server's cached space list (`ServerStatus.spaces`) from
/// `GET /v1/spaces` (needs a live session). Called after a session is (re)established
/// — claim/join/login/refresh/onboard — so the subsequent status snapshot names the
/// caller's spaces without a separate round-trip. A failure (or no session) is
/// swallowed: the snapshot just keeps the prior/empty list rather than failing the
/// otherwise-successful login.
async fn refresh_spaces_cache(state: &AppState, server_id: &str) {
    if let Err(e) = try_refresh_spaces_cache(state, server_id).await {
        log::debug!("cloud: space list refresh skipped for server {server_id}: {e:?}");
    }
}

/// Body of [`refresh_spaces_cache`]; no linked config or no session is `Ok`.
async fn try_refresh_spaces_cache(state: &AppState, server_id: &str) -> ApiResult<()> {
    let (Some(cfg), Some(access)) = (
        state.cloud.config_for(Some(server_id))?,
        state.cloud.access_token_for(Some(server_id))?,
    ) else {
        return Ok(());
    };
    let base_url = cfg.base_url;
    let spaces = blocking_api(move || {
        let http = client::http();
        identity::list_spaces(http, &base_url, &access).map_err(ApiError::from)
    })
    .await?;
    let entries = spaces
        .into_iter()
        .map(|s| SpaceEntry {
            space_id: s.space_id,
            name: s.name,
            role: s.role,
        })
        .collect();
    state.cloud.set_spaces_for(Some(server_id), Some(entries))
}

/// Best-effort server-side logout before a link or session is dropped locally.
/// The local drop happens either way, so a failure (offline server, expired
/// session) is only logged; the server-side session then expires on its own.
async fn best_effort_logout(cfg: ServerConfig, access: String) {
    let sid = cfg.server_id.clone();
    let result = blocking_api(move || {
        let http = client::http();
        identity::logout(http, &cfg.base_url, &access).map_err(ApiError::from)
    })
    .await;
    if let Err(e) = result {
        log::debug!("cloud: best-effort logout failed for server {sid}: {e:?}");
    }
}

/// Best-effort server-side goodbye before a link is forgotten: this device is
/// revoked, its sessions with it. Nothing here can sign in as it again once its
/// id is forgotten, and an active device left behind would only clutter the
/// account's Devices list. A server that will not revoke still gets the logout.
async fn best_effort_leave(cfg: ServerConfig, access: String) {
    let sid = cfg.server_id.clone();
    let result = blocking_api(move || {
        let http = client::http();
        identity::device_revoke(http, &cfg.base_url, &access, &cfg.device_id)
            .or_else(|_| identity::logout(http, &cfg.base_url, &access))
            .map_err(ApiError::from)
    })
    .await;
    if let Err(e) = result {
        log::debug!("cloud: best-effort device revoke failed for server {sid}: {e:?}");
    }
}

/// A session to say goodbye with: the one in memory, else a fresh one from the
/// stored refresh token, since a link not used since the app started has none
/// in memory. None when neither works: the goodbye is best effort.
async fn goodbye_access(state: &AppState, cfg: &ServerConfig) -> Option<String> {
    if let Ok(Some(access)) = state.cloud.access_token_for(Some(&cfg.server_id)) {
        return Some(access);
    }
    let refresh_token = tokens::load_refresh(&cfg.server_id)?;
    let base = cfg.base_url.clone();
    let session = blocking_api(move || {
        identity::refresh(client::http(), &base, &refresh_token).map_err(ApiError::from)
    })
    .await
    .ok()?;
    persist_refresh(&cfg.server_id, &session.refresh_token);
    Some(session.access_token)
}

/// Saves a link, returning the device it held before when the new config names
/// another one. Signing in again on a linked server enrolls a fresh device (an
/// SSO reassertion, escrow, a new pairing, a repeat join), and the link then
/// forgets the old one.
fn upsert_link(state: &AppState, cfg: ServerConfig) -> ApiResult<Option<String>> {
    let replaced = state
        .cloud
        .config_for(Some(&cfg.server_id))?
        .map(|old| old.device_id)
        .filter(|old| *old != cfg.device_id);
    state.cloud.upsert_config(cfg)?;
    Ok(replaced)
}

/// Best effort, once the new device is signed in: revokes the device a sign-in
/// replaced on this link, with the new session (the same account's). Nothing
/// could sign in as it again, and left active it would sit in the account's
/// Devices list for good.
async fn retire_replaced_device(state: &AppState, server_id: &str, replaced: Option<String>) {
    let Some(old) = replaced else { return };
    let (Ok(Some(cfg)), Ok(Some(access))) = (
        state.cloud.config_for(Some(server_id)),
        state.cloud.access_token_for(Some(server_id)),
    ) else {
        return;
    };
    let result = blocking_api(move || {
        identity::device_revoke(client::http(), &cfg.base_url, &access, &old)
            .map_err(ApiError::from)
    })
    .await;
    if let Err(e) = result {
        log::debug!("cloud: could not revoke the replaced device on server {server_id}: {e:?}");
    }
}

/// Status of one server (defaults to the active server).
#[tauri::command]
pub async fn server_status(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    state.cloud.status_for(server_id.as_deref())
}

/// Public, session-less probe of a server instance (`GET /v1/instance`): its name,
/// whether it has been claimed, its opaque instance id, version, and advertised
/// sign-in methods. Drives the Add-server flow's setup-code-vs-join branch. Needs no
/// session — just a base URL (mirrors `server_join_preview`).
#[tauri::command]
pub async fn server_instance_info(base_url: String) -> ApiResult<dto::InstanceInfoDto> {
    client::validate_base_url(&base_url)?;
    blocking_api(move || {
        let http = client::http();
        let info = identity::instance_info(http, &base_url)?;
        Ok(dto::InstanceInfoDto {
            claimed: info.claimed,
            // Server-facing `name` is optional; the frontend field is a plain string.
            name: info.name.unwrap_or_default(),
            version: info.version,
            instance_id: info.instance_id,
            auth: info.auth,
            oidc: info.oidc.map(|o| dto::OidcInfoDto {
                issuer: o.issuer,
                client_id: o.client_id,
            }),
        })
    })
    .await
}

/// The full list of linked servers + the active id.
#[tauri::command]
pub async fn server_list(state: State<'_, AppState>) -> ApiResult<ServerList> {
    state.cloud.list()
}

/// Switch the active server (the one argument-less commands resolve to).
#[tauri::command]
pub async fn server_set_active(
    server_id: String,
    state: State<'_, AppState>,
) -> ApiResult<ServerList> {
    state.cloud.set_active(&server_id)?;
    state.cloud.list()
}

/// Forget ONE server link (config entry + tokens) after revoking this device on
/// it (best effort). Other servers are untouched. Returns the updated list.
#[tauri::command]
pub async fn server_remove(server_id: String, state: State<'_, AppState>) -> ApiResult<ServerList> {
    // Space of the server being removed — to unbind its cloud vaults so they
    // aren't left orphaned pointing at a now-gone server (they become reclaimable
    // via re-link or manual bind).
    let removed_space = state
        .cloud
        .config_for(Some(&server_id))?
        .map(|c| c.space_id);
    if let Some(cfg) = state.cloud.config_for(Some(&server_id))? {
        if let Some(access) = goodbye_access(&state, &cfg).await {
            best_effort_leave(cfg, access).await;
        }
    }
    state.cloud.remove(&server_id)?;
    if let Some(space) = removed_space {
        let core = state.core.clone();
        let unbound = blocking_api(move || {
            core.clear_cloud_vault_binding(space)
                .map_err(ApiError::from)
        })
        .await;
        if let Err(e) = unbound {
            // The link is already gone; its vaults stay bound to the old space
            // until re-linked or rebound by hand, which the UI still offers.
            log::warn!("cloud: failed to unbind vaults of removed server {server_id}: {e:?}");
        }
    }
    state.cloud.list()
}

/// Join an instance with an invite token. Learns the instance id (`GET /v1/instance`),
/// redeems the invite (`POST /v1/join`), logs in, then appends a new server link,
/// makes it active, and returns its status. The primary granted space is stored as
/// the cloud-vault binding label (a full multi-space model lands in a later task).
#[tauri::command]
pub async fn server_join(
    base_url: String,
    invite_token: String,
    display_name: Option<String>,
    handle: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    client::validate_base_url(&base_url)?;
    let core = state.core.clone();
    let base = base_url.clone();
    let dn = display_name;
    let hd = handle.clone();

    // Redeem the invite. This is IRREVERSIBLE — the single-use token is consumed and
    // the account + device are created server-side. Deliberately NOT coupled with the
    // follow-up login: a transient login failure must still leave a persisted link so
    // the user can retry (a re-join would 409 on the now-redeemed invite).
    let (outcome, instance) = blocking_api(move || {
        let http = client::http();
        // The join response carries only account/device/spaces; the opaque
        // instance id (link identity) comes from the public instance descriptor.
        let instance = identity::instance_info(http, &base)?;
        let reg = core.build_registration_request().map_err(ApiError::from)?;
        // `binding_mac` is None for now — the server accepts a join without the
        // optional invite-binding proof; wiring the MAC is a later concern.
        let outcome = identity::join(http, &base, &invite_token, reg, None, dn, hd)?;
        Ok((outcome, instance))
    })
    .await?;

    // Persist the link IMMEDIATELY after the irreversible join, BEFORE login, so a
    // transient login failure leaves a recoverable ServerConfig (the Settings "Sign
    // in" branch → server_login retries against it). Bind cloud vaults on this link
    // to the primary granted space (first entry). Idempotent: re-joining the same
    // server (same base_url + instance + account) reuses its existing link id (via
    // find_by_identity) instead of minting a duplicate.
    let space_id = outcome.spaces.first().cloned().unwrap_or_default();
    let server_id = state
        .cloud
        .find_by_identity(&base_url, &instance.instance_id, &outcome.account_id)?
        .unwrap_or_else(new_server_id);
    let account_id = outcome.account_id;
    let device_id = outcome.device_id;
    let replaced = upsert_link(
        &state,
        ServerConfig {
            server_id: server_id.clone(),
            base_url: base_url.clone(),
            instance_id: instance.instance_id,
            space_id,
            account_id: account_id.clone(),
            device_id: device_id.clone(),
            handle,
            // Joiners are never instance owners.
            owned: false,
        },
    )?;

    // Log in. A failure here is now recoverable — the link above is persisted, so
    // server_login (the "Sign in" recovery branch) can re-authenticate against it.
    let core = state.core.clone();
    let session = blocking_api(move || {
        let http = client::http();
        identity::login(http, &base_url, &core, &account_id, &device_id).map_err(ApiError::from)
    })
    .await?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token))?;
    persist_refresh(&server_id, &session.refresh_token);
    retire_replaced_device(&state, &server_id, replaced).await;
    refresh_spaces_cache(&state, &server_id).await;
    state.cloud.status_for(Some(&server_id))
}

/// Claim an unclaimed instance and become its owner. The `setup_code` (printed by
/// the server on first boot) authorizes the single-winner claim; the server creates
/// the owner account + device + a first space and returns their ids. Logs in and
/// links the server (active). A claimed instance returns 409.
#[tauri::command]
pub async fn server_claim(
    base_url: String,
    setup_code: String,
    space_name: Option<String>,
    handle: Option<String>,
    display_name: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    client::validate_base_url(&base_url)?;
    let core = state.core.clone();
    let base = base_url.clone();
    let code = setup_code;
    let dn = display_name;
    let hd = handle.clone();
    let sn = space_name;

    // Claim the instance. This is IRREVERSIBLE — the single-use setup code is consumed
    // and the owner account + device + first space are created server-side (a re-claim
    // returns 409). Deliberately NOT coupled with the follow-up login: a transient login
    // failure must still leave a persisted link so the user can retry.
    let outcome = blocking_api(move || {
        let http = client::http();
        let reg = core.build_registration_request().map_err(ApiError::from)?;
        identity::claim(http, &base, &code, reg, dn, hd, sn).map_err(ApiError::from)
    })
    .await?;

    // Persist the link IMMEDIATELY after the irreversible claim, BEFORE login, so a
    // transient login failure leaves a recoverable ServerConfig (the Settings "Sign
    // in" branch → server_login retries against it). Idempotent: a retry reuses the
    // existing link id (via find_by_identity) rather than minting a duplicate.
    let server_id = state
        .cloud
        .find_by_identity(&base_url, &outcome.instance_id, &outcome.account_id)?
        .unwrap_or_else(new_server_id);
    let account_id = outcome.account_id;
    let device_id = outcome.device_id;
    state.cloud.upsert_config(ServerConfig {
        server_id: server_id.clone(),
        base_url: base_url.clone(),
        instance_id: outcome.instance_id,
        space_id: outcome.space_id,
        account_id: account_id.clone(),
        device_id: device_id.clone(),
        handle,
        owned: true, // you claimed it → your instance + first Space (owner)
    })?;

    // Log in. A failure here is now recoverable — the link above is persisted, so
    // server_login (the "Sign in" recovery branch) can re-authenticate against it.
    let core = state.core.clone();
    let session = blocking_api(move || {
        let http = client::http();
        identity::login(http, &base_url, &core, &account_id, &device_id).map_err(ApiError::from)
    })
    .await?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token))?;
    persist_refresh(&server_id, &session.refresh_token);
    refresh_spaces_cache(&state, &server_id).await;
    state.cloud.status_for(Some(&server_id))
}

/// Sign in with SSO (OIDC Authorization Code + PKCE). Probes the instance (SSO must be
/// enabled; learns issuer + client_id), resolves the IdP endpoints via discovery,
/// opens the system browser to the authorize URL with `nonce = Core::oidc_nonce()`
/// (the keyset key-binding), catches the `?code=` redirect on a localhost loopback
/// listener, exchanges the code for an `id_token`, and presents it + the self-attested
/// keyset registration to `POST /v1/oidc/callback`. The server mints the session and
/// (for a fresh SSO identity) provisions the account; on return the link is stored and
/// made active. Requires the local keyset to be unlocked (it signs the registration and
/// derives the nonce) — same precondition as claim/join.
///
/// MANUAL-TEST NOTE: the browser↔IdP hop needs a real IdP + browser and cannot be
/// exercised in CI. The server side is proven by `oidc_http` (Task 4).
#[tauri::command]
pub async fn server_oidc_login(
    base_url: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    client::validate_base_url(&base_url)?;
    let core = state.core.clone();
    let base = base_url.clone();

    let (instance, outcome, session) = blocking_api(move || {
        let http = client::http();
        // 1. Probe: SSO must be enabled, and the instance must advertise its IdP.
        let instance = identity::instance_info(http, &base)?;
        if !instance.auth.iter().any(|a| a == "oidc") {
            return Err(ApiError::other("this server does not offer SSO sign-in"));
        }
        let oidc_info = instance.oidc.clone().ok_or_else(|| {
            ApiError::other(
                "the server advertises SSO but did not expose its OIDC issuer/client_id",
            )
        })?;

        // 2. Resolve the IdP authorize/token endpoints from its discovery document.
        let endpoints = oidc::discover(http, &oidc_info.issuer)?;

        // 3. Keyset key-binding nonce (requires an unlocked local keyset).
        let nonce = core.oidc_nonce().map_err(ApiError::from)?;

        // 4. PKCE + CSRF state + a loopback redirect target.
        let (verifier, challenge) = oidc::pkce();
        let state_param = oidc::random_state();
        let (listener, redirect_uri) = oidc::bind_loopback()?;

        // 5. Open the system browser to the authorize URL, then catch the redirect.
        let authorize_url = oidc::build_authorize_url(
            &endpoints.authorization_endpoint,
            &oidc_info.client_id,
            &redirect_uri,
            &state_param,
            &nonce,
            &challenge,
        );
        app.opener()
            .open_url(authorize_url, None::<&str>)
            .map_err(|e| ApiError::other(format!("failed to open the system browser: {e}")))?;
        let code = oidc::wait_for_redirect(listener, &state_param)?;

        // 6. Exchange the code for the IdP-signed id_token, then run the callback.
        let id_token = oidc::exchange_code(
            http,
            &endpoints.token_endpoint,
            &oidc_info.client_id,
            &code,
            &verifier,
            &redirect_uri,
        )?;
        let reg = core.build_registration_request().map_err(ApiError::from)?;
        let (outcome, session) = identity::oidc_callback(http, &base, &id_token, reg)?;
        Ok((instance, outcome, session))
    })
    .await?;

    // Bind cloud vaults on this link to the primary granted space (first entry),
    // mirroring server_join. Idempotent: re-signing-in reuses the existing link id.
    let space_id = outcome.spaces.first().cloned().unwrap_or_default();
    let server_id = state
        .cloud
        .find_by_identity(&base_url, &instance.instance_id, &outcome.account_id)?
        .unwrap_or_else(new_server_id);
    let replaced = upsert_link(
        &state,
        ServerConfig {
            server_id: server_id.clone(),
            base_url,
            instance_id: instance.instance_id,
            space_id,
            account_id: outcome.account_id,
            device_id: outcome.device_id,
            handle: None,
            // SSO sign-in never confers instance ownership.
            owned: false,
        },
    )?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token))?;
    persist_refresh(&server_id, &session.refresh_token);
    // Every SSO sign-in, reassertion included, enrolls a fresh device.
    retire_replaced_device(&state, &server_id, replaced).await;
    refresh_spaces_cache(&state, &server_id).await;
    state.cloud.status_for(Some(&server_id))
}

/// Re-authenticate using a stored config (e.g. on app boot). Requires the core
/// to be unlocked (the keyset signs the challenge). Defaults to the active server.
#[tauri::command]
pub async fn server_login(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let sid = cfg.server_id.clone();
    let core = state.core.clone();
    let session = blocking_api(move || {
        let http = client::http();
        identity::login(http, &cfg.base_url, &core, &cfg.account_id, &cfg.device_id)
            .map_err(ApiError::from)
    })
    .await?;
    state
        .cloud
        .set_access_token_for(Some(&sid), Some(session.access_token))?;
    persist_refresh(&sid, &session.refresh_token);
    refresh_spaces_cache(&state, &sid).await;
    state.cloud.status_for(Some(&sid))
}

/// Rotate tokens via the stored refresh token (no keyset needed). Defaults to active.
#[tauri::command]
pub async fn server_refresh_session(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let sid = cfg.server_id.clone();
    let refresh_token = tokens::load_refresh(&sid).ok_or_else(|| ApiError::Server {
        code: "unauthenticated".into(),
        message: "no refresh token stored".into(),
    })?;
    let session = blocking_api(move || {
        let http = client::http();
        identity::refresh(http, &cfg.base_url, &refresh_token).map_err(ApiError::from)
    })
    .await?;
    state
        .cloud
        .set_access_token_for(Some(&sid), Some(session.access_token))?;
    persist_refresh(&sid, &session.refresh_token);
    refresh_spaces_cache(&state, &sid).await;
    state.cloud.status_for(Some(&sid))
}

/// Revoke the current session (best-effort) and drop local session state. Keeps
/// the server link/config so the user can sign in again. Defaults to active.
#[tauri::command]
pub async fn server_logout(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    let sid = require_config(&state, server_id.as_deref())?.server_id;
    if let (Some(cfg), Some(access)) = (
        state.cloud.config_for(Some(&sid))?,
        state.cloud.access_token_for(Some(&sid))?,
    ) {
        best_effort_logout(cfg, access).await;
    }
    state.cloud.drop_session(Some(&sid))?;
    state.cloud.status_for(Some(&sid))
}

/// Forget the server link entirely (config + tokens), after revoking this device on it.
/// Back-compat alias of `server_remove` keyed by the active (or given) server.
#[tauri::command]
pub async fn server_disconnect(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerList> {
    let sid = require_config(&state, server_id.as_deref())?.server_id;
    if let Some(cfg) = state.cloud.config_for(Some(&sid))? {
        if let Some(access) = goodbye_access(&state, &cfg).await {
            best_effort_leave(cfg, access).await;
        }
    }
    state.cloud.remove(&sid)?;
    state.cloud.list()
}

/// Preview an invite before joining (does not consume it): the instance name and
/// the spaces (with roles) the invite grants. Stateless.
#[tauri::command]
pub async fn server_join_preview(
    base_url: String,
    token: String,
) -> ApiResult<identity::JoinPreview> {
    client::validate_base_url(&base_url)?;
    blocking_api(move || {
        let http = client::http();
        identity::join_preview(http, &base_url, &token).map_err(ApiError::from)
    })
    .await
}

/// Add a sibling device under this account (shared keyset). Returns its device id (b64).
#[tauri::command]
pub async fn server_device_add(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::device_add(http, &cfg.base_url, &access).map_err(ApiError::from)
    })
    .await
}

/// List the caller's own account devices (self-service).
#[tauri::command]
pub async fn server_list_devices(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::DeviceInfo>> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::device_list(http, &cfg.base_url, &access).map_err(ApiError::from)
    })
    .await
}

/// Revoke a device (own, or another's if instance-admin).
#[tauri::command]
pub async fn server_device_revoke(
    device_id: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::device_revoke(http, &cfg.base_url, &access, &device_id).map_err(ApiError::from)
    })
    .await
}

/// Set this account's display_name / handle (server-visible metadata).
#[tauri::command]
pub async fn server_account_profile(
    display_name: Option<String>,
    handle: Option<String>,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    let mut cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let sid = cfg.server_id.clone();
    let base = cfg.base_url.clone();
    let dn = display_name;
    let hd = handle.clone();
    blocking_api(move || {
        let http = client::http();
        identity::account_profile(http, &base, &access, dn, hd).map_err(ApiError::from)
    })
    .await?;
    if handle.is_some() {
        cfg.handle = handle;
        state.cloud.set_config(cfg)?;
    }
    state.cloud.status_for(Some(&sid))
}

// ---------- cloud vaults + sync ----------

/// Create a cloud (server-synced) vault, BOUND 1:1 to a server (defaults to the
/// active server) by a space label, and propagated to THAT server on the next
/// `server_sync_now`. Requires a linked server: with none, `require_config` errors
/// (the UI offers the Cloud option for a linked server, signed in or not, and a
/// space only with a session). Returns the vault id (hex).
///
/// - `space_id: None` — a LOCAL operation: the vault is created bound to the
///   link's primary space label, and its first push makes it a personal vault of
///   the account on the server.
/// - `space_id: Some(space)` — the vault is to live IN that space (one the caller
///   admins, or just created): its id is claimed there on the server first (see
///   [`claim_in_space`]), which needs a live session, and only then is the vault
///   created locally, bound to that space's label. A refused or failed claim
///   creates nothing.
#[tauri::command]
pub async fn server_create_cloud_vault(
    server_id: Option<String>,
    name: String,
    space_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let core = state.core.clone();
    let Some(space) = space_id else {
        return blocking_api(move || {
            core.create_cloud_vault(name, cfg.space_id)
                .map_err(ApiError::from)
        })
        .await;
    };
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let new_id = claim_in_space(&core, &cfg.base_url, &access, &space, None)?;
        core.create_cloud_vault_as(name, space, new_id)
            .map_err(ApiError::from)
    })
    .await
}

/// Reserves a cloud vault id in the core and claims it in `space` on the server
/// (`POST /v1/vaults/claim`), so the vault's first push lands in that space
/// instead of becoming a personal vault of the account. Done BEFORE the vault
/// exists locally: a refusal (not a member of the space) or a network failure
/// then changes nothing on this device but the reservation.
///
/// The claim cannot be taken back, which is why the id is the core's to keep
/// (`reserve_cloud_vault_id`): it is stored before the claim is sent, and the
/// same id comes back for the same space — and the same `source_vault_id`,
/// when a local vault is being moved — until a vault was created with it. A
/// retry after a failure therefore claims the same id again (a no-op on the
/// server) instead of leaving one more claimed, empty vault there. With a
/// source the core also refuses here what the move itself would refuse, so
/// nothing is claimed for a move that cannot happen.
///
/// Returns the raw id for `create_cloud_vault_as` / `convert_vault_to_cloud`.
fn claim_in_space(
    core: &unissh_ffi::Core,
    base_url: &str,
    access: &str,
    space: &str,
    source_vault_id: Option<&str>,
) -> ApiResult<Vec<u8>> {
    let id = core
        .reserve_cloud_vault_id(space.to_owned(), source_vault_id.map(str::to_owned))
        .map_err(ApiError::from)?;
    let newly = identity::claim_vault(client::http(), base_url, access, &client::b64(&id), space)?;
    if !newly {
        log::info!("cloud: the vault id was already claimed by an earlier attempt; reusing it");
    }
    Ok(id)
}

/// Bind every still-unbound (legacy) cloud vault to a server's `space_id`
/// (defaults to the active server). One-time migration for vaults created before
/// the 1:1 cloud-vault↔server binding existed. Safe to call repeatedly (already-
/// bound vaults are untouched); the client invokes it only when exactly one server
/// is linked, so the binding can't go to the wrong server. Returns the count bound.
#[tauri::command]
pub async fn server_bind_unbound_cloud_vaults(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<u32> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let core = state.core.clone();
    blocking_api(move || {
        core.bind_unbound_cloud_vaults(cfg.space_id)
            .map_err(ApiError::from)
    })
    .await
}

/// Bind ONE currently-unbound cloud vault (by hex vault id) to a server's
/// `space_id` (defaults to the active server). Reclaims a vault orphaned by a
/// server removal, or one that couldn't be auto-bound (e.g. 2+ servers linked).
#[tauri::command]
pub async fn server_bind_cloud_vault(
    vault_id: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let core = state.core.clone();
    blocking_api(move || {
        core.bind_cloud_vault(vault_id, cfg.space_id)
            .map_err(ApiError::from)
    })
    .await
}

/// Unbind ONE cloud vault (by hex vault id) from whichever server it's bound to —
/// clears its local binding label so it stops syncing. No `server_id` is needed:
/// unbinding only clears the vault's own label. The vault and its data stay on
/// this device; any server-side copy is left as-is (it can be re-bound later).
#[tauri::command]
pub async fn server_unbind_cloud_vault(
    vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<bool> {
    let core = state.core.clone();
    // Returns true iff a bound cloud vault was actually cleared (false = nothing to do),
    // so the UI only reports "unbound" when something changed.
    blocking_api(move || core.unbind_cloud_vault(vault_id).map_err(ApiError::from)).await
}

/// Run a full sync against a linked server (defaults to active): push local cloud
/// objects, then pull + verify the delta (the pull runs even when the push
/// failed; the push failure is then the error). Requires an active session.
/// Returns a report of what changed, including the items the server refused as
/// too large.
///
/// `retry_refused` (a sync the user asked for by hand) offers those refused
/// items to the server again — the way to upload them once its limit was raised.
/// Background syncs leave it unset, so a refused item is not re-uploaded on
/// every pass.
#[tauri::command]
pub async fn server_sync_now(
    server_id: Option<String>,
    retry_refused: Option<bool>,
    state: State<'_, AppState>,
) -> ApiResult<dto::SyncReport> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    let report = blocking_api(move || {
        // 1:1-binding: sync_now pushes ONLY cloud vaults bound to this server's
        // space. Sync scopes to base_url + Bearer on the wire; the space is the
        // local binding label selecting which vaults participate.
        let space = cfg.space_id.clone();
        if retry_refused == Some(true) {
            core.retry_refused_uploads(space.clone())
                .map_err(ApiError::from)?;
        }
        let transport: Arc<dyn unissh_ffi::FfiSyncTransport> =
            Arc::new(HttpSyncTransport::new(cfg.base_url, access));
        core.sync_now(transport, space, unissh_ffi::FfiSyncMode::Full)
            .map_err(ApiError::from)
    })
    .await?;
    Ok(report.into())
}

/// Full re-pull (defaults to active): reset this space's pull cursor, then sync.
/// Re-fetches the WHOLE server history instead of the delta since the last seq, so
/// vaults that were rejected under a prior identity (e.g. objects pulled before this
/// device re-attached to the account that owns them) are reconsidered and recovered.
/// Incremental "sync now" cannot do this — a reject still advances the cursor, so the
/// owner would never see those seqs again. Requires an active session.
#[tauri::command]
pub async fn server_repull(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<dto::SyncReport> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    let report = blocking_api(move || {
        let space = cfg.space_id.clone();
        core.reset_pull_cursor(space.clone())
            .map_err(ApiError::from)?;
        let transport: Arc<dyn unissh_ffi::FfiSyncTransport> =
            Arc::new(HttpSyncTransport::new(cfg.base_url, access));
        core.sync_now(transport, space, unissh_ffi::FfiSyncMode::Full)
            .map_err(ApiError::from)
    })
    .await?;
    Ok(report.into())
}

/// Restore cloud vaults deleted LOCALLY but still live on the server (defaults to
/// active). A local delete tombstones the vault at a higher version; if it never
/// reached the server (e.g. the link was removed before it synced), the server's
/// live copy is now older, so an ordinary pull can't bring it back (LWW keeps the
/// tombstone) and the list hides it. This purges those local tombstone records and
/// re-pulls, re-materializing whatever the server still holds. Vaults also deleted
/// on the server stay deleted. Returns how many local records were purged. Requires
/// a session.
#[tauri::command]
pub async fn server_restore_deleted_vaults(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<u32> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    let restored = blocking_api(move || {
        let space = cfg.space_id.clone();
        let restored = core
            .restore_deleted_cloud_vaults(space.clone())
            .map_err(ApiError::from)?;
        let transport: Arc<dyn unissh_ffi::FfiSyncTransport> =
            Arc::new(HttpSyncTransport::new(cfg.base_url, access));
        core.sync_now(transport, space, unissh_ffi::FfiSyncMode::Full)
            .map_err(ApiError::from)?;
        Ok(restored)
    })
    .await?;
    Ok(restored)
}

// ---------- per-vault catalog / pull / adopt (Phase 4) ----------

/// List the vaults available on a server (defaults to active) that this caller can
/// access, each enriched with local state (is it already on this device, is it bound).
/// Lets the picker offer Pull / Push / in-sync per vault. Requires a session.
#[tauri::command]
pub async fn server_list_vaults(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::ServerVault>> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    blocking_api(move || {
        let transport = HttpSyncTransport::new(cfg.base_url, access);
        let catalog = transport.list_vaults().map_err(ApiError::from)?;
        let locals = core.list_vaults().map_err(ApiError::from)?;
        let out = catalog
            .into_iter()
            .map(|c| {
                // Local vault ids are hex too (create_cloud_vault returns hex).
                let local = locals
                    .iter()
                    .find(|l| l.vault_id.eq_ignore_ascii_case(&c.vault_id));
                dto::ServerVault {
                    vault_id: c.vault_id,
                    latest_version: c.latest_version,
                    tombstone: c.tombstone,
                    is_local: local.is_some(),
                    bound: local.is_some_and(|l| l.sync_tenant.is_some()),
                    local_name: local.map(|l| l.name.clone()),
                }
            })
            .collect();
        Ok(out)
    })
    .await
}

/// **Pull ONE vault** (by hex id) from a server (defaults to active) onto this device:
/// targeted fetch of just that vault's objects + verify-before-apply, WITHOUT advancing
/// the pull cursor (`HttpSyncTransport::pull_vault`, shared with the CLI). The vault is
/// fetched and applied page by page, in the server's order, so it is never held in
/// memory whole; the report is the sum over the pages. Requires a session.
#[tauri::command]
pub async fn server_pull_vault(
    vault_id: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<dto::SyncReport> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    let report = blocking_api(move || {
        let transport = HttpSyncTransport::new(cfg.base_url, access);
        transport
            .pull_vault(&core, &cfg.space_id, &vault_id)
            .map_err(ApiError::from)
    })
    .await?;
    Ok(report.into())
}

/// The vaults a teammate shared with this account that are not on this device yet
/// (from a server, defaults to active), each inspected by the core: the
/// fingerprint of the key that created it, this account's role, and what this
/// device has pinned for it. The owner's handle/name come from the server's
/// directory and are a CLAIM, never verified. Vaults this account created are
/// left out (a sync brings them). Writes nothing. Requires unlock and a session.
#[tauri::command]
pub async fn server_pending_shared_vaults(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<dto::PendingSharedVaults> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    blocking_api(move || {
        let list =
            shared::pending_shared_vaults(&core, &cfg.base_url, &access).map_err(ApiError::from)?;
        Ok(dto::PendingSharedVaults {
            vaults: list.vaults.into_iter().map(Into::into).collect(),
            malformed: u32::try_from(list.malformed).unwrap_or(u32::MAX),
        })
    })
    .await
}

/// **Trust the owner of a vault shared with this account** (on a server, defaults to
/// active): the core reads the vault's membership from the server, compares
/// `expected_fingerprint` with the fingerprint of the key that created it and pins
/// that key in one step. `expected_fingerprint` is REQUIRED — the one the owner gave
/// the user, or the one the app displayed and the user confirmed; nothing pins
/// "whatever the server presents". A mismatch pins nothing. Pull the vault after
/// `trusted`/`alreadyTrusted` (`server_pull_vault`). Requires unlock and a session.
#[tauri::command]
pub async fn server_trust_shared_vault(
    vault_id: String,
    expected_fingerprint: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<dto::TrustOutcome> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    blocking_api(move || {
        let transport = HttpSyncTransport::new(cfg.base_url, access);
        transport
            .trust_vault(&core, &vault_id, &expected_fingerprint)
            .map(Into::into)
            .map_err(ApiError::from)
    })
    .await
}

/// **Bind an already-cloud vault to a server, then push it** (the "Push" action in the
/// server vaults list; the server defaults to the active one). Sets the cloud vault's
/// binding label to the server's space via `bind_cloud_vault` (re-dirtying the vault and
/// its contents so all of it uploads), then runs `sync_now` for that space and returns
/// its report. Only cloud-target vaults are bindable: for a local vault the bind matches
/// no row and the sync pushes nothing of it (converting a local vault is a separate
/// operation). Requires a session.
#[tauri::command]
pub async fn server_bind_and_push_vault(
    vault_id: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<dto::SyncReport> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    let report = blocking_api(move || {
        let space = cfg.space_id.clone();
        core.bind_cloud_vault(vault_id, space.clone())
            .map_err(ApiError::from)?;
        let transport: Arc<dyn unissh_ffi::FfiSyncTransport> =
            Arc::new(HttpSyncTransport::new(cfg.base_url, access));
        core.sync_now(transport, space, unissh_ffi::FfiSyncMode::Full)
            .map_err(ApiError::from)
    })
    .await?;
    Ok(report.into())
}

/// **Move a LOCAL vault to a server** (the "Move to server…" action; the server
/// defaults to the active one). Requires a live session up front, so a signed-out
/// server refuses before anything changes.
///
/// 1. With `space_id: Some(space)` the vault is to live IN that space: a vault
///    id is reserved in the core and claimed there on the server first (see
///    [`claim_in_space`]). A refused or failed claim stops here with the vault
///    untouched. With `None` there is no claim: the vault is bound to the link's
///    primary space label and its first push makes it a personal vault of the
///    account, like a cloud vault created without a space.
/// 2. The core converts the vault (`convert_vault_to_cloud`: a re-keyed copy
///    into the new cloud vault, the local vault tombstoned, all in one
///    transaction). If it fails, the vault is untouched and the claimed id is
///    kept: a retry into the same space claims and uses the same id.
/// 3. The first push runs — a push only (`FfiSyncMode::PushOnly`), not a full sync: a
///    pull under a space label this device does not otherwise sync would start
///    from an empty cursor and bind every unbound cloud vault it meets to that
///    space. It carries the vault data alone: the account state and the audit
///    log go with the ordinary sync of the primary space. A failed push does NOT undo the conversion: the vault stays bound and
///    dirty, a later sync of its space uploads it, and the failure comes back in
///    `push_error` next to the new vault id.
#[tauri::command]
pub async fn server_move_vault_to_server(
    vault_id: String,
    server_id: Option<String>,
    space_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<dto::MovedVault> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    blocking_api(move || {
        // The claim cannot be taken back: the core refuses, before anything is
        // claimed, what the conversion would refuse (a locked core, a vault
        // that is gone or is already a cloud vault), and keeps the claimed id
        // for a retry if the conversion then fails.
        let reserved = match space_id.as_deref() {
            Some(space) => Some(claim_in_space(
                &core,
                &cfg.base_url,
                &access,
                space,
                Some(vault_id.as_str()),
            )?),
            None => None,
        };
        let space = space_id.unwrap_or(cfg.space_id);
        let new_id = core
            .convert_vault_to_cloud(vault_id, space.clone(), reserved)
            .map_err(ApiError::from)?;
        let transport: Arc<dyn unissh_ffi::FfiSyncTransport> =
            Arc::new(HttpSyncTransport::new(cfg.base_url, access));
        let pushed = core.sync_now(transport, space, unissh_ffi::FfiSyncMode::PushOnly);
        let (push, push_error) = match pushed {
            Ok(report) => (Some(report.into()), None),
            Err(e) => (None, Some(ApiError::from(e))),
        };
        Ok(dto::MovedVault {
            vault_id: new_id,
            push,
            push_error,
        })
    })
    .await
}

// ---------- membership / sharing ----------
//
// add_member / rotate_vk / confirm_member_pin / list_members / member_fingerprint
// are LOCAL core operations: they build the signed membership manifest + per-member
// grant objects in local storage. Those objects propagate to the server (and thus
// to other members) on the next `server_sync_now`.

/// List accounts on a server (instance-admin only; defaults to active) with hex
/// member pubkeys ready for `server_add_member`.
#[tauri::command]
pub async fn server_list_accounts(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::AccountInfo>> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::list_accounts(http, &cfg.base_url, &access).map_err(ApiError::from)
    })
    .await
}

/// Add (or re-grant) a member to a cloud vault at the latest epoch.
#[tauri::command]
pub async fn server_add_member(
    vault_id: String,
    member_ed25519_hex: String,
    member_x25519_hex: String,
    role: dto::MemberRole,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking_api(move || {
        core.add_member(vault_id, member_ed25519_hex, member_x25519_hex, role.into())
            .map_err(ApiError::from)
    })
    .await
}

/// List the members of a cloud vault at the latest epoch.
#[tauri::command]
pub async fn server_list_members(
    vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::MemberInfo>> {
    let core = state.core.clone();
    let members = blocking_api(move || core.list_members(vault_id).map_err(ApiError::from)).await?;
    Ok(members.into_iter().map(Into::into).collect())
}

/// OOB fingerprint (hex SHA-256) of a member's Ed25519 pubkey, for confirmation.
#[tauri::command]
pub async fn server_member_fingerprint(
    ed25519_pub_hex: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking_api(move || {
        core.member_fingerprint(ed25519_pub_hex)
            .map_err(ApiError::from)
    })
    .await
}

/// Pin (TOFU) a member's pubkey under an account_id — protects against the server
/// substituting a pubkey. Re-pinning the same key is ok; a different key errors.
#[tauri::command]
pub async fn server_confirm_member_pin(
    account_id: String,
    ed25519_pub_hex: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking_api(move || {
        core.confirm_member_pin(account_id, ed25519_pub_hex)
            .map_err(ApiError::from)
    })
    .await
}

/// Designate the account's personal vault (A3.2). Stored in the synced per-account
/// state; syncs to the account's other devices.
#[tauri::command]
pub async fn set_personal_vault(vault_id: String, state: State<'_, AppState>) -> ApiResult<()> {
    let core = state.core.clone();
    blocking_api(move || core.set_personal_vault(vault_id).map_err(ApiError::from)).await
}

/// Set the account-default SSH username (A3.2).
#[tauri::command]
pub async fn set_account_default_username(
    username: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking_api(move || {
        core.set_account_default_username(username)
            .map_err(ApiError::from)
    })
    .await
}

/// The account's personal vault id (hex), if designated (A3.2).
#[tauri::command]
pub async fn get_personal_vault(state: State<'_, AppState>) -> ApiResult<Option<String>> {
    let core = state.core.clone();
    blocking_api(move || core.get_personal_vault().map_err(ApiError::from)).await
}

/// The account-default SSH username, if set (A3.2).
#[tauri::command]
pub async fn get_account_default_username(state: State<'_, AppState>) -> ApiResult<Option<String>> {
    let core = state.core.clone();
    blocking_api(move || core.get_account_default_username().map_err(ApiError::from)).await
}

/// Eager VK rotation (revocation): new key epoch over the remaining members.
/// Members not listed (except the owner) are revoked. Returns the new epoch.
#[tauri::command]
pub async fn server_rotate_vk(
    vault_id: String,
    remaining: Vec<dto::RemainingMember>,
    state: State<'_, AppState>,
) -> ApiResult<u64> {
    let core = state.core.clone();
    let core_remaining: Vec<unissh_ffi::RemainingMember> =
        remaining.into_iter().map(Into::into).collect();
    blocking_api(move || {
        core.rotate_vk(vault_id, core_remaining)
            .map_err(ApiError::from)
    })
    .await
}

// ---------- spaces / directory / pending / invites (server-v2) ----------
//
// These are server-trusted grouping/authority surfaces (a space role is an
// authority label, NOT a decryption capability — vault crypto grants remain a
// core+sync concern). Every command resolves its Bearer from the server link
// (defaults to the active server), like the sibling identity commands.

/// Mint a one-link invite for a SINGLE space intent (`space_id` at `role`) on a
/// server (defaults to active). Caller must be an admin of that space. The returned
/// token is shown once (the server stores only its hash).
#[tauri::command]
pub async fn server_invite(
    space_id: String,
    role: String,
    ttl_seconds: Option<i64>,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<dto::InviteInfo> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::invite(http, &cfg.base_url, &access, &space_id, &role, ttl_seconds)
            .map_err(ApiError::from)
    })
    .await
}

/// List the caller's own spaces (with roles) on a server (defaults to active).
#[tauri::command]
pub async fn server_list_spaces(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::SpaceInfo>> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::list_spaces(http, &cfg.base_url, &access).map_err(ApiError::from)
    })
    .await
}

/// Create a space (instance owner) on a server (defaults to active). The creator
/// becomes its admin. Returns the new space id (base64).
#[tauri::command]
pub async fn server_create_space(
    name: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::create_space(http, &cfg.base_url, &access, &name).map_err(ApiError::from)
    })
    .await
}

/// Add (idempotent) an account to a space at a role (space-admin) on a server
/// (defaults to active).
#[tauri::command]
pub async fn server_add_space_member(
    space_id: String,
    account_id: String,
    role: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::add_space_member(http, &cfg.base_url, &access, &space_id, &account_id, &role)
            .map_err(ApiError::from)
    })
    .await
}

/// The shared people directory on a server (defaults to active): handles + hex
/// canonical keys, ready to feed `server_add_member` / `server_add_space_member`.
#[tauri::command]
pub async fn server_directory(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::DirectoryEntry>> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::directory(http, &cfg.base_url, &access).map_err(ApiError::from)
    })
    .await
}

/// The caller's outstanding vault-admin crypto actions (`grant`/`revoke`) on a
/// server (defaults to active). Fulfil each via `server_add_member` / `server_rotate_vk`
/// (which publish the manifest+grant through the existing core+sync path — the server
/// marks rows done by observing them; clients never self-report).
#[tauri::command]
pub async fn server_pending(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::PendingAction>> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::pending(http, &cfg.base_url, &access).map_err(ApiError::from)
    })
    .await
}

/// Publish an OPAQUE key-binding attestation about an account (space-admin) on a
/// server (defaults to active). `blob`/`signature` are base64, produced+verified by
/// clients (the server stores them verbatim, never interpreting them).
#[tauri::command]
pub async fn server_attestations_put(
    account_id: String,
    blob: String,
    signature: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let blob = client::unb64(&blob)?;
        let signature = client::unb64(&signature)?;
        let http = client::http();
        identity::attestation_put(http, &cfg.base_url, &access, &account_id, &blob, &signature)
            .map_err(ApiError::from)
    })
    .await
}

/// Every attestation about an account on a server (defaults to active). Opaque
/// blob+signature (base64); the caller verifies signatures.
#[tauri::command]
pub async fn server_attestations_list(
    account_id: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::AttestationInfo>> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::attestations_list(http, &cfg.base_url, &access, &account_id)
            .map_err(ApiError::from)
    })
    .await
}

// ---------- keyset escrow (Path A) ----------

/// Escrow this device's (already-encrypted) keyset blob to a server (defaults to
/// active) AND arm keyless-escrow sign-in for it: a fresh device holding only the
/// password + Secret Key can then recover the keyset by handle (Path A). The escrow
/// block (`sha256(K_auth)` + Argon2id params) is derived ONCE, from the SAME
/// `password` + `secret_key_hex` that wraps the uploaded blob, so a later
/// `server_escrow_fetch_and_unlock` re-derives an identical `K_auth`. `password` is
/// `None` for passwordless/SSO accounts. Returns the stored generation.
#[tauri::command]
pub async fn server_keyset_push(
    password: Option<String>,
    secret_key_hex: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<i64> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let keyset_path = state.keyset_path.clone();
    let core = state.core.clone();
    blocking_api(move || {
        let blob = std::fs::read(&keyset_path).map_err(|e| ApiError::Server {
            code: "keyset".into(),
            message: format!("read keyset sidecar: {e}"),
        })?;
        // Derive the escrow credentials ONCE (fresh Argon2id params + salt) from the
        // same password+SecretKey that wraps this blob, and upload EXACTLY those params
        // so a fetch reproduces the same K_auth. The blob is uploaded as-is (its own KDF
        // header is separate; the escrow argon_* serve ONLY K_auth re-derivation).
        let creds = core
            .derive_escrow_credentials(password, secret_key_hex)
            .map_err(ApiError::from)?;
        let escrow = identity::EscrowEnroll {
            k_auth: creds.k_auth,
            argon_salt: creds.argon_salt,
            argon_mem_kib: creds.argon_mem_kib,
            argon_iterations: creds.argon_iterations,
            argon_parallelism: creds.argon_parallelism,
        };
        let http = client::http();
        identity::keyset_put(http, &cfg.base_url, &access, &blob, Some(&escrow))
            .map_err(ApiError::from)
    })
    .await
}

/// Pull the escrowed keyset blob and unlock this instance from it (Path A restore).
/// Requires an active session (a keyless first-time device should use Path B).
#[tauri::command]
pub async fn server_keyset_pull_and_unlock(
    app: tauri::AppHandle,
    password: Option<String>,
    secret_key_hex: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    // The installed keyset may be wrapped under another password.
    blocking_api(crate::biometric::installing_keyset(
        &app,
        &state,
        move || {
            let http = client::http();
            let (blob, _generation) = identity::keyset_get(http, &cfg.base_url, &access)?;
            core.unlock_from_server_blob(blob, password, secret_key_hex)
                .map_err(ApiError::from)
        },
    ))
    .await?;
    crate::commands::resume_after_unlock(&app);
    Ok(())
}

/// Fetch the escrow Argon2id params for a `handle` from a server (PUBLIC — no session).
/// A fresh device uses these to re-derive `K_auth`. NOTE: a 200 is NOT proof the handle
/// exists — the server returns a shaped decoy for unknown/unenrolled handles, so callers
/// must not treat this as an existence oracle.
#[tauri::command]
pub async fn server_escrow_params(
    base_url: String,
    handle: String,
) -> ApiResult<dto::EscrowParamsInfo> {
    client::validate_base_url(&base_url)?;
    blocking_api(move || {
        let http = client::http();
        let p = identity::escrow_params(http, &base_url, &handle)?;
        Ok(dto::EscrowParamsInfo {
            argon_salt: client::b64(&p.argon_salt),
            argon_mem_kib: p.argon_mem_kib,
            argon_iterations: p.argon_iterations,
            argon_parallelism: p.argon_parallelism,
        })
    })
    .await
}

/// Shared tail for the identity-recovery paths (server ESCROW fetch, offline Emergency-Kit
/// import): with the keyset ALREADY unlocked in `core`, register a FRESH device (keyset-signed
/// self-enroll — PUBLIC, no session), authenticate it, resolve the instance id + primary space,
/// then persist the link (idempotent via `find_by_identity`, preserving a prior `owned` flag) +
/// set the access token + persist the refresh, and return the resulting `ServerStatus` —
/// mirroring claim/join. The self-enroll is the only server-mutating step; a login failure right
/// after it (same server, same round-trip) is rare and any orphaned device is revocable — so,
/// unlike the irreversible claim/join, this need not persist a link before login.
///
/// `account_id_override` is the account the caller already knows the recovered keyset belongs to
/// (escrow's fetch identity); `None` takes the self-enroll's account id — the same keyset resolves
/// the same account, so they agree, and the offline path has no fetch to learn it from. `handle`
/// is stored on the link when known (escrow keys off one; offline import has none).
async fn self_enroll_login_and_persist(
    state: &AppState,
    base_url: String,
    account_id_override: Option<String>,
    handle: Option<String>,
) -> ApiResult<ServerStatus> {
    let core = state.core.clone();
    let base = base_url.clone();
    let (instance, account_id, device_id, session, primary_space) = blocking_api(move || {
        let http = client::http();
        // Register a FRESH device for the account (keyset-signed; no session). Prefer the
        // caller's account id (escrow's fetch identity) when supplied; else take the
        // self-enroll's — the recovered keyset resolves the same account either way.
        let reg = core.build_registration_request().map_err(ApiError::from)?;
        let (enroll_account_id, device_id) = identity::device_self_enroll(http, &base, &reg)?;
        let account_id = account_id_override.unwrap_or(enroll_account_id);
        // Authenticate the new device (the recovered keyset signs the challenge).
        let session = identity::login(http, &base, &core, &account_id, &device_id)?;
        // The opaque instance id (link identity) comes from the public descriptor; the
        // primary space (cloud-vault binding label) is the caller's first space, if any.
        let instance = identity::instance_info(http, &base)?;
        let primary_space = identity::list_spaces(http, &base, &session.access_token)
            .ok()
            .and_then(|spaces| spaces.first().map(|s| s.space_id.clone()))
            .unwrap_or_default();
        Ok((instance, account_id, device_id, session, primary_space))
    })
    .await?;

    // Persist the link (active). Idempotent: re-recovering on this device reuses the existing
    // link id (via find_by_identity) rather than minting a duplicate, and preserves its `owned`
    // flag so an owner recovering on a fresh device isn't downgraded (a brand-new link has no
    // prior flag → false, matching join/oidc: recovery confers no NEW ownership).
    let server_id = state
        .cloud
        .find_by_identity(&base_url, &instance.instance_id, &account_id)?
        .unwrap_or_else(new_server_id);
    let owned = state
        .cloud
        .config_for(Some(&server_id))?
        .map(|c| c.owned)
        .unwrap_or(false);
    let replaced = upsert_link(
        state,
        ServerConfig {
            server_id: server_id.clone(),
            base_url,
            instance_id: instance.instance_id,
            space_id: primary_space,
            account_id,
            device_id,
            handle,
            owned,
        },
    )?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token))?;
    persist_refresh(&server_id, &session.refresh_token);
    retire_replaced_device(state, &server_id, replaced).await;
    refresh_spaces_cache(state, &server_id).await;
    state.cloud.status_for(Some(&server_id))
}

/// Sign in with an existing identity via a server's ESCROW: recover this device's keyset
/// by handle, register this device, authenticate, and persist the link (PUBLIC — the
/// escrow + self-enroll endpoints are session-less). The full flow, run keyset-first so a
/// brand-new device with no prior local link can obtain a session:
///   1. `GET /v1/escrow/params` — the enrolled Argon2id params for the handle.
///   2. `derive_escrow_auth_with_params` — re-derive `K_auth` with THOSE params (so it
///      reproduces what enrollment uploaded; the server gates the fetch on `sha256(K_auth)`).
///   3. `POST /v1/escrow/fetch` — the encrypted keyset blob + the account it belongs to.
///   4. `unlock_from_server_blob` — install + unlock the keyset locally (now loaded).
/// Then the shared `self_enroll_login_and_persist` tail self-enrolls THIS device, logs in,
/// and persists the link. `password` is `None` for passwordless/SSO accounts; `secret_key_hex`
/// is the account Secret Key (from the Emergency Kit). A wrong password/key → the server's 403.
///
/// Zero-knowledge: credentials are used locally by the core FFI; the installed
/// Secret Key is remembered in the OS keychain. Only the derived `K_auth`
/// and the keyset-signed registration leave the device.
#[tauri::command]
pub async fn server_escrow_fetch_and_unlock(
    app: tauri::AppHandle,
    base_url: String,
    handle: String,
    password: Option<String>,
    secret_key_hex: String,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    client::validate_base_url(&base_url)?;
    let core = state.core.clone();
    let base = base_url.clone();
    let hd = handle.clone();

    // Recover + unlock the keyset in one blocking pass, then hand off to the shared tail.
    // The recovered keyset may be wrapped under another password (see `installing_keyset`).
    let install = crate::biometric::installing_keyset(&app, &state, move || {
        let http = client::http();
        // 1–2. Enrolled Argon2id params → re-derive K_auth with THOSE params (enroll/fetch
        //       symmetry). password/secret_key only enter the core here.
        let params = identity::escrow_params(http, &base, &hd)?;
        let k_auth = core
            .derive_escrow_auth_with_params(
                password.clone(),
                secret_key_hex.clone(),
                params.argon_salt,
                params.argon_mem_kib,
                params.argon_iterations,
                params.argon_parallelism,
            )
            .map_err(ApiError::from)?;
        // 3–4. Fetch the escrowed keyset blob + the account it belongs to, then install +
        //       unlock it locally (this loads the keyset the self-enroll tail signs with).
        let (blob, account_id) = identity::escrow_fetch(http, &base, &hd, &k_auth)?;
        super::recovery::install_keyset(
            &core,
            blob,
            password,
            secret_key_hex,
            crate::keychain::save_secret_key_now,
        )?;
        Ok(account_id)
    });
    let (account_id, _) = blocking_api(install).await?;

    // Keep escrow's fetched account id as the link identity and its handle on the link.
    crate::commands::resume_after_unlock(&app);
    self_enroll_login_and_persist(&state, base_url, Some(account_id), Some(handle)).await
}

/// Restore this device's identity OFFLINE from an Emergency-Kit keyset FILE, then self-enroll +
/// sign in — the escrow path's tail with the encrypted keyset blob sourced from a FILE instead of
/// the server's escrow (PUBLIC — self-enroll is session-less). `keyset_blob` is the raw
/// `EncryptedKeyset` bytes of the kit (exactly what `unlock_from_server_blob` consumes);
/// `password` is `None` for passwordless/SSO accounts; `secret_key_hex` is the account Secret Key
/// (also in the Emergency Kit). No prior local link or session is needed, so a brand-new device
/// holding only the kit file + Secret Key can recover its identity and re-attach to the account.
///
/// Zero-knowledge: `password` / `secret_key_hex` / `keyset_blob` flow ONLY into the core FFI (to
/// unwrap + install the keyset) — never logged, never sent; only the keyset-signed device
/// registration leaves the device.
#[tauri::command]
pub async fn server_import_keyset_and_unlock(
    app: tauri::AppHandle,
    base_url: String,
    keyset_blob: Vec<u8>,
    password: Option<String>,
    secret_key_hex: String,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    client::validate_base_url(&base_url)?;
    let core = state.core.clone();
    // Install + unlock the keyset from the file blob (blocking; the raw bytes + credentials enter
    // ONLY the core here). Unlike escrow there is no fetch to learn the account id from — the
    // follow-up self-enroll returns it (the same keyset resolves the same account).
    // The imported keyset may be wrapped under another password (see `installing_keyset`).
    blocking_api(crate::biometric::installing_keyset(
        &app,
        &state,
        move || {
            super::recovery::install_keyset(
                &core,
                keyset_blob,
                password,
                secret_key_hex,
                crate::keychain::save_secret_key_now,
            )
            .map_err(ApiError::from)
        },
    ))
    .await?;
    // Offline import carries no handle (escrow keys off one); the account's handle syncs later.
    crate::commands::resume_after_unlock(&app);
    self_enroll_login_and_persist(&state, base_url, None, None).await
}

// ---------- device-to-device onboarding (Path B) ----------

/// (Existing device) Pre-create the new device + open a relay channel, returning
/// the pairing payload to hand to the new device. Follow with `server_onboard_complete`.
/// The server keeps the device pending until the new device first signs in, so a
/// pairing that is cancelled or fails leaves no device on the account.
#[tauri::command]
pub async fn server_onboard_initiate(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<dto::PairingPayload> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let base = cfg.base_url.clone();
    let (device_id, channel_id) = blocking_api(move || {
        let http = client::http();
        let device_id = identity::device_add(http, &base, &access)?;
        let channel_id = identity::relay_open(http, &base, &access)?;
        Ok((device_id, channel_id))
    })
    .await?;
    let oob_code = client::b64(Uuid::new_v4().as_bytes());
    Ok(dto::PairingPayload {
        base_url: cfg.base_url,
        instance_id: cfg.instance_id,
        space_id: cfg.space_id,
        account_id: cfg.account_id,
        device_id,
        channel_id,
        oob_code,
    })
}

/// (Existing device) Run the initiator side of the PAKE: seals the keyset and
/// relays it to the new device. Blocks until the new device responds (or times out).
#[tauri::command]
pub async fn server_onboard_complete(
    channel_id: String,
    oob_code: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let cfg = require_config(&state, server_id.as_deref())?;
    // The new device must receive THIS device's account Secret Key (model A: one
    // shared key across all devices). Read it from the OS keychain in Rust — it
    // never enters JS. Absent (e.g. on mobile, where it isn't stored) → a clear
    // error: initiate "Add device" from a desktop that has the key stored.
    let secret_key_hex = crate::keychain::keychain_get_secret_key()
        .await?
        .ok_or_else(|| {
            ApiError::other(
                "no Secret Key stored on this device to share — start \"Add device\" from a \
             desktop device that has your Secret Key in its keychain",
            )
        })?;
    let core = state.core.clone();
    let base = cfg.base_url;
    blocking_api(move || {
        let http = client::http();
        let code = client::unb64(&oob_code)?;
        onboard::initiator_complete(&core, http, &base, &channel_id, code, secret_key_hex)
            .map_err(ApiError::from)
    })
    .await
}

/// (New device) Join via a pairing payload: run the responder PAKE, install the
/// sealed keyset (opens the instance), persist a new cloud link (active), sign in.
#[tauri::command]
#[expect(
    clippy::too_many_arguments,
    reason = "a #[tauri::command]'s parameters are the named fields of the frontend's invoke payload; a params struct would change that IPC contract"
)]
pub async fn server_onboard_join(
    app: tauri::AppHandle,
    base_url: String,
    instance_id: String,
    space_id: String,
    account_id: String,
    device_id: String,
    channel_id: String,
    oob_code: String,
    password: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    client::validate_base_url(&base_url)?;
    let core = state.core.clone();

    // 1) Run the PAKE responder — installs the keyset and opens the local instance.
    let core_pake = core.clone();
    let base = base_url.clone();
    let channel = channel_id.clone();
    // A keyset from another device: nothing sealed here before may open it.
    blocking_api(crate::biometric::installing_keyset(
        &app,
        &state,
        move || {
            let http = client::http();
            let code = client::unb64(&oob_code)?;
            onboard::responder_join(
                &core_pake,
                http,
                &base,
                &channel,
                code,
                password,
                crate::keychain::save_secret_key_now,
            )?;
            Ok(())
        },
    ))
    .await?;

    // 2) Persist a cloud link for the new device and make it active. Idempotent:
    // re-joining the same server reuses its existing link id (no duplicate). The
    // instance id + primary space are inherited from the initiator's pairing payload.
    let server_id = state
        .cloud
        .find_by_identity(&base_url, &instance_id, &account_id)?
        .unwrap_or_else(new_server_id);
    let replaced = upsert_link(
        &state,
        ServerConfig {
            server_id: server_id.clone(),
            base_url: base_url.clone(),
            instance_id: instance_id.clone(),
            space_id: space_id.clone(),
            account_id: account_id.clone(),
            device_id: device_id.clone(),
            handle: None,
            // New device joining an existing account via PAKE: ownership is a server-side
            // account property, not carried in the handoff — default false (the personal
            // vault is already set via synced account-state; re-designation is rare).
            owned: false,
        },
    )?;

    // 3) Sign in (the shared keyset, now installed, signs the challenge).
    let session = blocking_api(move || {
        let http = client::http();
        identity::login(http, &base_url, &core, &account_id, &device_id).map_err(ApiError::from)
    })
    .await?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token))?;
    persist_refresh(&server_id, &session.refresh_token);
    retire_replaced_device(&state, &server_id, replaced).await;
    refresh_spaces_cache(&state, &server_id).await;
    state.cloud.status_for(Some(&server_id))
}

// ---------- audit (read-only) ----------

/// Read a server's audit log (instance-admin only; defaults to active): observed
/// events like logins.
#[tauri::command]
pub async fn server_audit_query(
    since_seq: Option<i64>,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::AuditEntry>> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    blocking_api(move || {
        let http = client::http();
        identity::audit_query(http, &cfg.base_url, &access, since_seq).map_err(ApiError::from)
    })
    .await
}
