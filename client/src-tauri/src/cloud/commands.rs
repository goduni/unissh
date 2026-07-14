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
use crate::cloud::{client, identity, oidc, onboard, tokens, ServerList, ServerStatus};
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
        .config_for(server_id)
        .ok_or_else(|| ApiError::Server {
            code: "not_connected".into(),
            message: "no server is linked".into(),
        })
}

/// Resolve the target server's in-memory access token (defaults to active).
fn require_access(state: &AppState, server_id: Option<&str>) -> ApiResult<String> {
    state
        .cloud
        .access_token_for(server_id)
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
    let (base_url, access) = match (
        state.cloud.config_for(Some(server_id)),
        state.cloud.access_token_for(Some(server_id)),
    ) {
        (Some(cfg), Some(access)) => (cfg.base_url, access),
        _ => return,
    };
    let fetched = blocking_api(move || {
        let http = client::http();
        identity::list_spaces(http, &base_url, &access)
    })
    .await;
    if let Ok(spaces) = fetched {
        let entries = spaces
            .into_iter()
            .map(|s| SpaceEntry {
                space_id: s.space_id,
                name: s.name,
                role: s.role,
            })
            .collect();
        state.cloud.set_spaces_for(Some(server_id), Some(entries));
    }
}

/// Status of one server (defaults to the active server).
#[tauri::command]
pub async fn server_status(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    Ok(state.cloud.status_for(server_id.as_deref()))
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
    Ok(state.cloud.list())
}

/// Switch the active server (the one argument-less commands resolve to).
#[tauri::command]
pub async fn server_set_active(
    server_id: String,
    state: State<'_, AppState>,
) -> ApiResult<ServerList> {
    state.cloud.set_active(&server_id)?;
    Ok(state.cloud.list())
}

/// Forget ONE server link (config entry + tokens) after a best-effort logout.
/// Other servers are untouched. Returns the updated list.
#[tauri::command]
pub async fn server_remove(server_id: String, state: State<'_, AppState>) -> ApiResult<ServerList> {
    // Space of the server being removed — to unbind its cloud vaults so they
    // aren't left orphaned pointing at a now-gone server (they become reclaimable
    // via re-link or manual bind).
    let removed_space = state.cloud.config_for(Some(&server_id)).map(|c| c.space_id);
    if let (Some(cfg), Some(access)) = (
        state.cloud.config_for(Some(&server_id)),
        state.cloud.access_token_for(Some(&server_id)),
    ) {
        let _ = blocking_api(move || {
            let http = client::http();
            identity::logout(http, &cfg.base_url, &access)
        })
        .await;
    }
    state.cloud.remove(&server_id)?;
    if let Some(space) = removed_space {
        let core = state.core.clone();
        let _ = blocking_api(move || {
            core.clear_cloud_vault_binding(space)
                .map_err(ApiError::from)
        })
        .await;
    }
    Ok(state.cloud.list())
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
        .find_by_identity(&base_url, &instance.instance_id, &outcome.account_id)
        .unwrap_or_else(new_server_id);
    let account_id = outcome.account_id;
    let device_id = outcome.device_id;
    state.cloud.upsert_config(ServerConfig {
        server_id: server_id.clone(),
        base_url: base_url.clone(),
        instance_id: instance.instance_id,
        space_id,
        account_id: account_id.clone(),
        device_id: device_id.clone(),
        handle,
        // Joiners are never instance owners.
        owned: false,
    })?;

    // Log in. A failure here is now recoverable — the link above is persisted, so
    // server_login (the "Sign in" recovery branch) can re-authenticate against it.
    let core = state.core.clone();
    let session = blocking_api(move || {
        let http = client::http();
        identity::login(http, &base_url, &core, &account_id, &device_id)
    })
    .await?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token));
    persist_refresh(&server_id, &session.refresh_token);
    refresh_spaces_cache(&state, &server_id).await;
    Ok(state.cloud.status_for(Some(&server_id)))
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
        identity::claim(http, &base, &code, reg, dn, hd, sn)
    })
    .await?;

    // Persist the link IMMEDIATELY after the irreversible claim, BEFORE login, so a
    // transient login failure leaves a recoverable ServerConfig (the Settings "Sign
    // in" branch → server_login retries against it). Idempotent: a retry reuses the
    // existing link id (via find_by_identity) rather than minting a duplicate.
    let server_id = state
        .cloud
        .find_by_identity(&base_url, &outcome.instance_id, &outcome.account_id)
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
        identity::login(http, &base_url, &core, &account_id, &device_id)
    })
    .await?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token));
    persist_refresh(&server_id, &session.refresh_token);
    refresh_spaces_cache(&state, &server_id).await;
    Ok(state.cloud.status_for(Some(&server_id)))
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
        .find_by_identity(&base_url, &instance.instance_id, &outcome.account_id)
        .unwrap_or_else(new_server_id);
    state.cloud.upsert_config(ServerConfig {
        server_id: server_id.clone(),
        base_url,
        instance_id: instance.instance_id,
        space_id,
        account_id: outcome.account_id,
        device_id: outcome.device_id,
        handle: None,
        // SSO sign-in never confers instance ownership.
        owned: false,
    })?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token));
    persist_refresh(&server_id, &session.refresh_token);
    refresh_spaces_cache(&state, &server_id).await;
    Ok(state.cloud.status_for(Some(&server_id)))
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
    })
    .await?;
    state
        .cloud
        .set_access_token_for(Some(&sid), Some(session.access_token));
    persist_refresh(&sid, &session.refresh_token);
    refresh_spaces_cache(&state, &sid).await;
    Ok(state.cloud.status_for(Some(&sid)))
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
        identity::refresh(http, &cfg.base_url, &refresh_token)
    })
    .await?;
    state
        .cloud
        .set_access_token_for(Some(&sid), Some(session.access_token));
    persist_refresh(&sid, &session.refresh_token);
    refresh_spaces_cache(&state, &sid).await;
    Ok(state.cloud.status_for(Some(&sid)))
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
        state.cloud.config_for(Some(&sid)),
        state.cloud.access_token_for(Some(&sid)),
    ) {
        let _ = blocking_api(move || {
            let http = client::http();
            identity::logout(http, &cfg.base_url, &access)
        })
        .await;
    }
    state.cloud.drop_session(Some(&sid));
    Ok(state.cloud.status_for(Some(&sid)))
}

/// Forget the server link entirely (config + tokens), after a best-effort logout.
/// Back-compat alias of `server_remove` keyed by the active (or given) server.
#[tauri::command]
pub async fn server_disconnect(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerList> {
    let sid = require_config(&state, server_id.as_deref())?.server_id;
    if let (Some(cfg), Some(access)) = (
        state.cloud.config_for(Some(&sid)),
        state.cloud.access_token_for(Some(&sid)),
    ) {
        let _ = blocking_api(move || {
            let http = client::http();
            identity::logout(http, &cfg.base_url, &access)
        })
        .await;
    }
    state.cloud.remove(&sid)?;
    Ok(state.cloud.list())
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
        identity::join_preview(http, &base_url, &token)
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
        identity::device_add(http, &cfg.base_url, &access)
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
        identity::device_list(http, &cfg.base_url, &access)
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
        identity::device_revoke(http, &cfg.base_url, &access, &device_id)
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
        identity::account_profile(http, &base, &access, dn, hd)
    })
    .await?;
    if handle.is_some() {
        cfg.handle = handle;
        state.cloud.set_config(cfg)?;
    }
    Ok(state.cloud.status_for(Some(&sid)))
}

// ---------- cloud vaults + sync ----------

/// Create a cloud (server-synced) vault, BOUND 1:1 to a server (defaults to the
/// active server) by a `space_id`. This is a LOCAL operation — the vault is marked
/// Cloud in local storage, bound to the chosen space, and propagates to THAT server
/// on the next `server_sync_now`. `space_id` selects the bound space (an existing
/// space the caller admins, or one just created); when `None` it defaults to the
/// link's primary space. Requires a linked server: with none, `require_config` errors
/// (the UI also gates the Cloud option behind a session). Returns the vault id (hex).
#[tauri::command]
pub async fn server_create_cloud_vault(
    server_id: Option<String>,
    name: String,
    space_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let core = state.core.clone();
    // Bind to the caller-chosen space when supplied; otherwise the link's primary.
    // The binding is a local label — the server enforces space authority at sync time
    // via the Bearer + space membership, so a stale/foreign pick can't leak the vault.
    let space = space_id.unwrap_or(cfg.space_id);
    blocking_api(move || core.create_cloud_vault(name, space).map_err(ApiError::from)).await
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

/// Run a full sync against a linked server (defaults to active): push local cloud
/// objects, then pull + verify the delta. Requires an active session. Returns a
/// report of what changed.
#[tauri::command]
pub async fn server_sync_now(
    server_id: Option<String>,
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
        let transport: Arc<dyn unissh_ffi::FfiSyncTransport> =
            Arc::new(HttpSyncTransport::new(cfg.base_url, access));
        core.sync_now(transport, space).map_err(ApiError::from)
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
        core.sync_now(transport, space).map_err(ApiError::from)
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
        core.sync_now(transport, space).map_err(ApiError::from)?;
        Ok(restored)
    })
    .await?;
    Ok(restored)
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
        identity::list_accounts(http, &cfg.base_url, &access)
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

/// Pin (TOFU) the genesis-owner of a teammate-created vault at share-accept (A0).
/// Without it the vault's records fail authority verification on sync. Re-pinning
/// the same key is ok; a different key errors (anti-rebind).
#[tauri::command]
pub async fn server_pin_vault_genesis_owner(
    vault_id: String,
    ed25519_pub_hex: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking_api(move || {
        core.pin_vault_genesis_owner(vault_id, ed25519_pub_hex)
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
        identity::list_spaces(http, &cfg.base_url, &access)
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
        identity::create_space(http, &cfg.base_url, &access, &name)
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
        identity::directory(http, &cfg.base_url, &access)
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
        identity::pending(http, &cfg.base_url, &access)
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
    })
    .await
}

/// Pull the escrowed keyset blob and unlock this instance from it (Path A restore).
/// Requires an active session (a keyless first-time device should use Path B).
#[tauri::command]
pub async fn server_keyset_pull_and_unlock(
    password: Option<String>,
    secret_key_hex: String,
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let core = state.core.clone();
    blocking_api(move || {
        let http = client::http();
        let (blob, _generation) = identity::keyset_get(http, &cfg.base_url, &access)?;
        core.unlock_from_server_blob(blob, password, secret_key_hex)
            .map_err(ApiError::from)
    })
    .await
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

/// Recover this device's keyset from a server's ESCROW by handle and unlock it (PUBLIC —
/// no session; the escrow endpoints are unauthenticated). Reads the enrolled Argon2id
/// params (`GET /v1/escrow/params`), re-derives `K_auth` with THOSE params so it matches
/// what enrollment uploaded (the server gates the fetch on `sha256(K_auth)`), fetches the
/// encrypted keyset blob (`POST /v1/escrow/fetch`), then unlocks the local instance from
/// it. `password` is `None` for passwordless/SSO accounts; `secret_key_hex` is the
/// account Secret Key (from the Emergency Kit). A wrong password/key → the server's 403.
#[tauri::command]
pub async fn server_escrow_fetch_and_unlock(
    base_url: String,
    handle: String,
    password: Option<String>,
    secret_key_hex: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    client::validate_base_url(&base_url)?;
    let core = state.core.clone();
    blocking_api(move || {
        let http = client::http();
        let params = identity::escrow_params(http, &base_url, &handle)?;
        // Re-derive K_auth with the SERVER-STORED params (not fresh ones) so it
        // reproduces the K_auth enrollment uploaded — enroll/fetch symmetry.
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
        let blob = identity::escrow_fetch(http, &base_url, &handle, &k_auth)?;
        core.unlock_from_server_blob(blob, password, secret_key_hex)
            .map_err(ApiError::from)
    })
    .await
}

// ---------- device-to-device onboarding (Path B) ----------

/// (Existing device) Pre-create the new device + open a relay channel, returning
/// the pairing payload to hand to the new device. Follow with `server_onboard_complete`.
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
    let secret_key_hex = crate::keychain::keychain_get_secret_key()?.ok_or_else(|| {
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
    })
    .await
}

/// (New device) Join via a pairing payload: run the responder PAKE, install the
/// sealed keyset (opens the instance), persist a new cloud link (active), sign in.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn server_onboard_join(
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
    blocking_api(move || {
        let http = client::http();
        let code = client::unb64(&oob_code)?;
        onboard::responder_join(&core_pake, http, &base, &channel, code, password)
    })
    .await?;

    // 2) Persist a cloud link for the new device and make it active. Idempotent:
    // re-joining the same server reuses its existing link id (no duplicate). The
    // instance id + primary space are inherited from the initiator's pairing payload.
    let server_id = state
        .cloud
        .find_by_identity(&base_url, &instance_id, &account_id)
        .unwrap_or_else(new_server_id);
    state.cloud.upsert_config(ServerConfig {
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
    })?;

    // 3) Sign in (the shared keyset, now installed, signs the challenge).
    let session = blocking_api(move || {
        let http = client::http();
        identity::login(http, &base_url, &core, &account_id, &device_id)
    })
    .await?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token));
    persist_refresh(&server_id, &session.refresh_token);
    refresh_spaces_cache(&state, &server_id).await;
    Ok(state.cloud.status_for(Some(&server_id)))
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
        identity::audit_query(http, &cfg.base_url, &access, since_seq)
    })
    .await
}
