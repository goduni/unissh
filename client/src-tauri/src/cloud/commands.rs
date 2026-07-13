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
use uuid::Uuid;

use crate::cloud::config::{new_server_id, ServerConfig};
use crate::cloud::transport::HttpSyncTransport;
use crate::cloud::{client, identity, onboard, tokens, ServerList, ServerStatus};
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

/// Status of one server (defaults to the active server).
#[tauri::command]
pub async fn server_status(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<ServerStatus> {
    Ok(state.cloud.status_for(server_id.as_deref()))
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

    let (outcome, instance, session) = blocking_api(move || {
        let http = client::http();
        // The join response carries only account/device/spaces; the opaque
        // instance id (link identity) comes from the public instance descriptor.
        let instance = identity::instance_info(http, &base)?;
        let reg = core.build_registration_request().map_err(ApiError::from)?;
        // `binding_mac` is None for now — the server accepts a join without the
        // optional invite-binding proof; wiring the MAC is a later concern.
        let outcome = identity::join(http, &base, &invite_token, reg, None, dn, hd)?;
        let session = identity::login(http, &base, &core, &outcome.account_id, &outcome.device_id)?;
        Ok((outcome, instance, session))
    })
    .await?;

    // Bind cloud vaults on this link to the primary granted space (first entry).
    let space_id = outcome.spaces.first().cloned().unwrap_or_default();
    // Idempotent: re-joining the same server (same base_url + instance + account)
    // reuses its existing link id instead of minting a duplicate.
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
        handle,
        // Joiners are never instance owners.
        owned: false,
    })?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token));
    persist_refresh(&server_id, &session.refresh_token);
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

    let (outcome, session) = blocking_api(move || {
        let http = client::http();
        let reg = core.build_registration_request().map_err(ApiError::from)?;
        let outcome = identity::claim(http, &base, &code, reg, dn, hd, sn)?;
        let session = identity::login(http, &base, &core, &outcome.account_id, &outcome.device_id)?;
        Ok((outcome, session))
    })
    .await?;

    let server_id = state
        .cloud
        .find_by_identity(&base_url, &outcome.instance_id, &outcome.account_id)
        .unwrap_or_else(new_server_id);
    state.cloud.upsert_config(ServerConfig {
        server_id: server_id.clone(),
        base_url,
        instance_id: outcome.instance_id,
        space_id: outcome.space_id,
        account_id: outcome.account_id,
        device_id: outcome.device_id,
        handle,
        owned: true, // you claimed it → your instance + first Space (owner)
    })?;
    state
        .cloud
        .set_access_token_for(Some(&server_id), Some(session.access_token));
    persist_refresh(&server_id, &session.refresh_token);
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
/// active server) by its `space_id`. This is a LOCAL operation — the vault is
/// marked Cloud in local storage, bound to the server's space, and propagates to
/// THAT server on the next `server_sync_now`. Requires a linked server: with none,
/// `require_config` errors (the UI also gates the Cloud option behind a session).
/// Returns the vault id (hex).
#[tauri::command]
pub async fn server_create_cloud_vault(
    server_id: Option<String>,
    name: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let core = state.core.clone();
    blocking_api(move || {
        core.create_cloud_vault(name, cfg.space_id)
            .map_err(ApiError::from)
    })
    .await
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

// ---------- keyset escrow (Path A) ----------

/// Escrow this device's (already-encrypted) keyset blob to a server (defaults to
/// active), so another device can restore it. Returns the stored generation.
#[tauri::command]
pub async fn server_keyset_push(
    server_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<i64> {
    let cfg = require_config(&state, server_id.as_deref())?;
    let access = require_access(&state, server_id.as_deref())?;
    let keyset_path = state.keyset_path.clone();
    blocking_api(move || {
        let blob = std::fs::read(&keyset_path).map_err(|e| ApiError::Server {
            code: "keyset".into(),
            message: format!("read keyset sidecar: {e}"),
        })?;
        let http = client::http();
        identity::keyset_put(http, &cfg.base_url, &access, &blob)
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
