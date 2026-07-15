//! Tauri commands wrapping the `unissh_ffi::Core` facade.
//!
//! Every core method is synchronous/blocking (the core owns its own tokio
//! runtime + `block_on`), so each command offloads to a blocking thread via
//! `spawn_blocking` — calling `block_on` on Tauri's async worker would panic.
//! Long-lived objects (sessions/tunnels/sftp/broadcast) are stored in `AppState`
//! and addressed by a generated id.

use std::sync::Arc;
use tauri::ipc::Channel;
use tauri::{Manager, State};
use unissh_ffi::{
    BroadcastObserver, CancelToken, ExecObserver, FfiError, SessionObserver, SftpProgressObserver,
};

use crate::dto;
use crate::error::{ApiError, ApiResult};
use crate::observers::{
    BroadcastEvent, ChannelBroadcastObserver, ChannelExecObserver, ChannelSessionObserver,
    ChannelSftpProgress, ExecEvent, ProgressEvent, TermEvent,
};
use crate::state::{new_id, AppState, LiveSession};

// ---------- helpers ----------

/// Run a blocking, fallible core call off the async runtime.
pub(crate) async fn blocking<T, F>(f: F) -> ApiResult<T>
where
    F: FnOnce() -> Result<T, FfiError> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await?
        .map_err(ApiError::from)
}

/// Run a blocking, infallible core call off the async runtime.
async fn blocking_ok<T, F>(f: F) -> ApiResult<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Ok(tauri::async_runtime::spawn_blocking(f).await?)
}

fn conv_jumps(j: Vec<dto::JumpHost>) -> Vec<unissh_ffi::JumpHost> {
    j.into_iter().map(Into::into).collect()
}

// ---------- account / instance ----------

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceStatus {
    /// Both instance files present → ready to unlock / already unlocked.
    pub exists: bool,
    /// Exactly one of the two files present → inconsistent on disk. The UI must
    /// offer a repair/reset rather than a (doomed) unlock or a blocked onboarding.
    pub partial: bool,
    pub unlocked: bool,
    /// Whether the on-disk instance needs a master password to unlock. `None`
    /// when there's no readable keyset (no instance / partial). Lets the UI gate
    /// the "start unlocked" auto-unlock, which only works passwordless.
    pub requires_password: Option<bool>,
}

#[tauri::command]
pub async fn instance_status(state: State<'_, AppState>) -> ApiResult<InstanceStatus> {
    let exists = state.instance_exists();
    let partial = state.instance_partial();
    let core = state.core.clone();
    let (unlocked, requires_password) =
        blocking_ok(move || (core.is_unlocked(), core.instance_requires_password())).await?;
    Ok(InstanceStatus {
        exists,
        partial,
        unlocked,
        requires_password,
    })
}

/// Clear a half-written instance (exactly one of the DB / keyset present) so the
/// user can start fresh from onboarding. Hard-guarded so it can NEVER destroy a
/// complete or unlocked instance: it only ever removes stray files that cannot
/// form an openable instance anyway. Surfaced behind an explicit user confirm.
#[tauri::command]
pub async fn reset_partial_instance(state: State<'_, AppState>) -> ApiResult<()> {
    // Never touch a complete instance — that's real, recoverable data. Check this
    // FIRST and synchronously, so there is no `.await` window before the guard.
    if state.instance_exists() {
        return Err(ApiError::AlreadyExists);
    }
    let core = state.core.clone();
    if blocking_ok(move || core.is_unlocked()).await? {
        return Err(ApiError::other("refusing to reset an unlocked instance"));
    }
    // Re-check synchronously right before deleting (after the await): only a
    // still-partial instance is safe to clear. If a concurrent op completed the
    // instance in the meantime, refuse rather than destroy it; if both files are
    // already gone there's simply nothing to do.
    if state.instance_exists() {
        return Err(ApiError::AlreadyExists);
    }
    if !state.instance_partial() {
        return Ok(());
    }
    // Partial: clearing the stray file is the desired end state, so a missing-file
    // error (the other path was never written) is fine to ignore.
    let _ = std::fs::remove_file(&state.db_path);
    let _ = std::fs::remove_file(&state.keyset_path);
    Ok(())
}

/// Full, destructive reset of THIS device's instance — the "can't unlock → start
/// over" escape on the lock screen. Removes the encrypted DB + keyset (and the
/// pre-migration backup sidecar), forgets every linked cloud server, and drops the
/// stale OS-keychain Secret Key, so the next boot lands on a clean onboarding.
/// Refuses while the core is unlocked (you have access → no need to wipe; lock
/// first), so a misclick from inside the app can't destroy reachable data.
/// Idempotent: already-missing files are the desired end state.
#[tauri::command]
pub async fn reset_instance(state: State<'_, AppState>) -> ApiResult<()> {
    // Never wipe an instance the caller can actually open. Check synchronously
    // (no `.await` before it) so there is no unlocked->reset race window.
    let core = state.core.clone();
    if blocking_ok(move || core.is_unlocked()).await? {
        return Err(ApiError::other(
            "refusing to reset an unlocked instance — lock it first",
        ));
    }
    let _ = std::fs::remove_file(&state.db_path);
    let _ = std::fs::remove_file(&state.keyset_path);
    // The pre-migration keyset backup (`<keyset>.pre-migration.bak`), if present.
    let mut bak = state.keyset_path.clone().into_os_string();
    bak.push(".pre-migration.bak");
    let _ = std::fs::remove_file(std::path::PathBuf::from(bak));
    // Forget cloud links + the stale keychain Secret Key so re-onboarding is clean.
    state.cloud.clear_all();
    let _ = crate::keychain::keychain_delete_secret_key();
    Ok(())
}

/// Absolute path to the per-OS application log directory (where the rotating log
/// file lives). Shown in Settings so the user can find their logs.
#[tauri::command]
pub fn log_dir(app: tauri::AppHandle) -> ApiResult<String> {
    let dir = app.path().app_log_dir().map_err(ApiError::other)?;
    Ok(dir.to_string_lossy().to_string())
}

/// Open the log directory in the OS file manager. Desktop only — spawns the
/// platform opener on the app's OWN log dir (a fixed, non-user-controlled path)
/// and returns at once. Mobile has no user-facing file manager for the app's
/// sandboxed log dir, so it reports that plainly instead of spawning a missing
/// `xdg-open`.
#[cfg(not(mobile))]
#[tauri::command]
pub fn reveal_log_dir(app: tauri::AppHandle) -> ApiResult<()> {
    let dir = app.path().app_log_dir().map_err(ApiError::other)?;
    std::fs::create_dir_all(&dir).ok();
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(&dir)
        .spawn()
        .map_err(ApiError::other)?;
    Ok(())
}

#[cfg(mobile)]
#[tauri::command]
pub fn reveal_log_dir(_app: tauri::AppHandle) -> ApiResult<()> {
    Err(ApiError::other(
        "opening the log folder is only available on desktop",
    ))
}

#[tauri::command]
pub async fn create_account(
    password: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.create_account(password)).await
}

#[tauri::command]
pub async fn unlock(
    password: Option<String>,
    secret_key_hex: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.unlock(password, secret_key_hex)).await
}

#[tauri::command]
pub async fn lock(state: State<'_, AppState>) -> ApiResult<()> {
    // Drop every live object first (sessions/tunnels/sftp close on drop).
    state.sessions.clear();
    state.tunnels.clear();
    state.sftp.clear();
    state.broadcasts.clear();
    state.exec_handles.clear();
    let core = state.core.clone();
    blocking_ok(move || core.lock()).await
}

#[tauri::command]
pub async fn is_unlocked(state: State<'_, AppState>) -> ApiResult<bool> {
    let core = state.core.clone();
    blocking_ok(move || core.is_unlocked()).await
}

/// Set the SSH keepalive interval (seconds) for subsequent connections; 0 = off.
/// Cheap (an atomic store), so no need to hop onto the blocking pool.
#[tauri::command]
pub async fn set_keepalive_secs(secs: u64, state: State<'_, AppState>) -> ApiResult<()> {
    state.core.set_keepalive_secs(secs);
    Ok(())
}

#[tauri::command]
pub async fn change_password(
    old_password: Option<String>,
    new_password: Option<String>,
    secret_key_hex: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.change_password(old_password, new_password, secret_key_hex)).await
}

// ---------- vaults ----------

#[tauri::command]
pub async fn list_vaults(state: State<'_, AppState>) -> ApiResult<Vec<dto::VaultInfo>> {
    let core = state.core.clone();
    let v = blocking(move || core.list_vaults()).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn create_vault(
    vault_id: String,
    name: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.create_vault(vault_id, name)).await
}

#[tauri::command]
pub async fn rename_vault(
    vault_id: String,
    new_name: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.rename_vault(vault_id, new_name)).await
}

#[tauri::command]
pub async fn delete_vault(vault_id: String, state: State<'_, AppState>) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.delete_vault(vault_id)).await
}

// ---------- vault integrity / maintenance ----------

#[tauri::command]
pub async fn verify_vault_integrity(
    vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::VaultIntegrityReport> {
    let core = state.core.clone();
    let r = blocking(move || core.verify_vault_integrity(vault_id)).await?;
    Ok(r.into())
}

#[tauri::command]
pub async fn check_consistency(state: State<'_, AppState>) -> ApiResult<dto::DbConsistencyReport> {
    let core = state.core.clone();
    let r = blocking(move || core.check_consistency()).await?;
    Ok(r.into())
}

#[tauri::command]
pub async fn purge_vault(vault_id: String, state: State<'_, AppState>) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.purge_vault(vault_id)).await
}

#[tauri::command]
pub async fn account_id(state: State<'_, AppState>) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.account_id()).await
}

// ---------- items: keys / certs ----------

#[tauri::command]
pub async fn list_items(
    vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::ItemInfo>> {
    let core = state.core.clone();
    let v = blocking(move || core.list_items(vault_id)).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn generate_ssh_key(
    vault_id: String,
    item_id: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.generate_ssh_key(vault_id, item_id)).await
}

#[tauri::command]
pub async fn import_ssh_key(
    vault_id: String,
    item_id: String,
    openssh_private: String,
    passphrase: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.import_ssh_key(vault_id, item_id, openssh_private, passphrase)).await
}

#[tauri::command]
pub async fn import_ssh_certificate(
    vault_id: String,
    key_item_id: String,
    cert_openssh: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.import_ssh_certificate(vault_id, key_item_id, cert_openssh)).await
}

#[tauri::command]
pub async fn get_public_key(
    vault_id: String,
    item_id: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::PublicKeyInfo> {
    let core = state.core.clone();
    let p = blocking(move || core.get_public_key(vault_id, item_id)).await?;
    Ok(p.into())
}

/// Export the private OpenSSH key of an item (backup/migration). The UI gates
/// this behind an explicit confirmation and writes it to a user-chosen file.
#[tauri::command]
pub async fn export_ssh_key(
    vault_id: String,
    item_id: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.export_ssh_key(vault_id, item_id)).await
}

/// Rotate an SSH key in place (same item id): regenerate the keypair so every
/// host referencing it follows along. Returns the new public key to install.
#[tauri::command]
pub async fn rotate_ssh_key(
    vault_id: String,
    item_id: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.rotate_ssh_key(vault_id, item_id)).await
}

#[tauri::command]
pub async fn rename_item(
    vault_id: String,
    item_id: String,
    new_item_id: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.rename_item(vault_id, item_id, new_item_id)).await
}

#[tauri::command]
pub async fn delete_item(
    vault_id: String,
    item_id: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.delete_item(vault_id, item_id)).await
}

#[tauri::command]
pub async fn list_item_versions(
    vault_id: String,
    item_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<u64>> {
    let core = state.core.clone();
    blocking(move || core.list_item_versions(vault_id, item_id)).await
}

// ---------- passwords (type-gated reveal) ----------

#[tauri::command]
pub async fn save_password(
    vault_id: String,
    item_id: String,
    password: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.save_password(vault_id, item_id, password)).await
}

#[tauri::command]
pub async fn get_password(
    vault_id: String,
    item_id: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.get_password(vault_id, item_id)).await
}

#[tauri::command]
pub async fn get_password_version(
    vault_id: String,
    item_id: String,
    version: u64,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.get_password_version(vault_id, item_id, version)).await
}

// ---------- notes ----------

#[tauri::command]
pub async fn save_note(
    vault_id: String,
    item_id: String,
    text: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.save_note(vault_id, item_id, text)).await
}

#[tauri::command]
pub async fn get_note(
    vault_id: String,
    item_id: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.get_note(vault_id, item_id)).await
}

#[tauri::command]
pub async fn get_note_version(
    vault_id: String,
    item_id: String,
    version: u64,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.get_note_version(vault_id, item_id, version)).await
}

// ---------- known hosts / TOFU ----------

#[tauri::command]
pub async fn list_known_hosts(state: State<'_, AppState>) -> ApiResult<Vec<dto::KnownHostInfo>> {
    let core = state.core.clone();
    let v = blocking(move || core.list_known_hosts()).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn forget_host(host: String, port: u16, state: State<'_, AppState>) -> ApiResult<bool> {
    let core = state.core.clone();
    blocking(move || core.forget_host(host, port)).await
}

#[tauri::command]
pub async fn trust_host(
    host: String,
    port: u16,
    expected_fingerprint: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.trust_host(host, port, expected_fingerprint)).await
}

#[tauri::command]
pub async fn import_known_hosts(
    text: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::KnownHostsImport> {
    let core = state.core.clone();
    let r = blocking(move || core.import_known_hosts(text)).await?;
    Ok(r.into())
}

// ---------- connection profiles (hosts) ----------

#[tauri::command]
pub async fn save_connection(
    vault_id: String,
    profile: dto::ConnectionProfile,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    let p = profile.into();
    blocking(move || core.save_connection(vault_id, p)).await
}

#[tauri::command]
pub async fn list_connections(
    vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::ConnectionProfile>> {
    let core = state.core.clone();
    let v = blocking(move || core.list_connections(vault_id)).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn get_connection(
    vault_id: String,
    profile_id: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::ConnectionProfile> {
    let core = state.core.clone();
    let p = blocking(move || core.get_connection(vault_id, profile_id)).await?;
    Ok(p.into())
}

#[tauri::command]
pub async fn delete_connection(
    vault_id: String,
    profile_id: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.delete_connection(vault_id, profile_id)).await
}

// ---------- identities (personal SSH creds) ----------

#[tauri::command]
pub async fn save_identity(
    vault_id: String,
    identity: dto::Identity,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    let i = identity.into();
    blocking(move || core.save_identity(vault_id, i)).await
}

#[tauri::command]
pub async fn list_identities(
    vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::Identity>> {
    let core = state.core.clone();
    let v = blocking(move || core.list_identities(vault_id)).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn get_identity(
    vault_id: String,
    identity_id: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::Identity> {
    let core = state.core.clone();
    let i = blocking(move || core.get_identity(vault_id, identity_id)).await?;
    Ok(i.into())
}

#[tauri::command]
pub async fn delete_identity(
    vault_id: String,
    identity_id: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.delete_identity(vault_id, identity_id)).await
}

// ---------- identity bindings (personal vault ↔ shared host) ----------

#[tauri::command]
pub async fn set_binding(
    personal_vault_id: String,
    binding: dto::IdentityBinding,
    allow_rebind: bool,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    let b = binding.into();
    blocking(move || core.set_binding(personal_vault_id, b, allow_rebind)).await
}

#[tauri::command]
pub async fn get_binding(
    personal_vault_id: String,
    team_vault_id: String,
    profile_uid: String,
    state: State<'_, AppState>,
) -> ApiResult<Option<dto::IdentityBinding>> {
    let core = state.core.clone();
    let b =
        blocking(move || core.get_binding(personal_vault_id, team_vault_id, profile_uid)).await?;
    Ok(b.map(Into::into))
}

#[tauri::command]
pub async fn list_bindings(
    personal_vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::IdentityBinding>> {
    let core = state.core.clone();
    let v = blocking(move || core.list_bindings(personal_vault_id)).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn delete_binding(
    personal_vault_id: String,
    team_vault_id: String,
    profile_uid: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.delete_binding(personal_vault_id, team_vault_id, profile_uid)).await
}

#[tauri::command]
pub async fn resolve_host_binding(
    personal_vault_id: String,
    team_vault_id: String,
    profile_uid: String,
    current_destination: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::BindingResolution> {
    let core = state.core.clone();
    let r = blocking(move || {
        core.resolve_host_binding(
            personal_vault_id,
            team_vault_id,
            profile_uid,
            current_destination,
        )
    })
    .await?;
    Ok(r.into())
}

#[tauri::command]
pub async fn resolve_personal_auth(
    team_vault_id: String,
    profile_uid: String,
    current_destination: String,
    profile_user_fallback: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::PersonalAuth> {
    let core = state.core.clone();
    let p = blocking(move || {
        core.resolve_personal_auth(
            team_vault_id,
            profile_uid,
            current_destination,
            profile_user_fallback,
        )
    })
    .await?;
    Ok(p.into())
}

// Pure string renderers (no lock, no IO) — call directly. Exposed so the client
// renders the anti-redirect destination the SAME way for bind-pin and connect.
#[tauri::command]
pub async fn personal_destination(
    host: String,
    port: u16,
    username_template: Option<String>,
    jumps: Vec<dto::JumpHost>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    // jumps are part of the pin (anti-redirect along the ProxyJump chain) — we convert them into
    // the core type with the same conv_jumps as save_connection/connect.
    Ok(state
        .core
        .personal_destination(host, port, username_template, conv_jumps(jumps)))
}

#[tauri::command]
pub async fn apply_username_template(
    base_user: String,
    username_template: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    Ok(state
        .core
        .apply_username_template(base_user, username_template))
}

#[tauri::command]
pub async fn import_ssh_config(
    vault_id: String,
    config_text: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<String>> {
    let core = state.core.clone();
    blocking(move || core.import_ssh_config(vault_id, config_text)).await
}

#[tauri::command]
pub async fn export_ssh_config(vault_id: String, state: State<'_, AppState>) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.export_ssh_config(vault_id)).await
}

#[tauri::command]
pub async fn import_putty_sessions(
    vault_id: String,
    reg_text: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::HostImportReport> {
    let core = state.core.clone();
    let r = blocking(move || core.import_putty_sessions(vault_id, reg_text)).await?;
    Ok(r.into())
}

// ---------- groups ----------

#[tauri::command]
pub async fn save_group(
    vault_id: String,
    group: dto::ServerGroup,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    let g = group.into();
    blocking(move || core.save_group(vault_id, g)).await
}

#[tauri::command]
pub async fn list_groups(
    vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::ServerGroup>> {
    let core = state.core.clone();
    let v = blocking(move || core.list_groups(vault_id)).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn get_group(
    vault_id: String,
    group_id: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::ServerGroup> {
    let core = state.core.clone();
    let g = blocking(move || core.get_group(vault_id, group_id)).await?;
    Ok(g.into())
}

#[tauri::command]
pub async fn delete_group(
    vault_id: String,
    group_id: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.delete_group(vault_id, group_id)).await
}

#[tauri::command]
pub async fn dry_run_group(
    vault_id: String,
    group_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::GroupTargetPlan>> {
    let core = state.core.clone();
    let v = blocking(move || core.dry_run_group(vault_id, group_id)).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

// ---------- exec (one-shot / fleet) ----------

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn ssh_exec(
    host: String,
    port: u16,
    user: String,
    auth: dto::AuthMethod,
    command: String,
    jumps: Vec<dto::JumpHost>,
    state: State<'_, AppState>,
) -> ApiResult<dto::SshExecResult> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let r = blocking(move || core.ssh_exec(host, port, user, auth, command, jumps)).await?;
    Ok(r.into())
}

#[tauri::command]
pub async fn ssh_exec_multi(
    targets: Vec<dto::MultiExecTarget>,
    command: String,
    max_concurrency: u32,
    timeout_secs: u32,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::MultiExecResult>> {
    let core = state.core.clone();
    let targets: Vec<unissh_ffi::MultiExecTarget> = targets.into_iter().map(Into::into).collect();
    let v = blocking(move || core.ssh_exec_multi(targets, command, max_concurrency, timeout_secs))
        .await?;
    Ok(v.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn ssh_exec_by_tags(
    vault_id: String,
    tags: Vec<String>,
    match_all: bool,
    command: String,
    max_concurrency: u32,
    timeout_secs: u32,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::MultiExecResult>> {
    let core = state.core.clone();
    let v = blocking(move || {
        core.ssh_exec_by_tags(
            vault_id,
            tags,
            match_all,
            command,
            max_concurrency,
            timeout_secs,
        )
    })
    .await?;
    Ok(v.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn ssh_exec_group(
    vault_id: String,
    group_id: String,
    command: String,
    max_concurrency: u32,
    timeout_secs: u32,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::MultiExecResult>> {
    let core = state.core.clone();
    let v = blocking(move || {
        core.ssh_exec_group(vault_id, group_id, command, max_concurrency, timeout_secs)
    })
    .await?;
    Ok(v.into_iter().map(Into::into).collect())
}

// ---------- streaming exec ----------

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn exec_stream_open(
    host: String,
    port: u16,
    user: String,
    auth: dto::AuthMethod,
    command: String,
    jumps: Vec<dto::JumpHost>,
    on_event: Channel<ExecEvent>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let obs: Arc<dyn ExecObserver> = Arc::new(ChannelExecObserver { chan: on_event });
    let handle =
        blocking(move || core.ssh_exec_stream(host, port, user, auth, command, jumps, obs)).await?;
    let id = new_id();
    state.exec_handles.insert(id.clone(), handle);
    Ok(id)
}

#[tauri::command]
pub async fn exec_stream_write(
    id: String,
    data: Vec<u8>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let h = state
        .exec_handles
        .get(&id)
        .ok_or_else(|| ApiError::not_found("exec handle"))?
        .clone();
    blocking(move || h.write_stdin(data)).await
}

#[tauri::command]
pub async fn exec_stream_close(id: String, state: State<'_, AppState>) -> ApiResult<()> {
    if let Some((_, h)) = state.exec_handles.remove(&id) {
        blocking(move || h.close()).await?;
    }
    Ok(())
}

// ---------- interactive PTY sessions ----------

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn session_open(
    host: String,
    port: u16,
    user: String,
    auth: dto::AuthMethod,
    jumps: Vec<dto::JumpHost>,
    term: String,
    cols: u32,
    rows: u32,
    on_event: Channel<TermEvent>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let obs: Arc<dyn SessionObserver> = Arc::new(ChannelSessionObserver { chan: on_event });
    let session =
        blocking(move || core.open_session(host, port, user, auth, jumps, term, cols, rows, obs))
            .await?;
    let id = new_id();
    state
        .sessions
        .insert(id.clone(), LiveSession::Plain(session));
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn session_open_reconnecting(
    host: String,
    port: u16,
    user: String,
    auth: dto::AuthMethod,
    jumps: Vec<dto::JumpHost>,
    term: String,
    cols: u32,
    rows: u32,
    max_retries: u32,
    backoff_ms: u32,
    on_event: Channel<TermEvent>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let obs: Arc<dyn SessionObserver> = Arc::new(ChannelSessionObserver { chan: on_event });
    let session = blocking(move || {
        core.open_reconnecting_session(
            host,
            port,
            user,
            auth,
            jumps,
            term,
            cols,
            rows,
            max_retries,
            backoff_ms,
            obs,
        )
    })
    .await?;
    let id = new_id();
    state
        .sessions
        .insert(id.clone(), LiveSession::Reconnecting(session));
    Ok(id)
}

#[tauri::command]
pub async fn session_write(id: String, data: Vec<u8>, state: State<'_, AppState>) -> ApiResult<()> {
    // Clone the handle out so the DashMap shard lock isn't held across the call.
    let s = state
        .sessions
        .get(&id)
        .ok_or_else(|| ApiError::not_found("session"))?
        .value()
        .clone();
    // Core write drives the session's own tokio runtime via block_on, which would
    // panic on Tauri's async worker — offload to a blocking thread like every other
    // core call (this is why typed input never reached the PTY before).
    blocking(move || s.write(data)).await
}

#[tauri::command]
pub async fn session_resize(
    id: String,
    cols: u32,
    rows: u32,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = state
        .sessions
        .get(&id)
        .ok_or_else(|| ApiError::not_found("session"))?
        .value()
        .clone();
    // Same blocking-thread offload as session_write (core resize uses block_on too).
    blocking(move || s.resize(cols, rows)).await
}

#[tauri::command]
pub async fn session_close(id: String, state: State<'_, AppState>) -> ApiResult<()> {
    if let Some((_, s)) = state.sessions.remove(&id) {
        blocking_ok(move || s.close()).await?;
    }
    Ok(())
}

// ---------- broadcast (cluster-ssh) ----------

#[tauri::command]
pub async fn broadcast_open(
    targets: Vec<dto::MultiExecTarget>,
    term: String,
    cols: u32,
    rows: u32,
    on_event: Channel<BroadcastEvent>,
    state: State<'_, AppState>,
) -> ApiResult<dto::OpenedBroadcast> {
    let core = state.core.clone();
    let targets: Vec<unissh_ffi::MultiExecTarget> = targets.into_iter().map(Into::into).collect();
    let obs: Arc<dyn BroadcastObserver> = Arc::new(ChannelBroadcastObserver { chan: on_event });
    let session = blocking(move || core.open_broadcast(targets, term, cols, rows, obs)).await?;
    let statuses = session.statuses().into_iter().map(Into::into).collect();
    let id = new_id();
    state.broadcasts.insert(id.clone(), session);
    Ok(dto::OpenedBroadcast { id, statuses })
}

#[tauri::command]
pub async fn broadcast_write_all(
    id: String,
    data: Vec<u8>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = state
        .broadcasts
        .get(&id)
        .ok_or_else(|| ApiError::not_found("broadcast"))?
        .clone();
    blocking(move || s.write_all(data)).await
}

#[tauri::command]
pub async fn broadcast_resize_all(
    id: String,
    cols: u32,
    rows: u32,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = state
        .broadcasts
        .get(&id)
        .ok_or_else(|| ApiError::not_found("broadcast"))?
        .clone();
    blocking(move || s.resize_all(cols, rows)).await
}

#[tauri::command]
pub async fn broadcast_close(id: String, state: State<'_, AppState>) -> ApiResult<()> {
    if let Some((_, s)) = state.broadcasts.remove(&id) {
        blocking_ok(move || s.close()).await?;
    }
    Ok(())
}

// ---------- tunnels (port forwarding) ----------

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn tunnel_open_local(
    host: String,
    port: u16,
    user: String,
    auth: dto::AuthMethod,
    jumps: Vec<dto::JumpHost>,
    local_bind: String,
    remote_host: String,
    remote_port: u16,
    state: State<'_, AppState>,
) -> ApiResult<dto::OpenedTunnel> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let t = blocking(move || {
        core.open_local_forward(
            host,
            port,
            user,
            auth,
            jumps,
            local_bind,
            remote_host,
            remote_port,
        )
    })
    .await?;
    let bind_address = t.bind_address();
    let id = new_id();
    state.tunnels.insert(id.clone(), t);
    Ok(dto::OpenedTunnel { id, bind_address })
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn tunnel_open_dynamic(
    host: String,
    port: u16,
    user: String,
    auth: dto::AuthMethod,
    jumps: Vec<dto::JumpHost>,
    local_bind: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::OpenedTunnel> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let t = blocking(move || core.open_dynamic_forward(host, port, user, auth, jumps, local_bind))
        .await?;
    let bind_address = t.bind_address();
    let id = new_id();
    state.tunnels.insert(id.clone(), t);
    Ok(dto::OpenedTunnel { id, bind_address })
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn tunnel_open_remote(
    host: String,
    port: u16,
    user: String,
    auth: dto::AuthMethod,
    jumps: Vec<dto::JumpHost>,
    remote_bind: String,
    remote_port: u16,
    local_host: String,
    local_port: u16,
    state: State<'_, AppState>,
) -> ApiResult<dto::OpenedTunnel> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let t = blocking(move || {
        core.open_remote_forward(
            host,
            port,
            user,
            auth,
            jumps,
            remote_bind,
            remote_port,
            local_host,
            local_port,
        )
    })
    .await?;
    let bind_address = t.bind_address();
    let id = new_id();
    state.tunnels.insert(id.clone(), t);
    Ok(dto::OpenedTunnel { id, bind_address })
}

#[tauri::command]
pub async fn tunnel_close(id: String, state: State<'_, AppState>) -> ApiResult<()> {
    if let Some((_, t)) = state.tunnels.remove(&id) {
        blocking_ok(move || t.close()).await?;
    }
    Ok(())
}

// ---------- SFTP ----------

#[tauri::command]
pub async fn sftp_open(
    host: String,
    port: u16,
    user: String,
    auth: dto::AuthMethod,
    jumps: Vec<dto::JumpHost>,
    parallelism: u32,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let sftp = blocking(move || core.open_sftp(host, port, user, auth, jumps, parallelism)).await?;
    let id = new_id();
    state.sftp.insert(id.clone(), sftp);
    Ok(id)
}

fn get_sftp(state: &AppState, id: &str) -> ApiResult<Arc<unissh_ffi::SftpFfi>> {
    Ok(state
        .sftp
        .get(id)
        .ok_or_else(|| ApiError::not_found("sftp"))?
        .clone())
}

#[tauri::command]
pub async fn sftp_list_dir(
    id: String,
    path: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::SftpEntry>> {
    let s = get_sftp(&state, &id)?;
    let v = blocking(move || s.list_dir(path)).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

/// List a LOCAL directory in one shot (name + is_dir + size + mtime), avoiding
/// the readDir + per-file stat IPC fan-out the client would otherwise do.
#[tauri::command]
pub async fn local_list_dir(path: String) -> ApiResult<Vec<dto::LocalEntry>> {
    tauri::async_runtime::spawn_blocking(move || -> ApiResult<Vec<dto::LocalEntry>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&path).map_err(ApiError::other)? {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name().to_string_lossy().into_owned();
            let md = entry.metadata().ok();
            let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = md.as_ref().map(|m| m.len()).unwrap_or(0);
            let mtime = md
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            out.push(dto::LocalEntry {
                name,
                is_dir,
                size,
                mtime,
            });
        }
        Ok(out)
    })
    .await?
}

#[tauri::command]
pub async fn sftp_stat(
    id: String,
    path: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::SftpFileStat> {
    let s = get_sftp(&state, &id)?;
    let st = blocking(move || s.stat(path)).await?;
    Ok(st.into())
}

#[tauri::command]
pub async fn sftp_realpath(
    id: String,
    path: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let s = get_sftp(&state, &id)?;
    blocking(move || s.realpath(path)).await
}

/// Re-open a dropped SFTP channel on the (still-live) SSH connection.
#[tauri::command]
pub async fn sftp_reopen(id: String, state: State<'_, AppState>) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    blocking(move || s.reopen()).await
}

#[tauri::command]
pub async fn sftp_mkdir(id: String, path: String, state: State<'_, AppState>) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    blocking(move || s.mkdir(path)).await
}

#[tauri::command]
pub async fn sftp_rmdir(id: String, path: String, state: State<'_, AppState>) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    blocking(move || s.rmdir(path)).await
}

#[tauri::command]
pub async fn sftp_rmdir_recursive(
    id: String,
    path: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    blocking(move || s.rmdir_recursive(path)).await
}

#[tauri::command]
pub async fn sftp_remove(id: String, path: String, state: State<'_, AppState>) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    blocking(move || s.remove(path)).await
}

#[tauri::command]
pub async fn sftp_rename(
    id: String,
    from: String,
    to: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    blocking(move || s.rename(from, to)).await
}

/// chmod a remote path (low 12 mode bits).
#[tauri::command]
pub async fn sftp_chmod(
    id: String,
    path: String,
    mode: u32,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    blocking(move || s.chmod(path, mode)).await
}

#[tauri::command]
pub async fn sftp_read_file(
    id: String,
    path: String,
    state: State<'_, AppState>,
) -> ApiResult<tauri::ipc::Response> {
    let s = get_sftp(&state, &id)?;
    let bytes = blocking(move || s.read_file(path)).await?;
    Ok(tauri::ipc::Response::new(bytes))
}

#[tauri::command]
pub async fn sftp_write_file(
    id: String,
    path: String,
    data: Vec<u8>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    blocking(move || s.write_file(path, data)).await
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn sftp_download(
    id: String,
    remote_path: String,
    local_path: String,
    offset: u64,
    known_size: Option<u64>,
    on_progress: Channel<ProgressEvent>,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<bool> {
    let s = get_sftp(&state, &id)?;
    let cancel = cancel_id.and_then(|cid| state.cancels.get(&cid).map(|c| c.clone()));
    let progress: Option<Arc<dyn SftpProgressObserver>> =
        Some(Arc::new(ChannelSftpProgress { chan: on_progress }));
    blocking(move || {
        s.sftp_download(
            remote_path,
            local_path,
            offset,
            known_size,
            progress,
            cancel,
        )
    })
    .await
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn sftp_upload(
    id: String,
    local_path: String,
    remote_path: String,
    offset: u64,
    on_progress: Channel<ProgressEvent>,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<bool> {
    let s = get_sftp(&state, &id)?;
    let cancel = cancel_id.and_then(|cid| state.cancels.get(&cid).map(|c| c.clone()));
    let progress: Option<Arc<dyn SftpProgressObserver>> =
        Some(Arc::new(ChannelSftpProgress { chan: on_progress }));
    blocking(move || s.sftp_upload(local_path, remote_path, offset, progress, cancel)).await
}

#[tauri::command]
pub async fn sftp_close(id: String, state: State<'_, AppState>) -> ApiResult<()> {
    if let Some((_, s)) = state.sftp.remove(&id) {
        blocking_ok(move || s.close()).await?;
    }
    Ok(())
}

// ---------- cancel tokens (for resumable transfers) ----------

#[tauri::command]
pub fn cancel_new(state: State<'_, AppState>) -> String {
    let token = CancelToken::new();
    let id = new_id();
    state.cancels.insert(id.clone(), token);
    id
}

#[tauri::command]
pub fn cancel_trigger(id: String, state: State<'_, AppState>) {
    if let Some(t) = state.cancels.get(&id) {
        t.cancel();
    }
}

#[tauri::command]
pub fn cancel_dispose(id: String, state: State<'_, AppState>) {
    state.cancels.remove(&id);
}
