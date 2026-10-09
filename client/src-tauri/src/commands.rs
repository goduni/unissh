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
    BroadcastObserver, CancelToken, ExecObserver, FfiAlgorithmPolicy, FfiError, SessionObserver,
    SftpProgressObserver,
};

use crate::dto;
use crate::error::{ApiError, ApiResult};
use crate::observers::{
    AppApprover, AppPrompter, BroadcastEvent, ChannelBroadcastObserver, ChannelExecObserver,
    ChannelSessionObserver, ChannelSftpProgress, ExecEvent, ProgressEvent, TermEvent,
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

/// Run blocking wrapper-level work (keychain, biometric prompt, files) off the
/// async runtime and the main thread. The one copy of this helper: keychain
/// and biometric commands both need it, and a prompt served by the main loop
/// must never be waited on from that loop.
pub(crate) async fn blocking_api<T, F>(f: F) -> ApiResult<T>
where
    F: FnOnce() -> ApiResult<T> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f).await?
}

/// What every successful unlock does next, however it was asked for (typed
/// password, trusted-device keychain, biometric, server restore) and on a
/// screen unlock or wake: give paused MCP and system-agent access back.
pub(crate) fn resume_after_unlock(app: &tauri::AppHandle) {
    #[cfg(desktop)]
    {
        crate::mcp::resume_access(app);
        crate::system_agent::resume_access(app);
    }
    #[cfg(mobile)]
    let _ = app;
}

/// The counterpart for lock, reset, screen lock and sleep: pause MCP and
/// system-agent access.
pub(crate) fn revoke_agent_access(app: &tauri::AppHandle) {
    #[cfg(desktop)]
    {
        crate::mcp::revoke(app);
        crate::system_agent::revoke(app);
    }
    #[cfg(mobile)]
    let _ = app;
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

fn conv_proxy(p: Option<dto::ProxyConfig>) -> Option<unissh_ffi::ProxyConfig> {
    p.map(Into::into)
}

// ---------- account / instance ----------

#[tauri::command]
pub async fn terminal_workspace_load(
    state: State<'_, AppState>,
) -> ApiResult<(u64, Option<String>)> {
    let core = state.core.clone();
    blocking(move || core.terminal_workspace_load()).await
}

#[tauri::command]
pub async fn terminal_workspace_save(
    epoch: u64,
    document: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.terminal_workspace_save(epoch, document)).await
}

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
pub async fn reset_partial_instance(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    revoke_agent_access(&app);
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
pub async fn reset_instance(app: tauri::AppHandle, state: State<'_, AppState>) -> ApiResult<()> {
    revoke_agent_access(&app);
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
    let _ = crate::keychain::keychain_delete_secret_key().await;
    // And biometric unlock: the sealed password beside the keyset and its
    // device secret in the platform store. Idempotent, best-effort like the rest.
    let blob = crate::biometric::blob_path(&state);
    let _ = blocking_api(move || crate::biometric::forget_now(&blob)).await;
    Ok(())
}

/// True when the session is run by a tiling window manager.
///
/// Decides only the DEFAULT for the custom window chrome, never the final answer
/// — an explicit user choice always wins (see `lsCustomChrome` on the JS side).
/// Under a tiling WM the app's own title bar is worse than useless: it spends a
/// row of a deliberately dense layout on a drag handle that cannot drag, next to
/// buttons for maximize and minimize that the compositor does not implement, in
/// a session whose whole premise is that the user closes windows from the
/// keyboard. Every other desktop keeps the current look.
///
/// Detected from the environment rather than by asking the compositor: each of
/// these exports something unmistakable, and a wrong guess is cosmetic and
/// one toggle away from being fixed. The socket variables come first because
/// they are set by the compositor process itself; XDG_CURRENT_DESKTOP is a
/// fallback since a display manager can rewrite it.
///
/// No cfg gate and no mobile twin, unlike `reveal_log_dir` below: this reads
/// nothing but environment variables, so one body is correct everywhere and
/// simply answers `false` off Linux.
#[tauri::command]
pub fn tiling_session() -> bool {
    if !cfg!(target_os = "linux") && !cfg!(target_os = "freebsd") {
        return false;
    }
    let has = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    if has("NIRI_SOCKET") || has("SWAYSOCK") || has("HYPRLAND_INSTANCE_SIGNATURE") || has("I3SOCK")
    {
        return true;
    }
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .or_else(|_| std::env::var("XDG_SESSION_DESKTOP"))
        .or_else(|_| std::env::var("DESKTOP_SESSION"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    [
        "niri",
        "sway",
        "hyprland",
        "river",
        "wayfire",
        "dwl",
        "i3",
        "bspwm",
        "xmonad",
        "awesome",
        "qtile",
        "dwm",
        "herbstluftwm",
        "leftwm",
        "spectrwm",
    ]
    .iter()
    .any(|wm| desktop.split(':').any(|part| part.trim() == *wm))
}

/// The front end reporting that it has finished handling a `system-lock` suspend
/// signal — locked, or decided not to.
///
/// This is what lets the machine actually go to sleep: the Linux listener is
/// holding a logind delay inhibitor and the Windows one is sitting in its window
/// proc, and both release on this. It must therefore be called for EVERY suspend
/// signal, including one the user's settings say to ignore, or a suspend waits
/// out the full timeout for nothing.
///
/// `token` is the one the `system-lock` event carried. Answers naming a suspend
/// that is already over are dropped rather than released onto the current one.
#[tauri::command]
pub fn system_lock_ack(token: u64) {
    #[cfg(desktop)]
    crate::system_lock::ack(token);
    #[cfg(not(desktop))]
    let _ = token;
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
    // A new keyset: nothing left from an earlier instance may unlock it.
    let (secret_key, _) = blocking_api(crate::biometric::installing_keyset(&state, move || {
        Ok(core.create_account(password)?)
    }))
    .await?;
    Ok(secret_key)
}

#[tauri::command]
pub async fn unlock(
    app: tauri::AppHandle,
    password: Option<String>,
    secret_key_hex: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.unlock(password, secret_key_hex)).await?;
    resume_after_unlock(&app);
    Ok(())
}

#[tauri::command]
pub async fn lock(app: tauri::AppHandle, state: State<'_, AppState>) -> ApiResult<()> {
    revoke_agent_access(&app);
    // Drop every live object first (sessions/tunnels/sftp close on drop).
    state.sessions.clear();
    state.tunnels.clear();
    invalidate_sftp(&state);
    state.broadcasts.clear();
    state.exec_handles.clear();
    let core = state.core.clone();
    let result = blocking_ok(move || core.lock()).await;
    invalidate_sftp(&state);
    result
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
pub async fn list_recordings(
    vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::RecordingMeta>> {
    let core = state.core.clone();
    let v = blocking(move || core.list_recordings(vault_id)).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

/// The asciicast v2 document — for replay in-app or export to a file.
#[tauri::command]
pub async fn get_recording(
    vault_id: String,
    recording_id: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.get_recording(vault_id, recording_id)).await
}

#[tauri::command]
pub async fn delete_recording(
    vault_id: String,
    recording_id: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.delete_recording(vault_id, recording_id)).await
}

/// Answers a forwarded agent's request to sign.
///
/// Refusal is the default everywhere in this path: an unanswered prompt, a dead
/// window, a timeout — all decline.
#[tauri::command]
pub async fn submit_agent_approval(
    id: u64,
    approved: bool,
    approver: State<'_, Arc<AppApprover>>,
) -> ApiResult<()> {
    approver.answer(id, approved);
    Ok(())
}

/// Keys the OS ssh-agent currently holds — the picker's data source.
///
/// Needs no unlock: this reads the agent, not the vault.
#[tauri::command]
pub async fn system_agent_keys(state: State<'_, AppState>) -> ApiResult<Vec<dto::SystemAgentKey>> {
    let core = state.core.clone();
    let v = blocking(move || core.system_agent_keys()).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

/// What an ~/.ssh/config import would drop. Read-only: it parses the text and
/// writes nothing, so the user can see the damage before agreeing to it.
#[tauri::command]
pub async fn ssh_config_report(
    config_text: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::SshConfigReport> {
    let core = state.core.clone();
    Ok(blocking(move || core.ssh_config_report(config_text))
        .await?
        .into())
}

/// The same report for a config **file**, whose `Include` directives are
/// followed. Read-only, and it reads more than the one file it was given — every
/// file it touched comes back in `files_read` for the preview to show, which is
/// the whole reason this is separate from the text-based call.
#[tauri::command]
pub async fn ssh_config_report_at_path(
    path: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::SshConfigReport> {
    let core = state.core.clone();
    Ok(blocking(move || core.ssh_config_report_at_path(path))
        .await?
        .into())
}

/// Sets which algorithms new SSH connections may negotiate. Also an atomic
/// store, so it stays off the blocking pool.
#[tauri::command]
pub async fn set_algorithm_policy(modern: bool, state: State<'_, AppState>) -> ApiResult<()> {
    state.core.set_algorithm_policy(if modern {
        FfiAlgorithmPolicy::Modern
    } else {
        FfiAlgorithmPolicy::Balanced
    });
    Ok(())
}

/// Change, add or remove the master password. On success the biometric unlock
/// material sealed for the old password is wiped; the answer says whether there
/// was any and whether the wipe worked, so Settings can ask for it to be turned
/// on again (with the new password, in this session) or say it failed.
#[tauri::command]
pub async fn change_password(
    old_password: Option<String>,
    new_password: Option<String>,
    secret_key_hex: String,
    state: State<'_, AppState>,
) -> ApiResult<crate::biometric::KeysetWipe> {
    let core = state.core.clone();
    let ((), wipe) = blocking_api(crate::biometric::installing_keyset(&state, move || {
        Ok(core.change_password(old_password, new_password, secret_key_hex)?)
    }))
    .await?;
    Ok(wipe)
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

/// Write a vault out as a portable encrypted backup.
///
/// The path is passed in and the file is written HERE rather than handing the
/// bytes back to the webview: a backup carries every item in the vault, session
/// recordings included, and Tauri serialises a byte array over IPC as a JSON
/// array of numbers — several bytes of JSON per byte of payload. A 40 MB vault
/// would cross the bridge as a few hundred MB of text before anyone could save
/// it. The path comes from the user's own save dialog, so this is the same trust
/// as writing it from the frontend, minus the round trip.
///
/// The bundle is decryptable with the passphrase ALONE — no keyset, no account.
/// That is the point of a backup and also its whole risk, so the passphrase is
/// the user's to choose and never stored.
#[tauri::command]
pub async fn vault_export_backup(
    vault_id: String,
    passphrase: String,
    path: String,
    state: State<'_, AppState>,
) -> ApiResult<u64> {
    let core = state.core.clone();
    blocking(move || {
        let bytes = core.export_vault(vault_id, passphrase)?;
        let len = bytes.len() as u64;
        std::fs::write(&path, &bytes).map_err(|e| FfiError::Other {
            msg: format!("could not write {path}: {e}"),
        })?;
        Ok(len)
    })
    .await
}

/// Read a backup back into a NEW vault. Never overwrites an existing one — the
/// core refuses a vault id that is already taken, and a restore that silently
/// replaced a live vault would be a data-loss feature.
///
/// `name` is applied AFTER the import, because a backup carries the name the
/// vault had: the name is a signed record inside the bundle, not a property of
/// the id it is restored under. Without this the restore silently kept the
/// source's name, so restoring beside the original — the normal case — produced
/// two entries called the same thing with no way to tell them apart, and the
/// "Restore as" field the user had just filled in did nothing.
///
/// Renaming here rather than in the frontend so the two are one call: a restore
/// that succeeded and a rename that never ran would leave exactly the state this
/// is fixing, and nothing in the UI would say so.
#[tauri::command]
pub async fn vault_import_backup(
    path: String,
    passphrase: String,
    new_vault_id: String,
    name: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || {
        let bytes = std::fs::read(&path).map_err(|e| FfiError::Other {
            msg: format!("could not read {path}: {e}"),
        })?;
        core.import_vault(bytes, passphrase, new_vault_id.clone())?;
        core.rename_vault(new_vault_id, name).map_err(|e| {
            // The vault IS restored at this point. Say so, or the message reads
            // as "the restore failed" and invites a second attempt that then
            // collides with the vault this one just created.
            FfiError::Other {
                msg: format!("restored, but could not be renamed: {e}"),
            }
        })
    })
    .await
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

/// Staged rotation, step 1: generate a candidate key beside `key_id` (a separate
/// ordinary key item, linked device-locally). Returns the candidate's item id.
#[tauri::command]
pub async fn begin_key_rotation(
    vault_id: String,
    key_id: String,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    blocking(move || core.begin_key_rotation(vault_id, key_id)).await
}

/// Staged rotation, commit: the candidate's material becomes a new version of
/// `key_id` (old material kept in history); the certificate and candidate go.
#[tauri::command]
pub async fn finish_key_rotation(
    vault_id: String,
    key_id: String,
    candidate_id: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.finish_key_rotation(vault_id, key_id, candidate_id)).await
}

/// Staged rotation, abandon: tombstone the candidate; the original is untouched.
#[tauri::command]
pub async fn abandon_key_rotation(
    vault_id: String,
    candidate_id: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.abandon_key_rotation(vault_id, candidate_id)).await
}

/// Rotations in progress on this device for a vault (live candidates only).
#[tauri::command]
pub async fn list_key_rotations(
    vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::KeyRotationLink>> {
    let core = state.core.clone();
    let links = blocking(move || core.list_key_rotations(vault_id)).await?;
    Ok(links.into_iter().map(Into::into).collect())
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
    proxy: Option<dto::ProxyConfig>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    // jumps are part of the pin (anti-redirect along the ProxyJump chain) — we convert them into
    // the core type with the same conv_jumps as save_connection/connect.
    Ok(state.core.personal_destination(
        host,
        port,
        username_template,
        conv_jumps(jumps),
        conv_proxy(proxy),
    ))
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

/// Imports a config **file**, following its `Include` directives. `only` is the
/// set of aliases the preview left ticked; `None` imports every host.
///
/// The path is the one the user chose in the OS file picker. Following includes
/// widens the read beyond it, which is why `ssh_config_report_at_path` runs
/// first and discloses every file before anything is written.
#[tauri::command]
pub async fn import_ssh_config_at_path(
    vault_id: String,
    path: String,
    only: Option<Vec<String>>,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::ImportedSshHost>> {
    let core = state.core.clone();
    let v = blocking(move || core.import_ssh_config_at_path(vault_id, path, only)).await?;
    Ok(v.into_iter().map(Into::into).collect())
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
pub async fn save_snippet(
    vault_id: String,
    snippet: dto::Snippet,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    let s = snippet.into();
    blocking(move || core.save_snippet(vault_id, s)).await
}

#[tauri::command]
pub async fn list_snippets(
    vault_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::Snippet>> {
    let core = state.core.clone();
    let v = blocking(move || core.list_snippets(vault_id)).await?;
    Ok(v.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub async fn delete_snippet(
    vault_id: String,
    snippet_id: String,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.delete_snippet(vault_id, snippet_id)).await
}

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
    proxy: Option<dto::ProxyConfig>,
    state: State<'_, AppState>,
) -> ApiResult<dto::SshExecResult> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let proxy = conv_proxy(proxy);
    let r = blocking(move || core.ssh_exec(host, port, user, auth, command, jumps, proxy)).await?;
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
    proxy: Option<dto::ProxyConfig>,
    on_event: Channel<ExecEvent>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let proxy = conv_proxy(proxy);
    let obs: Arc<dyn ExecObserver> = Arc::new(ChannelExecObserver { chan: on_event });
    let handle =
        blocking(move || core.ssh_exec_stream(host, port, user, auth, command, jumps, proxy, obs))
            .await?;
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
    proxy: Option<dto::ProxyConfig>,
    term: String,
    cols: u32,
    rows: u32,
    on_event: Channel<TermEvent>,
    recording: Option<dto::RecordingRequest>,
    agent_forward: bool,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let proxy = conv_proxy(proxy);
    let obs: Arc<dyn SessionObserver> = Arc::new(ChannelSessionObserver { chan: on_event });
    let rec = recording.map(Into::into);
    let session = blocking(move || {
        core.open_session(
            host,
            port,
            user,
            auth,
            jumps,
            proxy,
            term,
            cols,
            rows,
            obs,
            rec,
            agent_forward,
        )
    })
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
    proxy: Option<dto::ProxyConfig>,
    term: String,
    cols: u32,
    rows: u32,
    max_retries: u32,
    backoff_ms: u32,
    on_event: Channel<TermEvent>,
    agent_forward: bool,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let proxy = conv_proxy(proxy);
    let obs: Arc<dyn SessionObserver> = Arc::new(ChannelSessionObserver { chan: on_event });
    let session = blocking(move || {
        core.open_reconnecting_session(
            host,
            port,
            user,
            auth,
            jumps,
            proxy,
            term,
            cols,
            rows,
            max_retries,
            backoff_ms,
            obs,
            agent_forward,
        )
    })
    .await?;
    let id = new_id();
    state
        .sessions
        .insert(id.clone(), LiveSession::Reconnecting(session));
    Ok(id)
}

/// Open a shell on this machine, in the same session id space as SSH panes.
///
/// `spec` is already resolved by the frontend (see `local_shell_default`), so
/// the program is always a concrete path — the wrapper does not reinterpret the
/// user's settings.
#[tauri::command]
pub async fn local_session_open(
    spec: dto::LocalSpec,
    cols: u32,
    rows: u32,
    on_event: Channel<TermEvent>,
    recording: Option<dto::RecordingRequest>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let core = state.core.clone();
    let spec = spec.into();
    let obs: Arc<dyn SessionObserver> = Arc::new(ChannelSessionObserver { chan: on_event });
    let rec = recording.map(Into::into);
    let session = blocking(move || core.open_local_session(spec, cols, rows, obs, rec)).await?;
    let id = new_id();
    state
        .sessions
        .insert(id.clone(), LiveSession::Local(session));
    Ok(id)
}

/// The shell a local terminal would start by default, and who/where this machine
/// is. Feeds both the Settings placeholder and the actual open.
#[tauri::command]
pub async fn local_shell_default(state: State<'_, AppState>) -> ApiResult<dto::LocalShellInfo> {
    let core = state.core.clone();
    blocking_ok(move || core.local_shell_default().into()).await
}

/// Split an argument string into words the way a shell would. `null` when it
/// does not parse (an unbalanced quote), so Settings can say so.
#[tauri::command]
pub async fn local_shell_split_args(
    text: String,
    state: State<'_, AppState>,
) -> ApiResult<Option<Vec<String>>> {
    let core = state.core.clone();
    blocking_ok(move || core.local_shell_split_args(text)).await
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
    proxy: Option<dto::ProxyConfig>,
    local_bind: String,
    remote_host: String,
    remote_port: u16,
    state: State<'_, AppState>,
) -> ApiResult<dto::OpenedTunnel> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let proxy = conv_proxy(proxy);
    let t = blocking(move || {
        core.open_local_forward(
            host,
            port,
            user,
            auth,
            jumps,
            proxy,
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
    proxy: Option<dto::ProxyConfig>,
    local_bind: String,
    state: State<'_, AppState>,
) -> ApiResult<dto::OpenedTunnel> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let proxy = conv_proxy(proxy);
    let t = blocking(move || {
        core.open_dynamic_forward(host, port, user, auth, jumps, proxy, local_bind)
    })
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
    proxy: Option<dto::ProxyConfig>,
    remote_bind: String,
    remote_port: u16,
    local_host: String,
    local_port: u16,
    state: State<'_, AppState>,
) -> ApiResult<dto::OpenedTunnel> {
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let proxy = conv_proxy(proxy);
    let t = blocking(move || {
        core.open_remote_forward(
            host,
            port,
            user,
            auth,
            jumps,
            proxy,
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

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn sftp_open(
    host: String,
    port: u16,
    user: String,
    auth: dto::AuthMethod,
    jumps: Vec<dto::JumpHost>,
    proxy: Option<dto::ProxyConfig>,
    parallelism: u32,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let epoch = *state.sftp_epoch.lock().unwrap_or_else(|e| e.into_inner());
    let core = state.core.clone();
    let auth = auth.into();
    let jumps = conv_jumps(jumps);
    let proxy = conv_proxy(proxy);
    let sftp =
        blocking(move || core.open_sftp(host, port, user, auth, jumps, proxy, parallelism)).await?;
    let guard = state.sftp_epoch.lock().unwrap_or_else(|e| e.into_inner());
    if *guard != epoch || !state.core.is_unlocked() {
        sftp.close();
        return Err(ApiError::other(
            "SFTP connection expired during vault change",
        ));
    }
    let id = new_id();
    state.sftp.insert(id.clone(), sftp);
    Ok(id)
}

fn invalidate_sftp(state: &AppState) {
    let mut epoch = state.sftp_epoch.lock().unwrap_or_else(|e| e.into_inner());
    *epoch = epoch.wrapping_add(1);
    let sessions: Vec<_> = state.sftp.iter().map(|s| s.value().clone()).collect();
    state.sftp.clear();
    drop(epoch);
    for session in sessions {
        session.close();
    }
}

#[tauri::command]
pub async fn sftp_invalidate(state: State<'_, AppState>) -> ApiResult<()> {
    invalidate_sftp(&state);
    Ok(())
}

fn transfer_cancel(
    state: &AppState,
    id: Option<String>,
) -> ApiResult<Option<Arc<unissh_ffi::CancelToken>>> {
    id.map(|id| {
        state
            .cancels
            .get(&id)
            .map(|token| token.clone())
            .ok_or_else(|| ApiError::not_found("cancel token"))
    })
    .transpose()
}

fn get_sftp(state: &AppState, id: &str) -> ApiResult<Arc<unissh_ffi::SftpFfi>> {
    if !state.core.is_unlocked() {
        return Err(ApiError::other("Instance is locked"));
    }
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

fn local_mode(md: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        md.mode()
    }
    #[cfg(not(unix))]
    {
        if md.is_symlink() {
            0o120000
        } else if md.is_dir() {
            0o040700
        } else if md.is_file() {
            0o100600
        } else {
            0o010000
        }
    }
}

#[tauri::command]
pub async fn sftp_fingerprint(
    id: String,
    path: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<u8>> {
    let s = get_sftp(&state, &id)?;
    blocking(move || s.fingerprint(path)).await
}

#[tauri::command]
pub async fn sftp_commit(
    id: String,
    from: String,
    to: String,
    replace: bool,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    let cancel = transfer_cancel(&state, cancel_id)?;
    blocking(move || match cancel {
        Some(token) => s.commit_cancel(from, to, replace, token),
        None => s.commit(from, to, replace),
    })
    .await
}

#[tauri::command]
pub async fn sftp_set_metadata(
    id: String,
    path: String,
    mode: Option<u32>,
    mtime: Option<u32>,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    let cancel = transfer_cancel(&state, cancel_id)?;
    blocking(move || match cancel {
        Some(token) => s.set_metadata_cancel(path, mode, mtime, token),
        None => s.set_metadata(path, mode, mtime),
    })
    .await
}

/// Create a new owner-only file for writing. Fails if anything already exists
/// at `path`, a symbolic link included: the link is never followed.
fn create_private(path: &str) -> ApiResult<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(ApiError::other)
}

#[tauri::command]
pub async fn local_create_private(path: String) -> ApiResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        create_private(&path)?;
        Ok(())
    })
    .await?
}

fn open_regular(path: &str) -> ApiResult<std::fs::File> {
    if !std::fs::symlink_metadata(path)
        .map_err(ApiError::other)?
        .is_file()
    {
        return Err(ApiError::other("Not a regular file"));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(ApiError::other)?;
    if !file.metadata().map_err(ApiError::other)?.is_file() {
        return Err(ApiError::other("Not a regular file"));
    }
    Ok(file)
}

/// Open a file the caller already created for writing. Never creates one and
/// never writes through a symbolic link.
fn open_prepared(path: &str) -> ApiResult<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(ApiError::other)?;
    if !file.metadata().map_err(ApiError::other)?.is_file() {
        return Err(ApiError::other("Not a regular file"));
    }
    Ok(file)
}

/// Stream `source` into `target` from the target's current position.
fn copy_contents(source: &mut std::fs::File, target: &mut std::fs::File) -> ApiResult<u64> {
    use std::io::Write;
    let bytes = std::io::copy(source, target).map_err(ApiError::other)?;
    target.flush().map_err(ApiError::other)?;
    Ok(bytes)
}

#[tauri::command]
pub async fn local_copy_prepared(from: String, to: String) -> ApiResult<u64> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut source = open_regular(&from)?;
        let mut target = open_prepared(&to)?;
        let source_identity =
            same_file::Handle::from_file(source.try_clone().map_err(ApiError::other)?)
                .map_err(ApiError::other)?;
        let target_identity =
            same_file::Handle::from_file(target.try_clone().map_err(ApiError::other)?)
                .map_err(ApiError::other)?;
        if source_identity == target_identity {
            return Err(ApiError::other("Cannot copy a file onto itself"));
        }
        target.set_len(0).map_err(ApiError::other)?;
        copy_contents(&mut source, &mut target)
    })
    .await?
}

#[tauri::command]
pub async fn local_same_file(from: String, to: String) -> ApiResult<bool> {
    tauri::async_runtime::spawn_blocking(move || {
        same_file::is_same_file(from, to).map_err(ApiError::other)
    })
    .await?
}

#[tauri::command]
pub async fn local_realpath(path: String) -> ApiResult<String> {
    tauri::async_runtime::spawn_blocking(move || {
        std::fs::canonicalize(path)
            .map_err(ApiError::other)?
            .into_os_string()
            .into_string()
            .map_err(|_| ApiError::other("Path is not valid UTF-8"))
    })
    .await?
}

#[tauri::command]
pub async fn local_commit(from: String, to: String, replace: bool) -> ApiResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        if replace {
            return std::fs::rename(from, to).map_err(ApiError::other);
        }
        // link(2) publishes the prepared inode only if the destination is absent.
        // It also preserves a symlink inode on Unix. Never fall back to overwrite.
        #[cfg(unix)]
        {
            std::fs::hard_link(&from, &to).map_err(ApiError::other)?;
            std::fs::remove_file(from).map_err(ApiError::other)
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let from: Vec<u16> = std::ffi::OsStr::new(&from)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let to: Vec<u16> = std::ffi::OsStr::new(&to)
                .encode_wide()
                .chain(Some(0))
                .collect();
            // Flags=0 refuses replacement and preserves directory symlinks too.
            if unsafe {
                windows_sys::Win32::Storage::FileSystem::MoveFileExW(from.as_ptr(), to.as_ptr(), 0)
            } == 0
            {
                return Err(ApiError::other(std::io::Error::last_os_error()));
            }
            Ok(())
        }
    })
    .await?
}

#[tauri::command]
pub async fn local_set_metadata(
    path: String,
    mode: Option<u32>,
    mtime: Option<u64>,
) -> ApiResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mtime) = mtime {
                let path_c = std::ffi::CString::new(path.as_bytes()).map_err(ApiError::other)?;
                let seconds = libc::time_t::try_from(mtime).map_err(ApiError::other)?;
                let times = [
                    libc::timespec {
                        tv_sec: 0,
                        tv_nsec: libc::UTIME_OMIT,
                    },
                    libc::timespec {
                        tv_sec: seconds,
                        tv_nsec: 0,
                    },
                ];
                if unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        path_c.as_ptr(),
                        times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    return Err(ApiError::other(std::io::Error::last_os_error()));
                }
            }
            if let Some(mode) = mode {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & 0o777))
                    .map_err(ApiError::other)?;
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_WRITE_ATTRIBUTES,
            };
            let _ = mode;
            if let Some(mtime) = mtime {
                let file = std::fs::OpenOptions::new()
                    .access_mode(FILE_WRITE_ATTRIBUTES)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(path)
                    .map_err(ApiError::other)?;
                file.set_times(
                    std::fs::FileTimes::new().set_modified(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime),
                    ),
                )
                .map_err(ApiError::other)?;
            }
        }
        Ok(())
    })
    .await?
}

#[tauri::command]
pub async fn local_read_text(path: String, limit: u32) -> ApiResult<String> {
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Read;
        let file = open_regular(&path)?;
        if !file.metadata().map_err(ApiError::other)?.is_file() {
            return Err(ApiError::other("Not a regular file"));
        }
        let mut bytes = Vec::new();
        file.take(u64::from(limit.min(2 * 1024 * 1024)) + 1)
            .read_to_end(&mut bytes)
            .map_err(ApiError::other)?;
        if bytes.len() > limit.min(2 * 1024 * 1024) as usize {
            return Err(ApiError::other("File exceeds editor size limit"));
        }
        String::from_utf8(bytes).map_err(ApiError::other)
    })
    .await?
}

/// Replace the contents of a prepared file (see `local_create_private`).
#[tauri::command]
pub async fn local_write_text(path: String, text: String) -> ApiResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Write;
        let mut target = open_prepared(&path)?;
        target.set_len(0).map_err(ApiError::other)?;
        target.write_all(text.as_bytes()).map_err(ApiError::other)?;
        target.flush().map_err(ApiError::other)
    })
    .await?
}

/// Give `target` the permission bits of `source`. Unix only; other platforms
/// leave the new file with their defaults.
fn carry_permissions(source: &std::fs::File, target: &std::fs::File) -> ApiResult<()> {
    #[cfg(unix)]
    {
        let permissions = source.metadata().map_err(ApiError::other)?.permissions();
        target.set_permissions(permissions).map_err(ApiError::other)
    }
    #[cfg(not(unix))]
    {
        let _ = (source, target);
        Ok(())
    }
}

/// Copy a file the OS picker returned into the local pane. The picker hands
/// back a `file://` URL on iOS and a plain path on desktop, hence `FilePath`.
/// On iOS this relies on the dialog picker's default copy mode; a
/// security-scoped pick would need `startAccessingSecurityScopedResource`.
///
/// The source must be a regular file. The destination is created exclusively:
/// an existing entry is never replaced and a link there is never followed. A
/// failed copy removes the file it created. An exclusive create starts
/// owner-only, so on Unix the source's permission bits are applied afterwards;
/// elsewhere the new file keeps the platform's defaults.
#[tauri::command]
pub async fn local_copy_file(from: tauri_plugin_fs::FilePath, to: String) -> ApiResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let from = from.into_path().map_err(ApiError::other)?;
        let from = from
            .to_str()
            .ok_or_else(|| ApiError::other("Path is not valid UTF-8"))?;
        let mut source = open_regular(from)?;
        let mut target = create_private(&to)?;
        let copied = copy_contents(&mut source, &mut target)
            .and_then(|_| carry_permissions(&source, &target));
        drop(target);
        if copied.is_err() {
            let _ = std::fs::remove_file(&to);
        }
        copied
    })
    .await?
}

#[tauri::command]
pub async fn sftp_list_dir_cancel(
    id: String,
    path: String,
    cancel_id: String,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::SftpEntry>> {
    let s = get_sftp(&state, &id)?;
    let cancel = state
        .cancels
        .get(&cancel_id)
        .ok_or_else(|| ApiError::not_found("cancel token"))?
        .clone();
    Ok(blocking(move || s.list_dir_cancel(path, cancel))
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

#[tauri::command]
pub async fn sftp_relay(
    id: String,
    target_id: String,
    remote: String,
    destination: String,
    on_progress: Channel<ProgressEvent>,
    cancel_id: String,
    state: State<'_, AppState>,
) -> ApiResult<bool> {
    let source = get_sftp(&state, &id)?;
    let target = get_sftp(&state, &target_id)?;
    let cancel = state
        .cancels
        .get(&cancel_id)
        .ok_or_else(|| ApiError::not_found("cancel token"))?
        .clone();
    let progress: Arc<dyn SftpProgressObserver> = Arc::new(ChannelSftpProgress::new(on_progress));
    blocking(move || source.relay_to(target, remote, destination, Some(progress), Some(cancel)))
        .await
}

/// List a LOCAL directory in one shot (name + is_dir + size + mtime), avoiding
/// the readDir + per-file stat IPC fan-out the client would otherwise do.
#[tauri::command]
pub async fn local_list_dir(
    path: String,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<Vec<dto::LocalEntry>> {
    let cancel = transfer_cancel(&state, cancel_id)?;
    tauri::async_runtime::spawn_blocking(move || list_local_entries(&path, cancel.as_deref()))
        .await?
}

fn list_local_entries(
    path: &str,
    cancel: Option<&unissh_ffi::CancelToken>,
) -> ApiResult<Vec<dto::LocalEntry>> {
    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    for entry in std::fs::read_dir(path).map_err(ApiError::other)? {
        if cancel.is_some_and(|token| token.is_cancelled()) {
            return Err(ApiError::other("transfer cancelled"));
        }
        if std::time::Instant::now() >= deadline {
            return Err(ApiError::other("directory listing deadline exceeded"));
        }
        let entry = entry.map_err(ApiError::other)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ApiError::other("Filename is not valid UTF-8"))?;
        let md = entry.metadata().map_err(ApiError::other)?;
        let is_dir = md.is_dir();
        let size = md.len();
        let mtime = md
            .modified()
            .map_err(ApiError::other)?
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        out.push(dto::LocalEntry {
            name,
            is_symlink: md.is_symlink(),
            mode: local_mode(&md),
            is_dir,
            size,
            mtime,
        });
    }
    Ok(out)
}

/// Local transfer metadata must not follow links (including dangling links).
#[tauri::command]
pub async fn local_lstat(path: String) -> ApiResult<Option<dto::LocalEntry>> {
    tauri::async_runtime::spawn_blocking(move || local_entry(&path, false)).await?
}

/// Like `local_lstat`, but follows links: a dangling link reads as absent.
#[tauri::command]
pub async fn local_stat(path: String) -> ApiResult<Option<dto::LocalEntry>> {
    tauri::async_runtime::spawn_blocking(move || local_entry(&path, true)).await?
}

fn local_entry(path: &str, follow: bool) -> ApiResult<Option<dto::LocalEntry>> {
    let md = if follow {
        std::fs::metadata(path)
    } else {
        std::fs::symlink_metadata(path)
    };
    let md = match md {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ApiError::other(e)),
    };
    Ok(Some(dto::LocalEntry {
        name: std::path::Path::new(path)
            .file_name()
            .unwrap_or_default()
            .to_str()
            .ok_or_else(|| ApiError::other("Filename is not valid UTF-8"))?
            .to_owned(),
        is_dir: md.is_dir(),
        is_symlink: md.is_symlink(),
        mode: local_mode(&md),
        size: md.len(),
        mtime: md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }))
}

/// Create one directory. Not recursive: a missing parent or a taken name fails.
#[tauri::command]
pub async fn local_mkdir(path: String) -> ApiResult<()> {
    tauri::async_runtime::spawn_blocking(move || std::fs::create_dir(path).map_err(ApiError::other))
        .await?
}

/// Remove a file or a directory. Without `recursive` a directory must be
/// empty. A symbolic link is removed itself; its referent is never followed.
#[tauri::command]
pub async fn local_remove(path: String, recursive: bool) -> ApiResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let md = std::fs::symlink_metadata(&path).map_err(ApiError::other)?;
        if md.is_dir() {
            return if recursive {
                std::fs::remove_dir_all(path)
            } else {
                std::fs::remove_dir(path)
            }
            .map_err(ApiError::other);
        }
        remove_entry(&path, &md)
    })
    .await?
}

/// Remove a file or a symbolic link itself, given its non-following metadata.
/// Windows removes a directory link as a directory; the referent stays.
fn remove_entry(path: &str, md: &std::fs::Metadata) -> ApiResult<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileTypeExt;
        if md.file_type().is_symlink_dir() {
            return std::fs::remove_dir(path).map_err(ApiError::other);
        }
    }
    #[cfg(not(windows))]
    let _ = md;
    std::fs::remove_file(path).map_err(ApiError::other)
}

#[tauri::command]
pub async fn local_readlink(path: String) -> ApiResult<String> {
    tauri::async_runtime::spawn_blocking(move || {
        std::fs::read_link(path)
            .map_err(ApiError::other)?
            .into_os_string()
            .into_string()
            .map_err(|_| ApiError::other("Symbolic link target is not valid UTF-8"))
    })
    .await?
}

/// Like native upload/download, these operate on paths selected for a transfer.
/// Keep the target literal: resolving it breaks relative and dangling links.
#[tauri::command]
pub async fn local_symlink(target: String, path: String, target_is_dir: bool) -> ApiResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(unix)]
        {
            let _ = target_is_dir;
            std::os::unix::fs::symlink(target, path).map_err(ApiError::other)
        }
        #[cfg(windows)]
        {
            if target_is_dir {
                std::os::windows::fs::symlink_dir(target, path)
            } else {
                std::os::windows::fs::symlink_file(target, path)
            }
            .map_err(ApiError::other)
        }
    })
    .await?
}

/// Unlink only the link, never recursively remove or follow its referent.
#[tauri::command]
pub async fn local_unlink(path: String) -> ApiResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let md = std::fs::symlink_metadata(&path).map_err(ApiError::other)?;
        if !md.is_symlink() {
            return Err(ApiError::other("Expected a symbolic link"));
        }
        remove_entry(&path, &md)
    })
    .await?
}

/// Mounted volumes, for the SFTP local pane's drive picker. Desktop only —
/// mobile is sandboxed to one directory, so it answers with an empty list and
/// the picker never appears.
///
/// The filtering is deliberately about what a person would call a drive: Linux
/// in particular mounts a great deal that is not one (every snap is a loop
/// device, containers bring their own overlays), and a picker listing 40 entries
/// of which 2 are real would be worse than the current no picker at all.
#[tauri::command]
pub async fn local_volumes() -> ApiResult<Vec<dto::LocalVolume>> {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        Ok(Vec::new())
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        tauri::async_runtime::spawn_blocking(|| {
            let disks = sysinfo::Disks::new_with_refreshed_list();
            let mut out: Vec<dto::LocalVolume> = Vec::new();
            for d in disks.list() {
                let mount = d.mount_point();
                let path = mount.to_string_lossy().into_owned();
                if path.is_empty() || d.total_space() == 0 {
                    continue;
                }
                // A bind-mounted FILE is a mount point too (containers do this
                // to /etc/hosts); a place you can browse to is a directory.
                if !mount.is_dir() {
                    continue;
                }
                if !is_browsable_volume(&path, d.is_removable()) {
                    continue;
                }
                let label = d.name().to_string_lossy().trim().to_owned();
                out.push(dto::LocalVolume {
                    // A Linux disk names itself by device ("/dev/sda2"), which is
                    // not a name for a place — drop it and let the client show the
                    // mount point. Windows/macOS give a real volume label.
                    label: if label.starts_with("/dev/") {
                        String::new()
                    } else {
                        label
                    },
                    path,
                    total_bytes: d.total_space(),
                    free_bytes: d.available_space(),
                    removable: d.is_removable(),
                });
            }
            // Shortest path first: "/" and "C:\" lead, their nested mounts follow.
            out.sort_by(|a, b| a.path.len().cmp(&b.path.len()).then(a.path.cmp(&b.path)));
            // One row per actual volume. The same filesystem surfaces under
            // several mount points (macOS lists the boot disk as both "/" and
            // "/Volumes/Macintosh HD"; bind mounts and btrfs subvolumes do the
            // same on Linux), and two rows that go to the same files are a
            // choice the user cannot make. Identity is name+capacity, and the
            // shortest path — the one sorted first — wins. Free space moves
            // constantly, so two genuinely different disks agreeing on label,
            // total AND free at the same instant is not a case worth designing
            // around; a duplicated boot volume on every Mac is.
            let mut seen: Vec<(String, u64, u64)> = Vec::new();
            out.retain(|v| {
                let id = (v.label.clone(), v.total_bytes, v.free_bytes);
                if seen.contains(&id) {
                    return false;
                }
                seen.push(id);
                true
            });
            Ok(out)
        })
        .await?
    }
}

/// Whether a mount point is a "drive" in the sense the picker means: somewhere a
/// person keeps files and would switch to on purpose.
///
/// An allowlist, not a blacklist of noise. A Unix box mounts a great deal that
/// is not a drive — every snap is a loop device, containers bind-mount their own
/// roots, systemd mounts a dozen tmpfs — and each new source of noise would need
/// another blacklist entry, whereas the places removable and secondary media
/// actually appear are few and stable.
#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn is_browsable_volume(path: &str, removable: bool) -> bool {
    // Windows: every mount point is a drive letter (or a folder someone mounted
    // a volume into, which is equally a place to browse).
    if cfg!(target_os = "windows") {
        return true;
    }
    if path == "/" {
        return true;
    }
    // Anything the OS considers removable is worth listing wherever it landed —
    // that is the USB stick the picker exists for.
    if removable {
        return true;
    }
    // Where macOS and the Linux desktops mount secondary and external media.
    const MEDIA_ROOTS: &[&str] = &["/Volumes", "/media", "/run/media", "/mnt"];
    MEDIA_ROOTS
        .iter()
        .any(|r| path.starts_with(&format!("{r}/")))
}

#[tauri::command]
pub async fn sftp_stat(
    id: String,
    path: String,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<dto::SftpFileStat> {
    let s = get_sftp(&state, &id)?;
    let cancel = transfer_cancel(&state, cancel_id)?;
    let st = blocking(move || match cancel {
        Some(token) => s.stat_cancel(path, true, token),
        None => s.stat(path),
    })
    .await?;
    Ok(st.into())
}

#[tauri::command]
pub async fn sftp_lstat(
    id: String,
    path: String,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<dto::SftpFileStat> {
    let s = get_sftp(&state, &id)?;
    let cancel = transfer_cancel(&state, cancel_id)?;
    Ok(blocking(move || match cancel {
        Some(token) => s.stat_cancel(path, false, token),
        None => s.lstat(path),
    })
    .await?
    .into())
}

#[tauri::command]
pub async fn sftp_readlink(
    id: String,
    path: String,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<String> {
    let s = get_sftp(&state, &id)?;
    let cancel = transfer_cancel(&state, cancel_id)?;
    blocking(move || match cancel {
        Some(token) => s.readlink_cancel(path, token),
        None => s.readlink(path),
    })
    .await
}

#[tauri::command]
pub async fn sftp_symlink(
    id: String,
    target: String,
    path: String,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    let cancel = transfer_cancel(&state, cancel_id)?;
    blocking(move || match cancel {
        Some(token) => s.symlink_cancel(target, path, token),
        None => s.symlink(target, path),
    })
    .await
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
pub async fn sftp_mkdir(
    id: String,
    path: String,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    let cancel = transfer_cancel(&state, cancel_id)?;
    blocking(move || match cancel {
        Some(token) => s.mkdir_cancel(path, token),
        None => s.mkdir(path),
    })
    .await
}

#[tauri::command]
pub async fn sftp_create_new_file(
    id: String,
    path: String,
    cancel_id: Option<String>,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let s = get_sftp(&state, &id)?;
    let cancel = transfer_cancel(&state, cancel_id)?;
    blocking(move || match cancel {
        Some(token) => s.create_new_cancel(path, token),
        None => s.create_new_file(path),
    })
    .await
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
    let bytes = blocking(move || s.read_file_bounded(path, 2 * 1024 * 1024)).await?;
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
    let cancel = transfer_cancel(&state, cancel_id)?;
    let progress: Option<Arc<dyn SftpProgressObserver>> =
        Some(Arc::new(ChannelSftpProgress::new(on_progress)));
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
    let cancel = transfer_cancel(&state, cancel_id)?;
    let progress: Option<Arc<dyn SftpProgressObserver>> =
        Some(Arc::new(ChannelSftpProgress::new(on_progress)));
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

/// Answers an outstanding interactive-authentication prompt.
///
/// `answers: None` is Cancel and aborts the connection. The core is blocked on
/// a thread waiting for this, so it must not itself touch the core — it only
/// hands the strings over.
#[tauri::command]
pub fn submit_auth_prompt(
    id: u64,
    answers: Option<Vec<String>>,
    prompter: State<'_, Arc<AppPrompter>>,
) {
    prompter.answer(id, answers);
}

#[tauri::command]
pub async fn mcp_recording_preferences(
    state: State<'_, AppState>,
) -> ApiResult<unissh_ffi::automation_recording::RecordingPreferences> {
    let core = state.core.clone();
    blocking(move || core.mcp_recording_preferences()).await
}
#[tauri::command]
pub async fn set_mcp_recording_preferences(
    value: unissh_ffi::automation_recording::RecordingPreferences,
    state: State<'_, AppState>,
) -> ApiResult<()> {
    let core = state.core.clone();
    blocking(move || core.set_mcp_recording_preferences(value)).await
}

#[cfg(test)]
mod local_symlink_tests {
    use super::{list_local_entries, local_lstat, local_readlink, local_symlink, local_unlink};

    #[test]
    fn prepared_copy_and_commit_preserve_existing_files() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
            std::fs::write(path("original"), b"original").unwrap();
            super::local_create_private(path("stage")).await.unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(path("stage"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
            std::fs::write(path("stage"), b"replacement").unwrap();
            assert!(super::local_commit(path("stage"), path("original"), false)
                .await
                .is_err());
            assert_eq!(std::fs::read(path("original")).unwrap(), b"original");
            assert!(
                super::local_copy_prepared(path("original"), path("original"))
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(path("original")).unwrap(), b"original");
            std::fs::hard_link(path("original"), path("alias")).unwrap();
            assert!(super::local_same_file(path("original"), path("alias"))
                .await
                .unwrap());
            assert!(super::local_copy_prepared(path("original"), path("alias"))
                .await
                .is_err());
            assert_eq!(std::fs::read(path("original")).unwrap(), b"original");
            super::local_commit(path("stage"), path("original"), true)
                .await
                .unwrap();
            assert_eq!(std::fs::read(path("original")).unwrap(), b"replacement");
            assert!(!dir.path().join("stage").exists());
        });
    }

    #[test]
    fn metadata_and_editor_limits_apply_to_actual_files() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("file").to_str().unwrap().to_owned();
            std::fs::write(&path, vec![42; 33]).unwrap();
            assert!(super::local_read_text(path.clone(), 32).await.is_err());
            let timestamp = 1_700_000_000;
            super::local_set_metadata(path.clone(), Some(0o4555), Some(timestamp))
                .await
                .unwrap();
            let md = std::fs::metadata(&path).unwrap();
            assert_eq!(
                md.modified()
                    .unwrap()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                timestamp
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(md.permissions().mode() & 0o7777, 0o555);
            }
            super::local_set_metadata(
                dir.path().to_str().unwrap().to_owned(),
                None,
                Some(timestamp),
            )
            .await
            .unwrap();
        });
    }

    #[test]
    fn stat_follows_links_and_reports_absence() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
            std::fs::create_dir(path("lib")).unwrap();
            let md = super::local_stat(path("lib")).await.unwrap().unwrap();
            assert!(md.is_dir);
            assert_eq!(md.name, "lib");
            assert!(super::local_stat(path("missing")).await.unwrap().is_none());
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink("lib", path("lib64")).unwrap();
                let md = super::local_stat(path("lib64")).await.unwrap().unwrap();
                assert!(md.is_dir && !md.is_symlink);
                std::os::unix::fs::symlink("missing", path("broken")).unwrap();
                assert!(super::local_stat(path("broken")).await.unwrap().is_none());
            }
        });
    }

    #[test]
    fn mkdir_creates_exactly_one_new_directory() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
            super::local_mkdir(path("new")).await.unwrap();
            assert!(dir.path().join("new").is_dir());
            assert!(super::local_mkdir(path("new")).await.is_err());
            let nested = dir.path().join("absent").join("child");
            assert!(super::local_mkdir(nested.to_str().unwrap().to_owned())
                .await
                .is_err());
            assert!(!dir.path().join("absent").exists());
        });
    }

    #[test]
    fn remove_is_recursive_only_on_request_and_spares_link_referents() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
            std::fs::create_dir(path("tree")).unwrap();
            std::fs::write(dir.path().join("tree").join("leaf"), b"leaf").unwrap();
            std::fs::write(path("file"), b"file").unwrap();
            super::local_remove(path("file"), false).await.unwrap();
            assert!(!dir.path().join("file").exists());
            assert!(super::local_remove(path("tree"), false).await.is_err());
            assert!(dir.path().join("tree").join("leaf").exists());
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink("tree", path("link")).unwrap();
                super::local_remove(path("link"), true).await.unwrap();
                assert!(std::fs::symlink_metadata(path("link")).is_err());
                assert!(dir.path().join("tree").join("leaf").exists());
            }
            super::local_remove(path("tree"), true).await.unwrap();
            assert!(!dir.path().join("tree").exists());
        });
    }

    #[test]
    fn copy_file_copies_a_picked_path_or_file_url_with_its_permissions() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
            std::fs::write(path("picked"), b"picked").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path("picked"), std::fs::Permissions::from_mode(0o640))
                    .unwrap();
            }
            super::local_copy_file(path("picked").parse().unwrap(), path("copy"))
                .await
                .unwrap();
            assert_eq!(std::fs::read(path("copy")).unwrap(), b"picked");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(path("copy"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o640
                );
                let url = format!("file://{}", path("picked"));
                super::local_copy_file(url.parse().unwrap(), path("from-url"))
                    .await
                    .unwrap();
                assert_eq!(std::fs::read(path("from-url")).unwrap(), b"picked");
            }
        });
    }

    #[test]
    fn copy_file_never_clobbers_an_existing_destination() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
            std::fs::write(path("picked"), b"picked").unwrap();
            std::fs::write(path("taken"), b"taken").unwrap();
            assert!(
                super::local_copy_file(path("picked").parse().unwrap(), path("taken"))
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(path("taken")).unwrap(), b"taken");
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink("taken", path("link")).unwrap();
                std::os::unix::fs::symlink("absent", path("dangling")).unwrap();
                for name in ["link", "dangling"] {
                    assert!(
                        super::local_copy_file(path("picked").parse().unwrap(), path(name))
                            .await
                            .is_err()
                    );
                    assert!(std::fs::symlink_metadata(path(name)).unwrap().is_symlink());
                }
                assert_eq!(std::fs::read(path("taken")).unwrap(), b"taken");
                assert!(!dir.path().join("absent").exists());
            }
        });
    }

    #[test]
    fn write_text_replaces_a_prepared_file_and_never_creates_one() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
            std::fs::write(path("stage"), b"a longer previous body").unwrap();
            super::local_write_text(path("stage"), "new".into())
                .await
                .unwrap();
            assert_eq!(std::fs::read(path("stage")).unwrap(), b"new");
            assert!(super::local_write_text(path("absent"), "new".into())
                .await
                .is_err());
            assert!(!dir.path().join("absent").exists());
        });
    }

    #[cfg(unix)]
    #[test]
    fn special_files_and_non_utf8_names_fail_explicitly() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(super::open_regular(fifo.to_str().unwrap()).is_err());
        match std::fs::write(
            dir.path().join(std::ffi::OsStr::from_bytes(&[255])),
            b"data",
        ) {
            Ok(()) => assert!(list_local_entries(dir.path().to_str().unwrap(), None).is_err()),
            // APFS rejects invalid UTF-8 before an entry can reach our scanner.
            Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => {}
            Err(error) => panic!("creating a non-UTF-8 fixture: {error}"),
        }
    }

    #[test]
    fn preserves_links_and_unlinks_without_touching_referents() {
        tauri::async_runtime::block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let path = |name: &str| temp.path().join(name).to_str().unwrap().to_owned();
            std::fs::create_dir(path("lib")).unwrap();
            std::fs::write(path("data"), b"contents must survive").unwrap();
            for (name, target, is_dir) in [
                ("lib64", "lib".to_owned(), true),
                ("file-link", "data".to_owned(), false),
                ("absolute", path("data"), false),
                ("broken", "missing".to_owned(), false),
                ("loop", "loop".to_owned(), false),
            ] {
                local_symlink(target.clone(), path(name), is_dir)
                    .await
                    .unwrap();
                assert_eq!(local_readlink(path(name)).await.unwrap(), target);
                let md = local_lstat(path(name)).await.unwrap().unwrap();
                assert!(md.is_symlink);
                let entries = list_local_entries(&path(""), None).unwrap();
                assert!(entries.iter().find(|e| e.name == name).unwrap().is_symlink);
                assert!(local_symlink("other".into(), path(name), false)
                    .await
                    .is_err());
                assert_eq!(local_readlink(path(name)).await.unwrap(), target);
                local_unlink(path(name)).await.unwrap();
                assert!(local_lstat(path(name)).await.unwrap().is_none());
            }
            assert!(local_unlink(path("data")).await.is_err());
            assert!(local_unlink(path("lib")).await.is_err());
            assert!(temp.path().join("lib").is_dir());
            assert_eq!(
                std::fs::read(path("data")).unwrap(),
                b"contents must survive"
            );
        });
    }
}
