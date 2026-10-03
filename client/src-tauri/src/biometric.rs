//! Unlock with Touch ID (macOS). Windows Hello plugs into the same seam later.
//!
//! What this is, precisely: after a successful password unlock the user may let
//! this device remember the master password behind a biometric. The password is
//! sealed by `unissh_keychain::device_wrap` under a **device secret**, and only
//! the sealed blob is written to disk (`biometric-unlock.bin`, beside the keyset).
//! The device secret itself lives in the platform's biometric-gated store; on
//! macOS that is a Keychain item whose access control requires the *current*
//! Touch ID set (see `macos.rs`), so re-enrolling a finger makes it unreadable.
//!
//! What it is not: a change to the key hierarchy. The Unlock Key derivation and
//! the keyset format are untouched, the password alone always unlocks, and a
//! biometric unlock ends in the very same `Core::unlock` a typed password does.
//! The password never reaches the webview — not when it is stored (the command
//! takes it once, from the form that already holds it, and keeps it in Rust) and
//! not when it is used (it is read, unsealed and handed to the core here).
//!
//! **The seam.** [`DeviceSecretStore`] is everything a platform contributes: make
//! a secret, read it behind the prompt, say whether it is still there, delete it.
//! Everything else — the blob, the password check, the unlock, the wipe on
//! invalidation — is platform-independent and lives in this file.
//!
//! Every call here may block (a Keychain query, a prompt the user is looking at,
//! an Argon2id run), so each command does its work on the blocking pool, never on
//! the main thread — the prompt is served by the very loop we would block.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::State;
use unissh_ffi::FfiError;
use unissh_keychain::device_wrap;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{ApiError, ApiResult};
use crate::keychain::stored_secret_key_hex_now;
use crate::state::AppState;

#[cfg(target_os = "macos")]
mod macos;

/// The sealed master password, next to the keyset. Ciphertext only: without the
/// device secret, which never leaves the platform store, it opens to nothing.
const BLOB_FILE: &str = "biometric-unlock.bin";

/// Whether the platform's biometric-gated secret exists. Asking must never
/// prompt.
// Constructed only by a platform adapter; on a target without one (Linux, and
// Windows until its adapter lands) the variants exist for the shared code alone.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretState {
    /// This device or build cannot do biometric unlock at all.
    Unsupported,
    /// Supported, and no secret stored (never enabled, or invalidated).
    Absent,
    /// A secret is stored.
    Present,
}

/// Why the device secret could not be produced.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum SecretError {
    /// The user dismissed the prompt, or the biometric did not match. The
    /// stored material stays; the user types the password this time.
    Cancelled,
    /// The secret is gone or permanently unreadable — on macOS, the Touch ID
    /// set changed. The material is dead and must be wiped; re-enable required.
    Invalidated,
    /// The platform refused for a reason the user cannot answer with a finger.
    /// Carries a diagnostic (an OS status code), never secret material.
    Failed(String),
}

/// What a platform contributes to biometric unlock. See the module note.
pub(crate) trait DeviceSecretStore {
    /// Non-interactive: never shows a prompt.
    fn state(&self) -> SecretState;
    /// Generate a fresh device secret, store it behind the biometric (replacing
    /// any earlier one), and return it. Storing does not prompt.
    fn create(&self) -> Result<Zeroizing<Vec<u8>>, SecretError>;
    /// Read the device secret. This is what shows the system prompt, carrying
    /// `reason` (already localised by the caller).
    fn read(&self, reason: &str) -> Result<Zeroizing<Vec<u8>>, SecretError>;
    /// Delete the device secret. Deleting nothing is a success.
    fn delete(&self) -> Result<(), SecretError>;
}

/// This platform's adapter, or `None` where biometric unlock is not offered.
/// Linux is not offered by decision: its fingerprint stack answers yes/no and
/// protects no secret. Mobile has its own (separate) story.
fn platform_store() -> Option<Box<dyn DeviceSecretStore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(macos::TouchId))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The answer the Settings row and the unlock screen read.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricStatus {
    /// This device can do biometric unlock (hardware present, a finger
    /// enrolled, and a build that may use the protected Keychain).
    pub supported: bool,
    /// Material is stored and its device secret is still there.
    pub enabled: bool,
    /// Material is stored but its device secret is gone (the biometric set
    /// changed): the user must re-enable.
    pub invalidated: bool,
}

/// How a biometric unlock attempt ended. Expected outcomes are values, not
/// errors: the unlock screen switches on them to decide what to show next.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BiometricUnlockOutcome {
    /// The vault is open.
    Unlocked,
    /// Prompt dismissed or not matched: show the password field.
    Cancelled,
    /// The stored material was dead and has been wiped: show the password
    /// field and say that biometric unlock must be enabled again.
    Invalidated,
}

fn blob_path(state: &AppState) -> PathBuf {
    state.keyset_path.with_file_name(BLOB_FILE)
}

fn unsupported() -> ApiError {
    ApiError::other("biometric unlock is not available on this device")
}

fn secret_error(e: SecretError) -> ApiError {
    match e {
        SecretError::Cancelled => ApiError::other("biometric prompt cancelled"),
        SecretError::Invalidated => ApiError::other("biometric unlock must be enabled again"),
        SecretError::Failed(msg) => ApiError::other(msg),
    }
}

async fn off_main<T, F>(f: F) -> ApiResult<T>
where
    F: FnOnce() -> ApiResult<T> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f).await?
}

/// Write the blob so that a crash leaves either the old file or the new one,
/// never half of one, and readable by this user only.
fn write_blob(path: &Path, blob: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("bin.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(blob)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// Wipe both halves: the blob and the device secret. Each is attempted even if
/// the other fails — "off" that leaves one half behind is the outcome to avoid.
/// Missing halves are not errors. This is the one place material is forgotten;
/// disabling, invalidation, and (ticket 03) a password change all come here.
pub(crate) fn forget_now(store: Option<&dyn DeviceSecretStore>, blob: &Path) -> ApiResult<()> {
    let file = match std::fs::remove_file(blob) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ApiError::other(e)),
    };
    let secret = match store {
        Some(s) => s.delete().map_err(secret_error),
        None => Ok(()),
    };
    file.and(secret)
}

fn status_now(store: Option<&dyn DeviceSecretStore>, blob: &Path) -> BiometricStatus {
    let secret = store.map_or(SecretState::Unsupported, |s| s.state());
    let stored = blob.exists();
    BiometricStatus {
        supported: secret != SecretState::Unsupported,
        enabled: stored && secret == SecretState::Present,
        // Not when merely `Unsupported`: a closed lid (clamshell) reports no
        // sensor for a while, and that is not a reason to call the material dead.
        invalidated: stored && secret == SecretState::Absent,
    }
}

// ---------- commands ----------

#[tauri::command]
pub async fn biometric_status(state: State<'_, AppState>) -> ApiResult<BiometricStatus> {
    let blob = blob_path(&state);
    off_main(move || {
        let store = platform_store();
        Ok(status_now(store.as_deref(), &blob))
    })
    .await
}

/// Remember the master password behind the biometric. Only while unlocked, and
/// only after the core has confirmed `password` against the keyset with the
/// Secret Key this device remembers — so enabling proves the password is held,
/// and a mistyped one is never stored.
#[tauri::command]
pub async fn biometric_enable(password: String, state: State<'_, AppState>) -> ApiResult<()> {
    let password = Zeroizing::new(password);
    let core = state.core.clone();
    let blob = blob_path(&state);
    off_main(move || {
        let store = platform_store().ok_or_else(unsupported)?;
        if store.state() == SecretState::Unsupported {
            return Err(unsupported());
        }
        let secret_key_hex = stored_secret_key_hex_now()?
            .ok_or_else(|| ApiError::other("the Secret Key is not remembered on this device"))?;
        core.verify_unlock_password(password.to_string(), secret_key_hex)?;
        let secret = store.create().map_err(secret_error)?;
        let sealed = device_wrap::wrap(password.as_bytes(), &secret).map_err(ApiError::other)?;
        if let Err(e) = write_blob(&blob, &sealed) {
            // Half-enabled is worse than off: drop the secret we just made.
            let _ = store.delete();
            return Err(ApiError::other(e));
        }
        log::info!("biometric unlock enabled");
        Ok(())
    })
    .await
}

/// Turn biometric unlock off: both the blob and the device secret, now.
#[tauri::command]
pub async fn biometric_disable(state: State<'_, AppState>) -> ApiResult<()> {
    let blob = blob_path(&state);
    off_main(move || {
        let store = platform_store();
        forget_now(store.as_deref(), &blob)?;
        log::info!("biometric unlock disabled");
        Ok(())
    })
    .await
}

/// Unlock with the biometric. Reads the device secret (the system prompt shows
/// `reason`), unseals the password, and calls the same core unlock a typed
/// password does, with the Secret Key this device remembers. The password
/// exists only inside this function.
#[tauri::command]
pub async fn biometric_unlock(
    app: tauri::AppHandle,
    reason: String,
    state: State<'_, AppState>,
) -> ApiResult<BiometricUnlockOutcome> {
    let core = state.core.clone();
    let blob = blob_path(&state);
    let outcome = off_main(move || {
        let store = platform_store().ok_or_else(unsupported)?;
        let sealed =
            std::fs::read(&blob).map_err(|_| ApiError::other("biometric unlock is not enabled"))?;
        let invalidated = |why: &str| {
            log::warn!("biometric unlock invalidated ({why}); material wiped");
            forget_now(Some(store.as_ref()), &blob).map(|()| BiometricUnlockOutcome::Invalidated)
        };
        // Before the prompt: a Touch ID that cannot end in an unlock is not asked for.
        let secret_key_hex = stored_secret_key_hex_now()?
            .ok_or_else(|| ApiError::other("the Secret Key is not remembered on this device"))?;
        let secret = match store.read(&reason) {
            Ok(secret) => secret,
            Err(SecretError::Cancelled) => return Ok(BiometricUnlockOutcome::Cancelled),
            Err(SecretError::Invalidated) => return invalidated("device secret gone"),
            Err(e) => return Err(secret_error(e)),
        };
        let Ok(mut material) = device_wrap::unwrap(&sealed, &secret) else {
            return invalidated("blob does not open under the device secret");
        };
        let password = match String::from_utf8(std::mem::take(&mut *material)) {
            Ok(password) => password,
            Err(e) => {
                e.into_bytes().zeroize();
                return invalidated("material is not a password");
            }
        };
        match core.unlock(Some(password), secret_key_hex) {
            Ok(()) => Ok(BiometricUnlockOutcome::Unlocked),
            // The stored password no longer opens the keyset: it was changed.
            Err(FfiError::InvalidCredentials) => invalidated("stored password no longer valid"),
            Err(e) => Err(e.into()),
        }
    })
    .await?;
    if matches!(outcome, BiometricUnlockOutcome::Unlocked) {
        #[cfg(desktop)]
        crate::mcp::resume_access(&app);
    }
    #[cfg(not(desktop))]
    let _ = &app;
    Ok(outcome)
}
