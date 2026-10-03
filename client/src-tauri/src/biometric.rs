//! Unlock with Touch ID (macOS) or Windows Hello (Windows).
//!
//! What this is, precisely: after a successful password unlock the user may let
//! this device remember the master password behind a biometric. The password is
//! sealed by `unissh_keychain::device_wrap` under a **device secret**, and only
//! the sealed blob is written to disk (`biometric-unlock.bin`, beside the keyset).
//! The device secret itself lives in the platform's biometric-gated store; on
//! macOS that is a Keychain item whose access control requires the *current*
//! Touch ID set (see `macos.rs`), so re-enrolling a finger makes it unreadable;
//! on Windows it is never stored at all — it is a Windows Hello signature over a
//! fixed challenge, reproduced behind the Hello prompt each time (see
//! `windows.rs`).
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
//! **The presence gate.** A Secret-Key-only vault on a device that remembers its
//! Secret Key opens with no typing at all. The user may ask for a Touch ID /
//! Windows Hello check in front of that (`biometric_presence_unlock`). It stores
//! nothing and seals nothing: the platform is asked "is the owner here" and, on
//! yes, the existing remembered-key unlock runs. It is a presence check, not a
//! protection of the key — see `THREAT_MODEL.md`.
//!
//! **Wiping is deliberately narrow.** Material is destroyed only on an explicit
//! "this is dead" signal — the adapter says `Invalidated`/`Absent`, the blob does
//! not open under the secret, or the core rejects the stored password. A closed
//! lid, a lockout, a failed finger or an OS status code nobody mapped is never
//! one of those: it falls back to the password and keeps the material. The
//! exceptions are the explicit ones: the user turns it off or forgets the
//! material from Settings, the instance is reset, or this device's keyset is
//! changed or replaced (a password change, a recovery, a pairing) — a password
//! sealed for the old keyset must not outlive it.
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

use crate::commands::{blocking_api, resume_after_unlock};
use crate::error::{ApiError, ApiResult};
use crate::keychain::{secret_key_remembered_now, stored_secret_key_hex_now};
use crate::state::AppState;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// The sealed master password, next to the keyset. Ciphertext only: without the
/// device secret, which never leaves the platform store, it opens to nothing.
const BLOB_FILE: &str = "biometric-unlock.bin";

/// What the platform knows about its biometric-gated secret. Asking must never
/// prompt.
// Absent/Present/Unknown are constructed only by a platform adapter; on a
// target without one (Linux) they exist for the shared code alone.
#[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretState {
    /// This device or build cannot do biometric unlock right now (no sensor,
    /// nothing enrolled, a closed lid, a build without the needed entitlement).
    Unsupported,
    /// Explicitly not there, or explicitly dead (on macOS: the item is not found,
    /// or the Touch ID set changed since it was made). The only state in which
    /// stored material counts as invalidated.
    Absent,
    /// A usable secret is stored.
    Present,
    /// The platform gave an answer nobody mapped. Never wipes and is never
    /// reported as invalidated; an unlock attempt will tell.
    Unknown,
}

/// Why the device secret could not be produced.
#[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum SecretError {
    /// The user dismissed the prompt, the biometric did not match, or it is
    /// locked out. The material stays; the user types the password this time.
    Cancelled,
    /// The secret is explicitly gone or dead. The material is wiped and the user
    /// is asked to enable biometric unlock again.
    Invalidated,
    /// The platform cannot do this here at all (see [`SecretState::Unsupported`]).
    /// Never wipes; the setting is simply not offered.
    Unsupported,
    /// Anything else. Carries a diagnostic (an OS status code), never secret
    /// material. Never wipes.
    Failed(String),
}

/// What a platform contributes to biometric unlock. See the module note.
///
/// Contract, written for more than one platform:
/// * `state` never prompts, on any platform.
/// * `create` makes a fresh secret behind the biometric, replacing any earlier
///   one, and returns it. Whether that prompts is the platform's business: on
///   macOS storing a Keychain item does not; Windows Hello prompts when the
///   credential is created and again on every signature.
/// * `read` produces the same secret behind the prompt. `reason` is the localised
///   line for the prompt; a platform whose prompt takes no message ignores it.
/// * `delete` is idempotent.
/// * `presence_available` and `confirm_presence` are the presence gate: the
///   platform's own "is the owner here" prompt with nothing stored behind it.
///   Available never prompts; confirm prompts with `reason` (where the platform
///   takes one) and creates or reads no secret.
/// * The blob itself is stored by the shared code (a file beside the keyset),
///   on every platform: it is ciphertext only. Whatever else an adapter needs
///   to reproduce its secret (the Windows challenge) is the adapter's to keep.
pub(crate) trait DeviceSecretStore {
    fn state(&self) -> SecretState;
    fn create(&self) -> Result<Zeroizing<Vec<u8>>, SecretError>;
    fn read(&self, reason: &str) -> Result<Zeroizing<Vec<u8>>, SecretError>;
    fn delete(&self) -> Result<(), SecretError>;
    fn presence_available(&self) -> bool;
    fn confirm_presence(&self, reason: &str) -> Result<(), SecretError>;
}

/// This platform's adapter, or `None` where biometric unlock is not offered.
/// Linux is not offered by decision: its fingerprint stack answers yes/no and
/// protects no secret. Mobile has its own (separate) story.
fn platform_store() -> Option<Box<dyn DeviceSecretStore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(macos::TouchId))
    }
    #[cfg(target_os = "windows")]
    {
        Some(Box::new(windows::WindowsHello))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// The answer the Settings row and the unlock screen read.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricStatus {
    /// This device can do biometric unlock right now (macOS: sensor present, a
    /// finger enrolled, and a build that may use the protected Keychain;
    /// Windows: Windows Hello set up for this user).
    pub supported: bool,
    /// Material is stored and its device secret is (as far as the platform
    /// says without a prompt) still there.
    pub enabled: bool,
    /// Material is stored but its device secret is explicitly gone (the
    /// biometric set changed): the user must re-enable.
    pub invalidated: bool,
    /// Material is stored but the platform says biometric unlock cannot be
    /// used here now (Windows Hello turned off by policy or its PIN removed,
    /// Touch ID gone or its lid closed). Shown as off, with the reason, and the
    /// leftover can be forgotten from Settings; nothing wipes it on its own,
    /// because "not now" (a closed lid) looks the same as "not any more".
    pub stranded: bool,
    /// The platform's presence prompt can be shown (the Secret-Key-only
    /// startup gate). Needs no stored material, so it can be there when
    /// `supported` is not (macOS: a build barred from the protected Keychain).
    pub presence_supported: bool,
    /// This device remembers the Secret Key in the OS keychain. Biometric unlock
    /// stores only the password, so without a remembered Secret Key it cannot
    /// unlock and is neither offered nor attempted; the presence gate guards the
    /// remembered key and so has nothing to guard without it. Only asked where
    /// `supported` or `presence_supported`.
    pub secret_key_remembered: bool,
}

/// How a biometric unlock attempt ended. Expected outcomes are values, not
/// errors: the unlock screen switches on them to decide what to show next.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BiometricUnlockOutcome {
    /// The vault is open.
    Unlocked,
    /// Prompt dismissed, not matched, or not possible right now: show the
    /// password field. The material is kept.
    Cancelled,
    /// The stored material was dead and has been wiped: show the password
    /// field and say that biometric unlock must be enabled again.
    Invalidated,
    /// The Secret Key is not remembered on this device, so the stored password
    /// alone cannot unlock. Nothing was prompted and nothing wiped.
    NoSecretKey,
}

pub(crate) fn blob_path(state: &AppState) -> PathBuf {
    state.keyset_path.with_file_name(BLOB_FILE)
}

fn unsupported() -> ApiError {
    ApiError::other("biometric unlock is not available on this device")
}

fn secret_error(e: SecretError) -> ApiError {
    match e {
        SecretError::Cancelled => ApiError::other("biometric prompt cancelled"),
        SecretError::Invalidated => ApiError::other("biometric unlock must be enabled again"),
        SecretError::Unsupported => unsupported(),
        SecretError::Failed(msg) => ApiError::other(msg),
    }
}

/// Write the blob so that a crash leaves either the old file or the new one,
/// never half of one, and readable by this user only. A failed write leaves no
/// temporary file behind.
fn write_blob(path: &Path, blob: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("bin.tmp");
    let write = || -> std::io::Result<()> {
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
    };
    write().inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Wipe both halves: the blob and the device secret. Each is attempted even if
/// the other fails — "off" that leaves one half behind is the outcome to avoid.
/// Missing halves are not errors. This is the one place material is forgotten:
/// disabling, invalidation, a failed enable, resetting the instance and a
/// changed keyset ([`forget_after_keyset_change`]) all come here.
fn forget_with(store: Option<&dyn DeviceSecretStore>, blob: &Path) -> ApiResult<()> {
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

/// [`forget_with`] this platform's store. Blocking.
pub(crate) fn forget_now(blob: &Path) -> ApiResult<()> {
    forget_with(platform_store().as_deref(), blob)
}

/// This device's keyset was just re-wrapped or replaced: the master password
/// changed (or was added or removed), or a keyset came from a recovery or a
/// pairing. A password sealed for the old keyset must not stay behind, so both
/// halves are wiped and biometric unlock has to be turned on again, with the
/// password of the keyset now on disk. Returns whether there was material to
/// wipe (so the UI can say "turn it on again"). Best-effort and blocking: the
/// keyset change has already happened and is not undone by a wipe that fails;
/// a stale password left behind is still caught (and wiped) by the next
/// biometric unlock, which the core then refuses.
pub(crate) fn forget_after_keyset_change(blob: &Path) -> bool {
    let had = blob.exists();
    if let Err(e) = forget_now(blob) {
        log::warn!("biometric: wipe after a keyset change failed: {e:?}");
    }
    had
}

/// The status from what the platform and the disk say. Pure.
fn status_from(
    secret: SecretState,
    stored: bool,
    presence_supported: bool,
    secret_key_remembered: bool,
) -> BiometricStatus {
    let supported = secret != SecretState::Unsupported;
    BiometricStatus {
        supported,
        enabled: stored && matches!(secret, SecretState::Present | SecretState::Unknown),
        // Only on an explicit "dead": a closed lid (Unsupported) or an
        // unmapped answer (Unknown) is not a reason to call the material gone.
        invalidated: stored && secret == SecretState::Absent,
        stranded: stored && !supported,
        presence_supported,
        secret_key_remembered: (supported || presence_supported) && secret_key_remembered,
    }
}

fn status_now(store: Option<&dyn DeviceSecretStore>, blob: &Path) -> BiometricStatus {
    let secret = store.map_or(SecretState::Unsupported, |s| s.state());
    let presence = store.is_some_and(|s| s.presence_available());
    // The keychain is asked only where an answer matters.
    let ask = secret != SecretState::Unsupported || presence;
    status_from(
        secret,
        blob.exists(),
        presence,
        ask && secret_key_remembered_now(),
    )
}

// ---------- commands ----------

#[tauri::command]
pub async fn biometric_status(state: State<'_, AppState>) -> ApiResult<BiometricStatus> {
    let blob = blob_path(&state);
    blocking_api(move || Ok(status_now(platform_store().as_deref(), &blob))).await
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
    blocking_api(move || {
        let store = platform_store().ok_or_else(unsupported)?;
        if store.state() == SecretState::Unsupported {
            return Err(unsupported());
        }
        let secret_key_hex = stored_secret_key_hex_now()?
            .ok_or_else(|| ApiError::other("the Secret Key is not remembered on this device"))?;
        core.verify_unlock_password(password.to_string(), secret_key_hex)?;
        // From here on a failure must leave the feature OFF, not half-on: a new
        // secret beside an old blob would read as "invalidated", and an old
        // secret is replaced by `create` anyway.
        let enabled = store
            .create()
            .map_err(secret_error)
            .and_then(|secret| {
                device_wrap::wrap(password.as_bytes(), &secret).map_err(ApiError::other)
            })
            .and_then(|sealed| write_blob(&blob, &sealed).map_err(ApiError::other));
        if let Err(e) = enabled {
            let _ = forget_with(Some(store.as_ref()), &blob);
            return Err(e);
        }
        log::info!("biometric unlock enabled");
        Ok(())
    })
    .await
}

/// Turn biometric unlock off: both the blob and the device secret, now. Also
/// what Settings calls to forget material stranded on a device that can no
/// longer use it.
#[tauri::command]
pub async fn biometric_disable(state: State<'_, AppState>) -> ApiResult<()> {
    let blob = blob_path(&state);
    blocking_api(move || {
        forget_now(&blob)?;
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
    let outcome = blocking_api(move || {
        let store = platform_store().ok_or_else(unsupported)?;
        let sealed =
            std::fs::read(&blob).map_err(|_| ApiError::other("biometric unlock is not enabled"))?;
        // Before the prompt: a Touch ID that cannot end in an unlock is not asked for.
        let Some(secret_key_hex) = stored_secret_key_hex_now()? else {
            return Ok(BiometricUnlockOutcome::NoSecretKey);
        };
        let invalidated = |why: &str| {
            log::warn!("biometric unlock invalidated ({why}); material wiped");
            forget_with(Some(store.as_ref()), &blob).map(|()| BiometricUnlockOutcome::Invalidated)
        };
        let secret = match store.read(&reason) {
            Ok(secret) => secret,
            Err(SecretError::Cancelled | SecretError::Unsupported) => {
                return Ok(BiometricUnlockOutcome::Cancelled)
            }
            Err(SecretError::Invalidated) => return invalidated("device secret gone"),
            Err(e @ SecretError::Failed(_)) => return Err(secret_error(e)),
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
        resume_after_unlock(&app);
    }
    Ok(outcome)
}

/// The Secret-Key-only startup gate: show the platform's presence prompt
/// (`reason` where it takes one) and, only on a match, run the same
/// remembered-key unlock `keychain_unlock` does. Nothing is stored or read
/// behind the prompt; a dismissed or impossible prompt leaves the vault
/// locked, and the unlock screen's manual path (the Secret Key from the
/// Emergency Kit) still works.
#[tauri::command]
pub async fn biometric_presence_unlock(
    app: tauri::AppHandle,
    reason: String,
    state: State<'_, AppState>,
) -> ApiResult<BiometricUnlockOutcome> {
    let core = state.core.clone();
    let outcome = blocking_api(move || {
        let store = platform_store().ok_or_else(unsupported)?;
        // Before the prompt: one that cannot end in an unlock is not shown.
        let Some(secret_key_hex) = stored_secret_key_hex_now()? else {
            return Ok(BiometricUnlockOutcome::NoSecretKey);
        };
        match store.confirm_presence(&reason) {
            Ok(()) => {}
            Err(SecretError::Cancelled | SecretError::Unsupported) => {
                return Ok(BiometricUnlockOutcome::Cancelled)
            }
            Err(e) => return Err(secret_error(e)),
        }
        core.unlock(None, secret_key_hex)?;
        Ok(BiometricUnlockOutcome::Unlocked)
    })
    .await?;
    if matches!(outcome, BiometricUnlockOutcome::Unlocked) {
        resume_after_unlock(&app);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every row of the status table: what Settings and the unlock screen are
    // told for each platform answer, with and without stored material.
    #[test]
    fn status_reports_each_platform_answer_honestly() {
        use SecretState::*;
        // (state, stored) -> (supported, enabled, invalidated, stranded)
        let table = [
            ((Present, true), (true, true, false, false)),
            ((Unknown, true), (true, true, false, false)),
            ((Absent, true), (true, false, true, false)),
            ((Unsupported, true), (false, false, false, true)),
            ((Present, false), (true, false, false, false)),
            ((Absent, false), (true, false, false, false)),
            ((Unsupported, false), (false, false, false, false)),
        ];
        for ((secret, stored), want) in table {
            let s = status_from(secret, stored, false, true);
            assert_eq!(
                (s.supported, s.enabled, s.invalidated, s.stranded),
                want,
                "{secret:?}, stored={stored}"
            );
        }
        // The presence gate needs no stored material and no protected store,
        // but a Secret Key it can guard; with neither prompt possible the
        // keychain answer is not reported.
        let gate = status_from(Unsupported, false, true, true);
        assert!(gate.presence_supported && gate.secret_key_remembered);
        assert!(!status_from(Unsupported, false, false, true).secret_key_remembered);
    }
}
