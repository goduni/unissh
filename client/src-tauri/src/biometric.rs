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
//! protection of the key — see `THREAT_MODEL.md`. Settings turns it on only
//! after the same prompt has worked once (`biometric_confirm_presence`), so a
//! prompt that never succeeds on this machine cannot lock the user out.
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
//! **One attempt, one result.** A prompt can outlive the moment it was asked
//! for: the user gives up on it and types the password, the vault is unlocked
//! and locked again, a second prompt is requested. [`UnlockAttempts`] numbers
//! the attempts; starting one, cancelling one, a typed unlock, a lock and a
//! reset each end the attempt before them. A result is acted on only while its
//! attempt is still the current one and the vault is still locked — otherwise
//! it is discarded: no unlock, no wipe, and a secret the prompt released is
//! zeroized unused; the command reports `Superseded`, which the unlock screen
//! ignores. Where the platform can take a prompt down, ending the attempt does
//! that too (see the adapters).
//!
//! That a **lock** wins over an unlock which began before it is not decided
//! here but in the core, for every kind of unlock alike: an attempt reads the
//! core's lock epoch when it begins — before its prompt — and
//! `Core::unlock_unless_locked_since` installs nothing if a lock came after.
//! No lock of this module is held across a prompt, a platform call or the core.
//!
//! Every call here may block (a Keychain query, a prompt the user is looking at,
//! an Argon2id run), so each command does its work on the blocking pool, never on
//! the main thread — the prompt is served by the very loop we would block.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::Serialize;
use tauri::{Emitter, State};
use unissh_ffi::{Core, FfiError};
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

/// Emitted (no payload) when stored material should have been wiped after this
/// device's keyset changed and could not be. One event for every path that
/// installs a keyset, so each of them tells the user the same way.
const WIPE_FAILED_EVENT: &str = "biometric-wipe-failed";

/// Emitted (no payload) when a keyset install that **failed** had already
/// rewritten the keyset, and biometric unlock was therefore turned off: the
/// command's error says nothing about that, and the user would find the
/// feature off with no word why. (An install that succeeded tells its own
/// story — a password change says so in Settings.)
const TURNED_OFF_EVENT: &str = "biometric-turned-off";

/// Takes a prompt down from another thread. Called at most once.
pub(crate) type Dismiss = Box<dyn FnOnce() + Send>;

/// The attempt that may still unlock, and how to take its prompt down.
#[derive(Default)]
struct CurrentAttempt {
    id: u64,
    dismiss: Option<Dismiss>,
}

fn held<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Poisoning protects no invariant here: an id and an optional callback.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Which biometric unlock attempt, if any, may still open the vault. See the
/// module note ("One attempt, one result"). One per app, in `AppState`.
///
/// Lock order: `current` is the only lock here and a leaf. Every method takes
/// it for a few assignments and releases it before anything else happens — it
/// is never held while a prompt is dismissed or waited on, nor across the core.
#[derive(Default)]
pub struct UnlockAttempts {
    current: Mutex<CurrentAttempt>,
}

impl UnlockAttempts {
    /// End the attempt under way: the id of the next one, and the ended
    /// prompt's dismisser, for the caller to run now that `current` is free.
    fn end(&self) -> (u64, Option<Dismiss>) {
        let mut current = held(&self.current);
        current.id = current.id.wrapping_add(1);
        (current.id, current.dismiss.take())
    }

    /// End the attempt under way, if any — its result will be discarded, and
    /// its prompt is taken down where the platform can — and name a new one.
    /// Called for a new prompt, for "use the password instead", for a typed
    /// unlock and for a reset. May block briefly (it talks to the platform).
    pub(crate) fn supersede(&self) -> u64 {
        let (id, dismiss) = self.end();
        if let Some(dismiss) = dismiss {
            dismiss();
        }
        id
    }

    /// Whether attempt `id` is still the one whose answer counts.
    fn is_current(&self, id: u64) -> bool {
        held(&self.current).id == id
    }

    /// Lock the vault (`lock`) and end any attempt. In that order of effect:
    /// the attempt is over first (two assignments), then the vault is locked,
    /// and only then is the platform asked to take the prompt down — a
    /// security lock does not wait on a third-party call. An unlock already
    /// past its "still wanted" check is stopped by the core, not here: it
    /// began before this lock (see the module note).
    pub(crate) fn locking<T>(&self, lock: impl FnOnce() -> T) -> T {
        let (_, dismiss) = self.end();
        let locked = lock();
        if let Some(dismiss) = dismiss {
            dismiss();
        }
        locked
    }

    /// Keep `dismiss` for attempt `id` while its prompt is up. An attempt that
    /// is already over gets it straight back, to be called at once.
    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    fn showing(&self, id: u64, dismiss: Dismiss) -> Option<Dismiss> {
        let mut current = held(&self.current);
        if current.id != id {
            drop(current);
            return Some(dismiss);
        }
        current.dismiss = Some(dismiss);
        drop(current);
        None
    }

    /// The prompt of attempt `id` has answered: nothing is left to take down.
    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    fn answered(&self, id: u64) {
        let mut current = held(&self.current);
        if current.id == id {
            current.dismiss = None;
        }
    }
}

/// The attempt a prompt is shown for. An adapter does one thing with it: wrap
/// its wait for the user in [`Prompt::wait`]. The shared code asks it whether
/// the answer still counts ([`Prompt::current`]).
pub(crate) struct Prompt<'a> {
    attempt: Option<(&'a UnlockAttempts, u64)>,
}

impl<'a> Prompt<'a> {
    const fn of(attempts: &'a UnlockAttempts, id: u64) -> Self {
        Self {
            attempt: Some((attempts, id)),
        }
    }
}

impl Prompt<'static> {
    /// A prompt nothing supersedes: enabling, and confirming the presence gate
    /// from Settings. They unlock nothing, so a late answer does no harm.
    const fn standalone() -> Self {
        Self { attempt: None }
    }
}

impl Prompt<'_> {
    /// Whether this prompt's answer still counts: its attempt has not been
    /// superseded. Always true for a standalone prompt.
    fn current(&self) -> bool {
        self.attempt
            .is_none_or(|(attempts, id)| attempts.is_current(id))
    }

    /// Wait for the user (`answer` blocks until the prompt ends), with
    /// `dismiss` able to end that wait from another thread if the attempt is
    /// superseded meanwhile. An attempt that is already over has `dismiss`
    /// called before `answer` runs, so the adapter must start its prompt in a
    /// way that a dismissal made just before still ends it (both adapters do:
    /// an invalidated `LAContext` refuses to evaluate, a cancelled WinRT
    /// operation completes as cancelled).
    ///
    /// Compiled only where something waits on a prompt: the macOS and Windows
    /// adapters, and the tests.
    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    pub(crate) fn wait<T>(&self, dismiss: Dismiss, answer: impl FnOnce() -> T) -> T {
        let Some((attempts, id)) = self.attempt else {
            return answer();
        };
        if let Some(dismiss) = attempts.showing(id, dismiss) {
            dismiss();
        }
        let answered = answer();
        attempts.answered(id);
        answered
    }
}

/// What the platform knows about its biometric-gated secret. Asking must never
/// prompt.
// Absent/Present/Unknown are constructed only by a platform adapter; on a
// target without one (Linux) they exist for the shared code alone.
#[cfg_attr(
    all(not(any(target_os = "macos", target_os = "windows")), not(test)),
    expect(
        dead_code,
        reason = "Absent/Present/Unknown come only from the macOS/Windows adapters; the tests build them too"
    )
)]
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
#[cfg_attr(
    not(any(target_os = "macos", target_os = "windows")),
    expect(
        dead_code,
        reason = "only the macOS/Windows adapters construct a SecretError; elsewhere the shared code just matches on it"
    )
)]
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
///   The wait for the user goes through [`Prompt::wait`], so that an attempt
///   which is superseded takes its prompt down where the platform can.
/// * `delete` is idempotent.
/// * `presence_available` and `confirm_presence` are the presence gate: the
///   platform's own "is the owner here" prompt with nothing stored behind it.
///   Available never prompts; confirm prompts with `reason` (where the platform
///   takes one) and creates or reads no secret. It waits through
///   [`Prompt::wait`] like `read`.
/// * The blob itself is stored by the shared code (a file beside the keyset),
///   on every platform: it is ciphertext only. Whatever else an adapter needs
///   to reproduce its secret (the Windows challenge) is the adapter's to keep.
pub(crate) trait DeviceSecretStore {
    fn state(&self) -> SecretState;
    fn create(&self) -> Result<Zeroizing<Vec<u8>>, SecretError>;
    fn read(&self, reason: &str, prompt: &Prompt<'_>) -> Result<Zeroizing<Vec<u8>>, SecretError>;
    fn delete(&self) -> Result<(), SecretError>;
    fn presence_available(&self) -> bool;
    fn confirm_presence(&self, reason: &str, prompt: &Prompt<'_>) -> Result<(), SecretError>;
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
    /// A sealed password is on disk, usable or not. Whatever else is true,
    /// Settings offers to forget it: this is what says there is something to
    /// forget (a vault whose password was removed has no other use for it).
    pub stored: bool,
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
    /// `supported` or `presence_supported`, and — unless the caller wants it
    /// regardless (`with_secret_key`) — only when material is stored.
    pub secret_key_remembered: bool,
}

/// How turning the presence gate on went: the prompt is shown once, and the
/// setting is stored only on `Confirmed`.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PresenceCheck {
    /// The platform confirmed the owner is here.
    Confirmed,
    /// Dismissed, not matched, or locked out.
    Cancelled,
    /// The prompt cannot be shown on this device right now.
    Unavailable,
}

/// What wiping biometric unlock after a keyset change did. Internal: the
/// window learns of it through the events above, and `change_password`
/// answers only whether biometric unlock was turned off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysetWipe {
    /// Nothing was stored.
    Nothing,
    /// The sealed password is gone: biometric unlock must be turned on again.
    /// (Its device secret went with it, or — if only that delete failed —
    /// stays in the platform store, where it opens nothing and is replaced by
    /// the next enable.)
    Erased,
    /// The sealed password is still on disk: it could not be removed. Nothing
    /// promises it is harmless or that it goes on its own — the new keyset may
    /// still take the same password, and a vault left without one never tries
    /// the biometric again — so the UI must not call it erased: the user is
    /// told ([`WIPE_FAILED_EVENT`]) and Settings offers to forget it.
    Failed,
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
    /// Nobody is waiting for this attempt any more: the password was chosen, a
    /// newer prompt was asked for, the vault was locked or reset, or it is
    /// open already. Nothing was unlocked and nothing wiped. The unlock screen
    /// ignores it — whatever ended the attempt has already put the screen
    /// where it belongs — which is why it is not reported as `Cancelled`:
    /// that would take a newer prompt off the screen.
    Superseded,
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
        // The write error is what the caller reports; a leftover temp file only
        // costs disk space and is overwritten by the next enable.
        if let Err(e) = std::fs::remove_file(&tmp) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("biometric: failed to remove the temporary blob: {e}");
            }
        }
    })
}

/// Wipe both halves: the blob and the device secret. Each is attempted even if
/// the other fails — "off" that leaves one half behind is the outcome to avoid.
/// The blob goes first: it is the half that holds the password. Missing halves
/// are not errors. This is the one place material is forgotten:
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
/// password of the keyset now on disk. Says what happened (so the UI can say
/// "turn it on again", or that the wipe failed). Best-effort and blocking: the
/// keyset change has already happened and is not undone by a wipe that fails.
/// A failed wipe is not left to sort itself out — a vault whose password was
/// removed never tries the biometric again, so nothing would ever notice the
/// old password still sealed on disk: [`installing_keyset`] reports it.
///
/// `Failed` means exactly "the sealed password is still on this device" — that
/// is what the user is then told. The blob is removed first, so a wipe that
/// failed only at the platform's half has still erased the password: it is
/// logged and counts as `Erased`.
///
/// Not called directly by commands: every keyset install runs inside
/// [`installing_keyset`], which makes the wipe (and the report of a failed
/// one) part of the install, so a new keyset-installing command cannot forget
/// either.
///
/// Without a blob there is no password to outlive the keyset, so the platform
/// store is not touched at all (a device secret alone opens nothing, and the
/// next enable replaces it): no Keychain or Windows Hello call on every new
/// account or pairing.
fn forget_after_keyset_change(store: Option<&dyn DeviceSecretStore>, blob: &Path) -> KeysetWipe {
    if !blob.exists() {
        return KeysetWipe::Nothing;
    }
    match forget_with(store, blob) {
        Ok(()) => KeysetWipe::Erased,
        Err(e) if blob.exists() => {
            log::warn!("biometric: wipe after a keyset change failed: {e:?}");
            KeysetWipe::Failed
        }
        Err(e) => {
            log::warn!(
                "biometric: the stored password was erased after a keyset change, but its device secret was not: {e:?}"
            );
            KeysetWipe::Erased
        }
    }
}

/// Run `install` and wipe biometric unlock if the keyset on disk may have
/// changed: always when it succeeded, and when it failed **after** rewriting
/// the keyset (the core writes the new record before its last fallible steps,
/// so "it returned an error" does not mean "the old password still stands").
/// A failure that left the keyset as it was wipes nothing.
///
/// `keyset_digest` is the core's digest of the record on disk
/// (`Core::keyset_record_digest`): where the record lives and how it is
/// written stay the core's business. Whether anything is stored is looked at
/// only afterwards, so a blob written while `install` ran is wiped too.
fn wipe_around_install<T>(
    store: Option<&dyn DeviceSecretStore>,
    keyset_digest: impl Fn() -> Option<[u8; 32]>,
    blob: &Path,
    install: impl FnOnce() -> ApiResult<T>,
) -> (ApiResult<T>, KeysetWipe) {
    let before = keyset_digest();
    let installed = install();
    let rewritten = installed.is_ok() || keyset_digest() != before;
    let wipe = if rewritten {
        forget_after_keyset_change(store, blob)
    } else {
        KeysetWipe::Nothing
    };
    (installed, wipe)
}

/// Wrap a blocking `install` that re-wraps or replaces this device's keyset
/// (create, change password, pull, recovery, pairing) so that biometric unlock
/// is wiped in the same blocking pass — see [`wipe_around_install`] for when —
/// and the user hears what they would otherwise not: a wipe that failed
/// ([`WIPE_FAILED_EVENT`]), whichever command it was and whether or not the
/// install itself succeeded, and biometric unlock turned off by an install
/// that failed ([`TURNED_OFF_EVENT`]). For `blocking_api`.
pub(crate) fn installing_keyset<T: Send + 'static>(
    app: &tauri::AppHandle,
    state: &AppState,
    install: impl FnOnce() -> ApiResult<T> + Send + 'static,
) -> impl FnOnce() -> ApiResult<(T, KeysetWipe)> + Send + 'static {
    let app = app.clone();
    let core = state.core.clone();
    let blob = blob_path(state);
    move || {
        let (installed, wipe) = wipe_around_install(
            platform_store().as_deref(),
            || core.keyset_record_digest(),
            &blob,
            install,
        );
        let tell = match wipe {
            KeysetWipe::Failed => Some(WIPE_FAILED_EVENT),
            KeysetWipe::Erased if installed.is_err() => Some(TURNED_OFF_EVENT),
            KeysetWipe::Erased | KeysetWipe::Nothing => None,
        };
        if let Some(event) = tell {
            if let Err(e) = app.emit(event, ()) {
                log::warn!("biometric: `{event}` could not be reported to the window: {e}");
            }
        }
        installed.map(|installed| (installed, wipe))
    }
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
        stored,
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

/// `with_secret_key`: also answer `secret_key_remembered` when no material is
/// stored (Settings, and the presence gate, need it). Without it the keychain
/// is asked only for stored material that could be used — so the password
/// unlock screen of a device without biometric unlock never waits on a
/// keychain read (on macOS one that may show a Keychain dialog). The answer is
/// cached per process anyway (`keychain::secret_key_remembered_now`).
///
/// That same question — the password unlock screen's, asked on every launch by
/// every user — does not reach the platform at all when nothing is stored: the
/// only thing the screen wants to know is whether there is a prompt to show,
/// and without a blob there is none. The platform probe is a Keychain query or
/// three WinRT round trips, and the screen waits on it. Everything but
/// `stored` is then reported as "no", unprobed.
fn status_now(
    store: Option<&dyn DeviceSecretStore>,
    blob: &Path,
    with_secret_key: bool,
) -> BiometricStatus {
    let stored = blob.exists();
    if !stored && !with_secret_key {
        return status_from(SecretState::Unsupported, false, false, false);
    }
    let secret = store.map_or(SecretState::Unsupported, DeviceSecretStore::state);
    let presence = store.is_some_and(DeviceSecretStore::presence_available);
    let usable = secret != SecretState::Unsupported;
    let ask = (stored && usable) || (with_secret_key && (usable || presence));
    status_from(secret, stored, presence, ask && secret_key_remembered_now())
}

// ---------- commands ----------

#[tauri::command]
pub async fn biometric_status(
    with_secret_key: bool,
    state: State<'_, AppState>,
) -> ApiResult<BiometricStatus> {
    let blob = blob_path(&state);
    blocking_api(move || {
        Ok(status_now(
            platform_store().as_deref(),
            &blob,
            with_secret_key,
        ))
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
    blocking_api(move || {
        let store = platform_store().ok_or_else(unsupported)?;
        if store.state() == SecretState::Unsupported {
            return Err(unsupported());
        }
        let secret_key_hex = stored_secret_key_hex_now()?
            .ok_or_else(|| ApiError::other("the Secret Key is not remembered on this device"))?;
        core.verify_unlock_password(password.to_string(), String::clone(&secret_key_hex))?;
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
            // Report the enable failure; a failed cleanup is logged so the
            // half-written material is diagnosable (Settings offers to forget it).
            if let Err(cleanup) = forget_with(Some(store.as_ref()), &blob) {
                log::warn!("biometric: cleanup after a failed enable failed: {cleanup:?}");
            }
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

/// "Use the password instead": end the attempt whose prompt is up. Its result
/// is discarded whatever it turns out to be, and the prompt is taken down
/// where the platform can (see the adapters). A typed unlock and a lock do the
/// same on their own; this is for the moment between giving up on the prompt
/// and submitting the password.
///
/// It names no attempt: it ends whichever is current. The unlock screen
/// therefore asks for a new prompt only after this has answered, so it can
/// never end the prompt that replaced the one given up on.
#[tauri::command]
pub async fn biometric_cancel(state: State<'_, AppState>) -> ApiResult<()> {
    let attempts = state.unlock_attempts.clone();
    blocking_api(move || {
        attempts.supersede();
        Ok(())
    })
    .await
}

/// What the command answers for `found`, the result of the attempt `prompt`
/// stands for. An attempt that was superseded reports only that, whatever it
/// found — errors included: nobody is waiting for them. The one exception is
/// an unlock that did happen (the attempt was ended a moment too late to stop
/// it): the vault is open, and the screen must follow.
fn reported(
    prompt: &Prompt<'_>,
    found: ApiResult<BiometricUnlockOutcome>,
) -> ApiResult<BiometricUnlockOutcome> {
    let reported = if matches!(found, Ok(BiometricUnlockOutcome::Unlocked)) || prompt.current() {
        found
    } else {
        Ok(BiometricUnlockOutcome::Superseded)
    };
    if matches!(reported, Ok(BiometricUnlockOutcome::Superseded)) {
        log::info!("biometric: an unlock attempt was discarded (superseded, locked meanwhile, or already unlocked)");
    }
    reported
}

/// The biometric unlock of the attempt `prompt` stands for, begun when the
/// core's lock epoch read `began`: read the device secret (the system prompt
/// shows `reason`), unseal the password and hand it to the core with the
/// Secret Key this device remembers. The password exists only in here.
fn unlock_with_stored_password(
    core: &Core,
    blob: &Path,
    reason: &str,
    prompt: &Prompt<'_>,
    began: u64,
) -> ApiResult<BiometricUnlockOutcome> {
    let store = platform_store().ok_or_else(unsupported)?;
    let sealed = std::fs::read(blob).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ApiError::other("biometric unlock is not enabled")
        } else {
            ApiError::other(format!("biometric unlock material is unreadable: {e}"))
        }
    })?;
    // Before the prompt: a Touch ID that cannot end in an unlock is not asked for.
    let Some(secret_key_hex) = stored_secret_key_hex_now()? else {
        return Ok(BiometricUnlockOutcome::NoSecretKey);
    };
    let read = store.read(reason, prompt);
    // The prompt is over. Its answer is acted on — wipes included — only if
    // this is still the attempt the user is waiting for and the vault is still
    // locked; otherwise `read` (a released secret is zeroized) is dropped here.
    if !prompt.current() || core.is_unlocked() {
        return Ok(BiometricUnlockOutcome::Superseded);
    }
    let invalidated = |why: &str| {
        log::warn!("biometric unlock invalidated ({why}); material wiped");
        forget_with(Some(store.as_ref()), blob).map(|()| BiometricUnlockOutcome::Invalidated)
    };
    let secret = match read {
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
    match core.unlock_unless_locked_since(began, Some(password), String::clone(&secret_key_hex)) {
        Ok(()) => Ok(BiometricUnlockOutcome::Unlocked),
        // A lock landed after this attempt began: the core installed nothing.
        Err(FfiError::Locked) => Ok(BiometricUnlockOutcome::Superseded),
        // The stored password no longer opens the keyset: it was changed.
        Err(FfiError::InvalidCredentials) => invalidated("stored password no longer valid"),
        Err(e) => Err(e.into()),
    }
}

/// The presence gate of the attempt `prompt` stands for, begun when the core's
/// lock epoch read `began`: the platform's prompt (`reason` where it takes
/// one) and, only on a match, the remembered-key unlock.
fn unlock_behind_presence(
    core: &Core,
    reason: &str,
    prompt: &Prompt<'_>,
    began: u64,
) -> ApiResult<BiometricUnlockOutcome> {
    let store = platform_store().ok_or_else(unsupported)?;
    // Before the prompt: one that cannot end in an unlock is not shown.
    let Some(secret_key_hex) = stored_secret_key_hex_now()? else {
        return Ok(BiometricUnlockOutcome::NoSecretKey);
    };
    let confirmed = store.confirm_presence(reason, prompt);
    // As for biometric unlock: only the attempt still waited for is acted on.
    if !prompt.current() || core.is_unlocked() {
        return Ok(BiometricUnlockOutcome::Superseded);
    }
    match confirmed {
        Ok(()) => {}
        Err(SecretError::Cancelled | SecretError::Unsupported) => {
            return Ok(BiometricUnlockOutcome::Cancelled)
        }
        Err(e @ (SecretError::Invalidated | SecretError::Failed(_))) => {
            return Err(secret_error(e))
        }
    }
    match core.unlock_unless_locked_since(began, None, String::clone(&secret_key_hex)) {
        Ok(()) => Ok(BiometricUnlockOutcome::Unlocked),
        // A lock landed after this attempt began: the core installed nothing.
        Err(FfiError::Locked) => Ok(BiometricUnlockOutcome::Superseded),
        // The remembered key no longer opens this vault (it belongs to
        // another keyset): the same as having none — type it from the Kit.
        Err(FfiError::InvalidCredentials) => Ok(BiometricUnlockOutcome::NoSecretKey),
        Err(e) => Err(e.into()),
    }
}

/// Unlock with the biometric. Reads the device secret (the system prompt shows
/// `reason`), unseals the password, and calls the same core unlock a typed
/// password does, with the Secret Key this device remembers.
///
/// The answer counts only for the attempt that asked: see [`UnlockAttempts`].
/// `Unlocked` is reported — and agent access resumed — only when the core said
/// the vault is open.
#[tauri::command]
pub async fn biometric_unlock(
    app: tauri::AppHandle,
    reason: String,
    state: State<'_, AppState>,
) -> ApiResult<BiometricUnlockOutcome> {
    let core = state.core.clone();
    let blob = blob_path(&state);
    let attempts = state.unlock_attempts.clone();
    let outcome = blocking_api(move || {
        // The attempt begins here, before its prompt, and a lock from now on
        // wins. A lock ends the current id and then bumps the core's epoch;
        // with the id taken first here, a lock that came too late to be seen
        // in the epoch read below has ended this id, and one that ends it
        // after the "still current" check bumps the epoch after this read.
        let prompt = Prompt::of(&attempts, attempts.supersede());
        let began = core.lock_epoch();
        let found = unlock_with_stored_password(&core, &blob, &reason, &prompt, began);
        reported(&prompt, found)
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
///
/// The answer counts only for the attempt that asked: see [`UnlockAttempts`].
#[tauri::command]
pub async fn biometric_presence_unlock(
    app: tauri::AppHandle,
    reason: String,
    state: State<'_, AppState>,
) -> ApiResult<BiometricUnlockOutcome> {
    let core = state.core.clone();
    let attempts = state.unlock_attempts.clone();
    let outcome = blocking_api(move || {
        // The attempt begins here, as in `biometric_unlock`.
        let prompt = Prompt::of(&attempts, attempts.supersede());
        let began = core.lock_epoch();
        let found = unlock_behind_presence(&core, &reason, &prompt, began);
        reported(&prompt, found)
    })
    .await?;
    if matches!(outcome, BiometricUnlockOutcome::Unlocked) {
        resume_after_unlock(&app);
    }
    Ok(outcome)
}

/// Before the presence gate is turned on: show the prompt once and report how
/// it went. Unlocks nothing and stores nothing; Settings saves the setting only
/// on `Confirmed`, so a gate whose prompt never works here is never switched on.
#[tauri::command]
pub async fn biometric_confirm_presence(reason: String) -> ApiResult<PresenceCheck> {
    blocking_api(move || {
        let Some(store) = platform_store() else {
            return Ok(PresenceCheck::Unavailable);
        };
        if !store.presence_available() {
            return Ok(PresenceCheck::Unavailable);
        }
        match store.confirm_presence(&reason, &Prompt::standalone()) {
            Ok(()) => Ok(PresenceCheck::Confirmed),
            Err(SecretError::Cancelled) => Ok(PresenceCheck::Cancelled),
            Err(SecretError::Unsupported | SecretError::Invalidated) => {
                Ok(PresenceCheck::Unavailable)
            }
            Err(e @ SecretError::Failed(_)) => Err(secret_error(e)),
        }
    })
    .await
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

    /// A platform that records being asked anything at all, and whose delete
    /// can be made to fail.
    #[derive(Default)]
    struct Watched {
        touched: std::sync::atomic::AtomicBool,
        delete_fails: bool,
    }

    impl Watched {
        fn touch(&self) {
            self.touched
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl DeviceSecretStore for Watched {
        fn state(&self) -> SecretState {
            self.touch();
            SecretState::Present
        }
        fn create(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
            self.touch();
            Err(SecretError::Unsupported)
        }
        fn read(&self, _: &str, _: &Prompt<'_>) -> Result<Zeroizing<Vec<u8>>, SecretError> {
            self.touch();
            Err(SecretError::Unsupported)
        }
        fn delete(&self) -> Result<(), SecretError> {
            self.touch();
            if self.delete_fails {
                Err(SecretError::Failed("delete refused".into()))
            } else {
                Ok(())
            }
        }
        fn presence_available(&self) -> bool {
            self.touch();
            true
        }
        fn confirm_presence(&self, _: &str, _: &Prompt<'_>) -> Result<(), SecretError> {
            self.touch();
            Err(SecretError::Unsupported)
        }
    }

    // The password unlock screen asks on every launch; a device that never
    // turned the feature on must get its answer without a platform round trip.
    #[test]
    fn unlock_screen_status_without_material_never_reaches_the_platform() {
        let dir = tempfile::tempdir().unwrap();
        let platform = Watched::default();
        let status = status_now(Some(&platform), &dir.path().join(BLOB_FILE), false);
        assert!(!platform.touched.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!status.stored && !status.enabled && !status.secret_key_remembered);
    }

    // A change that fails after the core has rewritten the keyset has still
    // changed the password: what was sealed for the old one goes. A failure
    // that left the keyset alone keeps it.
    #[test]
    fn failed_install_wipes_only_when_it_rewrote_the_keyset() {
        let dir = tempfile::tempdir().unwrap();
        let blob = dir.path().join(BLOB_FILE);
        std::fs::write(&blob, b"sealed").unwrap();
        let record = std::cell::Cell::new([0_u8; 32]);
        let digest = || Some(record.get());

        let (untouched, wipe) = wipe_around_install(None, digest, &blob, || -> ApiResult<()> {
            Err(unsupported())
        });
        assert!(untouched.is_err() && wipe == KeysetWipe::Nothing && blob.exists());

        let (rewritten, wipe) = wipe_around_install(None, digest, &blob, || -> ApiResult<()> {
            record.set([1; 32]);
            Err(unsupported())
        });
        assert!(rewritten.is_err() && wipe == KeysetWipe::Erased && !blob.exists());
    }

    // "Could not be erased" is said only while the sealed password is still on
    // disk: a wipe that failed at the platform's half has erased it all the same.
    #[test]
    fn wipe_counts_as_failed_only_while_the_sealed_password_remains() {
        let dir = tempfile::tempdir().unwrap();
        let blob = dir.path().join(BLOB_FILE);
        let platform = Watched {
            delete_fails: true,
            ..Watched::default()
        };

        std::fs::write(&blob, b"sealed").unwrap();
        assert_eq!(
            forget_after_keyset_change(Some(&platform), &blob),
            KeysetWipe::Erased
        );
        assert!(!blob.exists());

        // A blob that cannot be removed: a directory with something in it.
        std::fs::create_dir_all(&blob).unwrap();
        std::fs::write(blob.join("held"), b"").unwrap();
        assert_eq!(
            forget_after_keyset_change(Some(&platform), &blob),
            KeysetWipe::Failed
        );
    }

    // Ending an attempt takes its prompt down and makes its answer worthless;
    // an attempt that is already over is dismissed before it can wait.
    #[test]
    fn superseded_attempt_is_dismissed_and_reports_only_that() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        fn discarded(prompt: &Prompt<'_>) -> bool {
            matches!(
                reported(prompt, Err(unsupported())),
                Ok(BiometricUnlockOutcome::Superseded)
            )
        }

        let attempts = UnlockAttempts::default();
        let dismissed = Arc::new(AtomicUsize::new(0));
        let dismiss = || -> Dismiss {
            let dismissed = dismissed.clone();
            Box::new(move || {
                dismissed.fetch_add(1, Ordering::SeqCst);
            })
        };

        // Superseded while the prompt is up, by a lock — which is in force
        // before the platform is asked to take the prompt down.
        let locked = Arc::new(AtomicBool::new(false));
        let dismissed_once_locked = Arc::new(AtomicBool::new(false));
        let first = Prompt::of(&attempts, attempts.supersede());
        let note_order: Dismiss = {
            let (locked, noted) = (locked.clone(), dismissed_once_locked.clone());
            Box::new(move || noted.store(locked.load(Ordering::SeqCst), Ordering::SeqCst))
        };
        first.wait(note_order, || {
            attempts.locking(|| locked.store(true, Ordering::SeqCst));
        });
        assert!(dismissed_once_locked.load(Ordering::SeqCst));
        assert!(discarded(&first));
        // ...unless it did unlock: the vault is open and the screen follows.
        assert!(matches!(
            reported(&first, Ok(BiometricUnlockOutcome::Unlocked)),
            Ok(BiometricUnlockOutcome::Unlocked)
        ));

        // Superseded before the prompt could be shown.
        let second = Prompt::of(&attempts, attempts.supersede());
        attempts.supersede();
        second.wait(dismiss(), || ());
        assert_eq!(dismissed.load(Ordering::SeqCst), 1);

        // Left alone, an attempt keeps its answer, and its prompt is not dismissed after it answered.
        let third = Prompt::of(&attempts, attempts.supersede());
        third.wait(dismiss(), || ());
        assert!(!discarded(&third));
        attempts.supersede();
        assert_eq!(dismissed.load(Ordering::SeqCst), 1);
    }
}
