//! OS keychain storage for the instance Secret Key.
//!
//! Lets the app remember the Secret Key on a trusted device (macOS Keychain /
//! Windows Credential Manager / freedesktop Secret Service on Linux — GNOME
//! Keyring, KWallet or whatever else implements it — / iOS Keychain) so unlock
//! can prefill it. This matches the core's "trusted device" unlock model. Active
//! wherever a native keychain exists (`native_keychain` — every target except
//! Android, still a no-op pending a Keystore-backed plugin).
//!
//! Two layers on purpose. The `*_now` functions do the work and MUST be called
//! from a blocking thread; the `#[tauri::command]`s are `async` wrappers that put
//! them there. That is a correctness requirement rather than a courtesy: a
//! non-`async` command runs on the main thread, and on Linux a keychain call is a
//! D-Bus round trip that can pop the keyring's own unlock prompt — a prompt served
//! by the very loop we would be blocking. macOS can prompt for its own reasons.
//! The thread this runs on is not a detail.

use std::sync::atomic::{AtomicU8, Ordering};

use zeroize::Zeroizing;

use crate::error::{ApiError, ApiResult};

#[cfg(native_keychain)]
const SERVICE: &str = "me.goduni.unissh";
#[cfg(native_keychain)]
const ACCOUNT: &str = "secret-key";

#[cfg(native_keychain)]
fn ks_entry() -> Result<keyring::Entry, ApiError> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(ApiError::other)
}

/// Run a keychain call off the main thread. See the module note.
#[cfg(native_keychain)]
use crate::commands::blocking_api as off_main;

// ---------- blocking core (call only from a blocking thread) ----------

/// Store the Secret Key. Blocking; see the module note on threads.
///
/// Logged on failure as well as returned, because the only caller in the UI
/// (`rememberSecretKey`) treats the write as best-effort and swallows the error.
/// The failure that matters is a Linux desktop with no Secret Service provider
/// running at all: there the feature cannot work, and without a line in the log
/// it looks like the app simply chose not to remember. The error kind only —
/// never the key.
pub(crate) fn save_secret_key_now(secret_key: &str) -> ApiResult<()> {
    #[cfg(native_keychain)]
    {
        let saved = ks_entry()?.set_password(secret_key).map_err(|e| {
            log::warn!("keychain: failed to store the Secret Key: {e}");
            ApiError::other(e)
        });
        note_remembered(saved.as_ref().ok().map(|()| true));
        saved
    }
    #[cfg(not(native_keychain))]
    {
        let _ = secret_key;
        Err(ApiError::other("keychain unavailable on this platform"))
    }
}

/// Read the Secret Key, or `None` when this device has never stored one.
/// Blocking; see the module note on threads.
pub(crate) fn get_secret_key_now() -> ApiResult<Option<String>> {
    #[cfg(native_keychain)]
    {
        let direct = ks_entry().and_then(|e| match e.get_password() {
            Ok(s) => Ok(Some(s)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(ApiError::other(e)),
        });
        let found = match direct {
            Ok(Some(s)) => Ok(Some(s)),
            // Nothing stored, or no store to ask: an older Linux build kept the
            // key somewhere else. Look there before answering "not stored".
            Ok(None) => Ok(carry_over_from_keyutils(ACCOUNT)),
            Err(e) => match carry_over_from_keyutils(ACCOUNT) {
                Some(s) => Ok(Some(s)),
                None => Err(e),
            },
        };
        note_remembered(found.as_ref().ok().map(Option::is_some));
        found
    }
    #[cfg(not(native_keychain))]
    {
        Ok(None)
    }
}

/// The stored Secret Key normalised the way the core parses it (spacing and
/// dashes stripped, exactly as the old JS unlock path did), or `None` when this
/// device has never stored one. Blocking. Shared by every unlock that happens
/// entirely in Rust — the trusted-device one below and the biometric one.
pub(crate) fn stored_secret_key_hex_now() -> ApiResult<Option<Zeroizing<String>>> {
    Ok(get_secret_key_now()?.map(|raw| {
        let raw = Zeroizing::new(raw);
        Zeroizing::new(
            raw.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .collect(),
        )
    }))
}

/// What this process last learned about whether a Secret Key is stored:
/// unknown, no, yes. Set by every successful read, save and delete in this
/// module, so "is it remembered" costs one keychain access per process at
/// most. That matters on macOS, where a build whose code signature changed
/// since the item was written gets a Keychain dialog on every access.
static REMEMBERED: AtomicU8 = AtomicU8::new(UNKNOWN);
const UNKNOWN: u8 = 0;
const NO: u8 = 1;
const YES: u8 = 2;

#[cfg_attr(
    not(native_keychain),
    expect(
        dead_code,
        reason = "only the native keychain paths record an answer; Android's no-op stubs never call it"
    )
)]
fn note_remembered(answer: Option<bool>) {
    let v = match answer {
        None => UNKNOWN,
        Some(false) => NO,
        Some(true) => YES,
    };
    REMEMBERED.store(v, Ordering::Relaxed);
}

/// Whether this device remembers a Secret Key, without keeping it: the value
/// read to answer is wiped at once, and the answer is cached for the process
/// (see [`REMEMBERED`]). Blocking when it has to ask. A keychain error counts
/// as "no" and is not cached.
pub(crate) fn secret_key_remembered_now() -> bool {
    match REMEMBERED.load(Ordering::Relaxed) {
        YES => true,
        NO => false,
        _ => get_secret_key_now().is_ok_and(|k| k.map(Zeroizing::new).is_some()),
    }
}

// ---------- the pre-switch Linux store ----------
//
// Everything this app knows about keyutils lives in these two functions, and
// deliberately so: it is a store we read to empty it, never one we write to. The
// refresh-token module (`cloud::tokens`) shares the same service name and calls
// the same two, so there is exactly one description of the old world.

/// One-time carry-over from the store this app used on Linux before the switch to
/// the Secret Service: the kernel keyutils facility, which the `keyring` crate's
/// own docs describe as a cache that does not survive a reboot.
///
/// Anyone upgrading without having rebooted still has their credential sitting
/// there, and an update that silently forgets it is not an acceptable way to
/// change stores. What is found is promoted into the real keychain and the
/// volatile copy dropped — but only when the promote actually succeeded. On a
/// desktop with no Secret Service running the value is still returned and keyutils
/// keeps it, so that machine behaves exactly as it did before rather than losing
/// the credential on the way out.
#[cfg(target_os = "linux")]
pub(crate) fn carry_over_from_keyutils(account: &str) -> Option<String> {
    use keyring::credential::CredentialApi;
    let old =
        keyring::keyutils::KeyutilsCredential::new_with_target(None, SERVICE, account).ok()?;
    let value = old.get_password().ok()?;
    if keyring::Entry::new(SERVICE, account).is_ok_and(|e| e.set_password(&value).is_ok()) {
        log::info!("keychain: moved {account} from keyutils to the Secret Service");
        purge_keyutils_entry(&old, account);
    }
    Some(value)
}

#[cfg(all(native_keychain, not(target_os = "linux")))]
pub(crate) fn carry_over_from_keyutils(_account: &str) -> Option<String> {
    None
}

/// Drop an account from the old Linux store, best-effort.
///
/// Needed because `carry_over_from_keyutils` leaves a copy behind whenever the
/// promote could not happen (no Secret Service running), and every "forget this
/// credential" path must not leave a readable copy in a store the user cannot
/// see. Called by the delete paths in this module and in `cloud::tokens`.
#[cfg(target_os = "linux")]
pub(crate) fn purge_keyutils(account: &str) {
    if let Ok(old) = keyring::keyutils::KeyutilsCredential::new_with_target(None, SERVICE, account)
    {
        purge_keyutils_entry(&old, account);
    }
}

/// Delete one keyutils entry. Absence is success; any other failure is logged,
/// because a copy left in that store is still readable until the next reboot.
#[cfg(target_os = "linux")]
fn purge_keyutils_entry(old: &keyring::keyutils::KeyutilsCredential, account: &str) {
    use keyring::credential::CredentialApi;
    match old.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(e) => log::warn!("keychain: failed to drop the keyutils copy of {account}: {e}"),
    }
}

#[cfg(all(native_keychain, not(target_os = "linux")))]
pub(crate) fn purge_keyutils(_account: &str) {}

/// Forget the Secret Key. Deleting what is not there is a success, not an error.
/// Blocking; see the module note on threads.
pub(crate) fn delete_secret_key_now() -> ApiResult<()> {
    #[cfg(native_keychain)]
    {
        // The old Linux store too, and first: "forget my Secret Key" that leaves a
        // readable copy behind is the one outcome this function must not have.
        purge_keyutils(ACCOUNT);
        let deleted = match ks_entry()?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(ApiError::other(e)),
        };
        note_remembered(deleted.as_ref().ok().map(|()| false));
        deleted
    }
    #[cfg(not(native_keychain))]
    {
        Ok(())
    }
}

// ---------- commands ----------

#[tauri::command]
#[expect(
    clippy::missing_const_for_fn,
    reason = "a #[tauri::command] is only ever called through the generated IPC wrapper, where const buys nothing"
)]
pub fn keychain_available() -> bool {
    cfg!(native_keychain)
}

#[tauri::command]
pub async fn keychain_save_secret_key(secret_key: String) -> ApiResult<()> {
    #[cfg(native_keychain)]
    {
        off_main(move || save_secret_key_now(&secret_key)).await
    }
    #[cfg(not(native_keychain))]
    {
        save_secret_key_now(&secret_key)
    }
}

#[tauri::command]
pub async fn keychain_get_secret_key() -> ApiResult<Option<String>> {
    #[cfg(native_keychain)]
    {
        off_main(get_secret_key_now).await
    }
    #[cfg(not(native_keychain))]
    {
        get_secret_key_now()
    }
}

/// Trusted-device auto-unlock entirely inside Rust: read the Secret Key from the
/// OS keychain and hand it straight to the core's `unlock` — the key NEVER crosses
/// into the webview JS heap (where any future XSS could read it). The boot path
/// uses THIS instead of `keychain_get_secret_key` + `unlock`; `keychain_get` is
/// kept only for the explicit "show my Secret Key" reveal UI.
#[tauri::command]
pub async fn keychain_unlock(
    app: tauri::AppHandle,
    password: Option<String>,
    state: tauri::State<'_, crate::state::AppState>,
) -> ApiResult<()> {
    #[cfg(not(native_keychain))]
    let _ = &app;
    #[cfg(native_keychain)]
    {
        let secret_key_hex = off_main(stored_secret_key_hex_now)
            .await?
            .ok_or_else(|| ApiError::other("no Secret Key stored in keychain"))?;
        let core = state.core.clone();
        crate::commands::blocking(move || core.unlock(password, String::clone(&secret_key_hex)))
            .await?;
        crate::commands::resume_after_unlock(&app);
        Ok(())
    }
    #[cfg(not(native_keychain))]
    {
        let _ = (password, state);
        Err(ApiError::other("keychain unavailable on this platform"))
    }
}

#[tauri::command]
pub async fn keychain_delete_secret_key() -> ApiResult<()> {
    #[cfg(native_keychain)]
    {
        off_main(delete_secret_key_now).await
    }
    #[cfg(not(native_keychain))]
    {
        delete_secret_key_now()
    }
}
