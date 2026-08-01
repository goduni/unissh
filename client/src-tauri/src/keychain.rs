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
async fn off_main<T, F>(f: F) -> ApiResult<T>
where
    F: FnOnce() -> ApiResult<T> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f).await?
}

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
        ks_entry()?.set_password(secret_key).map_err(|e| {
            log::warn!("keychain: failed to store the Secret Key: {e}");
            ApiError::other(e)
        })
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
        match direct {
            Ok(Some(s)) => Ok(Some(s)),
            // Nothing stored, or no store to ask: an older Linux build kept the
            // key somewhere else. Look there before answering "not stored".
            Ok(None) => Ok(carry_over_from_keyutils(ACCOUNT)),
            Err(e) => match carry_over_from_keyutils(ACCOUNT) {
                Some(s) => Ok(Some(s)),
                None => Err(e),
            },
        }
    }
    #[cfg(not(native_keychain))]
    {
        Ok(None)
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
        let _ = old.delete_credential();
        log::info!("keychain: moved {account} from keyutils to the Secret Service");
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
    use keyring::credential::CredentialApi;
    if let Ok(old) = keyring::keyutils::KeyutilsCredential::new_with_target(None, SERVICE, account)
    {
        let _ = old.delete_credential();
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
        match ks_entry()?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(ApiError::other(e)),
        }
    }
    #[cfg(not(native_keychain))]
    {
        Ok(())
    }
}

// ---------- commands ----------

#[tauri::command]
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
    password: Option<String>,
    state: tauri::State<'_, crate::state::AppState>,
) -> ApiResult<()> {
    #[cfg(native_keychain)]
    {
        let raw = off_main(get_secret_key_now)
            .await?
            .ok_or_else(|| ApiError::other("no Secret Key stored in keychain"))?;
        // Normalize (strip spacing/dashes) exactly as the old JS unlock path did.
        let secret_key_hex: String = raw
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let core = state.core.clone();
        crate::commands::blocking(move || core.unlock(password, secret_key_hex)).await
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
