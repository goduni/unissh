//! Refresh-token storage in the OS keychain, per linked server.
//!
//! The refresh token is a long-lived bearer credential, so it gets the same
//! native-keychain treatment as the instance Secret Key (see `crate::keychain`);
//! the short-lived access token stays in memory only. Active wherever a native
//! keychain exists (`native_keychain`); on Android it is still a no-op (re-login
//! after restart) pending a Keystore-backed plugin.
//!
//! Tokens are namespaced by `server_id` (keychain account `refresh/<server_id>`)
//! so that disconnecting one server never wipes another's refresh token.

#[cfg(native_keychain)]
const SERVICE: &str = "me.goduni.unissh";

/// Keychain account name for a server's refresh token. The id is opaque and
/// path-safe (hex), so embedding it keeps each server's token distinct.
#[cfg(native_keychain)]
fn account(server_id: &str) -> String {
    format!("cloud-refresh-token/{server_id}")
}

/// Pre-multi-server account: a single global refresh token (no per-server id).
#[cfg(native_keychain)]
const LEGACY_ACCOUNT: &str = "cloud-refresh-token";

#[cfg(native_keychain)]
pub fn save_refresh(server_id: &str, token: &str) -> Result<(), String> {
    keyring::Entry::new(SERVICE, &account(server_id))
        .map_err(|e| e.to_string())?
        .set_password(token)
        .map_err(|e| e.to_string())
}

/// Read one account, falling back to the store this app used on Linux before the
/// switch to the Secret Service. See `crate::keychain::carry_over_from_keyutils`:
/// a refresh token an older build wrote there is promoted on the way past.
#[cfg(native_keychain)]
fn read_account(user: &str) -> Option<String> {
    if let Ok(entry) = keyring::Entry::new(SERVICE, user) {
        if let Ok(token) = entry.get_password() {
            return Some(token);
        }
    }
    crate::keychain::carry_over_from_keyutils(user)
}

#[cfg(native_keychain)]
pub fn load_refresh(server_id: &str) -> Option<String> {
    if let Some(token) = read_account(&account(server_id)) {
        return Some(token);
    }
    // Nothing on the per-server account: an install that predates multi-server
    // support kept one global token. Move it across now.
    //
    // Here rather than at load time, and that is deliberate. `CloudState::new`
    // runs on the main thread inside Tauri's `setup`, before there is a window,
    // and on Linux a keychain read is a Secret Service round trip that can raise
    // the keyring's own unlock prompt — which is not a thing to do on the main
    // thread of an app that has not drawn itself yet. Every caller of this
    // function is already off that thread, and this is the first moment the old
    // token is actually wanted.
    migrate_legacy(server_id)
}

#[cfg(native_keychain)]
pub fn delete_refresh(server_id: &str) -> Result<(), String> {
    delete_account(&account(server_id))
}

/// Delete one account from the keychain AND from the pre-switch Linux store.
/// Deleting what is not there is a success.
///
/// Both, because `read_account` leaves the keyutils copy behind whenever the
/// promote could not happen. A refresh token is a long-lived bearer credential:
/// "disconnect this server" that leaves one readable in a store the user cannot
/// inspect would be a worse bug than the one this replaced.
#[cfg(native_keychain)]
fn delete_account(user: &str) -> Result<(), String> {
    crate::keychain::purge_keyutils(user);
    let entry = keyring::Entry::new(SERVICE, user).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Move a pre-multi-server refresh token (single global account) onto the
/// per-server account on upgrade, then delete the legacy entry. Returns the token
/// when there was one. No-op if absent.
///
/// Best-effort: keychain errors are swallowed (worst case = one extra re-login).
/// The legacy entry is dropped only once the copy has actually landed — a failed
/// promote leaves the old token where it was rather than losing it in transit.
#[cfg(native_keychain)]
fn migrate_legacy(server_id: &str) -> Option<String> {
    let token = read_account(LEGACY_ACCOUNT)?;
    if save_refresh(server_id, &token).is_ok() {
        let _ = delete_account(LEGACY_ACCOUNT);
    }
    Some(token)
}

#[cfg(not(native_keychain))]
pub fn save_refresh(_server_id: &str, _token: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(native_keychain))]
pub fn load_refresh(_server_id: &str) -> Option<String> {
    None
}

#[cfg(not(native_keychain))]
pub fn delete_refresh(_server_id: &str) -> Result<(), String> {
    Ok(())
}
