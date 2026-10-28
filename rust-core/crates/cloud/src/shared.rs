//! Vaults a teammate shared with this account that this device cannot verify
//! yet, because their owner is not trusted here.
//!
//! The server lists every vault the account may read (`GET /v1/vaults`). A
//! vault a teammate created is rejected by sync until the user pins its owner,
//! confirmed out of band by fingerprint ([`unissh_ffi::Core::trust_shared_vault_paged`]).
//! Such a vault is in the server's list but not on this device.
//!
//! [`waiting_vaults`] is the cheap list (one request, no inspection), for a
//! count after every sync. [`inspect_pending`] inspects one vault, and
//! [`pending_shared_vaults`] every waiting one, for `vaults list`; the
//! owner's handle the server's directory claims for the key is put next to
//! each — a claim, never verified, shown only to help the user know whom to
//! ask.
//!
//! Vault ids come from the server, which is not trusted: an id that is not
//! exactly 32 hex digits is never used, shown or echoed, only counted.

use unissh_ffi::{Core, FfiError, NotHere, SharedVaultInfo};

use crate::client::http;
use crate::dto::DirectoryEntry;
use crate::identity;
use crate::transport::HttpSyncTransport;

/// A shared vault waiting for the user to trust its owner.
#[derive(Debug, Clone)]
pub struct PendingVault {
    /// The vault id (32 lowercase hex digits).
    pub vault_id: String,
    /// What its verified membership chain says, or why it cannot be offered
    /// for trust (a broken chain, no grant to this account, a page that
    /// could not be read), in words.
    pub inspected: Result<SharedVaultInfo, String>,
    /// The directory entry the server lists for the owner's key: its claim
    /// of who that is. NOT verified — the fingerprint is what the user
    /// confirms.
    pub claimed_owner: Option<DirectoryEntry>,
}

/// The vaults in the server's catalog that have no record on this device.
#[derive(Debug, Clone, Default)]
pub struct Waiting {
    /// Vaults not deleted on the server and not here, by validated id. A
    /// vault this account created may be among them until a sync brings it.
    pub vaults: Vec<NotHere>,
    /// How many catalog entries had an id that is not 32 hex digits; they
    /// are ignored.
    pub malformed: usize,
}

/// The shared vaults [`pending_shared_vaults`] inspected.
#[derive(Debug, Clone, Default)]
pub struct PendingList {
    /// Each waiting vault someone else created, inspected.
    pub vaults: Vec<PendingVault>,
    /// As [`Waiting::malformed`].
    pub malformed: usize,
}

/// A vault id as the server sent it, if it is exactly 32 hex digits (a
/// 16-byte cloud vault id), in its canonical lowercase form; `None`
/// otherwise. Only the re-encoded form is displayed, compared or put in a URL.
pub fn vault_id_from_server(raw: &str) -> Option<String> {
    // 32 ASCII hex digits are 16 bytes; lowercasing them is their re-encoding.
    (raw.len() == 32 && raw.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| raw.to_ascii_lowercase())
}

/// The catalog minus this device: one request and a local lookup, nothing
/// inspected. Requires unlock and a session.
pub fn waiting_vaults(core: &Core, transport: &HttpSyncTransport) -> Result<Waiting, FfiError> {
    let mut malformed = 0_usize;
    let mut ids = Vec::new();
    for entry in transport.list_vaults()? {
        if entry.tombstone {
            continue;
        }
        match vault_id_from_server(&entry.vault_id) {
            Some(id) => ids.push(id),
            None => malformed = malformed.saturating_add(1),
        }
    }
    Ok(Waiting {
        vaults: core.vaults_not_here(&ids)?,
        malformed,
    })
}

/// Inspects the waiting vault `vault_id` (a validated id, see
/// [`vault_id_from_server`]). `Ok(None)`: this account created it and it
/// needs no trust. The directory is read best-effort: without it no owner is
/// named. Requires unlock and a session.
pub fn inspect_pending(
    core: &Core,
    base_url: &str,
    access: &str,
    vault_id: &str,
) -> Result<Option<PendingVault>, FfiError> {
    let transport = HttpSyncTransport::new(base_url.to_owned(), access.to_owned());
    let directory = identity::directory(http(), base_url, access).unwrap_or_default();
    Ok(inspect_one(core, &transport, &directory, vault_id))
}

/// Every waiting vault someone else created, each inspected (see
/// [`inspect_pending`]). For listing, not for every sync: each vault's
/// objects are read page by page. Requires unlock and a session.
pub fn pending_shared_vaults(
    core: &Core,
    base_url: &str,
    access: &str,
) -> Result<PendingList, FfiError> {
    let transport = HttpSyncTransport::new(base_url.to_owned(), access.to_owned());
    let waiting = waiting_vaults(core, &transport)?;
    let directory = if waiting.vaults.is_empty() {
        Vec::new()
    } else {
        identity::directory(http(), base_url, access).unwrap_or_default()
    };
    let vaults = waiting
        .vaults
        .iter()
        .filter_map(|v| inspect_one(core, &transport, &directory, &v.vault_id))
        .collect();
    Ok(PendingList {
        vaults,
        malformed: waiting.malformed,
    })
}

/// `vault_id` inspected; `None` when this account created it.
fn inspect_one(
    core: &Core,
    transport: &HttpSyncTransport,
    directory: &[DirectoryEntry],
    vault_id: &str,
) -> Option<PendingVault> {
    let inspected = match transport.inspect_vault(core, vault_id) {
        Ok(None) => return None,
        Ok(Some(info)) => Ok(info),
        Err(e) => Err(e.to_string()),
    };
    let claimed_owner = inspected
        .as_ref()
        .ok()
        .and_then(|info| claimed_owner(directory, &info.owner_ed25519_hex));
    Some(PendingVault {
        vault_id: vault_id.to_owned(),
        inspected,
        claimed_owner,
    })
}

/// The directory entry for `owner_ed25519_hex`, if the server lists one.
pub fn claimed_owner(
    directory: &[DirectoryEntry],
    owner_ed25519_hex: &str,
) -> Option<DirectoryEntry> {
    directory
        .iter()
        .find(|d| d.ed25519_pub_hex.eq_ignore_ascii_case(owner_ed25519_hex))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::vault_id_from_server;

    /// Only an id of exactly 32 hex digits from the server is used, and only
    /// in its re-encoded lowercase form; anything else — an escape sequence
    /// that would repaint the terminal, a path, a short or long id — is not.
    #[test]
    fn only_a_32_hex_digit_vault_id_from_the_server_is_used() {
        assert_eq!(
            vault_id_from_server("0123456789ABCDEF0123456789abcdef").as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        for bad in [
            "",
            "0123456789abcdef",
            "0123456789abcdef0123456789abcdef00",
            "\u{1b}[2K\u{1b}[1Gowner fingerprint 0",
            "../../v1/admin?x=0123456789abcdef",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert_eq!(vault_id_from_server(bad), None, "{bad:?}");
        }
    }
}
