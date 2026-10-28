//! Vaults a teammate shared with this account that this device cannot verify
//! yet, because their owner is not trusted here.
//!
//! The server lists every vault the account may read (`GET /v1/vaults`). A
//! vault a teammate created is rejected by sync until the user pins its owner,
//! confirmed out of band by fingerprint ([`unissh_ffi::Core::inspect_shared_vault`]).
//! Such a vault is in the server's list but not on this device: each one is
//! inspected, and the owner's handle the server's directory claims for that key
//! is put next to it — a claim, never verified, shown only to help the user
//! know whom to ask.

use unissh_ffi::{Core, FfiError, SharedVaultInfo};

use crate::client::http;
use crate::dto::DirectoryEntry;
use crate::identity;
use crate::transport::HttpSyncTransport;

/// A shared vault waiting for the user to trust its owner.
pub struct PendingVault {
    /// The vault id (hex).
    pub vault_id: String,
    /// What its verified membership chain says, or why it cannot be offered
    /// for trust (a broken chain, no grant to this account).
    pub inspected: Result<SharedVaultInfo, FfiError>,
    /// The directory entry the server lists for the owner's key: its claim
    /// of who that is. NOT verified — the fingerprint is what the user
    /// confirms.
    pub claimed_owner: Option<DirectoryEntry>,
}

/// The vaults shared with this account that are not on this device: on the
/// server's list for the account, not deleted there, not here. A vault this
/// account created itself is left out (it needs no trust). The directory is
/// read best-effort: without it no owner is named. Requires unlock and a
/// session (`access`).
pub fn pending_shared_vaults(
    core: &Core,
    base_url: &str,
    access: &str,
) -> Result<Vec<PendingVault>, FfiError> {
    let transport = HttpSyncTransport::new(base_url.to_owned(), access.to_owned());
    let catalog = transport.list_vaults()?;
    let here = core.list_vaults()?;
    let directory = identity::directory(http(), base_url, access).unwrap_or_default();
    let mut pending = Vec::new();
    for entry in catalog {
        if entry.tombstone
            || here
                .iter()
                .any(|v| v.vault_id.eq_ignore_ascii_case(&entry.vault_id))
        {
            continue;
        }
        let inspected = match transport.inspect_vault(core, &entry.vault_id) {
            Ok(None) => continue,
            Ok(Some(info)) => Ok(info),
            Err(e) => Err(e),
        };
        let claimed_owner = inspected
            .as_ref()
            .ok()
            .and_then(|info| claimed_owner(&directory, &info.owner_ed25519_hex));
        pending.push(PendingVault {
            vault_id: entry.vault_id,
            inspected,
            claimed_owner,
        });
    }
    Ok(pending)
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
