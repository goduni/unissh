//! Staged SSH key rotation: a new key is generated beside the original as an
//! ordinary key item (the "candidate"), and only later committed into the
//! original item as a new version — or abandoned.
//!
//! The candidate → original link is device-local metadata in the instance's
//! `meta` table (SQLCipher-protected, never synced, never exported). The vault
//! itself sees nothing new: the candidate is a plain SSH key item, so no item
//! type, AAD or canonical encoding changes.

use std::collections::BTreeMap;

use unissh_ssh_agent::generate_ed25519_openssh;
use unissh_vault::Vault;

use super::{
    agent_key_id, cert_item_id, ensure_item_type, resolve_vid, Core, CoreState, FfiError,
    ITEM_TYPE_SSH_KEY,
};

/// Per-vault meta slot; the JSON maps original key id → candidate key id.
const META_PREFIX: &str = "key.rotation.v1:";

/// A rotation in progress on this device: `candidate_id` will replace the
/// material of `key_id` on finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotationLink {
    /// The original key item (hosts reference this id).
    pub key_id: String,
    /// The candidate key item holding the new material.
    pub candidate_id: String,
}

/// Id of the candidate item for `key_id`. Deterministic, so a candidate synced
/// from another device occupies the same id and blocks a second rotation there.
fn candidate_item_id(key_id: &str) -> String {
    format!("{key_id} (rotation)")
}

fn meta_key(vid: &[u8]) -> String {
    format!("{META_PREFIX}{}", hex::encode(vid))
}

fn load_links(state: &CoreState, vid: &[u8]) -> Result<BTreeMap<String, String>, FfiError> {
    match state
        .storage
        .get_meta(&meta_key(vid))
        .map_err(FfiError::other)?
    {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(FfiError::other),
        None => Ok(BTreeMap::new()),
    }
}

fn save_links(
    state: &CoreState,
    vid: &[u8],
    links: &BTreeMap<String, String>,
) -> Result<(), FfiError> {
    let bytes = serde_json::to_vec(links).map_err(FfiError::other)?;
    state
        .storage
        .set_meta(&meta_key(vid), &bytes)
        .map_err(FfiError::other)
}

/// The item exists, is live, and is an SSH key.
fn is_live_key(vault: &Vault, item_id: &str) -> Result<bool, FfiError> {
    Ok(vault
        .get_item(item_id.as_bytes())
        .map_err(FfiError::other)?
        .is_some_and(|i| i.item_type == ITEM_TYPE_SSH_KEY))
}

impl Core {
    /// Starts a staged rotation of `key_id`: generates a new Ed25519 key as a
    /// separate ordinary key item and records it as this key's candidate on this
    /// device. The original item is untouched. Returns the candidate's item id.
    ///
    /// Refused with [`FfiError::RotationInProgress`] while a live candidate exists
    /// — recorded here, or synced from another device under the same id.
    pub fn begin_key_rotation(&self, vault_id: String, key_id: String) -> Result<String, FfiError> {
        self.with_state_mut(|state| {
            let vid = resolve_vid(&state.storage, &vault_id);
            let vault =
                Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
            if !is_live_key(&vault, &key_id)? {
                return Err(FfiError::NotFound);
            }
            let mut links = load_links(state, &vid)?;
            if let Some(existing) = links.get(&key_id) {
                if vault
                    .get_item(existing.as_bytes())
                    .map_err(FfiError::other)?
                    .is_some()
                {
                    return Err(FfiError::RotationInProgress {
                        candidate_id: existing.clone(),
                    });
                }
            }
            let candidate_id = candidate_item_id(&key_id);
            if vault
                .get_item(candidate_id.as_bytes())
                .map_err(FfiError::other)?
                .is_some()
            {
                return Err(FfiError::RotationInProgress { candidate_id });
            }
            ensure_item_type(
                &state.storage,
                &vault_id,
                candidate_id.as_bytes(),
                ITEM_TYPE_SSH_KEY,
            )?;
            let (private_pem, _public) = generate_ed25519_openssh().map_err(FfiError::ssh)?;
            vault
                .put_item(
                    candidate_id.as_bytes(),
                    ITEM_TYPE_SSH_KEY,
                    private_pem.as_bytes(),
                )
                .map_err(FfiError::other)?;
            links.insert(key_id, candidate_id.clone());
            save_links(state, &vid, &links)?;
            Ok(candidate_id)
        })
    }

    /// Commits a staged rotation: the candidate's material becomes a new version
    /// of `key_id` (the previous material stays in the item's version history),
    /// the certificate attached to `key_id` is removed (it certifies the old
    /// public key), and the candidate is tombstoned. Only the candidate recorded
    /// for `key_id` on this device is accepted.
    pub fn finish_key_rotation(
        &self,
        vault_id: String,
        key_id: String,
        candidate_id: String,
    ) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let vid = resolve_vid(&state.storage, &vault_id);
            let vault =
                Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
            let mut links = load_links(state, &vid)?;
            if links.get(&key_id) != Some(&candidate_id) {
                return Err(FfiError::other("not a rotation candidate of this key"));
            }
            if !is_live_key(&vault, &key_id)? {
                return Err(FfiError::NotFound);
            }
            let candidate = vault
                .get_item(candidate_id.as_bytes())
                .map_err(FfiError::other)?
                .filter(|i| i.item_type == ITEM_TYPE_SSH_KEY)
                .ok_or(FfiError::NotFound)?;
            // Not one transaction (the vault layer opens its own): each step is
            // safe to repeat, and the candidate is buried last, so a failure
            // part-way leaves a retryable state rather than a lost key.
            vault
                .put_item_keep_history(
                    key_id.as_bytes(),
                    ITEM_TYPE_SSH_KEY,
                    candidate.content.as_slice(),
                )
                .map_err(FfiError::other)?;
            let cert = cert_item_id(&key_id);
            if vault
                .get_item(cert.as_bytes())
                .map_err(FfiError::other)?
                .is_some()
            {
                vault
                    .delete_item(cert.as_bytes())
                    .map_err(FfiError::other)?;
            }
            vault
                .delete_item(candidate_id.as_bytes())
                .map_err(FfiError::other)?;
            links.remove(&key_id);
            save_links(state, &vid, &links)?;
            // Both ids changed material: unload them, otherwise this session keeps
            // signing with the old pair (`load_key_into_agent` short-circuits).
            state.agent.remove(&agent_key_id(&vault_id, &key_id));
            state.agent.remove(&agent_key_id(&vault_id, &candidate_id));
            Ok(())
        })
    }

    /// Abandons a staged rotation: tombstones the candidate and forgets the link.
    /// The original key is not touched. Only a candidate recorded on this device
    /// is accepted, so this cannot delete an arbitrary key.
    pub fn abandon_key_rotation(
        &self,
        vault_id: String,
        candidate_id: String,
    ) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let vid = resolve_vid(&state.storage, &vault_id);
            let vault =
                Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
            let mut links = load_links(state, &vid)?;
            let before = links.len();
            links.retain(|_, c| *c != candidate_id);
            if links.len() == before {
                return Err(FfiError::other("not a rotation candidate"));
            }
            if is_live_key(&vault, &candidate_id)? {
                vault
                    .delete_item(candidate_id.as_bytes())
                    .map_err(FfiError::other)?;
            }
            save_links(state, &vid, &links)?;
            state.agent.remove(&agent_key_id(&vault_id, &candidate_id));
            Ok(())
        })
    }

    /// Rotations in progress on this device for `vault_id` whose candidate is
    /// still live. A link whose candidate was deleted elsewhere is omitted.
    pub fn list_key_rotations(&self, vault_id: String) -> Result<Vec<KeyRotationLink>, FfiError> {
        self.with_state_mut(|state| {
            let vid = resolve_vid(&state.storage, &vault_id);
            let vault =
                Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
            let mut out = Vec::new();
            for (key_id, candidate_id) in load_links(state, &vid)? {
                if is_live_key(&vault, &candidate_id)? {
                    out.push(KeyRotationLink {
                        key_id,
                        candidate_id,
                    });
                }
            }
            Ok(out)
        })
    }
}
