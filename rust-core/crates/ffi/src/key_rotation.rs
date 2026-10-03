//! Staged SSH key rotation: a new key is generated beside the original as an
//! ordinary key item (the "candidate"), and only later committed into the
//! original item as a new version — or abandoned.
//!
//! The candidate → original link is device-local metadata in the instance's
//! `meta` table (SQLCipher-protected, never synced, never exported). The vault
//! itself sees nothing new: the candidate is a plain SSH key item, so no item
//! type, AAD or canonical encoding changes.
//!
//! The candidate's id is derived from the original's, so a candidate started on
//! another device syncs in under the same id. Here it is listed as
//! `started_elsewhere`, blocks a second begin, and can be abandoned (a plain
//! tombstone) but never finished: finishing overwrites key material, and only
//! the device holding the link knows the pair is real rather than a name
//! coincidence.

use std::collections::{BTreeMap, HashSet};

use unissh_vault::Vault;

use super::{
    agent_key_id, drop_certificate, require_ssh_key, resolve_vid, store_new_ssh_key, Core,
    CoreState, FfiError, ITEM_TYPE_SSH_KEY,
};

/// Per-vault meta slot; the JSON maps original key id → candidate key id.
const META_PREFIX: &str = "key.rotation.v1:";

/// Suffix that turns an original key id into its candidate's id.
const CANDIDATE_SUFFIX: &str = " (rotation)";

/// A rotation in progress: `candidate_id` holds the new material for `key_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotationLink {
    /// The original key item (hosts reference this id).
    pub key_id: String,
    /// The candidate key item holding the new material.
    pub candidate_id: String,
    /// The rotation was started on another device: this one has no link, only
    /// the synced candidate. It can be abandoned here, not finished.
    pub started_elsewhere: bool,
}

/// Id of the candidate item for `key_id`.
fn candidate_item_id(key_id: &str) -> String {
    format!("{key_id}{CANDIDATE_SUFFIX}")
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

impl Core {
    /// Starts a staged rotation of `key_id`: generates a new Ed25519 key as a
    /// separate ordinary key item and records it as this key's candidate on this
    /// device. The original item is untouched. Returns the candidate's item id.
    ///
    /// Refused with [`FfiError::RotationInProgress`] while a live candidate key
    /// exists (started here or synced from another device), and with
    /// [`FfiError::AlreadyExists`] when another kind of item holds its id.
    pub fn begin_key_rotation(&self, vault_id: String, key_id: String) -> Result<String, FfiError> {
        self.with_state_mut(|state| {
            let vid = resolve_vid(&state.storage, &vault_id);
            let vault =
                Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
            require_ssh_key(&vault, &key_id)?;
            let candidate_id = candidate_item_id(&key_id);
            if let Some(existing) = vault
                .get_item(candidate_id.as_bytes())
                .map_err(FfiError::other)?
            {
                return Err(if existing.item_type == ITEM_TYPE_SSH_KEY {
                    FfiError::RotationInProgress { candidate_id }
                } else {
                    FfiError::AlreadyExists
                });
            }
            store_new_ssh_key(&state.storage, &vault, &vault_id, &candidate_id)?;
            let mut links = load_links(state, &vid)?;
            links.insert(key_id, candidate_id.clone());
            save_links(state, &vid, &links)?;
            Ok(candidate_id)
        })
    }

    /// Commits a staged rotation: the candidate's material becomes a new version
    /// of `key_id` (the previous material stays in the item's version history),
    /// the certificate attached to `key_id` is removed (it certifies the old
    /// public key), and the candidate is tombstoned. Only the candidate recorded
    /// for `key_id` on this device is accepted (`NotFound` otherwise).
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
                return Err(FfiError::NotFound);
            }
            require_ssh_key(&vault, &key_id)?;
            let candidate = require_ssh_key(&vault, &candidate_id)?;
            vault
                .put_item_keep_history(
                    key_id.as_bytes(),
                    ITEM_TYPE_SSH_KEY,
                    candidate.content.as_slice(),
                )
                .map_err(FfiError::other)?;
            // Not one transaction (the vault layer opens its own): each step is
            // safe to repeat and the candidate is buried last, so a failure
            // part-way leaves a state that a second finish completes.
            let rest = drop_certificate(&vault, &key_id)
                .and_then(|()| {
                    vault
                        .delete_item(candidate_id.as_bytes())
                        .map_err(FfiError::other)
                })
                .and_then(|()| {
                    links.remove(&key_id);
                    save_links(state, &vid, &links)
                });
            // The original's material changed whatever happened after the write:
            // unload both ids, otherwise this session keeps signing with the old
            // pair (`load_key_into_agent` short-circuits on `agent.contains`).
            state.agent.remove(&agent_key_id(&vault_id, &key_id));
            state.agent.remove(&agent_key_id(&vault_id, &candidate_id));
            rest
        })
    }

    /// Abandons a staged rotation: tombstones the candidate and forgets the link.
    /// The original key is not touched. Accepted for a candidate recorded on
    /// this device, or for a live candidate key started on another device (a
    /// plain tombstone, the same as deleting it); `NotFound` otherwise. Refused
    /// with [`FfiError::RotationPartlyFinished`] when an interrupted finish
    /// already wrote the candidate's material into the original.
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
            let linked = links
                .iter()
                .find(|(_, c)| **c == candidate_id)
                .map(|(k, _)| k.clone());
            let candidate = match &linked {
                Some(key_id) => {
                    let candidate = vault
                        .get_item(candidate_id.as_bytes())
                        .map_err(FfiError::other)?;
                    let original = vault.get_item(key_id.as_bytes()).map_err(FfiError::other)?;
                    if let (Some(c), Some(o)) = (&candidate, &original) {
                        if c.content.as_slice() == o.content.as_slice() {
                            return Err(FfiError::RotationPartlyFinished {
                                key_id: key_id.clone(),
                            });
                        }
                    }
                    candidate
                }
                None => {
                    let key_id = candidate_id
                        .strip_suffix(CANDIDATE_SUFFIX)
                        .ok_or(FfiError::NotFound)?;
                    require_ssh_key(&vault, key_id)?;
                    Some(require_ssh_key(&vault, &candidate_id)?)
                }
            };
            if candidate.is_some() {
                vault
                    .delete_item(candidate_id.as_bytes())
                    .map_err(FfiError::other)?;
            }
            if let Some(key_id) = linked {
                links.remove(&key_id);
                save_links(state, &vid, &links)?;
            }
            state.agent.remove(&agent_key_id(&vault_id, &candidate_id));
            Ok(())
        })
    }

    /// Rotations in progress for `vault_id`: this device's links whose candidate
    /// is still live, plus live candidate keys synced from another device (an
    /// SSH key at a key's derived candidate id with no link here), flagged
    /// `started_elsewhere`.
    pub fn list_key_rotations(&self, vault_id: String) -> Result<Vec<KeyRotationLink>, FfiError> {
        self.with_state_mut(|state| {
            let vid = resolve_vid(&state.storage, &vault_id);
            let vault =
                Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
            // Metadata only — no decryption needed to see which keys exist.
            let keys: HashSet<String> = vault
                .list_items()
                .map_err(FfiError::other)?
                .into_iter()
                .filter(|m| m.item_type == ITEM_TYPE_SSH_KEY)
                .map(|m| String::from_utf8_lossy(&m.item_id).into_owned())
                .collect();
            let links = load_links(state, &vid)?;
            let mut out: Vec<KeyRotationLink> = links
                .iter()
                .filter(|(_, c)| keys.contains(*c))
                .map(|(k, c)| KeyRotationLink {
                    key_id: k.clone(),
                    candidate_id: c.clone(),
                    started_elsewhere: false,
                })
                .collect();
            let mut elsewhere: Vec<KeyRotationLink> = keys
                .iter()
                .filter(|k| !links.contains_key(*k))
                .map(|k| (k, candidate_item_id(k)))
                .filter(|(_, c)| keys.contains(c) && !links.values().any(|l| l == c))
                .map(|(k, c)| KeyRotationLink {
                    key_id: k.clone(),
                    candidate_id: c,
                    started_elsewhere: true,
                })
                .collect();
            elsewhere.sort_by(|a, b| a.key_id.cmp(&b.key_id));
            out.append(&mut elsewhere);
            Ok(out)
        })
    }
}
