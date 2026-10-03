//! The system agent's key policy: which vault keys this device offers to local
//! programs (`ssh-add -l`, `git`, `ssh`) through UniSSH's agent socket.
//!
//! The choice is a property of this machine's exposure, not of the vault, so it
//! lives in the device-local `meta` table (inside the SQLCipher database) and is
//! never synced or exported. Each entry also pins the public key it was made
//! for: a key replaced under the same id — rotated, re-imported, or deleted and
//! re-created, here or by sync — is not offered until it is shared again.
//!
//! The set is resolved from the unlocked core on every request, so a toggle
//! takes effect on the next `ssh-add -l` and a locked core offers nothing.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use unissh_ssh_transport::{AgentKeys, OfferedKey};

use super::{agent_key_id, load_key_into_agent, lock_recover, Core, CoreState, FfiError};

// Keep the storage slot stable; a format change gets a new key.
const KEY: &str = "system-agent.shared.v1";

/// One shared key, as stored.
#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    vault_id: String,
    item_id: String,
    /// `<type> <base64>` of the key it was shared for.
    public: String,
}

/// A key this device offers to the system agent. Public identifiers only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentKey {
    /// Vault the key lives in.
    pub vault_id: String,
    /// The key item's id.
    pub item_id: String,
}

fn read_entries(state: &CoreState) -> Result<Vec<Entry>, FfiError> {
    match state.storage.get_meta(KEY).map_err(FfiError::other)? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(FfiError::other),
        None => Ok(Vec::new()),
    }
}

fn write_entries(state: &CoreState, entries: &[Entry]) -> Result<(), FfiError> {
    let bytes = serde_json::to_vec(entries).map_err(FfiError::other)?;
    state.storage.set_meta(KEY, &bytes).map_err(FfiError::other)
}

/// Loads the key into the embedded agent and returns its `<type> <base64>`.
fn current_public(state: &mut CoreState, vault_id: &str, item_id: &str) -> Option<String> {
    load_key_into_agent(state, vault_id, item_id).ok()?;
    let line = state
        .agent
        .public_key(&agent_key_id(vault_id, item_id))?
        .to_openssh()
        .ok()?;
    let mut fields = line.split_whitespace();
    Some(format!("{} {}", fields.next()?, fields.next()?))
}

/// The shared entries whose key is still the one they were shared for.
fn resolve(state: &mut CoreState) -> Vec<(Entry, String)> {
    let Ok(entries) = read_entries(state) else {
        log::warn!("system agent: the shared-key list is unreadable; offering nothing");
        return Vec::new();
    };
    entries
        .into_iter()
        .filter_map(|entry| {
            let public = current_public(state, &entry.vault_id, &entry.item_id)?;
            (public == entry.public).then_some((entry, public))
        })
        .collect()
}

/// The system agent's view of the core: the shared keys while unlocked,
/// nothing while locked.
struct SharedKeys {
    state: Arc<Mutex<Option<CoreState>>>,
}

impl AgentKeys for SharedKeys {
    fn offered(&self) -> Vec<OfferedKey> {
        let mut guard = lock_recover(&self.state);
        let Some(state) = guard.as_mut() else {
            return Vec::new();
        };
        resolve(state)
            .into_iter()
            .map(|(entry, public)| OfferedKey {
                key_id: agent_key_id(&entry.vault_id, &entry.item_id),
                public_openssh: public,
                comment: entry.item_id,
            })
            .collect()
    }

    fn sign(&self, _key: &OfferedKey, _data: &[u8]) -> Option<(String, Vec<u8>)> {
        // Signing arrives together with the per-request approval prompt; until
        // then the agent lists keys and refuses every signature.
        log::info!("system agent: signature refused (signing is not enabled)");
        None
    }
}

/// A handle that serves the system agent protocol over any stream. The listener
/// (a Unix socket, a named pipe) is the host's; this is the protocol and policy.
#[derive(Clone)]
pub struct SystemAgent {
    keys: Arc<SharedKeys>,
}

impl SystemAgent {
    /// Serves one client connection until it closes.
    pub async fn serve<S>(&self, stream: S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        unissh_ssh_transport::serve_agent(self.keys.clone(), stream).await;
    }
}

impl Core {
    /// The system agent over this core. Cheap; resolves keys per request.
    pub fn system_agent(&self) -> SystemAgent {
        SystemAgent {
            keys: Arc::new(SharedKeys {
                state: self.state.clone(),
            }),
        }
    }

    /// The keys this device currently offers to the system agent.
    pub fn system_agent_shared(&self) -> Result<Vec<SharedAgentKey>, FfiError> {
        self.with_state_mut(|state| {
            Ok(resolve(state)
                .into_iter()
                .map(|(entry, _)| SharedAgentKey {
                    vault_id: entry.vault_id,
                    item_id: entry.item_id,
                })
                .collect())
        })
    }

    /// Offers (or stops offering) a key to the system agent on this device.
    pub fn set_system_agent_shared(
        &self,
        vault_id: String,
        item_id: String,
        shared: bool,
    ) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let mut entries = read_entries(state)?;
            entries.retain(|e| !(e.vault_id == vault_id && e.item_id == item_id));
            if shared {
                let public = current_public(state, &vault_id, &item_id)
                    .ok_or_else(|| FfiError::other("item is not a usable SSH key"))?;
                entries.push(Entry {
                    vault_id,
                    item_id,
                    public,
                });
            }
            write_entries(state, &entries)
        })
    }
}
