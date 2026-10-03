//! The system agent's key policy: which vault keys this device offers to local
//! programs (`ssh-add -l`, `git`, `ssh`) through UniSSH's agent socket, and how
//! a signature with one of them is produced.
//!
//! The choice is a property of this machine's exposure, not of the vault, so it
//! lives in the device-local `meta` table (inside the SQLCipher database) and is
//! never synced or exported. Each entry also pins the public key it was made
//! for, compared against the key the vault item holds *now* (not the embedded
//! agent's cache, which a sync pull does not refresh): a key replaced under the
//! same id — rotated or re-imported here, or by another device and pulled — is
//! not offered until it is shared again. Deleting a key or its vault here drops
//! its entry; a deletion that arrives by sync leaves an entry that offers
//! nothing, and is re-offered only if the very same key comes back.
//!
//! Resolving the set also evicts a cached private key that a sync pull replaced
//! under the same id, so nothing signs with the old key afterwards. The cache is
//! shared with SSH connections: a live session forwarding that key loses it at
//! that moment, and its forwarded signatures are refused until it reconnects
//! (which loads the new key). The cache is also where a stale key would
//! otherwise have survived until the next lock.
//!
//! The set is resolved from the unlocked core on every request, so a toggle
//! takes effect on the next `ssh-add -l` and a locked core offers nothing.
//!
//! Every signature is approved first ([`LocalAgent`]): the registered
//! [`AgentApprover`] is asked with the key, the login the payload names and the
//! calling process. Only then is the key loaded into the embedded agent (if it
//! is not cached already) and the signature made there; the private key never
//! leaves it. The share is checked again after the approval, so a key unshared,
//! replaced or locked away while the prompt was open is not used.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use unissh_ssh_transport::{AgentCaller, AgentKeys, LocalAgent, LocalApproval, OfferedKey};

use super::{
    agent_key_id, load_key_into_agent, lock_recover, resolve_vid, userauth_target, AgentApprover,
    AgentSignOrigin, AgentSignRequest, Core, CoreState, FfiError, InMemoryAgent, Vault,
    ITEM_TYPE_SSH_KEY,
};

// Keep the storage slot stable; a format change gets a new key.
const KEY: &str = "system_agent.shared.v1";

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

/// The `<type> <base64>` of the key the vault item holds now.
///
/// Read from the item rather than the embedded agent: the agent caches a key
/// once loaded, and a key replaced by a sync pull would still answer from that
/// cache. A cached copy that no longer matches the item is evicted here, so
/// nothing later signs with the old key either.
fn current_public(state: &mut CoreState, vault_id: &str, item_id: &str) -> Option<String> {
    let item = Vault::open(
        &state.storage,
        &state.keyset,
        &resolve_vid(&state.storage, vault_id),
    )
    .ok()?
    .get_item(item_id.as_bytes())
    .ok()??;
    if item.item_type != ITEM_TYPE_SSH_KEY {
        return None;
    }
    // A throwaway agent parses the key; the private half is dropped with it.
    let mut parser = InMemoryAgent::new();
    parser.add_from_item(b"x".to_vec(), &item).ok()?;
    let public = type_and_key(&parser.public_key(b"x")?.to_openssh().ok()?)?;

    let akid = agent_key_id(vault_id, item_id);
    let cached = state
        .agent
        .public_key(&akid)
        .and_then(|k| k.to_openssh().ok());
    if cached.is_some_and(|c| type_and_key(&c).as_deref() != Some(public.as_str())) {
        state.agent.remove(&akid);
    }
    Some(public)
}

/// `<type> <base64>` of an OpenSSH public key line: its first two fields, the
/// comment dropped.
fn type_and_key(line: &str) -> Option<String> {
    let mut fields = line.split_whitespace();
    Some(format!("{} {}", fields.next()?, fields.next()?))
}

/// Drops the entries for a deleted key (`item_id`) or a deleted vault (`None`).
/// Best effort: the delete itself has already happened.
pub(crate) fn forget(state: &CoreState, vault_id: &str, item_id: Option<&str>) {
    let Ok(mut entries) = read_entries(state) else {
        return;
    };
    let before = entries.len();
    entries.retain(|e| !(e.vault_id == vault_id && item_id.is_none_or(|i| e.item_id == i)));
    if entries.len() != before && write_entries(state, &entries).is_err() {
        log::warn!("system agent: could not drop the entry of a deleted key");
    }
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

    /// Signs with a key that is still shared, still the same key, and the core
    /// still unlocked — checked again here, after the approval wait. Only ever
    /// reached through [`LocalAgent`], which asks first.
    fn sign(&self, key: &OfferedKey, data: &[u8]) -> Option<(String, Vec<u8>)> {
        let mut guard = lock_recover(&self.state);
        let Some(state) = guard.as_mut() else {
            log::info!("system agent: signature refused (vault locked)");
            return None;
        };
        let Some((entry, _)) = resolve(state).into_iter().find(|(entry, public)| {
            agent_key_id(&entry.vault_id, &entry.item_id) == key.key_id
                && *public == key.public_openssh
        }) else {
            log::info!("system agent: signature refused (key no longer shared)");
            return None;
        };
        if let Err(e) = load_key_into_agent(state, &entry.vault_id, &entry.item_id) {
            log::warn!("system agent: could not load the key: {e}");
            return None;
        }
        match state.agent.sign(&key.key_id, data) {
            Ok(signature) => Some((signature.algorithm, signature.signature)),
            Err(e) => {
                log::warn!("system agent: signing failed: {e}");
                None
            }
        }
    }
}

/// Puts each system-agent signature to the registered approver, without
/// holding any core lock while the person decides.
struct SystemApproval {
    approver: Arc<Mutex<Option<Arc<dyn AgentApprover>>>>,
}

impl LocalApproval for SystemApproval {
    fn approve(&self, key: &OfferedKey, caller: &AgentCaller, blob: &[u8]) -> bool {
        let Some(approver) = lock_recover(&self.approver).clone() else {
            log::info!("system agent: no approver registered; signature refused");
            return false;
        };
        approver.approve(AgentSignRequest {
            origin: AgentSignOrigin::SystemAgent {
                pid: caller.pid,
                executable: caller.executable.clone(),
            },
            host: String::new(),
            key: key.comment.clone(),
            target: userauth_target(blob).unwrap_or_default(),
        })
    }
}

/// A handle that serves the system agent protocol over any stream. The listener
/// (a Unix socket, a named pipe) is the host's; this is the protocol and policy.
#[derive(Clone)]
pub struct SystemAgent {
    keys: Arc<SharedKeys>,
    approval: Arc<SystemApproval>,
}

impl SystemAgent {
    /// Serves one client connection until it closes. `caller` is what the
    /// listener learned about the program on the other end; it is shown in
    /// every approval prompt of this connection.
    pub async fn serve<S>(&self, stream: S, caller: AgentCaller)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let policy = Arc::new(LocalAgent {
            keys: self.keys.clone(),
            approval: self.approval.clone(),
            caller,
        });
        unissh_ssh_transport::serve_agent(policy, stream).await;
    }
}

impl Core {
    /// The system agent over this core. Cheap; resolves keys per request.
    pub fn system_agent(&self) -> SystemAgent {
        SystemAgent {
            keys: Arc::new(SharedKeys {
                state: self.state.clone(),
            }),
            approval: Arc::new(SystemApproval {
                approver: self.approver.clone(),
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
