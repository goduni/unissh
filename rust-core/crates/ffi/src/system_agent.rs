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
//! The set is resolved from the unlocked core, so a toggle takes effect on the
//! next `ssh-add -l` and a locked core offers nothing. A listing is reused
//! for exactly as long as nothing it was resolved from has changed (the share
//! list, and the storage's revision of vaults, items and certificates), so a
//! program asking in a loop cannot keep the core's lock busy reopening vaults;
//! a signature never relies on a reused listing (it resolves again, below).
//!
//! A shared key with an attached certificate (`<key>.cert`) is offered twice:
//! the key, then the certificate, so certificate logins work from the shell.
//! Both identities carry the key's id; a signature asked for the certificate
//! is approved as the key and made with it. A certificate that does not
//! certify this key is not offered.
//!
//! Every signature is approved first ([`LocalAgent`]): the registered
//! [`AgentApprover`](crate::AgentApprover) is asked with the key and its
//! vault, the user the payload
//! would log in as and the calling process (as the OS reported it; advisory).
//! One prompt is open at a time, forwarded agents' included, and further
//! requests wait their turn in the core's one line (`crate::approvals`); a
//! connection that ends, however it ends, withdraws its prompt or gives up its
//! place, and a revoke ([`Core::revoke_system_agent_requests`]) ends every
//! request there is ([`limits`] bounds the connections). Only once approved
//! is the key loaded into the embedded agent (if it is not cached already) and
//! the signature made there; the private key never leaves it. The share is
//! checked again after the approval, so a key unshared, replaced or locked
//! away while the prompt was open is not used.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use unissh_ssh_transport::{
    AgentCaller, AgentKeys, LocalAgent, LocalApproval, OfferedKey, RsaHash,
};

use super::{
    agent_key_id, attached_certificate, load_key_into_agent, lock_recover, next_agent_sign_id,
    resolve_vid, userauth_login, AgentSignOrigin, AgentSignRequest, Approvals, Asker, Connection,
    Core, CoreState, FfiError, InMemoryAgent, Vault, ITEM_TYPE_SSH_KEY,
};

mod limits;

use limits::{ConnectionSlot, Stamped};

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
fn current_public(
    vault: &Vault,
    agent: &mut InMemoryAgent,
    vault_id: &str,
    item_id: &str,
) -> Option<String> {
    let item = vault.get_item(item_id.as_bytes()).ok()??;
    if item.item_type != ITEM_TYPE_SSH_KEY {
        return None;
    }
    // A throwaway agent parses the key; the private half is dropped with it.
    let mut parser = InMemoryAgent::new();
    parser.add_from_item(b"x".to_vec(), &item).ok()?;
    let public = type_and_key(&parser.public_key(b"x")?.to_openssh().ok()?)?;

    let akid = agent_key_id(vault_id, item_id);
    let cached = agent.public_key(&akid).and_then(|k| k.to_openssh().ok());
    if cached.is_some_and(|c| type_and_key(&c).as_deref() != Some(public.as_str())) {
        agent.remove(&akid);
    }
    Some(public)
}

/// `<type> <base64>` of the certificate attached to the key `item_id` in
/// `vault`, if it certifies `public` (that key's `<type> <base64>`). The rule
/// is [`attached_certificate`], the one connects use.
fn current_certificate(vault: &Vault, item_id: &str, public: &str) -> Option<String> {
    let key = unissh_ssh_agent::ssh_key::PublicKey::from_openssh(public).ok()?;
    type_and_key(&attached_certificate(vault, item_id, key.key_data())?)
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

/// A shared entry whose key is still the one it was shared for.
struct Resolved {
    entry: Entry,
    /// `<type> <base64>` of the key.
    public: String,
    /// `<type> <base64>` of its attached certificate, if one certifies it.
    certificate: Option<String>,
}

/// The shared entries whose key is still the one they were shared for, with
/// their certificates. Each vault is opened once per call.
fn resolve(state: &mut CoreState) -> Vec<Resolved> {
    let Ok(entries) = read_entries(state) else {
        log::warn!("system agent: the shared-key list is unreadable; offering nothing");
        return Vec::new();
    };
    let CoreState {
        storage,
        keyset,
        agent,
        ..
    } = state;
    let (storage, keyset) = (&*storage, &*keyset);
    let mut vaults: HashMap<String, Option<Vault>> = HashMap::new();
    let mut resolved = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(vault) = vaults
            .entry(entry.vault_id.clone())
            .or_insert_with(|| {
                Vault::open(storage, keyset, &resolve_vid(storage, &entry.vault_id)).ok()
            })
            .as_ref()
        else {
            continue;
        };
        let Some(public) = current_public(vault, agent, &entry.vault_id, &entry.item_id) else {
            continue;
        };
        if public != entry.public {
            continue;
        }
        let certificate = current_certificate(vault, &entry.item_id, &public);
        resolved.push(Resolved {
            entry,
            public,
            certificate,
        });
    }
    resolved
}

/// The system agent's view of the core: the shared keys while unlocked,
/// nothing while locked.
struct SharedKeys {
    state: Arc<Mutex<Option<CoreState>>>,
    /// The last listing, stamped with what it was resolved from: the stored
    /// share list and the storage's revision.
    listed: Stamped<(Vec<u8>, [u64; 2]), Vec<OfferedKey>>,
}

/// The identities `shared` amounts to: each key, then its certificate.
fn identities(shared: Vec<Resolved>) -> Vec<OfferedKey> {
    let mut offered = Vec::new();
    for Resolved {
        entry,
        public,
        certificate,
    } in shared
    {
        let key_id = agent_key_id(&entry.vault_id, &entry.item_id);
        offered.push(OfferedKey {
            key_id: key_id.clone(),
            public_openssh: public,
            comment: entry.item_id.clone(),
        });
        if let Some(certificate) = certificate {
            offered.push(OfferedKey {
                key_id,
                public_openssh: certificate,
                comment: entry.item_id,
            });
        }
    }
    offered
}

impl SharedKeys {
    /// The identities offered by the unlocked core `state`, resolved from its
    /// vaults unless nothing that resolution reads has changed since the last
    /// one.
    fn listing(&self, state: &mut CoreState) -> Vec<OfferedKey> {
        // Two cheap reads cover every input of `resolve`. The stored share
        // list is a `meta` row, which the revision does not count, so it is
        // part of the stamp itself: a toggle is never served stale. The
        // revision moves with every write to a vault, an item or a
        // certificate's record (a verified sync pull included), and belongs to
        // this unlock alone: after a lock and an unlock nothing matches.
        let stamp = state
            .storage
            .get_meta(KEY)
            .ok()
            .zip(state.storage.automation_revision().ok());
        let Some((shared, revision)) = stamp else {
            return identities(resolve(state));
        };
        self.listed
            .get_or((shared.unwrap_or_default(), revision), || {
                identities(resolve(state))
            })
    }
}

impl AgentKeys for SharedKeys {
    /// Under the core's lock from the unlocked check to the end of the
    /// resolution; a locked core offers nothing, whatever was listed before.
    fn offered(&self) -> Vec<OfferedKey> {
        lock_recover(&self.state)
            .as_mut()
            .map_or_else(Vec::new, |state| self.listing(state))
    }

    /// Signs with a key that is still shared, still the same key (or still
    /// certified by the same certificate), and the core still unlocked —
    /// checked again here, after the approval wait. Only ever reached through
    /// [`LocalAgent`], which asks first. A certificate identity signs with its
    /// key.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the guard must cover the re-check that the key is still shared, its load and the signature atomically"
    )]
    fn sign(&self, key: &OfferedKey, data: &[u8], rsa: RsaHash) -> Option<(String, Vec<u8>)> {
        let mut guard = lock_recover(&self.state);
        let Some(state) = guard.as_mut() else {
            log::info!("system agent: signature refused (vault locked)");
            return None;
        };
        let Some(Resolved { entry, .. }) = resolve(state).into_iter().find(|shared| {
            agent_key_id(&shared.entry.vault_id, &shared.entry.item_id) == key.key_id
                && (shared.public == key.public_openssh
                    || shared.certificate.as_ref() == Some(&key.public_openssh))
        }) else {
            log::info!("system agent: signature refused (key no longer shared)");
            return None;
        };
        if let Err(e) = load_key_into_agent(state, &entry.vault_id, &entry.item_id) {
            log::warn!("system agent: could not load the key: {e}");
            return None;
        }
        match state.agent.sign_with(&key.key_id, data, rsa) {
            Ok(signature) => Some((signature.algorithm, signature.signature)),
            Err(e) => {
                log::warn!("system agent: signing failed: {e}");
                None
            }
        }
    }
}

/// Puts each system-agent signature of one connection to the registered
/// approver, without holding any core lock while the person decides.
///
/// Lock order: the core's `state` is taken alone, before the request joins the
/// line; `connection` has its own rule ([`Connection`]).
struct SystemApproval {
    /// The approver and the line every request waits in for the one prompt.
    approvals: Arc<Approvals>,
    /// The line's system-agent epoch when this connection's listener started.
    epoch: u64,
    state: Arc<Mutex<Option<CoreState>>>,
    /// This connection's request in the line, and whether its client left.
    connection: Connection,
}

impl SystemApproval {
    /// The name of the vault holding `key`, for the prompt; empty if unknown.
    fn vault_name(&self, key: &OfferedKey) -> String {
        let mut guard = lock_recover(&self.state);
        let Some(state) = guard.as_mut() else {
            return String::new();
        };
        let Some(vault_id) = read_entries(state).ok().and_then(|entries| {
            entries
                .into_iter()
                .find(|e| agent_key_id(&e.vault_id, &e.item_id) == key.key_id)
                .map(|e| e.vault_id)
        }) else {
            return String::new();
        };
        let vid = resolve_vid(&state.storage, &vault_id);
        if let Some(name) = state.vault_names.get(&vid) {
            return name.clone();
        }
        let Ok(vault) = Vault::open(&state.storage, &state.keyset, &vid) else {
            return vault_id;
        };
        let name = String::from_utf8_lossy(vault.name()).to_string();
        state.vault_names.insert(vid, name.clone());
        drop(guard);
        name
    }
}

impl LocalApproval for SystemApproval {
    fn approve(&self, key: &OfferedKey, caller: &AgentCaller, blob: &[u8]) -> bool {
        if !self.approvals.registered() {
            log::info!("system agent: no approver registered; signature refused");
            return false;
        }
        let vault = self.vault_name(key);
        let id = next_agent_sign_id();
        // Named before it joins the line, so that `abandon` can take it out
        // of the line as well as off the screen.
        if !self.connection.begin(id) {
            return false;
        }
        let login = userauth_login(blob);
        // Blocks until this request is at the front of the line and answered.
        // `gone` closes the gap between the check above and joining: `abandon`
        // marks the connection closed before it withdraws, so a request it
        // did not find in the line finds the connection closed at the door.
        let approved = self.approvals.ask(
            AgentSignRequest {
                id,
                origin: AgentSignOrigin::SystemAgent {
                    pid: caller.pid,
                    executable: caller.executable.clone(),
                },
                host: String::new(),
                key: key.comment.clone(),
                vault,
                user: login
                    .as_ref()
                    .map(|(user, _)| user.clone())
                    .unwrap_or_default(),
                target: login
                    .map(|(user, service)| format!("{user}@{service}"))
                    .unwrap_or_default(),
                waiting: 0,
            },
            Asker::System {
                epoch: self.epoch,
                gone: &|| self.connection.closed(),
            },
        );
        self.connection.finish();
        approved
    }

    fn abandon(&self) {
        // Waiting in line, it gives up its place; on screen, it is withdrawn.
        self.connection.close(&self.approvals);
    }
}

/// A handle that serves the system agent protocol over any stream. The listener
/// (a Unix socket, a named pipe) is the host's; this is the protocol and policy.
#[derive(Clone)]
pub struct SystemAgent {
    keys: Arc<SharedKeys>,
    approvals: Arc<Approvals>,
    /// The line's system-agent epoch when this handle was made: its requests
    /// are refused once [`Core::revoke_system_agent_requests`] has moved it.
    epoch: u64,
    /// Connections being served; see [`limits::MAX_CONNECTIONS`].
    connections: Arc<AtomicUsize>,
    /// Whether the last connection was turned away for want of a slot, so
    /// that a burst of them is logged once.
    crowded: Arc<AtomicBool>,
}

/// Withdraws a connection's prompt when its serving ends, whichever way: the
/// client closed, went idle, or the listener dropped the connection mid-prompt
/// (a lock, a stop), which no read on the stream would ever report.
struct Withdraw(Arc<SystemApproval>);

impl Drop for Withdraw {
    fn drop(&mut self) {
        self.0.abandon();
    }
}

impl SystemAgent {
    /// Serves one client connection until it closes, goes idle (ten minutes
    /// without a request) or this future is dropped; any of them withdraws a
    /// prompt it has open or its place in line. `caller` says what the
    /// listener can learn about the program on the other end of `stream`; the
    /// answer is shown in every approval prompt of this connection. Returns at
    /// once, serving nothing and without asking `caller`, when too many
    /// connections are open already: the listener then closes the stream.
    /// Needs the runtime's time driver.
    pub async fn serve<S>(&self, stream: S, caller: impl FnOnce(&S) -> AgentCaller)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let Some(_slot) = ConnectionSlot::take(&self.connections, limits::MAX_CONNECTIONS) else {
            if !self.crowded.swap(true, Ordering::Relaxed) {
                log::warn!(
                    "system agent: too many open connections; closing new ones until one ends"
                );
            }
            return;
        };
        self.crowded.store(false, Ordering::Relaxed);
        // Only now: looking the caller up costs system calls, which a
        // connection that is turned away must not be able to spend.
        let caller = caller(&stream);
        let approval = Arc::new(SystemApproval {
            approvals: self.approvals.clone(),
            epoch: self.epoch,
            state: self.keys.state.clone(),
            connection: Connection::default(),
        });
        let _withdraw = Withdraw(approval.clone());
        let policy = Arc::new(LocalAgent {
            keys: self.keys.clone(),
            approval,
            caller,
        });
        unissh_ssh_transport::serve_agent_until_idle(policy, stream, limits::IDLE_TIMEOUT).await;
    }
}

impl Core {
    /// The system agent over this core, with its own connection limit: one
    /// per listener, made when the listener starts. Its signature requests
    /// wait in the core's one line with everyone else's, and are refused once
    /// [`Core::revoke_system_agent_requests`] has been called after it was
    /// made. Cheap.
    pub fn system_agent(&self) -> SystemAgent {
        SystemAgent {
            keys: Arc::new(SharedKeys {
                state: self.state.clone(),
                listed: Stamped::new(),
            }),
            approvals: self.approver.clone(),
            epoch: self.approver.system_epoch(),
            connections: Arc::new(AtomicUsize::new(0)),
            crowded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Ends every signature request of the system agent, at once: the prompt
    /// on screen is withdrawn at the approver, the requests waiting behind it
    /// are refused without ever being shown, and any further request of a
    /// [`SystemAgent`] made before this call is refused too. For the host to
    /// call when its listener stops (vault lock, screen lock, sleep, exit, the
    /// agent switched off); the next listener takes a fresh
    /// [`Core::system_agent`]. Forwarded agents' requests are not affected.
    /// Does not take the core's lock, so it is safe to call ahead of a lock.
    pub fn revoke_system_agent_requests(&self) {
        self.approver.revoke_system();
    }

    /// Tells the core where this process's own system agent listens (or
    /// `None`). A host using "system agent" auth whose `SSH_AUTH_SOCK` is this
    /// endpoint then fails with a typed error instead of asking UniSSH itself
    /// for a vault key; the OS-agent key picker refuses it the same way.
    pub fn set_system_agent_endpoint(&self, endpoint: Option<PathBuf>) {
        *lock_recover(&self.own_system_agent) = endpoint;
    }

    /// The keys this device currently offers to the system agent.
    pub fn system_agent_shared(&self) -> Result<Vec<SharedAgentKey>, FfiError> {
        self.with_state_mut(|state| {
            Ok(resolve(state)
                .into_iter()
                .map(|Resolved { entry, .. }| SharedAgentKey {
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
                let CoreState {
                    storage,
                    keyset,
                    agent,
                    ..
                } = &mut *state;
                let storage = &*storage;
                let public = Vault::open(storage, keyset, &resolve_vid(storage, &vault_id))
                    .ok()
                    .and_then(|vault| current_public(&vault, agent, &vault_id, &item_id))
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
