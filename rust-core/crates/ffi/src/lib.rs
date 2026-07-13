//! # unissh-ffi
//!
//! FFI boundary of the UniSSH core (spec 4). The [`Core`] facade ties `keychain`,
//! `storage`, `vault`, `ssh-agent`, `ssh-transport` into a stable contract for the UI
//! (UniFFI → Swift/Kotlin/…).
//!
//! ## Secret boundary (contract; pinned by the `secret_returning_surface` test)
//! The private **device keyset** (the instance's signing/encryption keys) NEVER
//! crosses the FFI boundary. Ordinary calls return only public keys and
//! session results. Secret material leaves ONLY through an explicit,
//! user-initiated action — and there are exactly a handful of such methods
//! (the exhaustive list is in the test):
//! - [`Core::get_password`] / [`Core::get_note`] — reveal of a user
//!   secret (password-manager behavior); for an item of another type — refused;
//! - [`Core::export_ssh_key`] — export of a private SSH key. This is a DELIBERATE
//!   capability: the user owns their keys and is entitled to take them out — we
//!   don't lock them into a closed ecosystem. The call is always explicit, on user action;
//! - [`Core::export_vault`] — a passphrase-encrypted vault backup.
//!
//! Any NEW method that returns secret material must be added both
//! here and to the enumerating test — this is a tripwire against accidental leakage.
//!
//! ## Model
//! A local instance = an encrypted DB file (`storage`) + a sidecar holding the encrypted
//! keyset. The SQLCipher key is derived from the secrets of the unwrapped keyset (requires
//! an unlock). SSH sessions are launched through the embedded agent (the key lives in the agent,
//! not in the UI).

#![allow(clippy::arc_with_non_send_sync)]

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use unissh_crypto::{aead_decrypt, aead_encrypt, derive_key, AssociatedData};
use unissh_keychain::{
    build_registration, build_registration_request, change_password, create_account,
    derive_escrow_auth_key, generate_account_id, load_account_id, sign_server_challenge,
    store_account_id, unlock_account, unlock_account_migrating, EncryptedKeyset, KdfParams,
    OnboardInitiator, OnboardResponder, SecretKey, ServerAuthChallenge,
};
use unissh_ssh_agent::{generate_ed25519_openssh, InMemoryAgent};
use unissh_ssh_transport::{
    canonical_host_key, trust_host_key, Auth, ConnectOptions, ExecHandle, ForwardGuard, OutputSink,
    SftpSession, ShellHandle, SshClient, SshConfig,
};
use unissh_storage::{CachePolicy, MemberRole, Storage, SyncTarget};
use unissh_sync::{
    reset_pull_cursor, sync_pull, sync_push, SyncContext, SyncObject, SyncTransport,
};
use unissh_vault::{
    member_fingerprint, open_account_payload, pin_and_verify_member, pin_and_verify_vault_anchor,
    seal_account_payload, sign_account_state, verify_chain_to_epoch, Member, Vault,
};

uniffi::setup_scaffolding!();

/// Item type for an SSH key (public metadata).
const ITEM_TYPE_SSH_KEY: u32 = 1;
/// Item type for an SSH user certificate.
const ITEM_TYPE_SSH_CERT: u32 = 2;
/// Item type for a connection profile (a saved "host").
const ITEM_TYPE_CONNECTION: u32 = 3;
/// Item type for a server password (content is the UTF-8 bytes of the password).
const ITEM_TYPE_PASSWORD: u32 = 4;
/// Item type for a host group (content is JSON [`StoredGroup`]).
const ITEM_TYPE_GROUP: u32 = 5;
/// Item type for an encrypted note (content is arbitrary UTF-8).
const ITEM_TYPE_NOTE: u32 = 6;
/// Item type for a personal identity (content is JSON [`StoredIdentity`]:
/// username + references to a key/password item in the same vault).
const ITEM_TYPE_IDENTITY: u32 = 7;
/// Item type for a binding of an identity to a shared host (content is JSON
/// [`StoredBinding`]). Lives in the PERSONAL vault; keyed by (team_vault_id,
/// profile_uid). Synced only between the account's devices.
const ITEM_TYPE_BINDING: u32 = 8;
/// Depth limit for expanding nested groups (guards against blow-up/cycling
/// beyond the visited-set).
const GROUP_MAX_DEPTH: u32 = 32;

/// Id of the certificate item for a given key.
fn cert_item_id(key_item_id: &str) -> String {
    format!("{key_item_id}.cert")
}

/// Locks a `Mutex`, recovering from poisoning (the data under these locks is ordinary,
/// not invariant-bearing, so a single panic must not permanently "jam" the FFI). Central
/// helper for the `m.lock().unwrap_or_else(|e| e.into_inner())` idiom used across the
/// [`Core`] state and the session/pool/tunnel types.
fn lock_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// FFI-boundary errors.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// The core is locked.
    #[error("core is locked")]
    Locked,
    /// Invalid password or Secret Key.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// Object not found.
    #[error("not found")]
    NotFound,
    /// An instance already exists at this path (guards against overwriting the keyset/DB).
    #[error("instance already exists")]
    AlreadyExists,
    /// The host key did not match the pinned one — a possible MITM (show the user
    /// the `fingerprint` of the presented key and offer `trust_host`).
    #[error("host key mismatch for {host}:{port}; presented {fingerprint}")]
    HostKeyMismatch {
        /// Host.
        host: String,
        /// Port.
        port: u16,
        /// SHA256 fingerprint of the key the server ACTUALLY presented.
        fingerprint: String,
    },
    /// SSH error.
    #[error("ssh error: {msg}")]
    Ssh {
        /// Message.
        msg: String,
    },
    /// Other error.
    #[error("{msg}")]
    Other {
        /// Message.
        msg: String,
    },
}

impl FfiError {
    fn other(e: impl std::fmt::Display) -> Self {
        FfiError::Other { msg: e.to_string() }
    }
    fn ssh(e: impl std::fmt::Display) -> Self {
        FfiError::Ssh { msg: e.to_string() }
    }
}

/// Brief information about a vault.
#[derive(uniffi::Record)]
pub struct VaultInfo {
    /// Vault identifier.
    pub vault_id: String,
    /// Vault name.
    pub name: String,
    /// Sync target: a local or a cloud vault. For the Local/Cloud badge in
    /// the UI and for gating cloud operations (membership/sync/onboarding are allowed only
    /// for Cloud). Taken from `VaultRecord.sync_target`.
    pub sync_target: FfiSyncTarget,
    /// **1:1 binding of a cloud vault to a server:** the server's `tenant_id` (the same base64
    /// string as in `ServerConfig.tenant_id`) with which this cloud
    /// vault is synced. `None` — not bound (a local vault OR a not-yet-bound legacy
    /// cloud vault). The UI shows which server the vault is bound to.
    pub sync_tenant: Option<String>,
}

/// Vault sync target for the UI (mirror of `unissh_storage::SyncTarget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSyncTarget {
    /// Local vault: never leaves for a server.
    Local,
    /// Cloud vault: synced with a server.
    Cloud,
}

impl FfiSyncTarget {
    fn from_core(t: SyncTarget) -> FfiSyncTarget {
        match t {
            SyncTarget::Local => FfiSyncTarget::Local,
            SyncTarget::Cloud => FfiSyncTarget::Cloud,
            // SyncTarget is non_exhaustive: an unknown future target → conservatively
            // Local (no cloud operations/gating for an unknown target).
            _ => FfiSyncTarget::Local,
        }
    }
}

/// Registration request to the server (server-tz §5.3): the canonical payload
/// (`RegistrationPayload::canonical`) + a self-signature (domain
/// `unissh-registration-v1`). The client sends them as two base64 fields
/// (`registration_payload` + `registration_signature`) to `/v1/bootstrap` or
/// `/v1/register`. Both are public data (account-id + public keys + signature).
#[derive(Debug, Clone, uniffi::Record)]
pub struct RegistrationRequest {
    /// Canonical payload: `u16 len(account_id) || account_id || x25519(32) || ed25519(32)`.
    pub payload: Vec<u8>,
    /// Signature of the payload by the keyset's Ed25519 key (a 67-byte blob).
    pub signature: Vec<u8>,
}

/// Brief information about an item.
#[derive(uniffi::Record)]
pub struct ItemInfo {
    /// Item identifier.
    pub item_id: String,
    /// Item type.
    pub item_type: u32,
    /// Version.
    pub version: u64,
    /// When created (unix seconds; 0 if unknown).
    pub created_at: i64,
    /// When last modified (unix seconds).
    pub updated_at: i64,
    /// Whether an SSH certificate is attached (for a key item).
    pub has_certificate: bool,
}

/// An item's public key + its fingerprint (for display/copy in the UI).
#[derive(uniffi::Record)]
pub struct PublicKeyInfo {
    /// Public key in OpenSSH format (`ssh-ed25519 AAAA...`).
    pub openssh: String,
    /// SHA256 fingerprint (`SHA256:...`).
    pub fingerprint: String,
}

/// An SFTP directory entry.
#[derive(uniffi::Record)]
pub struct SftpEntry {
    /// File name (without path).
    pub filename: String,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Size in bytes.
    pub size: u64,
    /// Unix mode bits (full st_mode), 0 if unknown.
    pub mode: u32,
    /// Modification time, seconds since the epoch; 0 if unknown.
    pub mtime: u64,
}

/// Result of an SFTP stat.
#[derive(uniffi::Record)]
pub struct SftpFileStat {
    /// Size in bytes.
    pub size: u64,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Unix mode bits (full st_mode), 0 if unknown.
    pub mode: u32,
    /// Modification time, seconds since the epoch; 0 if unknown.
    pub mtime: u64,
}

/// A saved connection profile (a "host"). `profile_id` is the item id in the vault.
#[derive(uniffi::Record, Clone)]
pub struct ConnectionProfile {
    /// Profile identifier (item_id in the vault).
    pub profile_id: String,
    /// Immutable profile uid (inside the ciphertext body; does not change on edits to
    /// host/label). A stable key for personal-identity bindings (B3).
    /// Empty on creation — the core mints it in [`Core::save_connection`].
    pub uid: String,
    /// Human-readable label.
    pub label: String,
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User.
    pub user: String,
    /// Authentication method (references to vault items; no secrets inside).
    pub auth: ProfileAuth,
    /// Username template: `%u` → the identity's username; for gateways that encode the target in
    /// the username template `{identity.user}:{target}` (B4.2, usually with `Personal`).
    pub username_template: Option<String>,
    /// ProxyJump chain.
    pub jumps: Vec<JumpHost>,
    /// Tags for organizing/selecting targets (e.g. `prod`, `web`, `eu`). This is
    /// a selection filter, not access rights (RBAC is server Milestone 2).
    pub tags: Vec<String>,
}

/// A personal identity: SSH credentials under a single name (username + optional references to
/// a key and/or a password item in the SAME vault). Lives primarily in the personal vault and
/// is linked to a shared host via a binding (Phase B3), so personal credentials do not
/// end up in the shared vault. `identity_id` is the item_id in the vault. A secret is not
/// embedded inside — only references (like `ProfileAuth`).
#[derive(uniffi::Record, Clone)]
pub struct Identity {
    /// Identifier (item_id in the vault).
    pub identity_id: String,
    /// Human-readable label.
    pub label: String,
    /// Login username.
    pub user: String,
    /// Reference to a key item (type "SSH key") in this vault, if set.
    pub key_item_id: Option<String>,
    /// Reference to a password item (type "password") in this vault, if set.
    pub password_item_id: Option<String>,
}

/// Serializable identity body (JSON in the item content). `identity_id` is not
/// serialized — it is the item id. Flat optional fields (as in `StoredProfile`)
/// for forward compatibility.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredIdentity {
    label: String,
    user: String,
    #[serde(default)]
    key_item_id: Option<String>,
    #[serde(default)]
    password_item_id: Option<String>,
    /// Forward compatibility (see [`StoredProfile::extra`]).
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

impl StoredIdentity {
    fn into_identity(self, identity_id: String) -> Identity {
        Identity {
            identity_id,
            label: self.label,
            user: self.user,
            key_item_id: self.key_item_id,
            password_item_id: self.password_item_id,
        }
    }
}

/// A binding of a personal identity to a shared host. Lives in the PERSONAL vault (synced
/// only between the account's devices), so personal credentials and the very fact of the linkage
/// are not visible to the team. Keyed by (`team_vault_id`, `profile_uid`): the vault
/// of the shared profile + its immutable uid (B2.1, resilient to id edits/recycling).
#[derive(uniffi::Record, Clone)]
pub struct IdentityBinding {
    /// The shared profile's vault (what we bind to).
    pub team_vault_id: String,
    /// The shared profile's immutable uid.
    pub profile_uid: String,
    /// Id of the identity (an item in the personal vault) we log in with.
    pub identity_item_id: String,
    /// The pinned destination (`host:port`; accounting for the username template and
    /// the username template) at bind time. An anti-redirect anchor: on connect
    /// it is checked against the currently rendered destination (see [`resolve_binding`]).
    pub destination_pin: String,
}

/// Serializable binding body (JSON in the content of a personal-vault item). The key fields
/// (`team_vault_id`, `profile_uid`) are duplicated in the body for listing; the item_id itself
/// is derived deterministically from them ([`binding_item_id`]).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredBinding {
    team_vault_id: String,
    profile_uid: String,
    identity_item_id: String,
    destination_pin: String,
    /// Forward compatibility (see [`StoredProfile::extra`]).
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

impl StoredBinding {
    fn into_binding(self) -> IdentityBinding {
        IdentityBinding {
            team_vault_id: self.team_vault_id,
            profile_uid: self.profile_uid,
            identity_item_id: self.identity_item_id,
            destination_pin: self.destination_pin,
        }
    }
}

/// The result of resolving a binding at connect time (with an anti-redirect check). Returned
/// to the client: `Unbound` → fallback; `Matched` → log in with the personal identity;
/// `Redirected` → show re-bind, do NOT send the personal credential. Strict in-core protection
/// (the connect itself refuses on a redirect) is finished by Personal-auth (B4); this is
/// a query primitive for the UX layer.
#[derive(uniffi::Enum, Debug, PartialEq, Eq, Clone)]
pub enum BindingResolution {
    /// No binding — use the fallback (prompt / connect without personal credentials).
    Unbound,
    /// A binding exists and the current destination matched the pinned one — one may
    /// log in with the personal identity `identity_item_id`.
    Matched { identity_item_id: String },
    /// A binding exists, but the current destination DIFFERS from the pinned one: the host
    /// may have been re-pointed (an in-place edit of host or the username template) →
    /// REFUSE to send the personal credential; an explicit re-bind is required.
    Redirected { pinned: String, current: String },
}

/// Pure anti-redirect logic: checks the currently rendered destination against
/// the one pinned in the binding. Never silently "learns" a new destination —
/// a mismatch always yields [`BindingResolution::Redirected`] (an explicit
/// re-bind is required). Split out for unit-testability without a live connect.
fn resolve_binding(
    binding: Option<&IdentityBinding>,
    current_destination: &str,
) -> BindingResolution {
    match binding {
        None => BindingResolution::Unbound,
        Some(b) if b.destination_pin == current_destination => BindingResolution::Matched {
            identity_item_id: b.identity_item_id.clone(),
        },
        Some(b) => BindingResolution::Redirected {
            pinned: b.destination_pin.clone(),
            current: current_destination.to_string(),
        },
    }
}

/// Deterministic item_id of a binding in the personal vault, from (team_vault_id,
/// profile_uid): one binding per pair, a direct O(1) lookup at connect time.
fn binding_item_id(team_vault_id: &str, profile_uid: &str) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"unissh-binding-v1");
    h.update((team_vault_id.len() as u64).to_be_bytes());
    h.update(team_vault_id.as_bytes());
    h.update(profile_uid.as_bytes());
    format!("binding:{}", hex::encode(&h.finalize()[..16]))
}

/// Resolved personal authentication for connecting to a shared host: a concrete
/// vault-qualified [`AuthMethod`] (a key/password from the PERSONAL vault) plus
/// the username from the identity. Returned by [`Core::resolve_personal_auth`] only
/// AFTER the anti-redirect check — i.e. the personal credential is resolved only for
/// the pinned destination.
#[derive(uniffi::Record, Clone)]
pub struct PersonalAuth {
    /// Username (identity.user → profile fallback → account-default).
    pub user: String,
    /// The concrete authentication method (a reference to a key/password in the personal vault).
    pub auth: AuthMethod,
}

/// Username chain for Personal: identity.user → profile fallback →
/// account-default → empty. The first non-empty (trimmed) one wins.
fn pick_username(
    identity_user: &str,
    profile_fallback: &str,
    account_default: Option<&str>,
) -> String {
    for c in [identity_user, profile_fallback] {
        if !c.trim().is_empty() {
            return c.to_string();
        }
    }
    account_default
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_default()
}

/// Canonical JUMP-CHAIN string for anti-redirect. An empty chain → "".
/// Each hop: `host:port:user` (inline) or `ref=vault/uid` (host-chain B2.2).
/// Any edit/insertion/reordering of a jump changes the string → changes the pin.
fn canonical_jumps(jumps: &[JumpHost]) -> String {
    jumps
        .iter()
        .map(|j| match &j.hop_ref {
            Some(r) => format!("ref={}/{}", r.vault_id, r.profile_uid),
            None => format!("{}:{}:{}", j.host, j.port, j.user),
        })
        .collect::<Vec<_>>()
        .join(">")
}

/// Canonical string destination for pinning/checking (anti-redirect).
/// INCLUDES the username template (`host:port#template`) so that editing it
/// changes the destination and triggers Redirected. ALSO includes the ProxyJump chain
/// (`|via=...`) when it is non-empty — otherwise a team admin could insert a MITM jump into
/// a shared Personal profile (host:port unchanged → the pin would still match) and siphon off
/// a member's personal credential through their own machine. Hosts without jumps yield the previous string
/// (backward compatibility with old pins); the appearance of a jump → Redirected →
/// refusal (fail-safe), not a leak. The client renders with this both the pin at bind time and
/// `current_destination` at connect time — the formats are guaranteed to match.
fn personal_destination(
    host: &str,
    port: u16,
    username_template: Option<&str>,
    jumps: &[JumpHost],
) -> String {
    let base = match username_template {
        Some(t) if !t.trim().is_empty() => format!("{host}:{port}#{}", t.trim()),
        _ => format!("{host}:{port}"),
    };
    if jumps.is_empty() {
        base
    } else {
        format!("{base}|via={}", canonical_jumps(jumps))
    }
}

/// Template for the final connect username (gateway-agnostic): substitution of `%u`
/// with the identity's username. Empty → just `base_user`. Covers warpgate-like
/// scenarios (`%u:prod-db` → `alice:prod-db`) and any gateway that encodes the target in the name
/// (`%u@target`, `target+%u`, etc.) without tying to a specific product. The client
/// applies the same template that goes into the destination pin (the formats match).
fn apply_username_template(base_user: &str, username_template: Option<&str>) -> String {
    match username_template {
        Some(t) if !t.trim().is_empty() => t.trim().replace("%u", base_user),
        _ => base_user.to_string(),
    }
}

/// The authentication method stored in a profile. Contains only **references** to
/// vault items — the secret itself is never embedded in the profile's JSON.
#[derive(uniffi::Enum, Clone)]
pub enum ProfileAuth {
    /// By a key from the vault (an item of type "SSH key").
    Key {
        /// Id of the key item.
        key_item_id: String,
    },
    /// By a password from the vault (an item of type "password").
    VaultPassword {
        /// Id of the password item.
        password_item_id: String,
    },
    /// The password is prompted from the user on every connection.
    PromptPassword,
    /// By a personal identity: a shared profile has NO stored credentials; each member
    /// links their own identity via a binding in the personal vault (B3). At connect time
    /// the credentials and username are taken from the personal vault ([`Core::resolve_personal_auth`]),
    /// personal secrets never reach the shared vault. The default when moving a host into
    /// a cloud vault (B5).
    Personal,
}

/// Internal (serializable) profile body. `profile_id` is not serialized — it is
/// the item id. The JSON is stored as the item's encrypted content (vault layer).
///
/// Compatibility: flat optional fields instead of an enum — old profiles (without
/// `password_item_id`) are read as-is; `password_item_id` takes priority over
/// `key_item_id`; both `None` → password authentication with a prompt at connect time.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredProfile {
    /// Immutable profile uid (inside the ciphertext body). Minted on creation,
    /// NOT rewritten on edits (host/label change, the uid does not). A stable
    /// key for bindings (Phase B3), resilient to item_id recycling after a
    /// tombstone. Legacy profiles without it get a deterministic fallback
    /// on read ([`legacy_profile_uid`]), pinned on the first re-save.
    #[serde(default)]
    uid: Option<String>,
    label: String,
    host: String,
    port: u16,
    user: String,
    #[serde(default)]
    key_item_id: Option<String>,
    #[serde(default)]
    password_item_id: Option<String>,
    /// Personal profile: there are no credentials in this (shared) vault; we log in with a personal
    /// identity via a binding (B4). Takes priority over key/password references.
    #[serde(default)]
    personal: bool,
    /// Username template: if set, the target
    /// server is encoded in the username (`{identity.user}:{target}`, B4.2). Usually
    /// together with `personal`. Editing the target is covered by anti-redirect (it is part of
    /// the pinned destination).
    #[serde(default)]
    username_template: Option<String>,
    jumps: Vec<StoredJump>,
    #[serde(default)]
    tags: Vec<String>,
    /// Forward compatibility: unknown fields (added by a future version)
    /// are preserved on round-trip rather than dropped. Otherwise an OLDER client would
    /// read the profile without the new field (e.g. `personal`), and on re-
    /// save would strip it → an LWW downgrade for everyone. Empty → serializes
    /// to nothing (existing signed items do not change byte-for-byte).
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

/// Serializable body of a host-chain reference (B2.2).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredHopRef {
    vault_id: String,
    profile_uid: String,
}

/// Serializable jump host. The legacy format stored `key_item_id` as a string
/// (possibly empty — "no key assigned"); new records set exactly one of the
/// fields. An inline password is impossible here by construction.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredJump {
    host: String,
    port: u16,
    user: String,
    #[serde(default)]
    key_item_id: Option<String>,
    #[serde(default)]
    password_item_id: Option<String>,
    /// Host-chain reference (B2.2): the hop references another profile by uid.
    #[serde(default)]
    hop_ref: Option<StoredHopRef>,
    /// Forward compatibility at the serde round-trip level. Note: when editing
    /// a profile, hops are rebuilt from the FFI `JumpHost` ([`jump_to_stored`]), so
    /// merge-on-save (as in [`StoredProfile::extra`]) is NOT performed for hops
    /// — jump-level future fields survive only a pure sync (raw bytes),
    /// not an FFI edit. Acceptable: hops rarely gain new synced fields.
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

/// Authentication method for a host (target or jump) when connecting.
///
/// References to vault items are **vault-qualified**: each method carries the `vault_id`
/// of the vault where the key/password lives. This lets the target and each jump hop
/// take credentials from DIFFERENT vaults (a shared bastion in the team vault + a personal
/// identity in the personal vault) — see [`resolve_auth`], which resolves each
/// method against its own vault, not a single shared one.
#[derive(uniffi::Enum, Clone)]
pub enum AuthMethod {
    /// By a key from the vault (via the embedded agent).
    Agent {
        /// The vault where the key item lives.
        vault_id: String,
        /// Id of the key item in the vault.
        key_item_id: String,
    },
    /// By a password entered by the user right now (not stored in the vault).
    Password {
        /// The password. ⚠️ Residual FFI-boundary risk: a UniFFI `Enum` cannot keep a
        /// field in `Zeroizing`, so this `String` (and the copy inside russh) is not
        /// zeroized automatically. On our side the password is moved into
        /// `Zeroizing` when building `ConnectOptions` ([`resolve_auth`]).
        password: String,
    },
    /// By a password from the vault (an item of type "password"). The core decrypts it itself at
    /// connect time; the plaintext never passes through the FFI.
    VaultPassword {
        /// The vault where the password item lives.
        vault_id: String,
        /// Id of the password item in the vault.
        password_item_id: String,
    },
}

/// A pinned host key (for the known_hosts management screen).
#[derive(uniffi::Record)]
pub struct KnownHostInfo {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Public host key (OpenSSH).
    pub key: String,
    /// Pin time (unix seconds).
    pub added_at: i64,
}

/// Result of importing hosts from an external format (PuTTY, etc.).
#[derive(uniffi::Record)]
pub struct HostImportReport {
    /// Ids of the created profiles.
    pub created_ids: Vec<String>,
    /// How many records were skipped (not SSH, no host, id collision).
    pub skipped: u32,
}

/// Result of importing `~/.ssh/known_hosts`.
#[derive(uniffi::Record)]
pub struct KnownHostsImport {
    /// How many (host, port) were pinned.
    pub imported: u32,
    /// How many lines were skipped as hashed (`|1|…` — irreversible, cannot be pinned).
    pub skipped_hashed: u32,
    /// How many lines were skipped as invalid (no key / does not parse).
    pub skipped_invalid: u32,
}

/// Description of a jump host for ProxyJump.
#[derive(uniffi::Record, Clone)]
pub struct JumpHost {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User.
    pub user: String,
    /// Authentication on the jump host (items are in the same vault as the target
    /// host). Only references are saved into the profile (a key/password from the vault);
    /// an inline `Password` is allowed only for a direct connection.
    pub auth: AuthMethod,
    /// Host-chain (B2.2): if set, the hop is a REFERENCE to another saved profile
    /// (by immutable uid, possibly in a DIFFERENT vault); its host/port/user/auth
    /// are resolved at connect time, and the inline fields above are IGNORED. Lets you
    /// reuse a bastion profile in chains without duplication.
    pub hop_ref: Option<HopRef>,
}

/// A host-chain reference to a saved bastion profile (B2.2). Resolves to the
/// host/port/user/auth of that profile at connect time (see [`resolve_profile_by_uid`]).
#[derive(uniffi::Record, Clone)]
pub struct HopRef {
    /// The vault where the bastion profile lives.
    pub vault_id: String,
    /// Immutable uid of the bastion profile (B2.1).
    pub profile_uid: String,
}

/// Result of executing an SSH command.
#[derive(Debug, uniffi::Record)]
pub struct SshExecResult {
    /// stdout (as text; invalid UTF-8 is replaced).
    pub stdout: String,
    /// stderr.
    pub stderr: String,
    /// Exit code (or -1 if not received).
    pub exit_status: i32,
}

/// A target for multi-exec: one host + key/jumps.
#[derive(uniffi::Record)]
pub struct MultiExecTarget {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User.
    pub user: String,
    /// Authentication method (carries the key/password `vault_id`; jump hops carry their own).
    pub auth: AuthMethod,
    /// ProxyJump chain (may be empty).
    pub jumps: Vec<JumpHost>,
}

/// Category of a structural DB-integrity violation (FFI mirror of `ConsistencyKind`).
#[derive(Debug, uniffi::Enum, PartialEq, Eq)]
pub enum DbConsistencyKind {
    /// An item with no vault record.
    OrphanItem,
    /// Version < 1.
    BadVersion,
    /// Length of `author_pubkey` != 32.
    BadAuthorLen,
    /// Signature too short.
    BadSignatureLen,
    /// A tombstone with non-empty content.
    TombstoneNotEmpty,
    /// Version history for a deleted/missing item.
    StaleHistory,
}

/// A DB-integrity violation (no secrets; identifiers are hex).
#[derive(Debug, uniffi::Record)]
pub struct DbConsistencyIssue {
    /// Category.
    pub kind: DbConsistencyKind,
    /// vault_id (hex).
    pub vault_id_hex: String,
    /// item_id (hex); empty for vault-level problems.
    pub item_id_hex: String,
    /// Machine-readable detail.
    pub detail: String,
}

/// Report of the instance DB's structural check (no secrets).
#[derive(Debug, uniffi::Record)]
pub struct DbConsistencyReport {
    /// Integrity and invariants hold.
    pub ok: bool,
    /// `PRAGMA integrity_check` passed.
    pub integrity_ok: bool,
    /// Violations found.
    pub issues: Vec<DbConsistencyIssue>,
}

/// Result of laying out a file onto one host ([`Core::sftp_put_multi`]).
#[derive(uniffi::Record)]
pub struct SftpPutResult {
    /// Host.
    pub host: String,
    /// Error if the write failed (otherwise `None`).
    pub error: Option<String>,
}

/// Status of one host in a broadcast session (by index in `targets`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct BroadcastHostStatus {
    /// Host.
    pub host: String,
    /// Index in the original target list (matches `host_index` in the observer).
    pub index: u32,
    /// Whether the PTY session was established.
    pub connected: bool,
    /// Error connecting/opening the shell, if any.
    pub error: Option<String>,
}

/// Reason an integrity check failed (FFI mirror of `IntegrityFailure`).
#[derive(Debug, uniffi::Enum)]
pub enum IntegrityFailureKind {
    /// The signature does not verify (blob corruption or a damaged sig).
    SignatureInvalid,
    /// `author_pubkey` did not match the vault owner (author spoofing).
    AuthorMismatch,
    /// Structurally invalid author/signature.
    Malformed,
}

/// A problematic record in the integrity report (no secrets).
#[derive(Debug, uniffi::Record)]
pub struct IntegrityIssueInfo {
    /// `item_id` (UTF-8 lossy); an empty string is a problem with the vault record itself.
    pub item_id: String,
    /// Record version.
    pub version: u64,
    /// Whether this is a tombstone.
    pub tombstone: bool,
    /// Reason.
    pub failure: IntegrityFailureKind,
}

/// Vault integrity-audit report (read-only, no plaintext/secrets).
#[derive(Debug, uniffi::Record)]
pub struct VaultIntegrityReport {
    /// All records (including tombstones) passed the check.
    pub ok: bool,
    /// How many records were checked.
    pub checked: u64,
    /// Problematic records.
    pub issues: Vec<IntegrityIssueInfo>,
}

/// A host group: a named set of references to profiles and/or nested groups in
/// the same vault. Serves organization (a folder tree via `parent_id`) and
/// operations (resolving members → multi-exec). This is not RBAC — a group carries no rights.
#[derive(uniffi::Record, Clone)]
pub struct ServerGroup {
    /// Group identifier (item_id in the vault).
    pub group_id: String,
    /// Human-readable label.
    pub label: String,
    /// Members: ids of connection profiles or ids of nested groups (of the same vault).
    pub member_ids: Vec<String>,
    /// Parent group for the folder tree in the UI (`None` = root).
    pub parent_id: Option<String>,
}

/// Serializable group body. References only, no credentials. `color` is a public
/// UI field; new fields are added with `#[serde(default)]` (forward-compat).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredGroup {
    label: String,
    #[serde(default)]
    member_ids: Vec<String>,
    #[serde(default)]
    parent_id: Option<String>,
    #[serde(default)]
    color: Option<String>,
}

/// Resolution status of a group member (for dry-run and diagnostics).
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResolveStatus {
    /// The member is an existing profile; the target was built.
    Ok,
    /// The reference points to neither a profile nor a group (deleted/typo).
    Dangling,
    /// The member's vault password is not known in advance (`PromptPassword`); it will require
    /// input at connect time and is unsuitable for a batch run without interaction.
    PromptPassword,
    /// The member group was already visited (a cycle) or the depth limit was exceeded — skipped.
    CycleSkipped,
    /// The member is a Personal host: logging in with a personal identity requires per-host
    /// binding resolution + an anti-redirect check, which is not yet supported in fan-out
    /// (B6). We do NOT connect with an empty password — it is excluded from the batch.
    Personal,
}

/// An expanded group target in a dry-run: what resolved and with which status, without
/// connecting/loading keys/decrypting passwords.
#[derive(uniffi::Record)]
pub struct GroupTargetPlan {
    /// Id of the member profile (or of the problematic reference).
    pub member_id: String,
    /// Host (empty if not resolved).
    pub host: String,
    /// Port.
    pub port: u16,
    /// User.
    pub user: String,
    /// Resolution status.
    pub status: ResolveStatus,
}

/// Result of multi-exec for a single host.
#[derive(uniffi::Record)]
pub struct MultiExecResult {
    /// Host.
    pub host: String,
    /// stdout.
    pub stdout: String,
    /// stderr.
    pub stderr: String,
    /// Exit code (or -1).
    pub exit_status: i32,
    /// Error connecting/executing, if any (in which case the other fields are empty).
    pub error: Option<String>,
    /// Duration of the command-execution phase (ms). 0 for connect errors.
    pub duration_ms: u64,
    /// The command exceeded the per-host timeout (`timeout_secs`). In that case `error`
    /// is also set and `exit_status == -1`.
    pub timed_out: bool,
}

// === Milestone 2: FFI types (cloud/membership/identity/cache/audit/sync) ===

/// A vault member's role (FFI mirror of `storage::MemberRole`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiMemberRole {
    /// Read-only.
    Viewer,
    /// Read and write items.
    Editor,
    /// Membership management (grant/revoke, rotation).
    Admin,
}

impl FfiMemberRole {
    fn to_core(self) -> MemberRole {
        match self {
            FfiMemberRole::Viewer => MemberRole::Viewer,
            FfiMemberRole::Editor => MemberRole::Editor,
            FfiMemberRole::Admin => MemberRole::Admin,
        }
    }
    fn from_core(r: MemberRole) -> FfiMemberRole {
        match r {
            MemberRole::Viewer => FfiMemberRole::Viewer,
            MemberRole::Editor => FfiMemberRole::Editor,
            MemberRole::Admin => FfiMemberRole::Admin,
            // non_exhaustive: a future role → conservatively Viewer (minimum rights).
            _ => FfiMemberRole::Viewer,
        }
    }
}

/// A vault's cache policy (FFI mirror of `storage::CachePolicy`, server-tz §6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiCachePolicy {
    /// Offline access allowed (weaker revocation).
    OfflineAllowed,
    /// Online only (strong revocation, no offline).
    OnlineOnly,
}

impl FfiCachePolicy {
    fn to_core(self) -> CachePolicy {
        match self {
            FfiCachePolicy::OfflineAllowed => CachePolicy::OfflineAllowed,
            FfiCachePolicy::OnlineOnly => CachePolicy::OnlineOnly,
        }
    }
    fn from_core(c: CachePolicy) -> FfiCachePolicy {
        match c {
            CachePolicy::OfflineAllowed => FfiCachePolicy::OfflineAllowed,
            CachePolicy::OnlineOnly => FfiCachePolicy::OnlineOnly,
            _ => FfiCachePolicy::OfflineAllowed,
        }
    }
}

/// A vault member for the UI: public keys (hex) + role + fingerprint. No secrets.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MemberInfo {
    /// The member's Ed25519 pubkey (member-id) in hex.
    pub ed25519_pub_hex: String,
    /// Role.
    pub role: FfiMemberRole,
    /// OOB fingerprint (hex(SHA-256(ed25519_pub)), 64 characters) for confirmation.
    pub fingerprint: String,
}

/// A remaining member during VK rotation: public keys (hex) + role.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RemainingMember {
    /// Ed25519-pubkey (member-id), hex.
    pub ed25519_pub_hex: String,
    /// X25519 pubkey (recipient of the VK' wrap), hex.
    pub x25519_pub_hex: String,
    /// Role.
    pub role: FfiMemberRole,
}

/// One element of a sync delta that the foreign transport hands to the core.
/// `object` — opaque bytes of a serialized sync object.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncDeltaItem {
    /// server_seq assigned by the server (NOT trusted — the engine verifies).
    pub server_seq: u64,
    /// The serialized object (opaque encrypted/signed bytes).
    pub object: Vec<u8>,
}

/// Sync report for the UI (FFI mirror of `sync::SyncReport`; no secrets).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSyncReport {
    /// How many objects were applied (merged).
    pub applied: u64,
    /// How many were skipped as stale/a version rollback.
    pub skipped_stale: u64,
    /// How many equal-version conflicts (local left untouched).
    pub conflicts: u32,
    /// How many untrusted objects were rejected (verify/floor/cursor fail).
    pub rejected: u32,
    /// How many objects were handed off for push.
    pub pushed: u64,
}

/// Audit entry for the UI (FFI mirror of `storage::AuditEntry`; blobs are opaque).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAuditEntry {
    /// Monotonic seq (assigned by storage; public metadata, not trusted for
    /// tamper-evidence in v1).
    pub seq: u64,
    /// The signed event (an opaque blob from a higher layer).
    pub entry_blob: Vec<u8>,
    /// Author's signature (an Ed25519 blob).
    pub signature: Vec<u8>,
    /// Author's public key (hex).
    pub author_pubkey_hex: String,
    /// When recorded (unix seconds).
    pub recorded_at: i64,
}

struct CoreState {
    storage: Storage,
    keyset: unissh_keychain::UnlockedKeyset,
    agent: InMemoryAgent,
    /// Cache of decrypted vault names (vault_id → name), so that `list_vaults` does not
    /// perform an HPKE VK unwrap for every vault on every call.
    vault_names: HashMap<Vec<u8>, String>,
}

/// Root core object for the UI. Manages a single local instance.
#[derive(uniffi::Object)]
pub struct Core {
    db_path: PathBuf,
    keyset_path: PathBuf,
    // Arc — to share the unwrapped state with ReconnectingSession
    // (reconnection needs access to the keyset/storage/agent).
    state: Arc<Mutex<Option<CoreState>>>,
    rt: Arc<tokio::runtime::Runtime>,
}

/// Escrow enrollment/fetch credentials derived on the device (spec 5.1 / server-tz
/// escrow). `k_auth` is the retrieval credential the server pins as `sha256(K_auth)`;
/// the `argon_*` fields are the Argon2id parameters (with a fresh salt) used to stretch
/// the password into `K_auth`. A pure derivation — nothing is persisted here.
#[derive(uniffi::Record)]
pub struct EscrowCreds {
    /// The 256-bit escrow retrieval credential `K_auth` (domain-separated from K_unlock).
    pub k_auth: Vec<u8>,
    /// Fresh Argon2id salt (16 bytes) that produced `k_auth`.
    pub argon_salt: Vec<u8>,
    /// Argon2id memory cost in KiB.
    pub argon_mem_kib: u32,
    /// Argon2id iterations (time cost).
    pub argon_iterations: u32,
    /// Argon2id parallelism (lanes).
    pub argon_parallelism: u32,
}

#[uniffi::export]
impl Core {
    /// Creates the facade over the DB and keyset-sidecar paths (not yet unlocked).
    #[uniffi::constructor]
    pub fn new(db_path: String, keyset_path: String) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Core {
            db_path: PathBuf::from(db_path),
            keyset_path: PathBuf::from(keyset_path),
            state: Arc::new(Mutex::new(None)),
            rt: Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime"),
            ),
        })
    }

    /// Creates a new account (the first device). Returns the Secret Key (hex) for
    /// the Emergency Kit — show it to the user **once**. `password = None` →
    /// passwordless mode (SSO/trusted devices).
    pub fn create_account(&self, password: Option<String>) -> Result<String, FfiError> {
        // Guards against overwriting an existing instance (otherwise — irreversible DB loss).
        if self.keyset_path.exists() || self.db_path.exists() {
            return Err(FfiError::AlreadyExists);
        }
        let has_password = password.is_some();
        let password = password.map(Zeroizing::new);
        let (secret_key, enc, unlocked) = create_account(
            password.as_deref().map(|s| s.as_bytes()),
            KdfParams::recommended(),
        )
        .map_err(FfiError::other)?;
        let enc_bytes = enc.to_bytes().map_err(FfiError::other)?;

        // Order matters (brick protection): first open the DB, and only on
        // success write the keyset sidecar — atomically (O_EXCL). On any failure after
        // creating the DB we roll back the files so that a retry starts clean.
        let db_key = derive_db_key(&unlocked);
        let storage = Storage::open(&self.db_path, &db_key[..]).map_err(|e| {
            let _ = std::fs::remove_file(&self.db_path);
            FfiError::other(e)
        })?;

        match open_keyset_file(&self.keyset_path, true) {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(&enc_bytes) {
                    drop(storage);
                    let _ = std::fs::remove_file(&self.keyset_path);
                    let _ = std::fs::remove_file(&self.db_path);
                    return Err(FfiError::other(e));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Race: the keyset appeared between the check and the write. We just
                // created the DB ourselves — remove it, and don't touch the other instance.
                drop(storage);
                let _ = std::fs::remove_file(&self.db_path);
                return Err(FfiError::AlreadyExists);
            }
            Err(e) => {
                drop(storage);
                let _ = std::fs::remove_file(&self.db_path);
                return Err(FfiError::other(e));
            }
        }

        *self.locked_state() = Some(CoreState {
            storage,
            keyset: unlocked,
            agent: InMemoryAgent::new(),
            vault_names: HashMap::new(),
        });
        log::info!("instance created (password-protected: {has_password})");
        // Emergency Kit: we zeroize the intermediate hex copy; the string returned through the FFI
        // is beyond our control (an FFI-boundary limitation).
        let kit = Zeroizing::new(hex::encode(secret_key.expose_bytes()));
        Ok(kit.as_str().to_string())
    }

    /// Unlocks the instance with a password (if needed) and the Secret Key (hex from the Emergency Kit).
    pub fn unlock(&self, password: Option<String>, secret_key_hex: String) -> Result<(), FfiError> {
        let password = password.map(Zeroizing::new);
        let secret_key_hex = Zeroizing::new(secret_key_hex);
        let enc_bytes = std::fs::read(&self.keyset_path).map_err(|_| FfiError::NotFound)?;
        let enc = EncryptedKeyset::from_bytes(&enc_bytes).map_err(FfiError::other)?;
        let sk_bytes = Zeroizing::new(
            hex::decode(secret_key_hex.trim()).map_err(|_| FfiError::InvalidCredentials)?,
        );
        let secret_key =
            SecretKey::from_slice(&sk_bytes).map_err(|_| FfiError::InvalidCredentials)?;

        // migrate-on-open: a keyset written by an old scheme (before round 2) is opened
        // via a probe and returned re-wrapped under the current scheme (`migrated`). This
        // fixes "invalid secret key/master password" for those who created an account on
        // earlier builds. Persisting the re-wrap is below, AFTER opening storage and the floor check.
        let (unlocked, migrated) =
            unlock_account_migrating(&enc, password.as_deref().map(|s| s.as_bytes()), &secret_key)
                .map_err(|e| match e {
                    unissh_keychain::KeychainError::InvalidCredentials
                    | unissh_keychain::KeychainError::PasswordRequired => {
                        FfiError::InvalidCredentials
                    }
                    other => FfiError::other(other),
                })?;

        let db_key = derive_db_key(&unlocked);
        let storage = Storage::open(&self.db_path, &db_key[..]).map_err(FfiError::other)?;

        // anti-rollback (server-tz §13.13b): the local sidecar is also under floor protection.
        // An attacker with disk access could swap the keyset file for an OLD
        // (lower-generation) blob — after a password change that is a downgrade. The same
        // logic as in unlock_from_server_blob: we REJECT a generation below the floor BEFORE
        // setting state (the floor lives in storage-meta, available only after
        // unlock+open). We read/raise the floor with the same keychain helper.
        let floor = unissh_keychain::keyset_gen_floor(&storage)
            .map_err(map_keychain_err)?
            .unwrap_or(0);
        let attempted = enc.generation as u64;
        if attempted < floor {
            // Security event: an on-disk keyset older than the recorded floor — a
            // possible downgrade attack. Generations are counters, not secrets.
            log::warn!(
                "keyset generation rollback rejected (attempted={attempted}, floor={floor})"
            );
            return Err(map_keychain_err(
                unissh_keychain::KeychainError::GenerationRollback { attempted, floor },
            ));
        }
        // The order is brick-safe: first atomically persist the re-wrapped keyset,
        // and ONLY then raise the floor to its (new, +1) generation. If the write fails
        // the floor is not raised — the old blob (generation=attempted) will still open on
        // the next launch and the migration will repeat. On success the old blob drops
        // below the floor — a downgrade to the old/weaker scheme will no longer pass.
        let accepted_gen = if let Some(new_enc) = migrated {
            // Back up the old sidecar before overwriting (logs the path) — reversibility.
            backup_keyset_sidecar(&self.keyset_path);
            let new_bytes = new_enc.to_bytes().map_err(FfiError::other)?;
            write_keyset_atomic(&self.keyset_path, &new_bytes)?;
            log::info!(
                "keyset migrated to current scheme (generation {} -> {})",
                attempted,
                new_enc.generation
            );
            new_enc.generation as u64
        } else {
            attempted
        };
        // Accepted: raise the floor to the accepted generation (TOFU; cannot lower — idempotent).
        unissh_keychain::raise_keyset_gen_floor(&storage, accepted_gen)
            .map_err(map_keychain_err)?;

        *self.locked_state() = Some(CoreState {
            storage,
            keyset: unlocked,
            agent: InMemoryAgent::new(),
            vault_names: HashMap::new(),
        });
        log::info!("instance unlocked");
        Ok(())
    }

    /// Whether the instance is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.locked_state().is_some()
    }

    /// Whether a master password is needed to unlock the on-disk instance. Reads only
    /// the keyset-sidecar header (KDF params present ⇔ Password mode) — without
    /// opening the DB and without access to secrets. `None` if there is no keyset yet or it
    /// could not be read/parsed. Lets the UI honestly show that
    /// the "open at startup" auto-unlock applies only to passwordless
    /// instances (the password is stored nowhere).
    pub fn instance_requires_password(&self) -> Option<bool> {
        let bytes = std::fs::read(&self.keyset_path).ok()?;
        let enc = EncryptedKeyset::from_bytes(&bytes).ok()?;
        Some(enc.kdf_params.is_some())
    }

    /// Locks the instance (in-memory secrets are zeroized on Drop).
    pub fn lock(&self) {
        log::info!("instance locked");
        *self.locked_state() = None;
    }

    /// Creates a local vault.
    pub fn create_vault(&self, vault_id: String, name: String) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let id = vault_id.into_bytes();
            Vault::create(&state.storage, &state.keyset, id.clone(), name.as_bytes())
                .map_err(FfiError::other)?;
            state.vault_names.insert(id, name);
            Ok(())
        })
    }

    /// Creates a **cloud vault** (server-tz §4.2): `vault_id` = a random UUIDv4
    /// (`vault::new_vault_id`), `SyncTarget::Cloud`, **bound to the server**
    /// `tenant_b64` (a 1:1 binding). `tenant_b64` is the base64 `tenant_id` of the active
    /// server (as in `ServerConfig.tenant_id`); stored as an opaque routing
    /// label by which `sync_now` decides which server to push the vault to.
    /// An empty `tenant_b64` is rejected (the client must pass an active server).
    /// Returns `vault_id` as a hex string (a UUIDv4 is non-UTF8 bytes; cloud methods
    /// accept hex).
    pub fn create_cloud_vault(&self, name: String, tenant_b64: String) -> Result<String, FfiError> {
        if tenant_b64.is_empty() {
            return Err(FfiError::Other {
                msg: "cloud vault requires an active server (empty tenant)".into(),
            });
        }
        self.with_state_mut(|state| {
            let vid = unissh_vault::new_vault_id();
            Vault::create_with_target(
                &state.storage,
                &state.keyset,
                vid.clone(),
                name.as_bytes(),
                SyncTarget::Cloud,
            )
            .map_err(map_vault_err)?;
            // Bind ONLY the freshly created vault by its vault_id (1:1), so as not to
            // affect other unbound legacy cloud vaults (they must be bound to
            // their own server, not this one).
            state
                .storage
                .set_vault_tenant(&vid, tenant_b64.as_bytes())
                .map_err(FfiError::other)?;
            let vid_hex = hex::encode(&vid);
            state.vault_names.insert(vid, name);
            Ok(vid_hex)
        })
    }

    /// **One-time binding of legacy cloud vaults to a server** (a 1:1-binding migration):
    /// sets `tenant_b64` on every cloud vault with an empty `sync_tenant`
    /// (created before multi-server). The client calls this EXACTLY when a single
    /// server is bound — otherwise it could bind to the wrong one. Idempotent
    /// (already-bound vaults are left untouched). Returns the number of vaults bound.
    pub fn bind_unbound_cloud_vaults(&self, tenant_b64: String) -> Result<u32, FfiError> {
        if tenant_b64.is_empty() {
            return Err(FfiError::Other {
                msg: "cannot bind cloud vaults to an empty tenant".into(),
            });
        }
        self.with_state(|state| {
            let n = state
                .storage
                .bind_unbound_cloud_vaults(tenant_b64.as_bytes())
                .map_err(FfiError::other)?;
            Ok(n as u32)
        })
    }

    /// Unbind all cloud vaults bound to `tenant_b64` (e.g. when
    /// removing a server) — they become unbound and can be rebound
    /// (via re-link or a manual binding). Returns the number of vaults affected.
    pub fn clear_cloud_vault_binding(&self, tenant_b64: String) -> Result<u32, FfiError> {
        if tenant_b64.is_empty() {
            return Ok(0);
        }
        self.with_state(|state| {
            let n = state
                .storage
                .clear_binding_for_tenant(tenant_b64.as_bytes())
                .map_err(FfiError::other)?;
            Ok(n as u32)
        })
    }

    /// Bind ONE cloud vault (by hex `vault_id`) to the server `tenant_b64` (1:1).
    /// For manually binding an unbound vault to a chosen server from the UI.
    pub fn bind_cloud_vault(&self, vault_id: String, tenant_b64: String) -> Result<(), FfiError> {
        if tenant_b64.is_empty() {
            return Err(FfiError::Other {
                msg: "cannot bind a cloud vault to an empty tenant".into(),
            });
        }
        let vid = hex::decode(vault_id.trim()).map_err(|_| FfiError::other("invalid vault id"))?;
        self.with_state(|state| {
            state
                .storage
                .set_vault_tenant(&vid, tenant_b64.as_bytes())
                .map_err(FfiError::other)?;
            Ok(())
        })
    }

    /// Adds/promotes a member of a cloud vault (server-tz §5): extends the set
    /// of the latest epoch with `(member_ed25519_pub, role)` and issues a VK wrap under
    /// `member_x25519_pub`. The owner stays `Admin`. Keys are hex (public
    /// material, not a secret). `vault_id` is hex (a cloud UUIDv4).
    pub fn add_member(
        &self,
        vault_id: String,
        member_ed25519_pub: String,
        member_x25519_pub: String,
        role: FfiMemberRole,
    ) -> Result<(), FfiError> {
        let vid = decode_vid(&vault_id)?;
        let member_ed = decode_pubkey32("member_ed25519_pub", &member_ed25519_pub)?;
        let member_x = decode_pubkey32("member_x25519_pub", &member_x25519_pub)?;
        self.with_state_mut(|state| {
            let owner_ed = state.keyset.signing.verifying.to_bytes().to_vec();
            let owner_x = state.keyset.encryption.public.to_bytes().to_vec();

            // The owner is ALWAYS Admin of their own vault. "Adding" the owner as a member below
            // via the upsert path would re-insert them with the passed role (e.g. Viewer); as
            // soon as `verify_record_authority` requires `can_write`, the vault becomes
            // unreadable for its own owner (an irreversible brick). We reject explicitly.
            if member_ed == owner_ed {
                return Err(FfiError::other(
                    "cannot add the vault owner as a member — the owner is always Admin",
                ));
            }

            let vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(map_vault_err)?;

            // target set = current (if a manifest exists) ∪ {owner Admin, new member}.
            let mut members: Vec<Member> = match state
                .storage
                .latest_membership_epoch(&vid)
                .map_err(FfiError::other)?
            {
                Some(latest) => verify_chain_to_epoch(&state.storage, &vid, latest, &owner_ed)
                    .map_err(map_vault_err)?
                    .members()
                    .to_vec(),
                None => Vec::new(),
            };
            // ensure owner=Admin is in the set
            if !members.iter().any(|m| m.ed25519_pub == owner_ed) {
                members.push(Member {
                    ed25519_pub: owner_ed.clone(),
                    role: MemberRole::Admin,
                });
            }
            // upsert the new member (their role)
            members.retain(|m| m.ed25519_pub != member_ed);
            members.push(Member {
                ed25519_pub: member_ed.clone(),
                role: role.to_core(),
            });

            let x25519_by_ed = vec![(owner_ed.clone(), owner_x), (member_ed.clone(), member_x)];
            vault
                .establish_or_extend_membership(&state.keyset, &members, &x25519_by_ed)
                .map_err(map_vault_err)?;
            Ok(())
        })
    }

    /// List of a cloud vault's members at the latest epoch (public keys + role +
    /// fingerprint). Empty if there is no membership yet.
    pub fn list_members(&self, vault_id: String) -> Result<Vec<MemberInfo>, FfiError> {
        let vid = decode_vid(&vault_id)?;
        self.with_state_mut(|state| {
            let owner_ed = state.keyset.signing.verifying.to_bytes().to_vec();
            let latest = match state
                .storage
                .latest_membership_epoch(&vid)
                .map_err(FfiError::other)?
            {
                Some(l) => l,
                None => return Ok(Vec::new()),
            };
            let verified = verify_chain_to_epoch(&state.storage, &vid, latest, &owner_ed)
                .map_err(map_vault_err)?;
            Ok(verified
                .members()
                .iter()
                .map(|m| MemberInfo {
                    ed25519_pub_hex: hex::encode(&m.ed25519_pub),
                    role: FfiMemberRole::from_core(m.role),
                    fingerprint: member_fingerprint(&m.ed25519_pub),
                })
                .collect())
        })
    }

    /// OOB fingerprint of a member's Ed25519 pubkey (hex(SHA-256), 64 characters) — for
    /// display/verification in the UI (like Bitwarden Confirm / 1Password fingerprint).
    pub fn member_fingerprint(&self, ed25519_pub: String) -> Result<String, FfiError> {
        let ed = decode_pubkey32("ed25519_pub", &ed25519_pub)?;
        Ok(member_fingerprint(&ed))
    }

    /// Confirms (TOFU-pins) a member's pubkey under `account_id` (server-tz §5.2):
    /// the first time it is pinned; repeating with the same key — ok; with a different one → an error
    /// (`PinMismatch`, protection against pubkey spoofing by the server). Requires unlock (storage).
    pub fn confirm_member_pin(
        &self,
        account_id: String,
        ed25519_pub: String,
    ) -> Result<(), FfiError> {
        let ed = decode_pubkey32("ed25519_pub", &ed25519_pub)?;
        self.with_state(|state| {
            pin_and_verify_member(&state.storage, account_id.as_bytes(), &ed).map_err(map_vault_err)
        })
    }

    /// Confirms (TOFU-pins) the genesis owner (creator-pubkey) of a vault created
    /// by a teammate — share-accept (A0): without this pin another's vault record fails
    /// authority verification on sync (the anchor = the local keyset). The first time it is
    /// pinned; repeating with the same key — ok; with a different one → `PinMismatch` (protection against
    /// a silent vault→owner re-binding by the server). `ed25519_pub` is the creator-pubkey,
    /// received OOB and verified by fingerprint (`member_fingerprint`). Requires unlock.
    pub fn pin_vault_genesis_owner(
        &self,
        vault_id: String,
        ed25519_pub: String,
    ) -> Result<(), FfiError> {
        let vid = decode_vid(&vault_id)?;
        let ed = decode_pubkey32("ed25519_pub", &ed25519_pub)?;
        self.with_state(|state| {
            // The anchor is pinned ONLY for others' (teammate) vaults. Pinning your own keyset as
            // a "teammate's genesis owner" is almost certainly a mistake/mis-anchoring: your own
            // vaults are authorized by the local keyset anyway (the fallback). We reject explicitly.
            if ed == state.keyset.signing.verifying.to_bytes() {
                return Err(FfiError::Other {
                    msg: "cannot pin your own keyset as a vault trust anchor".into(),
                });
            }
            pin_and_verify_vault_anchor(&state.storage, &vid, &ed).map_err(map_vault_err)
        })
    }

    /// Assigns the account's PERSONAL vault (A3.2): the pointer is stored in per-account
    /// state (a self-sealed payload, synced to the account's devices). `vault_id`
    /// is the hex of a cloud vault OR an arbitrary UTF-8 id of a local (offline) vault:
    /// the personal vault may also be fully local (the most private option —
    /// identities never leave the device). Requires unlock. Increments the version.
    ///
    /// Guard (B5.3): the personal vault must be single-member — identities and
    /// bindings are written into it, and a shared (multi-member) vault would sync them to the whole
    /// team (a leak of personal credentials + the fact/target of the binding). >1 member → refused;
    /// a local vault has no membership chain (0 members) → passes.
    pub fn set_personal_vault(&self, vault_id: String) -> Result<(), FfiError> {
        let vid = {
            let mut guard = self.locked_state();
            let state = guard.as_mut().ok_or(FfiError::Locked)?;
            // resolve_vid accepts both a local (UTF-8) and a cloud (hex) id; decode_vid
            // was hex-only and rejected local vaults.
            let vid = resolve_vid(&state.storage, &vault_id);
            let owner_ed = state.keyset.signing.verifying.to_bytes().to_vec();
            let members = match state
                .storage
                .latest_membership_epoch(&vid)
                .map_err(FfiError::other)?
            {
                Some(latest) => verify_chain_to_epoch(&state.storage, &vid, latest, &owner_ed)
                    .map_err(map_vault_err)?
                    .members()
                    .len(),
                None => 0, // a local / not-yet-shared vault — no members
            };
            if members > 1 {
                return Err(FfiError::other(
                    "cannot use a shared (multi-member) vault as your personal vault",
                ));
            }
            vid
        }; // the guard is released before update_account_state (which locks state itself)
        self.update_account_state(move |p| p.personal_vault_id = vid)
    }

    /// Account-default username (A3.2): used in login resolution when a host
    /// has none of its own. An empty string clears it. Requires unlock.
    pub fn set_account_default_username(&self, username: String) -> Result<(), FfiError> {
        self.update_account_state(move |p| p.default_username = username)
    }

    /// The account's personal vault, if assigned. The id is returned in the SAME representation as
    /// `list_vaults` (otherwise the UI won't match: there a local vault is a UTF-8 string, a cloud one is
    /// hex). An existing local vault → the raw UTF-8 string; a cloud or unknown one
    /// (e.g. deleted) → hex (as before).
    pub fn get_personal_vault(&self) -> Result<Option<String>, FfiError> {
        let raw = match self.read_account_state()? {
            Some(p) if !p.personal_vault_id.is_empty() => p.personal_vault_id,
            _ => return Ok(None),
        };
        self.with_state(|state| {
            let display = match state.storage.get_vault(&raw).map_err(FfiError::other)? {
                Some(rec) if !matches!(rec.sync_target, SyncTarget::Cloud) => {
                    String::from_utf8_lossy(&raw).to_string()
                }
                _ => hex::encode(&raw),
            };
            Ok(Some(display))
        })
    }

    /// Account-default username, if set.
    pub fn get_account_default_username(&self) -> Result<Option<String>, FfiError> {
        Ok(self.read_account_state()?.and_then(|p| {
            if p.default_username.is_empty() {
                None
            } else {
                Some(p.default_username)
            }
        }))
    }

    /// **Eager Vault Key rotation** of a cloud vault (server-tz §6.2): a new VK',
    /// a manifest at `epoch+1` over the remaining members, grants under VK', a re-wrap of live
    /// item keys, raising the epoch floor (atomically). The owner (this keyset) always
    /// stays `Admin` in the set. `remaining_member_pubkeys` are the additional
    /// remaining members as `(ed25519_hex, x25519_hex, role)`; those absent from
    /// the list (except the owner) are treated as revoked. Returns the new epoch.
    pub fn rotate_vk(
        &self,
        vault_id: String,
        remaining_member_pubkeys: Vec<RemainingMember>,
    ) -> Result<u64, FfiError> {
        let vid = decode_vid(&vault_id)?;
        self.with_state(|state| {
            let owner_ed = state.keyset.signing.verifying.to_bytes().to_vec();
            let owner_x = state.keyset.encryption.public.to_bytes().to_vec();

            // build the remaining set: the owner as Admin + those passed in.
            let mut members: Vec<Member> = vec![Member {
                ed25519_pub: owner_ed.clone(),
                role: MemberRole::Admin,
            }];
            let mut grants: Vec<(Vec<u8>, Vec<u8>, MemberRole)> =
                vec![(owner_x, owner_ed.clone(), MemberRole::Admin)];
            for rm in &remaining_member_pubkeys {
                let ed = decode_pubkey32("ed25519", &rm.ed25519_pub_hex)?;
                let x = decode_pubkey32("x25519", &rm.x25519_pub_hex)?;
                if ed == owner_ed {
                    continue; // the owner is already added
                }
                members.push(Member {
                    ed25519_pub: ed.clone(),
                    role: rm.role.to_core(),
                });
                grants.push((x, ed, rm.role.to_core()));
            }

            let vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(map_vault_err)?;
            vault
                .rotate_vk(&state.keyset, &members, &grants)
                .map_err(map_vault_err)
        })
    }

    /// **Cooperative hard-delete** of a cloud vault (server-tz §6.4): physically
    /// erases the record/items/history/manifests/grants/epoch-floor and zeroizes the VK.
    /// Best-effort/hygiene, NOT a remote wipe (a modified client will keep the data).
    pub fn purge_vault(&self, vault_id: String) -> Result<(), FfiError> {
        let vid = decode_vid(&vault_id)?;
        self.with_state_mut(|state| {
            let vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(map_vault_err)?;
            vault.purge_vault().map_err(map_vault_err)?;
            state.vault_names.remove(&vid);
            Ok(())
        })
    }

    /// Member-aware integrity audit of a cloud vault (server-tz §6.2): the D1 chain +
    /// the epoch floor. A report with no secrets. (For local vaults — `verify_vault_integrity`.)
    pub fn verify_chain(&self, vault_id: String) -> Result<VaultIntegrityReport, FfiError> {
        let vid = decode_vid(&vault_id)?;
        self.with_state_mut(|state| {
            let vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(map_vault_err)?;
            let report = vault.verify_chain().map_err(map_vault_err)?;
            Ok(integrity_report_to_ffi(report))
        })
    }

    /// Local account-id (server-tz §2.1): generated once and persisted in
    /// storage-meta; subsequent calls return the same id. A public
    /// identifier (NOT a secret), hex (16 bytes). Requires unlock (storage).
    pub fn account_id(&self) -> Result<String, FfiError> {
        self.with_state(|state| {
            let id = ensure_account_id(&state.storage)?;
            Ok(hex::encode(id))
        })
    }

    /// A self-attested registration blob (server-tz §2.1): binds the account-id to the
    /// keyset's public keys and signs it with the keyset's Ed25519 key. An opaque
    /// signed blob (NOT a secret) — published to the server. Requires unlock.
    pub fn build_registration(&self) -> Result<Vec<u8>, FfiError> {
        self.with_state(|state| {
            let id = ensure_account_id(&state.storage)?;
            build_registration(&state.keyset, &id).map_err(map_keychain_err)
        })
    }

    /// Like [`Core::build_registration`], but returns BOTH the canonical payload AND
    /// the signature — the server requires both fields (`registration_payload` +
    /// `registration_signature`). The payload is built in the core so the UI doesn't rebuild
    /// the canonical form (a risk of byte desync → verification failure on the server).
    pub fn build_registration_request(&self) -> Result<RegistrationRequest, FfiError> {
        self.with_state(|state| {
            let id = ensure_account_id(&state.storage)?;
            let (payload, signature) =
                build_registration_request(&state.keyset, &id).map_err(map_keychain_err)?;
            Ok(RegistrationRequest { payload, signature })
        })
    }

    /// Signs a server challenge with the keyset's Ed25519 key (server-tz §2.2,
    /// domain `unissh-server-auth-v1`). Returns the signature blob (NOT a secret);
    /// the private key never leaves. Nonce/expiry checking is done by the server.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_server_challenge(
        &self,
        host: String,
        account_id: String,
        device_id: String,
        key_id: String,
        nonce: Vec<u8>,
        expiry: u64,
    ) -> Result<Vec<u8>, FfiError> {
        self.with_state(|state| {
            let challenge = ServerAuthChallenge {
                host: host.into_bytes(),
                account_id: account_id.into_bytes(),
                device_id: device_id.into_bytes(),
                key_id: key_id.into_bytes(),
                nonce,
                expiry,
            };
            sign_server_challenge(&state.keyset, &challenge).map_err(map_keychain_err)
        })
    }

    /// Like [`Core::sign_server_challenge`], but takes the identifiers as **raw
    /// bytes** (host/account_id/device_id/key_id) rather than UTF-8 strings. Needed for
    /// the server auth flow: the server issues `account_id`/`device_id` as random 16
    /// bytes (NOT UTF-8), and performs signing/verification of the challenge over raw bytes
    /// (`ids::unb64` → `ServerAuthChallenge::canonical`). The string variant
    /// would sign the string's UTF-8 bytes → mismatch. Returns the signature blob (NOT
    /// a secret); nonce/expiry checking is done by the server.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_server_challenge_raw(
        &self,
        host: Vec<u8>,
        account_id: Vec<u8>,
        device_id: Vec<u8>,
        key_id: Vec<u8>,
        nonce: Vec<u8>,
        expiry: u64,
    ) -> Result<Vec<u8>, FfiError> {
        self.with_state(|state| {
            let challenge = ServerAuthChallenge {
                host,
                account_id,
                device_id,
                key_id,
                nonce,
                expiry,
            };
            sign_server_challenge(&state.keyset, &challenge).map_err(map_keychain_err)
        })
    }

    /// Reads a vault's cache policy (server-tz §6.6). `vault_id` is hex (cloud).
    pub fn get_cache_policy(&self, vault_id: String) -> Result<FfiCachePolicy, FfiError> {
        let vid = decode_vid(&vault_id)?;
        self.with_state_mut(|state| {
            let rec = state
                .storage
                .get_vault(&vid)
                .map_err(FfiError::other)?
                .ok_or(FfiError::NotFound)?;
            Ok(FfiCachePolicy::from_core(rec.cache_policy))
        })
    }

    /// Changes a vault's cache policy (version+1, re-signs the record). `vault_id` is hex.
    pub fn set_cache_policy(
        &self,
        vault_id: String,
        policy: FfiCachePolicy,
    ) -> Result<(), FfiError> {
        let vid = decode_vid(&vault_id)?;
        self.with_state_mut(|state| {
            let mut vault =
                Vault::open(&state.storage, &state.keyset, &vid).map_err(map_vault_err)?;
            vault
                .set_cache_policy(policy.to_core())
                .map_err(map_vault_err)
        })
    }

    /// Appends a signed audit entry (server-tz §8): storage stores
    /// `(entry_blob, signature, author_pubkey)` as-is and assigns a monotonic
    /// seq. Signing/verification is done by a higher layer — the FFI carries opaque
    /// blobs. `vault_id`/`author_pubkey` are hex. (vault_id is not stored in storage-audit v1
    /// — it is an instance-level log; accepted for future vault-scoping.)
    pub fn audit_append(
        &self,
        vault_id: String,
        entry_blob: Vec<u8>,
        signature: Vec<u8>,
        author_pubkey: String,
    ) -> Result<u64, FfiError> {
        let _vid = decode_vid(&vault_id)?; // format validation (for the future)
        let author = hex::decode(author_pubkey.trim())
            .map_err(|_| FfiError::other("invalid hex author_pubkey"))?;
        self.with_state(|state| {
            state
                .storage
                .append_audit(&entry_blob, &signature, &author)
                .map_err(FfiError::other)
        })
    }

    /// Audit entries with `seq > since_seq` (server-tz §8, admin view). The blobs
    /// are opaque; seq is public metadata (NOT trusted for tamper-evidence in v1).
    pub fn audit_query(&self, since_seq: u64) -> Result<Vec<FfiAuditEntry>, FfiError> {
        self.with_state(|state| {
            Ok(state
                .storage
                .list_audit(since_seq)
                .map_err(FfiError::other)?
                .into_iter()
                .map(|e| FfiAuditEntry {
                    seq: e.seq,
                    entry_blob: e.entry_blob,
                    signature: e.signature,
                    author_pubkey_hex: hex::encode(&e.author_pubkey),
                    recorded_at: e.recorded_at,
                })
                .collect())
        })
    }

    /// **Onboarding Path A** (server-tz §9): a new device accepts an encrypted
    /// keyset blob "from the server", unwraps it with the password + Secret Key, persists
    /// the blob into the local sidecar (already encrypted — not a secret) and opens the
    /// instance DB. Does not require a pre-existing local keyset.
    ///
    /// Anti-rollback: the db key is derived from the unwrapped keyset → first
    /// `unlock_account` (AEAD authentication of the credentials and key derivation), then
    /// opening the DB, then raising the generation floor to the accepted record (TOFU on
    /// the first onboarding; the floor cannot be lowered). v1 honest gap: confidentiality
    /// is present, freshness relative to the server is at a higher layer.
    pub fn unlock_from_server_blob(
        &self,
        keyset_blob: Vec<u8>,
        password: Option<String>,
        secret_key_hex: String,
    ) -> Result<(), FfiError> {
        // One guard for the whole method (serialization + final state installation):
        // the Mutex is not reentrant; a second self.locked_state() here → deadlock.
        let mut guard = self.locked_state();
        let password = password.map(Zeroizing::new);
        let secret_key_hex = Zeroizing::new(secret_key_hex);
        let enc = EncryptedKeyset::from_bytes(&keyset_blob).map_err(FfiError::other)?;
        let sk_bytes = Zeroizing::new(
            hex::decode(secret_key_hex.trim()).map_err(|_| FfiError::InvalidCredentials)?,
        );
        let secret_key =
            SecretKey::from_slice(&sk_bytes).map_err(|_| FfiError::InvalidCredentials)?;

        // migrate-on-open: a legacy blob (before round 2) from an old device is opened
        // via a probe and immediately re-wrapped under the current scheme — the local sidecar
        // will hold a v3 record (`migrated`), and offline unlock will proceed without probing.
        let (unlocked, migrated) =
            unlock_account_migrating(&enc, password.as_deref().map(|s| s.as_bytes()), &secret_key)
                .map_err(map_keychain_err)?;

        // the db key is derived from the unwrapped keyset, so the floor (in storage-meta)
        // is available only AFTER unlock+open. The raw-crypto unwrap (AEAD verification
        // of the credentials) does not introduce the keyset into the system and has no side effects; accepting
        // the blob = persisting the sidecar + installing state BELOW, and both are cut off by
        // anti-rollback BEFORE them.
        let db_key = derive_db_key(&unlocked);
        let storage = Storage::open(&self.db_path, &db_key[..]).map_err(FfiError::other)?;

        // anti-rollback (server-tz §13.13b): we REJECT a stale generation BEFORE
        // accepting the blob. The previous version only raised the floor — a stale
        // keyset blob below the floor passed contrary to the docstring. The same logic as in
        // unlock_account_checked (which cannot be called earlier: storage is still closed).
        let floor = unissh_keychain::keyset_gen_floor(&storage)
            .map_err(map_keychain_err)?
            .unwrap_or(0);
        let attempted = enc.generation as u64;
        if attempted < floor {
            // Security event: an on-disk keyset older than the recorded floor — a
            // possible downgrade attack. Generations are counters, not secrets.
            log::warn!(
                "keyset generation rollback rejected (attempted={attempted}, floor={floor})"
            );
            return Err(map_keychain_err(
                unissh_keychain::KeychainError::GenerationRollback { attempted, floor },
            ));
        }

        // Persist the keyset blob into the local sidecar (atomically) so that offline unlock
        // works afterward. An already-encrypted blob is not a secret. If the blob was legacy,
        // a re-wrapped (v3, generation+1) record lands on disk. Persisting BEFORE raising
        // the floor — brick protection (see `unlock`). We raise the floor to the actual
        // (persisted) generation.
        let record_to_persist = migrated.as_ref().unwrap_or(&enc);
        let accepted_gen = record_to_persist.generation as u64;
        // Back up the existing sidecar only if the overwrite is a legacy-blob migration
        // (logs the path). We don't touch a normal server-blob acceptance.
        if migrated.is_some() {
            backup_keyset_sidecar(&self.keyset_path);
        }
        let enc_bytes = record_to_persist.to_bytes().map_err(FfiError::other)?;
        write_keyset_atomic(&self.keyset_path, &enc_bytes)?;
        if migrated.is_some() {
            log::info!(
                "keyset migrated to current scheme on server-blob unlock (generation {} -> {})",
                attempted,
                accepted_gen
            );
        }
        // Accepted: raise the floor to the accepted generation (TOFU; cannot lower).
        unissh_keychain::raise_keyset_gen_floor(&storage, accepted_gen)
            .map_err(map_keychain_err)?;

        *guard = Some(CoreState {
            storage,
            keyset: unlocked,
            agent: InMemoryAgent::new(),
            vault_names: HashMap::new(),
        });
        log::info!("instance unlocked from server keyset");
        Ok(())
    }

    /// Derives the escrow credentials the client uploads (enroll) or presents (fetch):
    /// the retrieval credential `K_auth` plus the Argon2id parameters (with a fresh salt)
    /// used to stretch the password.
    ///
    /// `secret_key_hex` is the account Secret Key (the same key held by all of the
    /// account's devices; the Core does not persist it). `password = None` selects a
    /// passwordless (SecretKeyOnly / SSO) account: `K_auth` is derived from the Secret
    /// Key alone and the server authorizes the fetch by the OIDC session instead.
    ///
    /// This is a **pure derivation** — nothing is stored. **Caller contract (enroll):**
    /// the returned `argon_*` parameters MUST be uploaded alongside the escrow block so a
    /// fresh device re-derives the identical `K_auth` from the same password. Each call
    /// generates FRESH recommended params + a fresh salt; the enroll flow must persist the
    /// escrow block and THESE params together (and ensure the wrapped keyset the device
    /// recovers is consistent with them). Fetch simply re-runs this with the stored salt.
    pub fn derive_escrow_credentials(
        &self,
        password: Option<String>,
        secret_key_hex: String,
    ) -> Result<EscrowCreds, FfiError> {
        let password = password.map(Zeroizing::new);
        let secret_key_hex = Zeroizing::new(secret_key_hex);
        let sk_bytes = Zeroizing::new(
            hex::decode(secret_key_hex.trim()).map_err(|_| FfiError::InvalidCredentials)?,
        );
        let secret_key =
            SecretKey::from_slice(&sk_bytes).map_err(|_| FfiError::InvalidCredentials)?;

        let params = KdfParams::recommended();
        // None → SecretKeyOnly account: K_auth is derived from the Secret Key alone.
        let argon_key = match password.as_deref() {
            Some(p) => Some(derive_key(p.as_bytes(), &params).map_err(FfiError::other)?),
            None => None,
        };
        let k_auth = derive_escrow_auth_key(argon_key.as_ref(), &secret_key);

        Ok(EscrowCreds {
            k_auth: k_auth.expose_bytes().to_vec(),
            argon_salt: params.salt.clone(),
            argon_mem_kib: params.mem_kib,
            argon_iterations: params.iterations,
            argon_parallelism: params.parallelism,
        })
    }

    /// Derives ONLY the escrow retrieval credential `K_auth` from EXPLICIT Argon2id
    /// parameters (salt + cost), instead of minting fresh ones. This is the fetch-side
    /// counterpart to [`Core::derive_escrow_credentials`]: a fresh device recovers the
    /// enrolled `argon_salt`/params via `GET /v1/escrow/params` and re-derives the SAME
    /// `K_auth` that enrollment uploaded. The server gates the fetch on
    /// `sha256(K_auth)`, so the enroll-time and fetch-time derivations MUST agree
    /// bit-for-bit. Both funnel through the identical `derive_key` + `derive_escrow_auth_key`
    /// primitives, so enroll (fresh params) and fetch (these params) are symmetric by
    /// construction — feed this the params `derive_escrow_credentials` returned and it
    /// reproduces that call's `k_auth` (see the `escrow_*_symmetry` tests).
    ///
    /// `password = None` selects a passwordless (SecretKeyOnly / SSO) account: the
    /// Argon2id stage is skipped and `K_auth` derives from the Secret Key alone (the
    /// `argon_*` inputs are then irrelevant), exactly as `derive_escrow_credentials`.
    ///
    /// A **pure derivation** — nothing is persisted and no unlocked state is required.
    pub fn derive_escrow_auth_with_params(
        &self,
        password: Option<String>,
        secret_key_hex: String,
        argon_salt: Vec<u8>,
        argon_mem_kib: u32,
        argon_iterations: u32,
        argon_parallelism: u32,
    ) -> Result<Vec<u8>, FfiError> {
        let password = password.map(Zeroizing::new);
        let secret_key_hex = Zeroizing::new(secret_key_hex);
        let sk_bytes = Zeroizing::new(
            hex::decode(secret_key_hex.trim()).map_err(|_| FfiError::InvalidCredentials)?,
        );
        let secret_key =
            SecretKey::from_slice(&sk_bytes).map_err(|_| FfiError::InvalidCredentials)?;

        // Bound the SERVER-PROVIDED Argon2id cost before running the KDF: the escrow
        // params come from an untrusted `GET /v1/escrow/params`, so a malicious server
        // could otherwise pin absurd mem/time/lanes and force a huge Argon2 allocation
        // (memory-exhaustion / DoS) on a recovering device. These ceilings sit far above
        // the recommended enroll params (64 MiB, t=3, p=1), so a genuine fetch is
        // unaffected; anything past them is a hostile response → reject.
        const MAX_ESCROW_MEM_KIB: u32 = 1024 * 1024; // 1 GiB
        const MAX_ESCROW_ITERATIONS: u32 = 10;
        const MAX_ESCROW_PARALLELISM: u32 = 4;
        if argon_mem_kib > MAX_ESCROW_MEM_KIB
            || argon_iterations > MAX_ESCROW_ITERATIONS
            || argon_parallelism > MAX_ESCROW_PARALLELISM
        {
            return Err(FfiError::other(
                "escrow Argon2id parameters exceed the allowed maximum",
            ));
        }

        let params = KdfParams {
            mem_kib: argon_mem_kib,
            iterations: argon_iterations,
            parallelism: argon_parallelism,
            salt: argon_salt,
        };
        // None → SecretKeyOnly account: K_auth is derived from the Secret Key alone
        // and the Argon2id params are unused (mirrors derive_escrow_credentials).
        let argon_key = match password.as_deref() {
            Some(p) => Some(derive_key(p.as_bytes(), &params).map_err(FfiError::other)?),
            None => None,
        };
        let k_auth = derive_escrow_auth_key(argon_key.as_ref(), &secret_key);
        Ok(k_auth.expose_bytes().to_vec())
    }

    /// **Onboarding Path B (initiator):** completes PAKE using the responder's `msg2`,
    /// verifies the confirmation and E2E-encrypts the keyset secrets + the **shared account
    /// Secret Key** (`secret_key_hex`) under the channel key. Returns `msg3`
    /// (the sealed keyset — a relay blob; sealed, not a plaintext secret). Requires
    /// an unlocked keyset. The handle is one-shot (a second call → Other).
    ///
    /// `secret_key_hex` is THIS device's Secret Key (read by the Tauri layer from the
    /// keychain; the Core does not hold the key in memory) so that all of the account's devices
    /// share a single key (the 1Password model).
    pub fn onboard_confirm_and_seal(
        &self,
        handle: Arc<OnboardInitiatorHandle>,
        msg2: Vec<u8>,
        secret_key_hex: String,
    ) -> Result<Vec<u8>, FfiError> {
        self.with_state(|state| {
            let secret_key_hex = Zeroizing::new(secret_key_hex);
            let sk_bytes = Zeroizing::new(
                hex::decode(secret_key_hex.trim()).map_err(|_| FfiError::InvalidCredentials)?,
            );
            let secret_key =
                SecretKey::from_slice(&sk_bytes).map_err(|_| FfiError::InvalidCredentials)?;
            let init = lock_recover(&handle.inner)
                .take()
                .ok_or_else(|| FfiError::other("onboard initiator step already consumed"))?;
            init.confirm_and_seal(&msg2, &state.keyset, &secret_key)
                .map_err(map_keychain_err)
        })
    }

    /// **Onboarding Path B (responder):** accepts `msg3`, verifies the confirmation,
    /// decrypts the payload (the keyset secrets + the **shared account Secret Key**) and
    /// creates its own device record under this shared key and the local
    /// `password`, persists the keyset sidecar and opens the instance DB. Returns
    /// the shared Secret Key (hex) so the Tauri layer can store it in the device keychain
    /// for future unlocks. Does not require any prior state. One-shot.
    pub fn onboard_finish_install(
        &self,
        handle: Arc<OnboardResponderHandle>,
        msg3: Vec<u8>,
        password: Option<String>,
    ) -> Result<String, FfiError> {
        // One guard for the whole method (the Mutex is not reentrant — see unlock_from_server_blob).
        let mut guard = self.locked_state();
        if self.keyset_path.exists() || self.db_path.exists() {
            return Err(FfiError::AlreadyExists);
        }
        let password = password.map(Zeroizing::new);
        let resp = lock_recover(&handle.inner)
            .take()
            .ok_or_else(|| FfiError::other("onboard responder step already consumed"))?;
        let (secret_key, enc, unlocked) = resp
            .finish_install(
                &msg3,
                password.as_deref().map(|s| s.as_bytes()),
                KdfParams::recommended(),
            )
            .map_err(map_keychain_err)?;

        let db_key = derive_db_key(&unlocked);
        let storage = Storage::open(&self.db_path, &db_key[..]).map_err(|e| {
            let _ = std::fs::remove_file(&self.db_path);
            FfiError::other(e)
        })?;
        let enc_bytes = enc.to_bytes().map_err(FfiError::other)?;
        // sealed keyset sidecar (O_EXCL): on failure — roll back the DB/sidecar.
        match open_keyset_file(&self.keyset_path, true) {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(&enc_bytes) {
                    drop(storage);
                    let _ = std::fs::remove_file(&self.keyset_path);
                    let _ = std::fs::remove_file(&self.db_path);
                    return Err(FfiError::other(e));
                }
            }
            Err(e) => {
                drop(storage);
                let _ = std::fs::remove_file(&self.db_path);
                return Err(FfiError::other(e));
            }
        }
        // anti-rollback floor: TOFU on the generation of the accepted keyset.
        unissh_keychain::raise_keyset_gen_floor(&storage, enc.generation as u64)
            .map_err(map_keychain_err)?;

        *guard = Some(CoreState {
            storage,
            keyset: unlocked,
            agent: InMemoryAgent::new(),
            vault_names: HashMap::new(),
        });
        // The SHARED account Secret Key (identical on all devices, model A):
        // we return hex so the Tauri layer can store it in THIS device's keychain
        // for future unlocks. We do NOT show it to the user — there is no new Emergency
        // Kit; they already have the account one. We zeroize the intermediate hex; the string
        // crossing the FFI boundary is beyond our control (an FFI limitation).
        let kit = Zeroizing::new(hex::encode(secret_key.expose_bytes()));
        Ok(kit.as_str().to_string())
    }

    /// **Runs a sync** against the foreign transport (server-tz §3.3): first a push
    /// of local objects, then pull + verify-before-apply of the delta. The transport
    /// is untrusted — every object is verified (signature/epoch-floor/authority)
    /// before being applied. Returns an aggregated report (no secrets). Requires unlock.
    ///
    /// `tenant_b64` is the base64 `tenant_id` of the server being synced (as in
    /// `ServerConfig.tenant_id`). **1:1 binding:** the push emits ONLY the cloud vaults
    /// bound to this tenant (see `sync_push`); local vaults and those bound to
    /// other servers are not sent. An empty `tenant_b64` → nothing is pushed.
    pub fn sync_now(
        &self,
        transport: Arc<dyn FfiSyncTransport>,
        tenant_b64: String,
    ) -> Result<FfiSyncReport, FfiError> {
        self.with_state_mut(|state| {
            let genesis_owner = state.keyset.signing.verifying.to_bytes().to_vec();
            let ctx = SyncContext {
                genesis_owner,
                tenant: tenant_b64.as_bytes().to_vec(),
            };
            let mut adapter = ForeignTransportAdapter {
                inner: transport,
                push_err: Mutex::new(None),
            };

            // push: if the callback threw — propagate its error (don't mask it as Format).
            let push =
                sync_push(&mut adapter, &state.storage, tenant_b64.as_bytes()).map_err(|e| {
                    if let Some(fe) = lock_recover(&adapter.push_err).take() {
                        fe
                    } else {
                        map_sync_err(e)
                    }
                })?;
            // pull
            let pull = sync_pull(&mut adapter, &state.storage, &ctx).map_err(map_sync_err)?;

            Ok(FfiSyncReport {
                applied: pull.applied,
                skipped_stale: pull.skipped_stale,
                conflicts: pull.conflicts.len() as u32,
                rejected: pull.rejected.len() as u32,
                pushed: push.pushed,
            })
        })
    }

    /// Resets the tenant's pull cursor → the next `sync_now` re-reads the ENTIRE
    /// server history (a full re-pull) rather than an increment from the last seq. Needed
    /// when objects were already processed under a PREVIOUS authority context and rejected
    /// (a reject advances the cursor), and the keyset later changed to the owner (re-attach):
    /// without a reset the owner will not re-read the vault they can now decrypt.
    /// `tenant_b64` is the same string passed to `sync_now` (the cursor key
    /// is built from its bytes). Requires unlock.
    pub fn reset_pull_cursor(&self, tenant_b64: String) -> Result<(), FfiError> {
        self.with_state(|state| {
            reset_pull_cursor(&state.storage, tenant_b64.as_bytes()).map_err(map_sync_err)
        })
    }

    /// Restores cloud vaults deleted LOCALLY (tombstoned) but still
    /// alive on the server. The local tombstone is newer (the version grew on deletion) →
    /// LWW prevents the pull from overwriting it with the server copy, and `list_vaults`
    /// hides it: the vault is "stuck deleted" on this device. We physically erase its
    /// local record (`purge_vault_data`) and reset the tenant's pull cursor →
    /// the next `sync_now` re-pulls the live server copy anew. Vaults deleted
    /// on the server too will become tombstones again after re-pull (they won't resurrect — which is correct).
    /// We touch only tombstoned vaults bound to THIS tenant or unbound
    /// (after unlinking); others are left untouched. Returns the number of records purged.
    /// Requires unlock.
    pub fn restore_deleted_cloud_vaults(&self, tenant_b64: String) -> Result<u32, FfiError> {
        self.with_state_mut(|state| {
            let tenant = tenant_b64.as_bytes();
            let mut restored = 0u32;
            for v in state
                .storage
                .list_tombstoned_cloud_vaults()
                .map_err(FfiError::other)?
            {
                if !v.sync_tenant.is_empty() && v.sync_tenant != tenant {
                    continue; // bound to ANOTHER server — not ours, don't touch
                }
                state
                    .storage
                    .purge_vault_data(&v.vault_id)
                    .map_err(FfiError::other)?;
                state.vault_names.remove(&v.vault_id);
                restored += 1;
            }
            if restored > 0 {
                reset_pull_cursor(&state.storage, tenant).map_err(map_sync_err)?;
            }
            Ok(restored)
        })
    }

    /// Renames a vault.
    pub fn rename_vault(&self, vault_id: String, new_name: String) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            // Resolve once: the name cache is keyed by the RAW vault id (the storage
            // key), so for a cloud vault we must insert under the decoded UUID bytes,
            // not the hex string — otherwise list_vaults reads a stale name.
            let vid = resolve_vid(&state.storage, &vault_id);
            let mut vault =
                Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
            vault
                .set_name(new_name.as_bytes())
                .map_err(FfiError::other)?;
            state.vault_names.insert(vid, new_name);
            Ok(())
        })
    }

    /// Deletes a vault (tombstone). It disappears from the list.
    pub fn delete_vault(&self, vault_id: String) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let vid = resolve_vid(&state.storage, &vault_id);
            let vault =
                Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
            vault.delete().map_err(FfiError::other)?;
            state.vault_names.remove(vid.as_slice());
            Ok(())
        })
    }

    /// Deletes an item (tombstone) and, if it was an SSH key in the agent, unloads it.
    pub fn delete_item(&self, vault_id: String, item_id: String) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .delete_item(item_id.as_bytes())
                .map_err(FfiError::other)?;
            // A4a namespace: the agent stores the key under agent_key_id(vault_id,item_id), not
            // under the bare item_id — it must be unloaded with the same key, otherwise remove is a no-op and
            // a revoked/rotated private key stays alive in the agent until the end of the session.
            state.agent.remove(&agent_key_id(&vault_id, &item_id));
            Ok(())
        })
    }

    /// Saves/updates a server password as a vault item (type "password").
    /// The content is the UTF-8 bytes of the password; encryption/signing/versioning is the vault layer.
    /// (Password input from the UI is allowed — that is where it originates; the way back is only via
    /// the explicit [`Core::get_password`].)
    pub fn save_password(
        &self,
        vault_id: String,
        item_id: String,
        password: String,
    ) -> Result<(), FfiError> {
        // The password goes into Zeroizing immediately — zeroized on exit.
        let password = Zeroizing::new(password);
        self.with_state_mut(|state| {
            ensure_item_type(
                &state.storage,
                &vault_id,
                item_id.as_bytes(),
                ITEM_TYPE_PASSWORD,
            )?;
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .put_item_keep_history(item_id.as_bytes(), ITEM_TYPE_PASSWORD, password.as_bytes())
                .map_err(FfiError::other)?;
            Ok(())
        })
    }

    /// Returns a server password (reveal: display/copy in the UI on an explicit
    /// user action). Works **only** for an item of type "password" —
    /// a private key or any other item cannot be obtained through this call; the invariant
    /// "plaintext keys never cross the FFI" is preserved.
    ///
    /// ⚠️ The returned `String` crosses the FFI boundary and on the other side is not
    /// zeroized — the UI is responsible for a minimal lifetime (display/clipboard).
    pub fn get_password(&self, vault_id: String, item_id: String) -> Result<String, FfiError> {
        self.with_state_mut(|state| {
            let password = read_password_item(state, &vault_id, &item_id)?;
            Ok(password.as_str().to_string())
        })
    }

    /// Saves/updates an encrypted note as a vault item (type "note").
    /// The content is arbitrary UTF-8 (recovery codes, IPMI credentials, etc.).
    /// Encryption/signing/versioning is the vault layer; input from the UI is allowed, the way back is
    /// only via the explicit [`Core::get_note`].
    pub fn save_note(
        &self,
        vault_id: String,
        item_id: String,
        text: String,
    ) -> Result<(), FfiError> {
        let text = Zeroizing::new(text);
        self.with_state_mut(|state| {
            ensure_item_type(
                &state.storage,
                &vault_id,
                item_id.as_bytes(),
                ITEM_TYPE_NOTE,
            )?;
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .put_item_keep_history(item_id.as_bytes(), ITEM_TYPE_NOTE, text.as_bytes())
                .map_err(FfiError::other)?;
            Ok(())
        })
    }

    /// Returns a note's text (reveal for the UI). Works **only** for an item of type
    /// "note" — a key/password/other item cannot be obtained through this call.
    ///
    /// ⚠️ The returned `String` crosses the FFI boundary and is not zeroized there — the UI
    /// is responsible for its lifetime.
    pub fn get_note(&self, vault_id: String, item_id: String) -> Result<String, FfiError> {
        self.with_state_mut(|state| {
            let text = read_utf8_item(state, &vault_id, &item_id, ITEM_TYPE_NOTE, "a note")?;
            Ok(text.as_str().to_string())
        })
    }

    /// Item versions available for reveal: the current one + archived ones (the secret's history).
    /// Returns only the version numbers — it reveals no secrets.
    pub fn list_item_versions(
        &self,
        vault_id: String,
        item_id: String,
    ) -> Result<Vec<u64>, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .list_item_versions(item_id.as_bytes())
                .map_err(FfiError::other)
        })
    }

    /// Reveal of a specific password version from history (type-gated to "password").
    pub fn get_password_version(
        &self,
        vault_id: String,
        item_id: String,
        version: u64,
    ) -> Result<String, FfiError> {
        self.read_item_version(
            &vault_id,
            &item_id,
            version,
            ITEM_TYPE_PASSWORD,
            "a password",
        )
    }

    /// Reveal of a specific note version from history (type-gated to "note").
    pub fn get_note_version(
        &self,
        vault_id: String,
        item_id: String,
        version: u64,
    ) -> Result<String, FfiError> {
        self.read_item_version(&vault_id, &item_id, version, ITEM_TYPE_NOTE, "a note")
    }

    /// List of pinned host keys (for the known_hosts screen).
    pub fn list_known_hosts(&self) -> Result<Vec<KnownHostInfo>, FfiError> {
        self.with_state_mut(|state| {
            Ok(state
                .storage
                .list_known_hosts()
                .map_err(FfiError::other)?
                .into_iter()
                .map(|h| KnownHostInfo {
                    host: h.host,
                    port: h.port,
                    key: String::from_utf8_lossy(&h.host_key).to_string(),
                    added_at: h.added_at,
                })
                .collect())
        })
    }

    /// "Forget" a pinned host key. Returns whether there was a record.
    pub fn forget_host(&self, host: String, port: u16) -> Result<bool, FfiError> {
        self.with_state_mut(|state| {
            state
                .storage
                .remove_known_host(&host, port)
                .map_err(FfiError::other)
        })
    }

    /// Deliberately trust a NEW host key after [`FfiError::HostKeyMismatch`]:
    /// connects directly (handshake only), compares the presented key with
    /// the user-confirmed `expected_fingerprint` (from the mismatch error) and
    /// re-pins it only on a match. Returns the SHA256 fingerprint.
    /// Requires an unlock.
    ///
    /// If the key was swapped again between the warning and the consent,
    /// `HostKeyMismatch` is returned with the actual fingerprint (no pinning happens).
    /// Direct hosts only (no ProxyJump): for jump targets — `forget_host` +
    /// a normal reconnection (TOFU again).
    pub fn trust_host(
        &self,
        host: String,
        port: u16,
        expected_fingerprint: String,
    ) -> Result<String, FfiError> {
        self.with_state(|state| {
            self.rt
                .block_on(trust_host_key(
                    &host,
                    port,
                    &state.storage,
                    &expected_fingerprint,
                ))
                .map_err(|e| match e {
                    unissh_ssh_transport::TransportError::FingerprintMismatch { got, .. } => {
                        FfiError::HostKeyMismatch {
                            host: host.clone(),
                            port,
                            fingerprint: got,
                        }
                    }
                    other => map_transport_err(other),
                })
        })
    }

    /// Changes the instance master password (re-wraps the keyset under a new Unlock Key).
    /// Requires the old credentials (`old_password` + `secret_key_hex`) — this verifies
    /// their correctness and rules out a "brick". `new_password = None` → passwordless
    /// mode (SecretKeyOnly). May be called while locked (works
    /// with the on-disk keyset record).
    ///
    /// Only the keyset **wrapper** changes: the Secret Key, the keyset secrets and the DB key
    /// do not change, so the current unlocked session (if any) stays
    /// valid. This is a re-wrap, NOT a key rotation (VK rotation is ⏳ LATER).
    pub fn change_password(
        &self,
        old_password: Option<String>,
        new_password: Option<String>,
        secret_key_hex: String,
    ) -> Result<(), FfiError> {
        // Hold the state lock for the entire read-compute-write of the keyset record:
        // it serializes against a concurrent unlock/second change_password (TOCTOU).
        let mut guard = self.locked_state();
        let old_password = old_password.map(Zeroizing::new);
        let new_password = new_password.map(Zeroizing::new);
        let secret_key_hex = Zeroizing::new(secret_key_hex);

        let enc_bytes = std::fs::read(&self.keyset_path).map_err(|_| FfiError::NotFound)?;
        let enc = EncryptedKeyset::from_bytes(&enc_bytes).map_err(FfiError::other)?;
        let sk_bytes = Zeroizing::new(
            hex::decode(secret_key_hex.trim()).map_err(|_| FfiError::InvalidCredentials)?,
        );
        let secret_key =
            SecretKey::from_slice(&sk_bytes).map_err(|_| FfiError::InvalidCredentials)?;

        let new_enc = change_password(
            &enc,
            old_password.as_deref().map(|s| s.as_bytes()),
            new_password.as_deref().map(|s| s.as_bytes()),
            &secret_key,
            KdfParams::recommended(),
        )
        .map_err(|e| match e {
            unissh_keychain::KeychainError::InvalidCredentials
            | unissh_keychain::KeychainError::PasswordRequired => FfiError::InvalidCredentials,
            other => FfiError::other(other),
        })?;

        let new_bytes = new_enc.to_bytes().map_err(FfiError::other)?;
        write_keyset_atomic(&self.keyset_path, &new_bytes)?;

        // anti-rollback (server-tz §13.13b): raise the trusted generation floor to
        // the new generation, otherwise the old (lowered) keyset blob would again pass
        // unlock_account_checked / unlock_from_server_blob after a password change. The floor
        // lives in the instance's storage-meta: if the vault is already unlocked — use its
        // open storage; otherwise open the DB (the db key is invariant to the re-wrap —
        // the keyset secrets don't change — so we derive it from old-enc, whose credentials
        // change_password just verified).
        if let Some(state) = guard.as_mut() {
            unissh_keychain::raise_floor_after_change_password(&state.storage, &new_enc)
                .map_err(map_keychain_err)?;
        } else {
            let unlocked = unlock_account(
                &enc,
                old_password.as_deref().map(|s| s.as_bytes()),
                &secret_key,
            )
            .map_err(map_keychain_err)?;
            let db_key = derive_db_key(&unlocked);
            let storage = Storage::open(&self.db_path, &db_key[..]).map_err(FfiError::other)?;
            unissh_keychain::raise_floor_after_change_password(&storage, &new_enc)
                .map_err(map_keychain_err)?;
        }
        Ok(())
    }

    /// List of vaults. Names come from the cache; for uncached vaults —
    /// a single VK unwrap (HPKE) with caching.
    pub fn list_vaults(&self) -> Result<Vec<VaultInfo>, FfiError> {
        self.with_state_mut(|state| {
            let mut out = Vec::new();
            for record in state.storage.list_vaults().map_err(FfiError::other)? {
                let name = match state.vault_names.get(&record.vault_id) {
                    Some(n) => n.clone(),
                    None => {
                        let vault = Vault::open(&state.storage, &state.keyset, &record.vault_id)
                            .map_err(FfiError::other)?;
                        let name = String::from_utf8_lossy(vault.name()).to_string();
                        state
                            .vault_names
                            .insert(record.vault_id.clone(), name.clone());
                        name
                    }
                };
                // A cloud vault_id is a UUIDv4 (raw 16 bytes, not UTF-8): we return it as hex
                // so it matches the return of `create_cloud_vault` and is accepted by
                // the cloud methods (`decode_vid` expects hex). A local vault_id is a meaningful
                // UTF-8 string (round-trips via `as_bytes`), returned as-is.
                let vault_id = match record.sync_target {
                    SyncTarget::Cloud => hex::encode(&record.vault_id),
                    _ => String::from_utf8_lossy(&record.vault_id).to_string(),
                };
                // sync_tenant is stored as the bytes of the base64 tenant_id string (an opaque
                // routing label). Empty = not bound → None. Otherwise we return the same
                // base64 string back so the UI can match the vault to its associated server.
                let sync_tenant = if record.sync_tenant.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&record.sync_tenant).to_string())
                };
                out.push(VaultInfo {
                    vault_id,
                    name,
                    sync_target: FfiSyncTarget::from_core(record.sync_target),
                    sync_tenant,
                });
            }
            Ok(out)
        })
    }

    /// Generates an Ed25519 SSH key **in the core**, stores the private key encrypted in
    /// the vault and returns the **public** key (OpenSSH). The private key is not handed out.
    pub fn generate_ssh_key(&self, vault_id: String, item_id: String) -> Result<String, FfiError> {
        self.with_state_mut(|state| {
            let (private_pem, public) = generate_ed25519_openssh().map_err(FfiError::ssh)?;
            ensure_item_type(
                &state.storage,
                &vault_id,
                item_id.as_bytes(),
                ITEM_TYPE_SSH_KEY,
            )?;
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .put_item(
                    item_id.as_bytes(),
                    ITEM_TYPE_SSH_KEY,
                    private_pem.as_bytes(),
                )
                .map_err(FfiError::other)?;
            // The key material was replaced under the same id → unload the previous private key from
            // the agent (namespaced), otherwise connects in this session will keep signing
            // with the OLD key (load_key_into_agent short-circuits on agent.contains).
            state.agent.remove(&agent_key_id(&vault_id, &item_id));
            Ok(public)
        })
    }

    /// Imports an existing OpenSSH private key into the vault. Returns the public
    /// key. (Private-key input from the UI is allowed; it is not handed back.)
    pub fn import_ssh_key(
        &self,
        vault_id: String,
        item_id: String,
        openssh_private: String,
        passphrase: Option<String>,
    ) -> Result<String, FfiError> {
        // We keep the private key and password in Zeroizing — zeroized on exit.
        let openssh_private = Zeroizing::new(openssh_private);
        let passphrase = passphrase.map(Zeroizing::new);
        self.with_state_mut(|state| {
            // We accept not only the OpenSSH container but also classic PEM
            // (PKCS#1 `BEGIN RSA PRIVATE KEY`, SEC1 `BEGIN EC PRIVATE KEY`,
            // PKCS#8 `BEGIN PRIVATE KEY`, including password-encrypted ones): we normalize to
            // a canonical OpenSSH private key. Without a password for an encrypted key
            // an `Encrypted` error is returned — the UI will prompt for a password and retry.
            let normalized = unissh_ssh_agent::normalize_private_key_with_passphrase(
                &openssh_private,
                passphrase.as_deref().map(|p| p.as_str()),
            )
            .map_err(FfiError::ssh)?;
            // validate and extract the public key via a temporary agent
            let mut tmp = InMemoryAgent::new();
            tmp.add_from_openssh(b"tmp".to_vec(), normalized.as_bytes())
                .map_err(FfiError::ssh)?;
            let public = tmp
                .public_key(b"tmp")
                .ok_or_else(|| FfiError::ssh("no public key"))?
                .to_openssh()
                .map_err(FfiError::ssh)?;
            ensure_item_type(
                &state.storage,
                &vault_id,
                item_id.as_bytes(),
                ITEM_TYPE_SSH_KEY,
            )?;
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .put_item(item_id.as_bytes(), ITEM_TYPE_SSH_KEY, normalized.as_bytes())
                .map_err(FfiError::other)?;
            // The key material was replaced under the same id → unload the previous private key from
            // the agent (namespaced), otherwise connects in this session will keep signing
            // with the OLD key (load_key_into_agent short-circuits on agent.contains).
            state.agent.remove(&agent_key_id(&vault_id, &item_id));
            Ok(public)
        })
    }

    /// Attaches an OpenSSH user certificate to the key `key_item_id` (stored as
    /// the item `<key_item_id>.cert`). At connect time authentication will use the
    /// certificate (the agent does the signing, the private key never leaves the core).
    pub fn import_ssh_certificate(
        &self,
        vault_id: String,
        key_item_id: String,
        cert_openssh: String,
    ) -> Result<(), FfiError> {
        // validate the certificate
        unissh_ssh_agent::ssh_key::Certificate::from_openssh(cert_openssh.trim())
            .map_err(|_| FfiError::ssh("invalid certificate"))?;
        self.with_state_mut(|state| {
            let cert_id = cert_item_id(&key_item_id);
            ensure_item_type(
                &state.storage,
                &vault_id,
                cert_id.as_bytes(),
                ITEM_TYPE_SSH_CERT,
            )?;
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .put_item(
                    cert_id.as_bytes(),
                    ITEM_TYPE_SSH_CERT,
                    cert_openssh.as_bytes(),
                )
                .map_err(FfiError::other)?;
            Ok(())
        })
    }

    /// Returns the **public** key (OpenSSH) and its SHA256 fingerprint for
    /// an existing key item — so the UI can show/copy it into
    /// `authorized_keys`. The private key is not handed out.
    pub fn get_public_key(
        &self,
        vault_id: String,
        item_id: String,
    ) -> Result<PublicKeyInfo, FfiError> {
        self.with_state_mut(|state| {
            let item = {
                let vault = Vault::open(
                    &state.storage,
                    &state.keyset,
                    &resolve_vid(&state.storage, &vault_id),
                )
                .map_err(FfiError::other)?;
                vault
                    .get_item(item_id.as_bytes())
                    .map_err(FfiError::other)?
                    .ok_or(FfiError::NotFound)?
            };
            if item.item_type != ITEM_TYPE_SSH_KEY {
                return Err(FfiError::other("item is not an SSH key"));
            }
            // Extract the public key via a temporary agent (the private key is in a Zeroizing
            // DecryptedItem; the temporary agent is dropped on exit).
            let mut tmp = InMemoryAgent::new();
            tmp.add_from_item(b"x".to_vec(), &item)
                .map_err(FfiError::ssh)?;
            let pubkey = tmp
                .public_key(b"x")
                .ok_or_else(|| FfiError::ssh("no public key"))?;
            let openssh = pubkey.to_openssh().map_err(FfiError::ssh)?;
            let fingerprint = pubkey
                .fingerprint(unissh_ssh_agent::ssh_key::HashAlg::Sha256)
                .to_string();
            Ok(PublicKeyInfo {
                openssh,
                fingerprint,
            })
        })
    }

    /// ⚠️ Exports an item's **private** OpenSSH key out (backup/migration).
    /// By default the private key is not handed out of the core; this is an explicit, user-
    /// requested export of their own data. The returned string crosses
    /// the FFI boundary and is not zeroized — the UI is responsible for its fate (warn,
    /// don't log, write to a file, not to the shared clipboard by default).
    pub fn export_ssh_key(&self, vault_id: String, item_id: String) -> Result<String, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            let item = vault
                .get_item(item_id.as_bytes())
                .map_err(FfiError::other)?
                .ok_or(FfiError::NotFound)?;
            if item.item_type != ITEM_TYPE_SSH_KEY {
                return Err(FfiError::other("item is not an SSH key"));
            }
            String::from_utf8(item.content.to_vec())
                .map_err(|_| FfiError::other("key is not valid UTF-8"))
        })
    }

    /// Rotates an SSH key **on the same item id**: generates a new Ed25519 pair and
    /// overwrites the private key under the same identifier, so all hosts that
    /// reference this item automatically start using the new key —
    /// without "replacing it everywhere". Returns the **new public** key (which must be
    /// installed on the servers). An attached certificate (if any) no longer matches
    /// the key after rotation — the UI should warn about reinstalling it.
    pub fn rotate_ssh_key(&self, vault_id: String, item_id: String) -> Result<String, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            // The key must exist and be an SSH key — you can't "rotate" nothing.
            let existing = vault
                .get_item(item_id.as_bytes())
                .map_err(FfiError::other)?
                .ok_or(FfiError::NotFound)?;
            if existing.item_type != ITEM_TYPE_SSH_KEY {
                return Err(FfiError::other("item is not an SSH key"));
            }
            let (private_pem, public) = generate_ed25519_openssh().map_err(FfiError::ssh)?;
            vault
                .put_item(
                    item_id.as_bytes(),
                    ITEM_TYPE_SSH_KEY,
                    private_pem.as_bytes(),
                )
                .map_err(FfiError::other)?;
            // The attached certificate no longer matches the new pair — remove it,
            // otherwise `load_key_into_agent` would re-attach the mismatched cert on the
            // next connect and cert authentication would silently break.
            let cert = cert_item_id(&item_id);
            if vault
                .get_item(cert.as_bytes())
                .map_err(FfiError::other)?
                .is_some()
            {
                vault
                    .delete_item(cert.as_bytes())
                    .map_err(FfiError::other)?;
            }
            // Unload the old key from the in-memory agent (like delete_item/rename_item),
            // otherwise connects in this session would keep using the previous pair, since
            // `load_key_into_agent` short-circuits on `agent.contains()`.
            // A4a namespace: the agent stores the key under agent_key_id(vault_id,item_id), not
            // under the bare item_id — it must be unloaded with the same key, otherwise remove is a no-op and
            // a revoked/rotated private key stays alive in the agent until the end of the session.
            state.agent.remove(&agent_key_id(&vault_id, &item_id));
            Ok(public)
        })
    }

    /// Renames (moves) an item to a new id. Transfers the attached
    /// certificate (`<key>.cert`) and unloads the old key from the agent.
    pub fn rename_item(
        &self,
        vault_id: String,
        item_id: String,
        new_item_id: String,
    ) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .rename_item(item_id.as_bytes(), new_item_id.as_bytes())
                .map_err(map_vault_err)?;
            // Transfer the certificate if it was attached to the old id.
            let old_cert = cert_item_id(&item_id);
            if vault
                .get_item(old_cert.as_bytes())
                .map_err(FfiError::other)?
                .is_some()
            {
                vault
                    .rename_item(old_cert.as_bytes(), cert_item_id(&new_item_id).as_bytes())
                    .map_err(map_vault_err)?;
            }
            // A4a namespace: the agent stores the key under agent_key_id(vault_id,item_id), not
            // under the bare item_id — it must be unloaded with the same key, otherwise remove is a no-op and
            // a revoked/rotated private key stays alive in the agent until the end of the session.
            state.agent.remove(&agent_key_id(&vault_id, &item_id));
            Ok(())
        })
    }

    /// List of a vault's items.
    pub fn list_items(&self, vault_id: String) -> Result<Vec<ItemInfo>, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            let metas = vault.list_items().map_err(FfiError::other)?;
            // The set of all ids — to cheaply (without decryption) determine whether a
            // key has an attached certificate (`<key>.cert`).
            let ids: std::collections::HashSet<&[u8]> =
                metas.iter().map(|m| m.item_id.as_slice()).collect();
            Ok(metas
                .iter()
                .map(|m| {
                    let item_id = String::from_utf8_lossy(&m.item_id).to_string();
                    let has_certificate = m.item_type == ITEM_TYPE_SSH_KEY
                        && ids.contains(cert_item_id(&item_id).as_bytes());
                    ItemInfo {
                        item_id,
                        item_type: m.item_type,
                        version: m.version,
                        created_at: m.created_at,
                        updated_at: m.updated_at,
                        has_certificate,
                    }
                })
                .collect())
        })
    }

    /// Connects over SSH (optionally through a ProxyJump chain) and runs
    /// a command. Keys are loaded from the vault into the agent; they are not handed out.
    #[allow(clippy::too_many_arguments)]
    pub fn ssh_exec(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        command: String,
        jumps: Vec<JumpHost>,
    ) -> Result<SshExecResult, FfiError> {
        // Connect + authentication — under the Core lock (agent+storage are needed). Then
        // we release the lock and run the command without it.
        let client = self.connect_session(&auth, &jumps, host, port, user)?;
        let output = self
            .rt
            .block_on(client.exec(&command))
            .map_err(FfiError::ssh)?;
        let _ = self.rt.block_on(client.disconnect());

        Ok(SshExecResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_status: output.exit_status.map(|c| c as i32).unwrap_or(-1),
        })
    }

    /// Streaming exec (no PTY): stdout/stderr are streamed to `observer` separately,
    /// the exit code via `on_exit`. Returns a handle for stdin/closing/polling
    /// for completion. The Core lock is held only for the duration of the connect.
    #[allow(clippy::too_many_arguments)]
    pub fn ssh_exec_stream(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        command: String,
        jumps: Vec<JumpHost>,
        observer: Arc<dyn ExecObserver>,
    ) -> Result<Arc<ExecHandleFfi>, FfiError> {
        let client = self.connect_session(&auth, &jumps, host, port, user)?;
        let sink: Arc<dyn unissh_ssh_transport::ExecSink> = Arc::new(ExecSinkBridge(observer));
        let handle = self
            .rt
            .block_on(client.exec_stream(&command, sink))
            .map_err(FfiError::ssh)?;
        Ok(Arc::new(ExecHandleFfi {
            _client: Mutex::new(client),
            handle,
            rt: self.rt.clone(),
        }))
    }

    /// Sets the SSH keepalive interval (seconds) for subsequent connections;
    /// `0` — off. A global setting (does not require an unlock): it affects
    /// all new sessions, tunnels and broadcasts. It does not affect already-open ones.
    pub fn set_keepalive_secs(&self, secs: u64) {
        unissh_ssh_transport::set_keepalive_secs(secs);
    }

    /// Opens an interactive PTY session. Terminal output is streamed to
    /// `observer` (a callback). Returns a session object for input/resize/close.
    /// The Core lock is held only for the connect, not for the duration of the session.
    #[allow(clippy::too_many_arguments)]
    pub fn open_session(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        term: String,
        cols: u32,
        rows: u32,
        observer: Arc<dyn SessionObserver>,
    ) -> Result<Arc<SshSession>, FfiError> {
        check_term_size(cols, rows)?;
        let client = self.connect_session(&auth, &jumps, host, port, user)?;

        let sink: Arc<dyn OutputSink> = Arc::new(ObserverSink(observer));
        let shell = self
            .rt
            .block_on(client.open_shell(&term, cols, rows, sink))
            .map_err(FfiError::ssh)?;

        Ok(Arc::new(SshSession {
            _client: Mutex::new(client),
            shell,
            rt: self.rt.clone(),
        }))
    }

    /// Opens an interactive PTY session with auto-reconnect: on a drop (a `write`
    /// error) or on `reconnect()` the session is re-established up to `max_retries`
    /// times with linear backoff (`backoff_ms`). Credentials are re-resolved from the vault on
    /// each attempt; `HostKeyMismatch` is not reconnected. The initial connect also
    /// uses retries; the error after exhausting attempts is returned.
    #[allow(clippy::too_many_arguments)]
    pub fn open_reconnecting_session(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        term: String,
        cols: u32,
        rows: u32,
        max_retries: u32,
        backoff_ms: u32,
        observer: Arc<dyn SessionObserver>,
    ) -> Result<Arc<ReconnectingSession>, FfiError> {
        check_term_size(cols, rows)?;
        let session = Arc::new(ReconnectingSession {
            state: self.state.clone(),
            rt: self.rt.clone(),
            host,
            port,
            user,
            auth,
            jumps,
            term,
            cols,
            rows,
            max_retries,
            backoff_ms,
            observer,
            current: Mutex::new(None),
            reconnect_lock: Mutex::new(()),
        });
        session.connect_with_retry()?;
        Ok(session)
    }

    /// Runs a single command on multiple hosts. Connects happen sequentially
    /// (under the Core lock), execution is concurrent. An error on one host does not fail
    /// the others: it is placed in the `error` of the corresponding result.
    ///
    /// `max_concurrency` limits the number of commands executing at once
    /// (0 = no limit). `timeout_secs` is the per-host deadline for command execution
    /// (0 = no timeout); on expiry the result is marked `timed_out`, the host
    /// is disconnected, and the rest continue. Protects the fleet from resource exhaustion and
    /// from hung hosts.
    pub fn ssh_exec_multi(
        &self,
        targets: Vec<MultiExecTarget>,
        command: String,
        max_concurrency: u32,
        timeout_secs: u32,
    ) -> Result<Vec<MultiExecResult>, FfiError> {
        if !self.is_unlocked() {
            return Err(FfiError::Locked);
        }

        // Connect phase (under the lock, sequential).
        let mut connected: Vec<(String, SshClient)> = Vec::new();
        let mut results: Vec<MultiExecResult> = Vec::new();
        for t in &targets {
            match self.connect_session(&t.auth, &t.jumps, t.host.clone(), t.port, t.user.clone()) {
                Ok(client) => connected.push((t.host.clone(), client)),
                Err(e) => results.push(MultiExecResult {
                    host: t.host.clone(),
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_status: -1,
                    error: Some(e.to_string()),
                    duration_ms: 0,
                    timed_out: false,
                }),
            }
        }

        // Execution phase (concurrent, with an optional limit and timeout).
        let timeout_dur =
            (timeout_secs > 0).then(|| tokio::time::Duration::from_secs(timeout_secs as u64));
        let sem = (max_concurrency > 0)
            .then(|| Arc::new(tokio::sync::Semaphore::new(max_concurrency as usize)));
        let exec_results = self.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for (host, client) in connected {
                let cmd = command.clone();
                let sem = sem.clone();
                set.spawn(async move {
                    // Hold the permit for the whole exec → no more than max_concurrency
                    // commands at once (acquire_owned doesn't fail: the semaphore is not
                    // closed).
                    let _permit = match &sem {
                        Some(s) => Some(s.clone().acquire_owned().await.expect("semaphore open")),
                        None => None,
                    };
                    let started = std::time::Instant::now();
                    // None → the command did not fit within the timeout.
                    let outcome = match timeout_dur {
                        Some(d) => tokio::time::timeout(d, client.exec(&cmd)).await.ok(),
                        None => Some(client.exec(&cmd).await),
                    };
                    let elapsed = started.elapsed().as_millis() as u64;
                    let _ = client.disconnect().await;
                    (host, outcome, elapsed)
                });
            }
            let mut out = Vec::new();
            while let Some(joined) = set.join_next().await {
                if let Ok(triple) = joined {
                    out.push(triple);
                }
            }
            out
        });

        for (host, outcome, duration_ms) in exec_results {
            match outcome {
                Some(Ok(o)) => results.push(MultiExecResult {
                    host,
                    stdout: String::from_utf8_lossy(&o.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&o.stderr).to_string(),
                    exit_status: o.exit_status.map(|c| c as i32).unwrap_or(-1),
                    error: None,
                    duration_ms,
                    timed_out: false,
                }),
                Some(Err(e)) => results.push(MultiExecResult {
                    host,
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_status: -1,
                    error: Some(e.to_string()),
                    duration_ms,
                    timed_out: false,
                }),
                None => results.push(MultiExecResult {
                    host,
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_status: -1,
                    error: Some(format!("command timed out after {timeout_secs}s")),
                    duration_ms,
                    timed_out: true,
                }),
            }
        }
        Ok(results)
    }

    /// Builds multi-exec targets from the vault's profiles whose tags match the query
    /// (`match_all`: all query tags ⊆ the profile's tags; otherwise an intersection). An empty
    /// query → an empty result. This is target selection, not RBAC.
    ///
    /// `PromptPassword` is excluded (there is no known password in advance — otherwise
    /// a batch run would make a live connect with an empty password). `Personal`
    /// is resolved per-host (binding + anti-redirect): a bound one is included with
    /// the resolved user+auth, an unbound/redirected one is silently skipped
    /// (connect individually). An empty password never goes into the batch.
    pub fn select_targets_by_tags(
        &self,
        vault_id: String,
        tags: Vec<String>,
        match_all: bool,
    ) -> Result<Vec<MultiExecTarget>, FfiError> {
        let profiles = self.list_connections(vault_id.clone())?;
        let mut out = Vec::new();
        for p in profiles
            .into_iter()
            .filter(|p| tags_match(&p.tags, &tags, match_all))
        {
            match &p.auth {
                ProfileAuth::PromptPassword => {}
                ProfileAuth::Personal => {
                    let dest = self.personal_destination(
                        p.host.clone(),
                        p.port,
                        p.username_template.clone(),
                        p.jumps.clone(),
                    );
                    if let Ok(pa) = self.resolve_personal_auth(
                        vault_id.clone(),
                        p.uid.clone(),
                        dest,
                        p.user.clone(),
                    ) {
                        let user =
                            self.apply_username_template(pa.user, p.username_template.clone());
                        out.push(MultiExecTarget {
                            host: p.host,
                            port: p.port,
                            user,
                            auth: pa.auth,
                            jumps: p.jumps,
                        });
                    }
                }
                _ => out.push(profile_to_target(&vault_id, p)),
            }
        }
        Ok(out)
    }

    /// Runs a command on all profiles with matching tags (see
    /// [`Core::select_targets_by_tags`] and [`Core::ssh_exec_multi`]).
    #[allow(clippy::too_many_arguments)]
    pub fn ssh_exec_by_tags(
        &self,
        vault_id: String,
        tags: Vec<String>,
        match_all: bool,
        command: String,
        max_concurrency: u32,
        timeout_secs: u32,
    ) -> Result<Vec<MultiExecResult>, FfiError> {
        let targets = self.select_targets_by_tags(vault_id, tags, match_all)?;
        self.ssh_exec_multi(targets, command, max_concurrency, timeout_secs)
    }

    /// Lays out a single blob (`data`) to `remote_path` on multiple hosts via
    /// SFTP. `make_parent_dirs` — try to create the parent directory (an "already
    /// exists" error is swallowed). Connects are sequential (under the Core
    /// lock), the write is concurrent with `max_concurrency`/per-host `timeout_secs`.
    /// An error on one host does not fail the others — it is in the `error` of its result.
    #[allow(clippy::too_many_arguments)]
    pub fn sftp_put_multi(
        &self,
        targets: Vec<MultiExecTarget>,
        remote_path: String,
        data: Vec<u8>,
        make_parent_dirs: bool,
        max_concurrency: u32,
        timeout_secs: u32,
    ) -> Result<Vec<SftpPutResult>, FfiError> {
        if !self.is_unlocked() {
            return Err(FfiError::Locked);
        }
        let mut connected: Vec<(String, SshClient)> = Vec::new();
        let mut results: Vec<SftpPutResult> = Vec::new();
        for t in &targets {
            match self.connect_session(&t.auth, &t.jumps, t.host.clone(), t.port, t.user.clone()) {
                Ok(client) => connected.push((t.host.clone(), client)),
                Err(e) => results.push(SftpPutResult {
                    host: t.host.clone(),
                    error: Some(e.to_string()),
                }),
            }
        }

        let data = Arc::new(data);
        let remote_path = Arc::new(remote_path);
        let timeout_dur =
            (timeout_secs > 0).then(|| tokio::time::Duration::from_secs(timeout_secs as u64));
        let sem = (max_concurrency > 0)
            .then(|| Arc::new(tokio::sync::Semaphore::new(max_concurrency as usize)));
        let put_results = self.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for (host, client) in connected {
                let data = data.clone();
                let path = remote_path.clone();
                let sem = sem.clone();
                set.spawn(async move {
                    let _permit = match &sem {
                        Some(s) => Some(s.clone().acquire_owned().await.expect("semaphore open")),
                        None => None,
                    };
                    // The whole put (open_sftp+mkdir+write) is under a single timeout.
                    let res = match timeout_dur {
                        Some(d) => {
                            match tokio::time::timeout(
                                d,
                                sftp_put_one(&client, &path, &data, make_parent_dirs),
                            )
                            .await
                            {
                                Ok(r) => r,
                                Err(_) => Err("sftp put timed out".to_string()),
                            }
                        }
                        None => sftp_put_one(&client, &path, &data, make_parent_dirs).await,
                    };
                    let _ = client.disconnect().await;
                    (host, res)
                });
            }
            let mut out = Vec::new();
            while let Some(joined) = set.join_next().await {
                if let Ok(pair) = joined {
                    out.push(pair);
                }
            }
            out
        });
        for (host, res) in put_results {
            results.push(SftpPutResult {
                host,
                error: res.err(),
            });
        }
        Ok(results)
    }

    /// Opens a broadcast (cluster-ssh): a PTY session per host; shared input
    /// is fanned out to all. Each host's output goes to `observer` with its index.
    /// A host that failed to connect/open a shell is reflected in `statuses()` but does not
    /// fail the others. The Core lock is held only for the connect phase.
    pub fn open_broadcast(
        &self,
        targets: Vec<MultiExecTarget>,
        term: String,
        cols: u32,
        rows: u32,
        observer: Arc<dyn BroadcastObserver>,
    ) -> Result<Arc<BroadcastSession>, FfiError> {
        check_term_size(cols, rows)?;
        let mut sessions: Vec<(SshClient, ShellHandle)> = Vec::new();
        let mut statuses: Vec<BroadcastHostStatus> = Vec::new();
        for (i, t) in targets.iter().enumerate() {
            let index = i as u32;
            match self.connect_session(&t.auth, &t.jumps, t.host.clone(), t.port, t.user.clone()) {
                Ok(client) => {
                    let sink: Arc<dyn OutputSink> = Arc::new(TaggedSink {
                        observer: observer.clone(),
                        index,
                    });
                    match self.rt.block_on(client.open_shell(&term, cols, rows, sink)) {
                        Ok(shell) => {
                            sessions.push((client, shell));
                            statuses.push(BroadcastHostStatus {
                                host: t.host.clone(),
                                index,
                                connected: true,
                                error: None,
                            });
                        }
                        Err(e) => {
                            let _ = self.rt.block_on(client.disconnect());
                            statuses.push(BroadcastHostStatus {
                                host: t.host.clone(),
                                index,
                                connected: false,
                                error: Some(e.to_string()),
                            });
                        }
                    }
                }
                Err(e) => statuses.push(BroadcastHostStatus {
                    host: t.host.clone(),
                    index,
                    connected: false,
                    error: Some(e.to_string()),
                }),
            }
        }
        Ok(Arc::new(BroadcastSession {
            inner: Mutex::new(sessions),
            statuses,
            rt: self.rt.clone(),
        }))
    }

    // --- host groups ---

    /// Saves/updates a host group (an item of type "group"). Only references to
    /// profiles/groups; no secrets inside. Rejects self-membership, self-
    /// parenthood and an empty `group_id`; `ensure_item_type` guards against cross-type
    /// overwriting.
    pub fn save_group(&self, vault_id: String, group: ServerGroup) -> Result<(), FfiError> {
        if group.group_id.is_empty() {
            return Err(FfiError::other("group_id must not be empty"));
        }
        if group.member_ids.contains(&group.group_id) {
            return Err(FfiError::other("a group cannot be a member of itself"));
        }
        if group.parent_id.as_deref() == Some(group.group_id.as_str()) {
            return Err(FfiError::other("a group cannot be its own parent"));
        }
        self.with_state_mut(|state| {
            ensure_item_type(
                &state.storage,
                &vault_id,
                group.group_id.as_bytes(),
                ITEM_TYPE_GROUP,
            )?;
            let stored = StoredGroup {
                label: group.label,
                member_ids: group.member_ids,
                parent_id: group.parent_id,
                color: None,
            };
            let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .put_item(group.group_id.as_bytes(), ITEM_TYPE_GROUP, &json)
                .map_err(FfiError::other)?;
            Ok(())
        })
    }

    /// List of a vault's groups (broken JSON is skipped, tombstones are not visible).
    pub fn list_groups(&self, vault_id: String) -> Result<Vec<ServerGroup>, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            let mut out = Vec::new();
            for m in vault.list_items().map_err(FfiError::other)? {
                if m.item_type != ITEM_TYPE_GROUP {
                    continue;
                }
                if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
                    if let Ok(stored) = serde_json::from_slice::<StoredGroup>(&item.content) {
                        out.push(group_to_public(
                            String::from_utf8_lossy(&m.item_id).to_string(),
                            stored,
                        ));
                    }
                }
            }
            Ok(out)
        })
    }

    /// Returns a single group.
    pub fn get_group(&self, vault_id: String, group_id: String) -> Result<ServerGroup, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            let item = vault
                .get_item(group_id.as_bytes())
                .map_err(FfiError::other)?
                .filter(|i| i.item_type == ITEM_TYPE_GROUP)
                .ok_or(FfiError::NotFound)?;
            let stored: StoredGroup =
                serde_json::from_slice(&item.content).map_err(FfiError::other)?;
            Ok(group_to_public(group_id, stored))
        })
    }

    /// Deletes a group (tombstone). Dangling `parent_id`/`member_id` references to it
    /// in other groups remain and are ignored during resolution.
    pub fn delete_group(&self, vault_id: String, group_id: String) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .delete_item(group_id.as_bytes())
                .map_err(map_vault_err)?;
            Ok(())
        })
    }

    /// A dry run: expands the group (recursively, with cycle protection) into
    /// a target plan WITHOUT connecting, loading keys into the agent or decrypting passwords.
    /// For a preview before a destructive bulk command.
    pub fn dry_run_group(
        &self,
        vault_id: String,
        group_id: String,
    ) -> Result<Vec<GroupTargetPlan>, FfiError> {
        Ok(self.resolve_group(&vault_id, &group_id)?.1)
    }

    /// Runs a command on all hosts in the group (nested groups are expanded).
    /// Members that don't resolve (a dangling reference, a cycle, `PromptPassword`) go into
    /// the result as an `error` rather than being silently lost.
    pub fn ssh_exec_group(
        &self,
        vault_id: String,
        group_id: String,
        command: String,
        max_concurrency: u32,
        timeout_secs: u32,
    ) -> Result<Vec<MultiExecResult>, FfiError> {
        let (targets, plans) = self.resolve_group(&vault_id, &group_id)?;
        let mut results = self.ssh_exec_multi(targets, command, max_concurrency, timeout_secs)?;
        for plan in plans.iter().filter(|p| p.status != ResolveStatus::Ok) {
            let msg = match plan.status {
                ResolveStatus::Dangling => "unresolved member (no such profile/group)",
                ResolveStatus::CycleSkipped => "skipped: group cycle or depth limit",
                ResolveStatus::PromptPassword => {
                    "password prompt required; connect this host individually"
                }
                ResolveStatus::Personal => {
                    "personal-identity host; connect individually (fan-out identity \
                     resolution not yet supported)"
                }
                ResolveStatus::Ok => continue,
            };
            results.push(MultiExecResult {
                host: plan.member_id.clone(),
                stdout: String::new(),
                stderr: String::new(),
                exit_status: -1,
                error: Some(msg.to_string()),
                duration_ms: 0,
                timed_out: false,
            });
        }
        Ok(results)
    }

    // --- integrity audit ---

    /// Read-only vault integrity audit: re-verifies the signatures of the vault record and
    /// of all items (including tombstones) and checks the author against the owner. Catches
    /// blob corruption and author spoofing. The report contains no secrets/plaintext.
    pub fn verify_vault_integrity(
        &self,
        vault_id: String,
    ) -> Result<VaultIntegrityReport, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            let report = vault.verify_chain().map_err(FfiError::other)?;
            Ok(integrity_report_to_ffi(report))
        })
    }

    /// Structural check of the instance DB: `integrity_check` + orphans + domain
    /// invariants. Read-only, a report with no secrets.
    pub fn check_consistency(&self) -> Result<DbConsistencyReport, FfiError> {
        self.with_state_mut(|state| {
            let report = state.storage.check_consistency().map_err(FfiError::other)?;
            Ok(DbConsistencyReport {
                ok: report.ok,
                integrity_ok: report.integrity_ok,
                issues: report
                    .issues
                    .into_iter()
                    .map(|i| DbConsistencyIssue {
                        kind: match i.kind {
                            unissh_storage::ConsistencyKind::OrphanItem => {
                                DbConsistencyKind::OrphanItem
                            }
                            unissh_storage::ConsistencyKind::BadVersion => {
                                DbConsistencyKind::BadVersion
                            }
                            unissh_storage::ConsistencyKind::BadAuthorLen => {
                                DbConsistencyKind::BadAuthorLen
                            }
                            unissh_storage::ConsistencyKind::BadSignatureLen => {
                                DbConsistencyKind::BadSignatureLen
                            }
                            unissh_storage::ConsistencyKind::TombstoneNotEmpty => {
                                DbConsistencyKind::TombstoneNotEmpty
                            }
                            unissh_storage::ConsistencyKind::StaleHistory => {
                                DbConsistencyKind::StaleHistory
                            }
                        },
                        vault_id_hex: i.vault_id_hex,
                        item_id_hex: i.item_id_hex,
                        detail: i.detail,
                    })
                    .collect(),
            })
        })
    }

    // --- port forwarding (tunnels) ---

    /// Local forward: listens on `local_bind` (e.g. `127.0.0.1:0`) and
    /// tunnels to `remote_host:remote_port` from the server side. The tunnel lives
    /// as long as the returned object lives (or until `close`).
    #[allow(clippy::too_many_arguments)]
    pub fn open_local_forward(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        local_bind: String,
        remote_host: String,
        remote_port: u16,
    ) -> Result<Arc<SshTunnel>, FfiError> {
        let client = self.connect_session(&auth, &jumps, host, port, user)?;
        let guard = self
            .rt
            .block_on(client.local_forward(&local_bind, &remote_host, remote_port))
            .map_err(map_transport_err)?;
        let bind_addr = guard.local_addr().to_string();
        Ok(Arc::new(SshTunnel {
            client: Mutex::new(Some(client)),
            guard: Mutex::new(Some(guard)),
            rt: self.rt.clone(),
            bind_addr,
        }))
    }

    /// Dynamic forward (SOCKS5) on `local_bind`. **The address must be
    /// loopback** (SOCKS5 without authentication). The tunnel lives until `close`.
    #[allow(clippy::too_many_arguments)]
    pub fn open_dynamic_forward(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        local_bind: String,
    ) -> Result<Arc<SshTunnel>, FfiError> {
        let client = self.connect_session(&auth, &jumps, host, port, user)?;
        let guard = self
            .rt
            .block_on(client.dynamic_forward(&local_bind))
            .map_err(map_transport_err)?;
        let bind_addr = guard.local_addr().to_string();
        Ok(Arc::new(SshTunnel {
            client: Mutex::new(Some(client)),
            guard: Mutex::new(Some(guard)),
            rt: self.rt.clone(),
            bind_addr,
        }))
    }

    /// Remote forward: the server listens on `remote_bind:remote_port` and delivers
    /// incoming connections to the local `local_host:local_port`. `bind_address` returns
    /// `remote_bind:<actual port>`. The tunnel lives until `close`.
    #[allow(clippy::too_many_arguments)]
    pub fn open_remote_forward(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        remote_bind: String,
        remote_port: u16,
        local_host: String,
        local_port: u16,
    ) -> Result<Arc<SshTunnel>, FfiError> {
        let client = self.connect_session(&auth, &jumps, host, port, user)?;
        let assigned = self
            .rt
            .block_on(client.remote_forward(&remote_bind, remote_port, &local_host, local_port))
            .map_err(map_transport_err)?;
        Ok(Arc::new(SshTunnel {
            client: Mutex::new(Some(client)),
            guard: Mutex::new(None),
            rt: self.rt.clone(),
            bind_addr: format!("{remote_bind}:{assigned}"),
        }))
    }

    // --- SFTP ---

    /// Opens an SFTP session to a host (optionally through ProxyJump). The session lives as
    /// long as the returned object lives (or until `close`).
    #[allow(clippy::too_many_arguments)]
    /// `parallelism` — how many SFTP channels to keep over a single connection for
    /// parallel transfers (K from settings). Clamped to [1, 16]; 1 = the previous strictly
    /// sequential behavior. The first channel opens immediately, the rest —
    /// lazily on demand (see [`SftpFfi`]).
    pub fn open_sftp(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        parallelism: u32,
    ) -> Result<Arc<SftpFfi>, FfiError> {
        let client = self.connect_session(&auth, &jumps, host.clone(), port, user.clone())?;
        let sftp = self
            .rt
            .block_on(client.open_sftp())
            .map_err(map_transport_err)?;
        let max = (parallelism.clamp(1, 16)) as usize;
        Ok(Arc::new(SftpFfi {
            client: Mutex::new(Some(client)),
            pool: Mutex::new(SftpPool {
                idle: vec![sftp],
                created: 1,
                max,
                generation: 0,
                closed: false,
            }),
            pool_cv: Condvar::new(),
            rt: self.rt.clone(),
            state: self.state.clone(),
            host,
            port,
            user,
            auth,
            jumps,
            reconnect_lock: Mutex::new(()),
        }))
    }

    // --- connection profiles ("hosts") ---

    /// Saves/updates a connection profile (stored as an encrypted item
    /// of type "connection" in the vault). The secret itself is not embedded in the profile: for
    /// password authentication only a reference to the password item is stored; a jump host
    /// with an inline password (`AuthMethod::Password`) cannot be saved — an error.
    pub fn save_connection(
        &self,
        vault_id: String,
        profile: ConnectionProfile,
    ) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let ConnectionProfile {
                profile_id,
                uid,
                label,
                host,
                port,
                user,
                auth,
                username_template,
                jumps,
                tags,
            } = profile;
            if profile_id.is_empty() {
                return Err(FfiError::other("profile_id must not be empty"));
            }
            // Empty uid = creating a new profile → mint an immutable id. A non-empty one
            // (an edit: the UI returned the uid from get_connection) is kept as-is — the uid does not
            // change when host/label change.
            let uid = if uid.is_empty() {
                mint_profile_uid()
            } else {
                uid
            };
            let (key_item_id, password_item_id, personal) = match auth {
                ProfileAuth::Key { key_item_id } => (Some(key_item_id), None, false),
                ProfileAuth::VaultPassword { password_item_id } => {
                    (None, Some(password_item_id), false)
                }
                ProfileAuth::PromptPassword => (None, None, false),
                ProfileAuth::Personal => (None, None, true),
            };
            let mut stored = StoredProfile {
                uid: Some(uid),
                label,
                host,
                port,
                user,
                key_item_id,
                password_item_id,
                personal,
                username_template,
                jumps: jumps
                    .into_iter()
                    .map(jump_to_stored)
                    .collect::<Result<_, _>>()?,
                tags,
                extra: BTreeMap::new(),
            };
            ensure_item_type(
                &state.storage,
                &vault_id,
                profile_id.as_bytes(),
                ITEM_TYPE_CONNECTION,
            )?;
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            // Forward-compat: carry over the unknown fields of the existing profile.
            stored.extra = preserved_extra::<StoredProfile>(
                &vault,
                profile_id.as_bytes(),
                ITEM_TYPE_CONNECTION,
                |sp| sp.extra,
            );
            let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
            vault
                .put_item(profile_id.as_bytes(), ITEM_TYPE_CONNECTION, &json)
                .map_err(FfiError::other)?;
            Ok(())
        })
    }

    /// List of connection profiles in a vault.
    pub fn list_connections(&self, vault_id: String) -> Result<Vec<ConnectionProfile>, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            let mut out = Vec::new();
            for m in vault.list_items().map_err(FfiError::other)? {
                if m.item_type != ITEM_TYPE_CONNECTION {
                    continue;
                }
                if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
                    if let Ok(stored) = serde_json::from_slice::<StoredProfile>(&item.content) {
                        out.push(stored_to_profile(
                            &vault_id,
                            String::from_utf8_lossy(&m.item_id).to_string(),
                            stored,
                        ));
                    }
                }
            }
            Ok(out)
        })
    }

    /// Returns a single connection profile.
    pub fn get_connection(
        &self,
        vault_id: String,
        profile_id: String,
    ) -> Result<ConnectionProfile, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            let item = vault
                .get_item(profile_id.as_bytes())
                .map_err(FfiError::other)?
                .filter(|i| i.item_type == ITEM_TYPE_CONNECTION)
                .ok_or(FfiError::NotFound)?;
            let stored: StoredProfile =
                serde_json::from_slice(&item.content).map_err(FfiError::other)?;
            Ok(stored_to_profile(&vault_id, profile_id, stored))
        })
    }

    /// Deletes a connection profile.
    pub fn delete_connection(&self, vault_id: String, profile_id: String) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .delete_item(profile_id.as_bytes())
                .map_err(map_vault_err)?;
            Ok(())
        })
    }

    // ---------- identities (personal SSH creds) ----------

    /// Saves (creates or updates) a personal identity. Into the item content
    /// only `StoredIdentity` is written (username + references to a key/password item),
    /// the secret itself is not embedded. `identity_id` is the item_id in the vault.
    pub fn save_identity(&self, vault_id: String, identity: Identity) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
        let Identity {
            identity_id,
            label,
            user,
            key_item_id,
            password_item_id,
        } = identity;
        if identity_id.is_empty() {
            return Err(FfiError::other("identity_id must not be empty"));
        }
        // Privacy invariant (moved here from set_personal_vault): an identity must live
        // in a PRIVATE (single-member) vault — otherwise it syncs to a shared vault's
        // other members (leaked private cred). Refuse a shared/multi-member vault.
        let vid = resolve_vid(&state.storage, &vault_id);
        let owner_ed = state.keyset.signing.verifying.to_bytes().to_vec();
        let members = match state
            .storage
            .latest_membership_epoch(&vid)
            .map_err(FfiError::other)?
        {
            Some(latest) => verify_chain_to_epoch(&state.storage, &vid, latest, &owner_ed)
                .map_err(map_vault_err)?
                .members()
                .len(),
            None => 0, // local / not-yet-shared vault → single-member
        };
        if members > 1 {
            return Err(FfiError::other(
                "cannot store an identity in a shared (multi-member) vault — it would leak to the other members",
            ));
        }
        let mut stored = StoredIdentity {
            label,
            user,
            key_item_id,
            password_item_id,
            extra: BTreeMap::new(),
        };
        ensure_item_type(
            &state.storage,
            &vault_id,
            identity_id.as_bytes(),
            ITEM_TYPE_IDENTITY,
        )?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        stored.extra = preserved_extra::<StoredIdentity>(
            &vault,
            identity_id.as_bytes(),
            ITEM_TYPE_IDENTITY,
            |si| si.extra,
        );
        let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
        vault
            .put_item(identity_id.as_bytes(), ITEM_TYPE_IDENTITY, &json)
            .map_err(FfiError::other)?;
        Ok(())
        })
    }

    /// Returns a single identity by id.
    pub fn get_identity(
        &self,
        vault_id: String,
        identity_id: String,
    ) -> Result<Identity, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            let item = vault
                .get_item(identity_id.as_bytes())
                .map_err(FfiError::other)?
                .filter(|i| i.item_type == ITEM_TYPE_IDENTITY)
                .ok_or(FfiError::NotFound)?;
            let stored: StoredIdentity =
                serde_json::from_slice(&item.content).map_err(FfiError::other)?;
            Ok(stored.into_identity(identity_id))
        })
    }

    /// List of personal identities in a vault.
    pub fn list_identities(&self, vault_id: String) -> Result<Vec<Identity>, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            let mut out = Vec::new();
            for m in vault.list_items().map_err(FfiError::other)? {
                if m.item_type != ITEM_TYPE_IDENTITY {
                    continue;
                }
                if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
                    if let Ok(stored) = serde_json::from_slice::<StoredIdentity>(&item.content) {
                        out.push(
                            stored.into_identity(String::from_utf8_lossy(&m.item_id).to_string()),
                        );
                    }
                }
            }
            Ok(out)
        })
    }

    /// Deletes a personal identity.
    pub fn delete_identity(&self, vault_id: String, identity_id: String) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .delete_item(identity_id.as_bytes())
                .map_err(map_vault_err)?;
            Ok(())
        })
    }

    // ---------- identity bindings (personal vault ↔ shared host) ----------

    /// Creates/updates a binding of an identity to a shared host in the PERSONAL vault.
    /// The item_id is derived from (team_vault_id, profile_uid) → one binding per
    /// pair. `destination_pin` is set by the caller (the rendered host:port at
    /// bind time) — this is the anti-redirect anchor.
    ///
    /// First-bind guard: if a binding already exists with a DIFFERENT pinned
    /// destination, re-pinning requires an explicit `allow_rebind=true` — we do not silently
    /// rebind to a changed host (anti-redirect at bind time). The first
    /// binding and an idempotent re-pin (the same destination, e.g. changing only
    /// the identity) do not require the flag.
    pub fn set_binding(
        &self,
        personal_vault_id: String,
        binding: IdentityBinding,
        allow_rebind: bool,
    ) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let IdentityBinding {
                team_vault_id,
                profile_uid,
                identity_item_id,
                destination_pin,
            } = binding;
            if team_vault_id.is_empty() || profile_uid.is_empty() {
                return Err(FfiError::other(
                    "binding requires non-empty team_vault_id and profile_uid",
                ));
            }
            let item_id = binding_item_id(&team_vault_id, &profile_uid);
            ensure_item_type(
                &state.storage,
                &personal_vault_id,
                item_id.as_bytes(),
                ITEM_TYPE_BINDING,
            )?;
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &personal_vault_id),
            )
            .map_err(FfiError::other)?;
            // First-bind guard: we do not silently rebind to a changed destination.
            if !allow_rebind {
                if let Some(existing) = vault
                    .get_item(item_id.as_bytes())
                    .map_err(FfiError::other)?
                    .filter(|i| i.item_type == ITEM_TYPE_BINDING)
                    .and_then(|i| serde_json::from_slice::<StoredBinding>(&i.content).ok())
                {
                    if existing.destination_pin != destination_pin {
                        return Err(FfiError::other(format!(
                            "binding already pinned to {}; re-bind to {} requires \
                         explicit confirmation (allow_rebind)",
                            existing.destination_pin, destination_pin
                        )));
                    }
                }
            }
            let mut stored = StoredBinding {
                team_vault_id,
                profile_uid,
                identity_item_id,
                destination_pin,
                extra: BTreeMap::new(),
            };
            // Forward-compat: carry over the unknown fields of the existing binding.
            stored.extra = preserved_extra::<StoredBinding>(
                &vault,
                item_id.as_bytes(),
                ITEM_TYPE_BINDING,
                |sb| sb.extra,
            );
            let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
            vault
                .put_item(item_id.as_bytes(), ITEM_TYPE_BINDING, &json)
                .map_err(FfiError::other)?;
            Ok(())
        })
    }

    /// Returns the binding for (team_vault_id, profile_uid), if any.
    pub fn get_binding(
        &self,
        personal_vault_id: String,
        team_vault_id: String,
        profile_uid: String,
    ) -> Result<Option<IdentityBinding>, FfiError> {
        self.with_state_mut(|state| {
            let item_id = binding_item_id(&team_vault_id, &profile_uid);
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &personal_vault_id),
            )
            .map_err(FfiError::other)?;
            let Some(item) = vault
                .get_item(item_id.as_bytes())
                .map_err(FfiError::other)?
                .filter(|i| i.item_type == ITEM_TYPE_BINDING)
            else {
                return Ok(None);
            };
            let stored: StoredBinding =
                serde_json::from_slice(&item.content).map_err(FfiError::other)?;
            Ok(Some(stored.into_binding()))
        })
    }

    /// List of all bindings in the personal vault.
    pub fn list_bindings(
        &self,
        personal_vault_id: String,
    ) -> Result<Vec<IdentityBinding>, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &personal_vault_id),
            )
            .map_err(FfiError::other)?;
            let mut out = Vec::new();
            for m in vault.list_items().map_err(FfiError::other)? {
                if m.item_type != ITEM_TYPE_BINDING {
                    continue;
                }
                if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
                    if let Ok(stored) = serde_json::from_slice::<StoredBinding>(&item.content) {
                        out.push(stored.into_binding());
                    }
                }
            }
            Ok(out)
        })
    }

    /// Deletes the binding for (team_vault_id, profile_uid).
    pub fn delete_binding(
        &self,
        personal_vault_id: String,
        team_vault_id: String,
        profile_uid: String,
    ) -> Result<(), FfiError> {
        self.with_state_mut(|state| {
            let item_id = binding_item_id(&team_vault_id, &profile_uid);
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &personal_vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .delete_item(item_id.as_bytes())
                .map_err(map_vault_err)?;
            Ok(())
        })
    }

    /// Resolves a binding for connecting to a shared host with an anti-redirect check:
    /// compares `current_destination` (the host:port rendered by the client at this
    /// moment) with the one pinned in the binding. `Redirected` means the shared host
    /// was re-pointed after binding — the client shows re-bind and does NOT send the personal
    /// credential. `Matched` → log in with the identity `identity_item_id`. Strict
    /// in-core protection at connect time is finished by Personal-auth (B4).
    pub fn resolve_host_binding(
        &self,
        personal_vault_id: String,
        team_vault_id: String,
        profile_uid: String,
        current_destination: String,
    ) -> Result<BindingResolution, FfiError> {
        let binding = self.get_binding(personal_vault_id, team_vault_id, profile_uid)?;
        Ok(resolve_binding(binding.as_ref(), &current_destination))
    }

    /// Finds WHICH of the account's private vaults holds the binding for the host
    /// `(team_vault_id, profile_uid)` — by the binding item's deterministic id. This is
    /// a metadata check (`item_type`/`tombstone` are public, WITHOUT decryption): the first
    /// vault where such a binding item is alive holds the binding + the identity (co-location).
    /// This way different hosts can log in with identities from DIFFERENT private vaults
    /// (per-context) without a single "personal vault". Returns the vault's display id (hex
    /// for cloud, UTF-8 for local — like `list_vaults`).
    fn find_binding_vault(
        &self,
        team_vault_id: &str,
        profile_uid: &str,
    ) -> Result<Option<String>, FfiError> {
        let item_id = binding_item_id(team_vault_id, profile_uid);
        self.with_state(|state| {
            for rec in state.storage.list_vaults().map_err(FfiError::other)? {
                if let Some(item) = state
                    .storage
                    .get_item(&rec.vault_id, item_id.as_bytes())
                    .map_err(FfiError::other)?
                {
                    if item.item_type == ITEM_TYPE_BINDING && !item.tombstone {
                        return Ok(Some(match rec.sync_target {
                            SyncTarget::Cloud => hex::encode(&rec.vault_id),
                            _ => String::from_utf8_lossy(&rec.vault_id).to_string(),
                        }));
                    }
                }
            }
            Ok(None)
        })
    }

    /// Resolves Personal authentication for connecting to a shared host (B4):
    /// finds the vault holding the binding (co-location, [`Self::find_binding_vault`]), resolves by
    /// (`team_vault_id`, `profile_uid`) and CHECKS anti-redirect against
    /// `current_destination`. The personal credential is unwrapped ONLY if the destination
    /// matched the pinned one — on `Redirected` an error is returned, and the client
    /// does NOT send the credential to the re-pointed host (in-core enforcement). On `Unbound` —
    /// an error "an identity must be linked". Assembles a vault-qualified
    /// [`AuthMethod`] from the personal identity + a username (identity → profile
    /// fallback → account-default).
    ///
    /// Note: the method does not hold the lock itself — it calls the public getters
    /// sequentially (otherwise a re-acquisition of the `Mutex` would be a deadlock).
    pub fn resolve_personal_auth(
        &self,
        team_vault_id: String,
        profile_uid: String,
        current_destination: String,
        profile_user_fallback: String,
    ) -> Result<PersonalAuth, FfiError> {
        // Co-location: the binding lives in the SAME private vault as the identity it
        // points to. Search the account's vaults for this host's binding (a metadata
        // check — no decryption), then read binding/identity/creds from that vault.
        // This is what lets different hosts use identities from different private vaults
        // (per-context) — there is no single "personal vault" anymore.
        let vault = self
            .find_binding_vault(&team_vault_id, &profile_uid)?
            .ok_or_else(|| {
                FfiError::other("host is not bound to a personal identity; bind one first")
            })?;
        let binding = self.get_binding(vault.clone(), team_vault_id, profile_uid)?;
        match resolve_binding(binding.as_ref(), &current_destination) {
            BindingResolution::Unbound => Err(FfiError::other(
                "host is not bound to a personal identity; bind one first",
            )),
            BindingResolution::Redirected { pinned, current } => Err(FfiError::other(format!(
                "destination changed since binding (pinned {pinned}, now {current}); \
                 re-bind required before using the personal credential",
            ))),
            BindingResolution::Matched { identity_item_id } => {
                let identity = self.get_identity(vault.clone(), identity_item_id)?;
                let auth = if let Some(key_item_id) = identity.key_item_id.filter(|s| !s.is_empty())
                {
                    AuthMethod::Agent {
                        vault_id: vault,
                        key_item_id,
                    }
                } else if let Some(password_item_id) =
                    identity.password_item_id.filter(|s| !s.is_empty())
                {
                    AuthMethod::VaultPassword {
                        vault_id: vault,
                        password_item_id,
                    }
                } else {
                    return Err(FfiError::other(
                        "bound identity has neither a key nor a password",
                    ));
                };
                let account_default = self.get_account_default_username()?;
                let user = pick_username(
                    &identity.user,
                    &profile_user_fallback,
                    account_default.as_deref(),
                );
                Ok(PersonalAuth { user, auth })
            }
        }
    }

    /// Canonical destination for anti-redirect (the bind pin AND the connect check).
    /// The template is part of the destination → editing it = changing the destination.
    /// The client renders with this both `destination_pin` in [`Core::set_binding`] and
    /// `current_destination` in [`Core::resolve_personal_auth`] — the formats match.
    pub fn personal_destination(
        &self,
        host: String,
        port: u16,
        username_template: Option<String>,
        jumps: Vec<JumpHost>,
    ) -> String {
        personal_destination(&host, port, username_template.as_deref(), &jumps)
    }

    /// The final connect username per the template (`%u` → base_user), or
    /// just `base_user` without a template. The client applies it to
    /// [`PersonalAuth::user`] using the same `username_template` as the pin.
    pub fn apply_username_template(
        &self,
        base_user: String,
        username_template: Option<String>,
    ) -> String {
        apply_username_template(&base_user, username_template.as_deref())
    }

    /// Imports `~/.ssh/config`: for each concrete `Host` alias it creates
    /// a connection profile with an empty `key_item_id` (the core does not read files). The keys
    /// specified in `IdentityFile` are read and imported by the UI layer: it pulls in
    /// the private key via [`Core::import_ssh_key`] and attaches it to the profile
    /// with a second [`Core::save_connection`]. Returns the ids of the created profiles.
    pub fn import_ssh_config(
        &self,
        vault_id: String,
        config_text: String,
    ) -> Result<Vec<String>, FfiError> {
        let cfg = SshConfig::parse(&config_text).map_err(FfiError::other)?;
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            let mut created = Vec::new();
            for alias in cfg.host_aliases() {
                // Don't overwrite an existing item of another type (e.g. a key with the same id):
                // we skip such an alias, not counting it among the created ones.
                if ensure_item_type(
                    &state.storage,
                    &vault_id,
                    alias.as_bytes(),
                    ITEM_TYPE_CONNECTION,
                )
                .is_err()
                {
                    continue;
                }
                // #9: overwriting an existing profile MUST preserve its
                // immutable uid — personal bindings and hop_refs depend on it
                // (B2.1/B2.2); a fresh uid would orphan them. We reuse the existing
                // profile's uid, otherwise we mint a new one.
                let existing_uid = vault
                    .get_item(alias.as_bytes())
                    .ok()
                    .flatten()
                    .and_then(|it| serde_json::from_slice::<StoredProfile>(&it.content).ok())
                    .and_then(|sp| sp.uid)
                    .filter(|u| !u.is_empty());
                let s = cfg.resolve(&alias);
                let stored = StoredProfile {
                    uid: Some(existing_uid.unwrap_or_else(mint_profile_uid)),
                    label: alias.clone(),
                    host: s.hostname.unwrap_or_else(|| alias.clone()),
                    port: s.port.unwrap_or(22),
                    user: s.user.unwrap_or_default(),
                    key_item_id: None,
                    password_item_id: None,
                    personal: false,
                    username_template: None,
                    jumps: parse_proxy_jump(s.proxy_jump.as_deref()),
                    tags: Vec::new(),
                    extra: std::collections::BTreeMap::new(),
                };
                let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
                vault
                    .put_item(alias.as_bytes(), ITEM_TYPE_CONNECTION, &json)
                    .map_err(FfiError::other)?;
                created.push(alias);
            }
            Ok(created)
        })
    }

    /// Renders a vault's profiles into `~/.ssh/config` text (the inverse of
    /// [`Core::import_ssh_config`]). Private keys are not exported — only
    /// Host/HostName/Port/User/ProxyJump; for key authentication the key
    /// stays in the vault (only a comment goes into the config). Round-trip-compatible with
    /// the import.
    pub fn export_ssh_config(&self, vault_id: String) -> Result<String, FfiError> {
        let profiles = self.list_connections(vault_id)?;
        let mut out = String::new();
        for p in profiles {
            // OpenSSH `Host` is patterns separated by spaces, with special meaning
            // for `* ? !`. A profile_id with such characters can't be represented as a single
            // alias and would break the round-trip → we skip it with a note.
            if p.profile_id
                .contains(|c: char| c.is_whitespace() || matches!(c, '*' | '?' | '!'))
            {
                out.push_str(&format!(
                    "# skipped profile '{}': id contains a space/glob character\n\n",
                    p.profile_id
                ));
                continue;
            }
            out.push_str(&format!("Host {}\n", p.profile_id));
            out.push_str(&format!("    HostName {}\n", p.host));
            if p.port != 22 {
                out.push_str(&format!("    Port {}\n", p.port));
            }
            if !p.user.is_empty() {
                out.push_str(&format!("    User {}\n", p.user));
            }
            if !p.jumps.is_empty() {
                let hops: Vec<String> = p.jumps.iter().map(format_proxy_hop).collect();
                out.push_str(&format!("    ProxyJump {}\n", hops.join(",")));
            }
            if let ProfileAuth::Key { key_item_id } = &p.auth {
                out.push_str(&format!(
                    "    # IdentityFile: key '{key_item_id}' in the vault\n"
                ));
            }
            out.push('\n');
        }
        Ok(out)
    }

    /// Imports `~/.ssh/known_hosts` text: each (host, port) with
    /// a non-hashed name is pinned in the TOFU store. The key is canonicalized by the same
    /// `russh` as pinning during a live connect (a byte match). Hashed lines
    /// (`|1|…`) and invalid ones are skipped with a count.
    pub fn import_known_hosts(&self, text: String) -> Result<KnownHostsImport, FfiError> {
        self.with_state_mut(|state| {
            let mut imported = 0u32;
            let mut skipped_hashed = 0u32;
            let mut skipped_invalid = 0u32;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut tok = line.split_whitespace();
                let (Some(hosts), Some(keytype), Some(keyblob)) =
                    (tok.next(), tok.next(), tok.next())
                else {
                    skipped_invalid += 1;
                    continue;
                };
                // @cert-authority / @revoked markers are not a normal pin — we skip them.
                if hosts.starts_with('@') {
                    skipped_invalid += 1;
                    continue;
                }
                if hosts.contains('|') {
                    skipped_hashed += 1;
                    continue;
                }
                let key_bytes = match canonical_host_key(&format!("{keytype} {keyblob}")) {
                    Ok(b) => b,
                    Err(_) => {
                        skipped_invalid += 1;
                        continue;
                    }
                };
                let mut any = false;
                for entry in hosts.split(',') {
                    let (host, port) = split_host_port(entry);
                    if host.is_empty() {
                        continue;
                    }
                    // A glob/negation (`*`/`?`/`!`) does NOT match a point TOFU lookup —
                    // pinning such a token is pointless (a dead record that misleads
                    // with "the host is pinned"). We skip it (counted as skipped).
                    if host.contains(['*', '?', '!']) {
                        continue;
                    }
                    if state
                        .storage
                        .put_known_host(&host, port, &key_bytes)
                        .is_ok()
                    {
                        imported += 1;
                        any = true;
                    }
                }
                if !any {
                    skipped_invalid += 1;
                }
            }
            Ok(KnownHostsImport {
                imported,
                skipped_hashed,
                skipped_invalid,
            })
        })
    }

    /// Imports a PuTTY session export (`.reg`): each SSH session becomes
    /// a connection profile. Non-SSH sessions, ones without a host, and id collisions are skipped.
    /// `ProxyMethod=6` (SSH) with `ProxyHost` becomes a single jump hop.
    pub fn import_putty_sessions(
        &self,
        vault_id: String,
        reg_text: String,
    ) -> Result<HostImportReport, FfiError> {
        let sessions = parse_putty_reg(&reg_text);
        self.with_state_mut(|state| {
            let vid = resolve_vid(&state.storage, &vault_id);
            let vault =
                Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
            let mut created_ids = Vec::new();
            let mut skipped = 0u32;
            for s in sessions {
                let proto = if s.protocol.is_empty() {
                    "ssh"
                } else {
                    s.protocol.as_str()
                };
                if proto != "ssh" || s.host.is_empty() || s.name.is_empty() {
                    skipped += 1;
                    continue;
                }
                // Any existing live item with this id (including a profile of the same
                // type) is not overwritten; the import only creates new ones.
                let occupied = state
                    .storage
                    .get_item(&vid, s.name.as_bytes())
                    .map_err(FfiError::other)?
                    .map(|r| !r.tombstone)
                    .unwrap_or(false);
                if occupied {
                    skipped += 1;
                    continue;
                }
                let jumps = if s.proxy_method == 6 && !s.proxy_host.is_empty() {
                    vec![StoredJump {
                        host: s.proxy_host.clone(),
                        port: if s.proxy_port == 0 {
                            22
                        } else {
                            s.proxy_port as u16
                        },
                        user: s.proxy_user.clone(),
                        key_item_id: None,
                        password_item_id: None,
                        extra: std::collections::BTreeMap::new(),
                        hop_ref: None,
                    }]
                } else {
                    Vec::new()
                };
                let stored = StoredProfile {
                    uid: Some(mint_profile_uid()),
                    label: s.name.clone(),
                    host: s.host.clone(),
                    port: if s.port == 0 { 22 } else { s.port as u16 },
                    user: s.user.clone(),
                    key_item_id: None,
                    password_item_id: None,
                    personal: false,
                    username_template: None,
                    jumps,
                    tags: Vec::new(),
                    extra: std::collections::BTreeMap::new(),
                };
                let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
                vault
                    .put_item(s.name.as_bytes(), ITEM_TYPE_CONNECTION, &json)
                    .map_err(FfiError::other)?;
                created_ids.push(s.name);
            }
            Ok(HostImportReport {
                created_ids,
                skipped,
            })
        })
    }

    /// Exports a vault into a portable encrypted backup file (NOT a sync): all
    /// live items are decrypted and placed into a bundle, which is encrypted with an
    /// AEAD key derived from the `passphrase` (Argon2id). It can be opened only
    /// with this passphrase, without the source account's keyset.
    pub fn export_vault(&self, vault_id: String, passphrase: String) -> Result<Vec<u8>, FfiError> {
        let passphrase = Zeroizing::new(passphrase);
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;

            let mut items_buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
            let mut count = 0u32;
            for m in vault.list_items().map_err(FfiError::other)? {
                if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
                    put_len_bytes(&mut items_buf, &item.item_id);
                    items_buf.extend_from_slice(&item.item_type.to_be_bytes());
                    put_len_bytes(&mut items_buf, &item.content);
                    count += 1;
                }
            }
            let mut bundle: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
            put_len_bytes(&mut bundle, vault.name());
            bundle.extend_from_slice(&count.to_be_bytes());
            bundle.extend_from_slice(&items_buf);

            let params = KdfParams::recommended();
            let key = derive_key(passphrase.as_bytes(), &params).map_err(FfiError::other)?;
            let kdf_blob = params.to_blob().map_err(FfiError::other)?;
            // The AAD covers magic+version+kdf_blob → tampering with the KDF params/header
            // is detected on decryption (not just a change of vault_id).
            let aad = backup_aad(vault_id.as_bytes(), &kdf_blob);
            let ciphertext = aead_encrypt(&key, &bundle, &aad).map_err(FfiError::other)?;

            let mut out = Vec::new();
            out.extend_from_slice(BACKUP_MAGIC);
            out.push(BACKUP_VERSION);
            put_len_bytes(&mut out, &kdf_blob);
            put_len_bytes(&mut out, vault_id.as_bytes());
            put_len_bytes(&mut out, &ciphertext);
            Ok(out)
        })
    }

    /// Imports a backup into a new vault `new_vault_id` of the current instance: decryption
    /// with the passphrase key, items are re-encrypted under the new VK and re-signed
    /// by the current owner. A wrong passphrase/corruption → an error. Does not overwrite
    /// an existing vault.
    pub fn import_vault(
        &self,
        backup: Vec<u8>,
        passphrase: String,
        new_vault_id: String,
    ) -> Result<(), FfiError> {
        let passphrase = Zeroizing::new(passphrase);
        let mut r = ByteReader::new(&backup);
        if r.take(4)? != BACKUP_MAGIC {
            return Err(FfiError::other("invalid backup format"));
        }
        if r.u8()? != BACKUP_VERSION {
            return Err(FfiError::other("unsupported backup version"));
        }
        let kdf_blob = r.bytes()?;
        let orig_vault_id = r.bytes()?;
        let ciphertext = r.bytes()?;

        // KdfParams::from_blob rejects out-of-bounds parameters (DoS protection) BEFORE
        // derivation; the AAD covers kdf_blob → tampering with the parameters won't pass.
        let params = KdfParams::from_blob(kdf_blob).map_err(FfiError::other)?;
        let key = derive_key(passphrase.as_bytes(), &params).map_err(FfiError::other)?;
        let aad = backup_aad(orig_vault_id, kdf_blob);
        // A wrong passphrase or corruption (including of the header/KDF) → the AEAD does not verify.
        let bundle = Zeroizing::new(
            aead_decrypt(&key, ciphertext, &aad).map_err(|_| FfiError::InvalidCredentials)?,
        );

        // Parse the bundle into owned values BEFORE the transaction (the content is in Zeroizing).
        let mut br = ByteReader::new(&bundle);
        let name = br.bytes()?.to_vec();
        let count = br.u32()?;
        let mut items: Vec<(Vec<u8>, u32, Zeroizing<Vec<u8>>)> = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let item_id = br.bytes()?.to_vec();
            let item_type = br.u32()?;
            let content = Zeroizing::new(br.bytes()?.to_vec());
            items.push((item_id, item_type, content));
        }

        self.with_state_mut(|state| {
            // Any existing volume-id (live OR tombstone) is taken: creating over it
            // is not allowed (anti-rollback would reject it anyway), so we return a clear error.
            if state
                .storage
                .get_vault(new_vault_id.as_bytes())
                .map_err(FfiError::other)?
                .is_some()
            {
                return Err(FfiError::AlreadyExists);
            }
            // Atomically: creating the vault + all items in a single transaction — a partial failure
            // won't leave a half-imported vault.
            state
                .storage
                .transaction(|| {
                    let vault = Vault::create(
                        &state.storage,
                        &state.keyset,
                        new_vault_id.as_bytes().to_vec(),
                        &name,
                    )?;
                    for (item_id, item_type, content) in &items {
                        vault.put_item(item_id, *item_type, content)?;
                    }
                    Ok::<(), unissh_vault::VaultError>(())
                })
                .map_err(map_vault_err)?;
            state.vault_names.insert(
                new_vault_id.into_bytes(),
                String::from_utf8_lossy(&name).to_string(),
            );
            Ok(())
        })
    }
}

impl Core {
    /// Takes the state lock, recovering from mutex poisoning (the data
    /// under the lock is ordinary, not invariant-bearing) so that a single panic does not
    /// "jam" the entire Core forever on calls through the FFI.
    fn locked_state(&self) -> std::sync::MutexGuard<'_, Option<CoreState>> {
        lock_recover(&self.state)
    }

    /// Runs `f` with a shared reference to the unlocked state, or returns
    /// [`FfiError::Locked`] if the instance is locked. Collapses the repeated
    /// `let guard = self.locked_state(); let state = guard.as_ref().ok_or(Locked)?;`
    /// prologue. The lock is held for exactly the duration of `f` (same scope as the
    /// hand-written prologue — the guard drops when `f` returns).
    fn with_state<R>(
        &self,
        f: impl FnOnce(&CoreState) -> Result<R, FfiError>,
    ) -> Result<R, FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        f(state)
    }

    /// Mutable-state counterpart of [`Self::with_state`]. Same lock scope as the
    /// hand-written `let mut guard = ...; let state = guard.as_mut().ok_or(Locked)?;`.
    fn with_state_mut<R>(
        &self,
        f: impl FnOnce(&mut CoreState) -> Result<R, FfiError>,
    ) -> Result<R, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        f(state)
    }

    /// Reads + decrypts the current per-account state (A3.2), if any.
    fn read_account_state(&self) -> Result<Option<AccountStatePayload>, FfiError> {
        self.with_state(|state| {
            let author = state.keyset.signing.verifying.to_bytes().to_vec();
            match state
                .storage
                .get_account_state(&author)
                .map_err(FfiError::other)?
            {
                Some(row) => {
                    let plain =
                        open_account_payload(&state.keyset, &row.payload).map_err(map_vault_err)?;
                    Ok(Some(AccountStatePayload::decode(&plain)?))
                }
                None => Ok(None),
            }
        })
    }

    /// Read-modify-write of the per-account state (A3.2): decrypt the current (or
    /// an empty) one, apply the mutation, re-seal+sign with version+1, save. Synced
    /// to the account's devices on the next sync_push.
    fn update_account_state(
        &self,
        mutate: impl FnOnce(&mut AccountStatePayload),
    ) -> Result<(), FfiError> {
        self.with_state(|state| {
            let author = state.keyset.signing.verifying.to_bytes().to_vec();
            let (mut payload, cur_version) = match state
                .storage
                .get_account_state(&author)
                .map_err(FfiError::other)?
            {
                Some(row) => {
                    let plain =
                        open_account_payload(&state.keyset, &row.payload).map_err(map_vault_err)?;
                    (AccountStatePayload::decode(&plain)?, row.version)
                }
                None => (AccountStatePayload::default(), 0),
            };
            mutate(&mut payload);
            let sealed =
                seal_account_payload(&state.keyset, &payload.encode()).map_err(map_vault_err)?;
            let new_version = cur_version.saturating_add(1);
            let sig =
                sign_account_state(&state.keyset, new_version, &sealed).map_err(map_vault_err)?;
            state
                .storage
                .set_account_state(&author, new_version, &sealed, &sig)
                .map_err(FfiError::other)?;
            Ok(())
        })
    }

    /// Connect + authentication under the Core lock (agent+storage are needed: keys are loaded
    /// into the agent, vault passwords are unwrapped into the core's memory). Returns
    /// an owned client; the caller releases the lock immediately after.
    fn connect_session(
        &self,
        auth: &AuthMethod,
        jumps: &[JumpHost],
        host: String,
        port: u16,
        user: String,
    ) -> Result<SshClient, FfiError> {
        connect_with_state(&self.state, &self.rt, auth, jumps, host, port, user)
    }

    /// Reveal of a specific version of a UTF-8 secret from history, type-gated to
    /// `expected_type` (another type — including a key — is not read through this path).
    fn read_item_version(
        &self,
        vault_id: &str,
        item_id: &str,
        version: u64,
        expected_type: u32,
        what: &str,
    ) -> Result<String, FfiError> {
        self.with_state_mut(|state| {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, vault_id),
            )
            .map_err(FfiError::other)?;
            let item = vault
                .get_item_version(item_id.as_bytes(), version)
                .map_err(FfiError::other)?
                .ok_or(FfiError::NotFound)?;
            if item.item_type != expected_type {
                return Err(FfiError::other(format!("item is not {what}")));
            }
            let s = std::str::from_utf8(&item.content)
                .map_err(|_| FfiError::other(format!("{what} is not valid UTF-8")))?;
            Ok(s.to_string())
        })
    }

    /// Expands a group (recursively, dedup + protection against cycles/depth) into
    /// `(targets for exec, the full plan)`. Targets are only profiles ready to connect
    /// (not `PromptPassword`); the plan includes each member with its status. A pure
    /// read of the vault: no connect, no loading of keys, no decryption of passwords.
    fn resolve_group(
        &self,
        vault_id: &str,
        group_id: &str,
    ) -> Result<(Vec<MultiExecTarget>, Vec<GroupTargetPlan>), FfiError> {
        let groups: std::collections::HashMap<String, Vec<String>> = self
            .list_groups(vault_id.to_string())?
            .into_iter()
            .map(|g| (g.group_id, g.member_ids))
            .collect();
        if !groups.contains_key(group_id) {
            return Err(FfiError::NotFound);
        }
        let profiles_map: std::collections::HashMap<String, ConnectionProfile> = self
            .list_connections(vault_id.to_string())?
            .into_iter()
            .map(|p| (p.profile_id.clone(), p))
            .collect();
        let profiles_set: std::collections::HashSet<String> =
            profiles_map.keys().cloned().collect();
        let (member_ids, issues) =
            flatten_group_members(&groups, &profiles_set, group_id, GROUP_MAX_DEPTH);

        let mut targets = Vec::new();
        let mut plans = Vec::new();
        for pid in member_ids {
            let p = profiles_map
                .get(&pid)
                .expect("flattened member is a profile");
            match &p.auth {
                // No password known in advance → it doesn't go into the batch (interactive).
                ProfileAuth::PromptPassword => {
                    plans.push(GroupTargetPlan {
                        member_id: pid,
                        host: p.host.clone(),
                        port: p.port,
                        user: p.user.clone(),
                        status: ResolveStatus::PromptPassword,
                    });
                }
                // Personal: we resolve the personal identity per-host (binding +
                // anti-redirect). Bound → into the batch with the resolved user+auth;
                // unbound/on redirect → excluded (connect
                // individually — there the exact error will surface), we do NOT send an empty password.
                ProfileAuth::Personal => {
                    let dest = self.personal_destination(
                        p.host.clone(),
                        p.port,
                        p.username_template.clone(),
                        p.jumps.clone(),
                    );
                    match self.resolve_personal_auth(
                        vault_id.to_string(),
                        p.uid.clone(),
                        dest,
                        p.user.clone(),
                    ) {
                        Ok(pa) => {
                            let user =
                                self.apply_username_template(pa.user, p.username_template.clone());
                            plans.push(GroupTargetPlan {
                                member_id: pid,
                                host: p.host.clone(),
                                port: p.port,
                                user: user.clone(),
                                status: ResolveStatus::Ok,
                            });
                            targets.push(MultiExecTarget {
                                host: p.host.clone(),
                                port: p.port,
                                user,
                                auth: pa.auth,
                                jumps: p.jumps.clone(),
                            });
                        }
                        Err(_) => {
                            plans.push(GroupTargetPlan {
                                member_id: pid,
                                host: p.host.clone(),
                                port: p.port,
                                user: p.user.clone(),
                                status: ResolveStatus::Personal,
                            });
                        }
                    }
                }
                _ => {
                    plans.push(GroupTargetPlan {
                        member_id: pid,
                        host: p.host.clone(),
                        port: p.port,
                        user: p.user.clone(),
                        status: ResolveStatus::Ok,
                    });
                    targets.push(profile_to_target(vault_id, p.clone()));
                }
            }
        }
        for (member_id, status) in issues {
            plans.push(GroupTargetPlan {
                member_id,
                host: String::new(),
                port: 0,
                user: String::new(),
                status,
            });
        }
        Ok((targets, plans))
    }
}

/// Connect + authentication against the shared unwrapped state (under its
/// lock). Used by both [`Core::connect_session`] and [`ReconnectingSession`] —
/// the latter re-resolves credentials from the vault on every reconnect (plaintext is not
/// cached between attempts).
///
/// A note on parallelism: the state lock is held for the entire `block_on`
/// of the SSH handshake (up to `HANDSHAKE_TIMEOUT`=30s), i.e. connects are serialized. This
/// is inherent to the model: `storage` (rusqlite `Connection`) and the embedded agent are `!Sync`
/// and live under this lock, and the TOFU host-key check touches `storage` right during
/// the handshake. For a single-user client connects are sequential anyway,
/// so moving the network out from under the lock would require Sync storage.
#[allow(clippy::too_many_arguments)]
fn connect_with_state(
    state: &Arc<Mutex<Option<CoreState>>>,
    rt: &tokio::runtime::Runtime,
    auth: &AuthMethod,
    jumps: &[JumpHost],
    host: String,
    port: u16,
    user: String,
) -> Result<SshClient, FfiError> {
    let mut guard = lock_recover(state);
    let st = guard.as_mut().ok_or(FfiError::Locked)?;
    let mut chain = Vec::with_capacity(jumps.len());
    for j in jumps {
        // Host-chain (B2.2): a ref hop is resolved from another bastion profile (host/
        // port/user/auth are taken from there); a normal hop is inline, as before.
        let (host, port, user, auth) = match &j.hop_ref {
            Some(hr) => {
                let prof = resolve_profile_by_uid(st, &hr.vault_id, &hr.profile_uid)?;
                let auth = match prof.auth {
                    ProfileAuth::Key { key_item_id } => AuthMethod::Agent {
                        vault_id: hr.vault_id.clone(),
                        key_item_id,
                    },
                    ProfileAuth::VaultPassword { password_item_id } => AuthMethod::VaultPassword {
                        vault_id: hr.vault_id.clone(),
                        password_item_id,
                    },
                    ProfileAuth::PromptPassword | ProfileAuth::Personal => {
                        return Err(FfiError::other(
                            "referenced bastion profile has no stored credential usable as a hop",
                        ))
                    }
                };
                (prof.host, prof.port, prof.user, auth)
            }
            None => (j.host.clone(), j.port, j.user.clone(), j.auth.clone()),
        };
        let a = resolve_auth(st, &auth)?;
        chain.push(ConnectOptions::new(host, port, user, a));
    }
    let target_auth = resolve_auth(st, auth)?;
    let target = ConnectOptions::new(host, port, user, target_auth);
    rt.block_on(SshClient::connect_through(
        &chain,
        &target,
        &st.agent,
        &st.storage,
    ))
    .map_err(map_transport_err)
}

/// Linear backoff: the delay before attempt `attempt` (0-based) = `base_ms *
/// (attempt+1)`.
fn retry_backoff_ms(attempt: u32, base_ms: u32) -> u64 {
    base_ms as u64 * (attempt as u64 + 1)
}

/// Translates the FFI authentication method into a transport one: the key is loaded into the agent,
/// a vault password is decrypted into `Zeroizing` (the plaintext never leaves the core).
fn resolve_auth(state: &mut CoreState, auth: &AuthMethod) -> Result<Auth, FfiError> {
    Ok(match auth {
        AuthMethod::Agent {
            vault_id,
            key_item_id,
        } => {
            load_key_into_agent(state, vault_id, key_item_id)?;
            Auth::Agent {
                key_id: agent_key_id(vault_id, key_item_id),
            }
        }
        AuthMethod::Password { password } => Auth::Password {
            password: Zeroizing::new(password.clone()),
        },
        AuthMethod::VaultPassword {
            vault_id,
            password_item_id,
        } => Auth::Password {
            password: read_password_item(state, vault_id, password_item_id)?,
        },
    })
}

/// Reads an item of type "password" from the vault. For internal use only during a
/// connect and for an explicit reveal ([`Core::get_password`]); an item of another type (including
/// an SSH key) is not read through this path.
fn read_password_item(
    state: &CoreState,
    vault_id: &str,
    item_id: &str,
) -> Result<Zeroizing<String>, FfiError> {
    read_utf8_item(state, vault_id, item_id, ITEM_TYPE_PASSWORD, "a password")
}

/// Reads the UTF-8 content of an item of a given type (password/note). Type-gate: an item
/// of another type (including a private key) is not read through this path — the invariant
/// "plaintext keys never cross the FFI" is preserved. The content is in `Zeroizing`.
fn read_utf8_item(
    state: &CoreState,
    vault_id: &str,
    item_id: &str,
    expected_type: u32,
    what: &str,
) -> Result<Zeroizing<String>, FfiError> {
    let vault = Vault::open(
        &state.storage,
        &state.keyset,
        &resolve_vid(&state.storage, vault_id),
    )
    .map_err(FfiError::other)?;
    let item = vault
        .get_item(item_id.as_bytes())
        .map_err(FfiError::other)?
        .ok_or(FfiError::NotFound)?;
    if item.item_type != expected_type {
        return Err(FfiError::other(format!("item is not {what}")));
    }
    let s = std::str::from_utf8(&item.content)
        .map_err(|_| FfiError::other(format!("{what} is not valid UTF-8")))?;
    Ok(Zeroizing::new(s.to_string()))
}

/// Laying out a single file onto one host: open SFTP, optionally create the parent
/// directory (the "exists" error is swallowed), write. Errors are `String`s (for
/// consistency with the timeout branch in [`Core::sftp_put_multi`]).
async fn sftp_put_one(
    client: &SshClient,
    remote_path: &str,
    data: &[u8],
    make_parent_dirs: bool,
) -> Result<(), String> {
    let mut sftp = client.open_sftp().await.map_err(|e| e.to_string())?;
    if make_parent_dirs {
        if let Some(parent) = parent_dir(remote_path) {
            let _ = sftp.mkdir(&parent).await;
        }
    }
    sftp.write_file(remote_path, data)
        .await
        .map_err(|e| e.to_string())
}

/// The parent directory of a path (one level). `None` if there is no parent.
fn parent_dir(path: &str) -> Option<String> {
    let p = path.trim_end_matches('/');
    p.rfind('/').map(|i| {
        if i == 0 {
            "/".to_string()
        } else {
            p[..i].to_string()
        }
    })
}

/// Matching a host's tags against a query. `match_all` → query ⊆ the host's tags (AND);
/// otherwise the intersection is non-empty (OR). An empty query → we select nothing (protection against
/// an accidental "exec on all hosts").
fn tags_match(host_tags: &[String], query: &[String], match_all: bool) -> bool {
    if query.is_empty() {
        return false;
    }
    if match_all {
        query.iter().all(|q| host_tags.contains(q))
    } else {
        query.iter().any(|q| host_tags.contains(q))
    }
}

/// Recursive expansion of nested groups into a flat ordered list of profiles.
/// A member is a profile id (in `profiles`) or a nested-group id (a key in `groups`).
/// `visited_groups` breaks cycles, `seen_profiles` deduplicates, `max_depth`
/// limits the depth. Returns (profiles in traversal order, problems).
fn flatten_group_members(
    groups: &std::collections::HashMap<String, Vec<String>>,
    profiles: &std::collections::HashSet<String>,
    root: &str,
    max_depth: u32,
) -> (Vec<String>, Vec<(String, ResolveStatus)>) {
    struct Flattener<'a> {
        groups: &'a std::collections::HashMap<String, Vec<String>>,
        profiles: &'a std::collections::HashSet<String>,
        max_depth: u32,
        result: Vec<String>,
        seen_profiles: std::collections::HashSet<String>,
        visited_groups: std::collections::HashSet<String>,
        issues: Vec<(String, ResolveStatus)>,
    }
    impl Flattener<'_> {
        fn walk(&mut self, gid: &str, depth: u32) {
            if depth > self.max_depth {
                self.issues
                    .push((gid.to_string(), ResolveStatus::CycleSkipped));
                return;
            }
            let Some(members) = self.groups.get(gid) else {
                return;
            };
            for m in members.clone() {
                if self.groups.contains_key(&m) {
                    // A nested group: first time — descend; again — a cycle.
                    if self.visited_groups.insert(m.clone()) {
                        self.walk(&m, depth + 1);
                    } else {
                        self.issues.push((m, ResolveStatus::CycleSkipped));
                    }
                } else if self.profiles.contains(&m) {
                    if self.seen_profiles.insert(m.clone()) {
                        self.result.push(m);
                    }
                } else {
                    self.issues.push((m, ResolveStatus::Dangling));
                }
            }
        }
    }
    let mut f = Flattener {
        groups,
        profiles,
        max_depth,
        result: Vec::new(),
        seen_profiles: std::collections::HashSet::new(),
        visited_groups: std::collections::HashSet::from([root.to_string()]),
        issues: Vec::new(),
    };
    f.walk(root, 0);
    (f.result, f.issues)
}

/// Profile → a multi-exec target in the same vault. `PromptPassword` has no stored
/// secret → an empty `Password` (marked separately in group/tag resolution; in
/// a non-interactive run it yields an authentication error, not a silent success).
fn profile_to_target(vault_id: &str, p: ConnectionProfile) -> MultiExecTarget {
    MultiExecTarget {
        host: p.host,
        port: p.port,
        user: p.user,
        auth: profile_auth_to_method(vault_id, p.auth),
        jumps: p.jumps,
    }
}

/// Translates a profile's credential reference (`ProfileAuth`, vault-relative) into a
/// vault-qualified [`AuthMethod`], setting the `vault_id` of the vault where
/// the profile lives. `PromptPassword` → an empty inline `Password` (in a non-interactive
/// run it yields an authentication error, not a silent success).
fn profile_auth_to_method(vault_id: &str, auth: ProfileAuth) -> AuthMethod {
    match auth {
        ProfileAuth::Key { key_item_id } => AuthMethod::Agent {
            vault_id: vault_id.to_string(),
            key_item_id,
        },
        ProfileAuth::VaultPassword { password_item_id } => AuthMethod::VaultPassword {
            vault_id: vault_id.to_string(),
            password_item_id,
        },
        ProfileAuth::PromptPassword => AuthMethod::Password {
            password: String::new(),
        },
        // Personal normally does NOT reach here: the fan-out paths (resolve_group,
        // select_targets_by_tags) exclude it before profile_to_target, and
        // an individual connect goes through resolve_personal_auth (with an
        // anti-redirect check). We keep a defensive fail-safe (an empty Password yields
        // an authentication error on a normal server), not a silent success.
        // Correct resolution of Personal in fan-out is B6.
        ProfileAuth::Personal => AuthMethod::Password {
            password: String::new(),
        },
    }
}

/// Mapping of transport errors: a host-key mismatch is singled out for the UI.
fn map_transport_err(e: unissh_ssh_transport::TransportError) -> FfiError {
    match e {
        unissh_ssh_transport::TransportError::HostKeyMismatch {
            host,
            port,
            fingerprint,
        } => FfiError::HostKeyMismatch {
            host,
            port,
            fingerprint,
        },
        other => FfiError::ssh(other),
    }
}

/// Protection against cross-type overwriting: if there is already a **live** item at `item_id`
/// of another type, we refuse (otherwise, e.g., a connection profile with the id of an existing
/// key would silently destroy the key). The check is against the raw storage record — without
/// decryption/signature verification.
fn ensure_item_type(
    storage: &Storage,
    vault_id: &str,
    item_id: &[u8],
    expected_type: u32,
) -> Result<(), FfiError> {
    let vid = resolve_vid(storage, vault_id);
    if let Some(rec) = storage.get_item(&vid, item_id).map_err(FfiError::other)? {
        if !rec.tombstone && rec.item_type != expected_type {
            return Err(FfiError::AlreadyExists);
        }
    }
    Ok(())
}

/// Mapping of vault errors: not-found/already-exists are singled out for the UI.
fn map_vault_err(e: unissh_vault::VaultError) -> FfiError {
    match e {
        unissh_vault::VaultError::NotFound => FfiError::NotFound,
        unissh_vault::VaultError::AlreadyExists => FfiError::AlreadyExists,
        other => FfiError::other(other),
    }
}

/// The decrypted contents of the per-account state (A3.2): the pointer to the personal
/// vault + the account-default username. Encoding: `put(vault_id) || put(username_utf8)`
/// (u32-BE lengths). An empty vault_id/username = "not set".
#[derive(Default)]
struct AccountStatePayload {
    personal_vault_id: Vec<u8>,
    default_username: String,
}

impl AccountStatePayload {
    fn encode(&self) -> Vec<u8> {
        let user = self.default_username.as_bytes();
        let mut out = Vec::with_capacity(8 + self.personal_vault_id.len() + user.len());
        // Same u32-BE length-prefixed framing as the rest of the crate (see
        // `put_len_bytes` / `ByteReader`) — byte-identical to the previous hand-rolled form.
        put_len_bytes(&mut out, &self.personal_vault_id);
        put_len_bytes(&mut out, user);
        out
    }

    fn decode(b: &[u8]) -> Result<Self, FfiError> {
        let fmt = || FfiError::Other {
            msg: "malformed account-state payload".into(),
        };
        // Reuse the crate's bounds-checked reader (checked_add overflow guard +
        // truncation check) instead of a third hand-rolled framing copy. All parse
        // errors are mapped back to the single `malformed` message, so behavior is
        // unchanged; the trailing-bytes check is `pos == len` after both fields.
        let mut r = ByteReader::new(b);
        let vid = r.bytes().map_err(|_| fmt())?.to_vec();
        let user = r.bytes().map_err(|_| fmt())?.to_vec();
        if r.pos != b.len() {
            return Err(fmt());
        }
        Ok(AccountStatePayload {
            personal_vault_id: vid,
            default_username: String::from_utf8(user).map_err(|_| fmt())?,
        })
    }
}

/// Mapping of keychain errors: invalid credentials/generation rollback — singled out for the UI.
fn map_keychain_err(e: unissh_keychain::KeychainError) -> FfiError {
    use unissh_keychain::KeychainError as K;
    match e {
        K::InvalidCredentials | K::PasswordRequired => FfiError::InvalidCredentials,
        other => FfiError::other(other),
    }
}

/// Mapping of sync errors: fatal ones → Other with a message (details are in the report, not here).
fn map_sync_err(e: unissh_sync::SyncError) -> FfiError {
    FfiError::Other { msg: e.to_string() }
}

/// Decodes a hex `vault_id` (a cloud UUIDv4) into raw bytes. Broken hex → Other.
fn decode_vid(vault_id_hex: &str) -> Result<Vec<u8>, FfiError> {
    hex::decode(vault_id_hex.trim()).map_err(|_| FfiError::other("invalid hex vault_id"))
}

/// Resolves a vault identifier into **raw bytes** for item operations. A local vault
/// is addressed by an arbitrary UTF-8 string (used as-is); a cloud vault —
/// by the hex of a UUIDv4 (`create_cloud_vault`/`list_vaults` return hex, but it is stored under
/// raw 16 bytes). If the string decodes as 16-byte hex AND such a vault
/// exists — it is a cloud id, we take the decoded bytes; otherwise — local, we take
/// the string's bytes. A collision (a local id matching the hex of an existing cloud UUID)
/// is practically impossible (it would be a UUID set by the user as an id name).
fn resolve_vid(storage: &Storage, vault_id: &str) -> Vec<u8> {
    if let Ok(raw) = hex::decode(vault_id.trim()) {
        if raw.len() == 16 && matches!(storage.get_vault(&raw), Ok(Some(_))) {
            return raw;
        }
    }
    vault_id.as_bytes().to_vec()
}

/// Decodes a fixed-length hex pubkey (32 bytes, Ed25519/X25519). Otherwise Other.
fn decode_pubkey32(label: &str, hex_str: &str) -> Result<Vec<u8>, FfiError> {
    let b =
        hex::decode(hex_str.trim()).map_err(|_| FfiError::other(format!("invalid hex {label}")))?;
    if b.len() != 32 {
        return Err(FfiError::other(format!("{label} must be 32 bytes")));
    }
    Ok(b)
}

/// Returns the instance's persistent account-id, generating and saving it on
/// first access (idempotent; server-tz §2.1). A public id, not a secret.
fn ensure_account_id(storage: &Storage) -> Result<[u8; 16], FfiError> {
    match load_account_id(storage).map_err(map_keychain_err)? {
        Some(id) => Ok(id),
        None => {
            let id = generate_account_id();
            store_account_id(storage, &id).map_err(map_keychain_err)?;
            Ok(id)
        }
    }
}

/// Shared converter of a `vault` integrity report → an FFI Record (for the local and
/// cloud/member paths: `verify_vault_integrity` and `verify_chain`).
fn integrity_report_to_ffi(report: unissh_vault::IntegrityReport) -> VaultIntegrityReport {
    VaultIntegrityReport {
        ok: report.ok,
        checked: report.checked,
        issues: report
            .issues
            .into_iter()
            .map(|i| IntegrityIssueInfo {
                item_id: String::from_utf8_lossy(&i.item_id).to_string(),
                version: i.version,
                tombstone: i.tombstone,
                failure: match i.failure {
                    unissh_vault::IntegrityFailure::SignatureInvalid => {
                        IntegrityFailureKind::SignatureInvalid
                    }
                    unissh_vault::IntegrityFailure::AuthorMismatch => {
                        IntegrityFailureKind::AuthorMismatch
                    }
                    unissh_vault::IntegrityFailure::Malformed => IntegrityFailureKind::Malformed,
                    // non_exhaustive: a future reason → conservatively Malformed.
                    _ => IntegrityFailureKind::Malformed,
                },
            })
            .collect(),
    }
}

/// Opens the keyset file with `0600` permissions (on unix): the private sidecar must not
/// be accessible to other local users — even encrypted, this reduces
/// the risk of offline Argon2 brute-forcing. `exclusive` → `create_new` (O_EXCL).
fn open_keyset_file(path: &std::path::Path, exclusive: bool) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    if exclusive {
        o.create_new(true);
    } else {
        o.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Atomically overwrites the keyset sidecar: we write to a temporary file and
/// rename it over (on one filesystem rename is atomic; on a failure before the rename
/// the original is intact). The temp name is unique (pid) so that concurrent/orphaned temps
/// don't collide; after the rename — an fsync of the directory for durability.
fn write_keyset_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), FfiError> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = open_keyset_file(&tmp, false).map_err(FfiError::other)?;
        f.write_all(bytes).map_err(FfiError::other)?;
        f.sync_all().map_err(FfiError::other)?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(FfiError::other(e));
    }
    // fsync the directory — so the rename record reaches the disk.
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Backs up the keyset sidecar to `<path>.pre-migration.bak` BEFORE a migration
/// overwrite — makes the migration's single write operation (re-wrap to v3)
/// fully reversible. Best-effort: on failure — `warn` and continue (the migration is
/// brick-safe anyway — the new v3 record is self-consistent, the old blob is not lost until
/// the atomic rename). ONLY the path is logged (filesystem metadata), NOT the contents
/// of the keyset (the blob itself is encrypted, but we don't write crypto blobs to logs — see SECURITY.md).
fn backup_keyset_sidecar(path: &std::path::Path) {
    if !path.exists() {
        return; // nothing to back up (first onboarding — no sidecar yet)
    }
    let mut bak = path.as_os_str().to_owned();
    bak.push(".pre-migration.bak");
    let bak = PathBuf::from(bak);
    match std::fs::copy(path, &bak) {
        Ok(_) => log::info!(
            "keyset sidecar backed up before migration: {}",
            bak.display()
        ),
        Err(e) => log::warn!(
            "keyset sidecar backup failed (migration still safe, proceeding): {} ({e})",
            bak.display()
        ),
    }
}

/// An inline password in a profile's jump host → an error: the secret must not end up in
/// the profile's JSON (for a stored password there is the `VaultPassword` reference).
///
/// The method's `vault_id` is dropped here: a stored jump is vault-relative (the item
/// lives in the profile's vault, the same `vault_id` is restored on read in
/// [`stored_to_profile`]). Cross-vault hops are a separate model (`HopRef`).
fn jump_to_stored(j: JumpHost) -> Result<StoredJump, FfiError> {
    let hop_ref = j.hop_ref.map(|hr| StoredHopRef {
        vault_id: hr.vault_id,
        profile_uid: hr.profile_uid,
    });
    // Ref hop: inline auth is ignored, we save nothing from it (the auth itself is a
    // placeholder). A normal hop: as before (references only, no inline password).
    let (key_item_id, password_item_id) = if hop_ref.is_some() {
        (None, None)
    } else {
        match j.auth {
            AuthMethod::Agent { key_item_id, .. } => (Some(key_item_id), None),
            AuthMethod::VaultPassword {
                password_item_id, ..
            } => (None, Some(password_item_id)),
            AuthMethod::Password { .. } => {
                return Err(FfiError::other(
                    "inline password cannot be stored in a profile; save it as a vault item",
                ))
            }
        }
    };
    Ok(StoredJump {
        host: j.host,
        port: j.port,
        user: j.user,
        key_item_id,
        password_item_id,
        hop_ref,
        extra: std::collections::BTreeMap::new(),
    })
}

/// Validates a terminal size at the FFI boundary: both dimensions > 0, otherwise garbage
/// (e.g. 0×0 from an uninitialized UI) would go to the server.
fn check_term_size(cols: u32, rows: u32) -> Result<(), FfiError> {
    if cols == 0 || rows == 0 {
        return Err(FfiError::other("terminal size must be non-zero"));
    }
    Ok(())
}

fn group_to_public(group_id: String, s: StoredGroup) -> ServerGroup {
    ServerGroup {
        group_id,
        label: s.label,
        member_ids: s.member_ids,
        parent_id: s.parent_id,
    }
}

/// Mints a new immutable profile uid: 16 cryptographically random bytes in hex.
/// RANDOM (not derived from item_id) — a recycled-after-tombstone
/// item_id (the ssh-config import takes the alias as the id) won't collide in uid with an old
/// profile, so someone else's binding won't stick to the new host.
fn mint_profile_uid() -> String {
    hex::encode(unissh_crypto::random_bytes::<16>())
}

/// Reads the saved "unknown fields" (`extra`) of an existing item of the same
/// type, to CARRY them into the body being overwritten (forward-compat: the client does not
/// strip fields added by a future version → no silent LWW downgrade,
/// e.g. no loss of `personal`/`username_template`). Empty if there is no item / of another
/// type / it didn't parse.
fn preserved_extra<T>(
    vault: &Vault,
    item_id: &[u8],
    item_type: u32,
    pick: impl FnOnce(T) -> BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value>
where
    T: serde::de::DeserializeOwned,
{
    vault
        .get_item(item_id)
        .ok()
        .flatten()
        .filter(|i| i.item_type == item_type)
        .and_then(|i| serde_json::from_slice::<T>(&i.content).ok())
        .map(pick)
        .unwrap_or_default()
}

/// Deterministic uid for a legacy profile without a saved uid: sha256 of
/// (len-prefixed vault_id ‖ item_id), the first 16 bytes in hex. Stable across
/// devices until the first re-save (then it is pinned in the body). Recycling in
/// this window is impossible: the item_id is taken by the live profile it is computed for.
fn legacy_profile_uid(vault_id: &str, item_id: &str) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update((vault_id.len() as u64).to_be_bytes());
    h.update(vault_id.as_bytes());
    h.update(item_id.as_bytes());
    hex::encode(&h.finalize()[..16])
}

fn stored_to_profile(vault_id: &str, profile_id: String, s: StoredProfile) -> ConnectionProfile {
    let uid = s
        .uid
        .clone()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| legacy_profile_uid(vault_id, &profile_id));
    ConnectionProfile {
        uid,
        profile_id,
        label: s.label,
        host: s.host,
        port: s.port,
        user: s.user,
        tags: s.tags,
        username_template: s.username_template,
        // Personal takes priority over key/password references (Personal has none anyway).
        auth: if s.personal {
            ProfileAuth::Personal
        } else {
            match (s.password_item_id, s.key_item_id) {
                (Some(password_item_id), _) => ProfileAuth::VaultPassword { password_item_id },
                (None, Some(key_item_id)) => ProfileAuth::Key { key_item_id },
                (None, None) => ProfileAuth::PromptPassword,
            }
        },
        jumps: s
            .jumps
            .into_iter()
            .map(|j| JumpHost {
                host: j.host,
                port: j.port,
                user: j.user,
                // A stored profile's hops are vault-relative: their items live in the same
                // vault as the profile. We set this `vault_id`.
                auth: match (j.password_item_id, j.key_item_id) {
                    (Some(password_item_id), _) => AuthMethod::VaultPassword {
                        vault_id: vault_id.to_string(),
                        password_item_id,
                    },
                    (None, Some(key_item_id)) => AuthMethod::Agent {
                        vault_id: vault_id.to_string(),
                        key_item_id,
                    },
                    // A legacy import may have left the key unassigned: an empty id
                    // preserves the previous semantics "the UI will assign it later" (a connect with
                    // it will give NotFound).
                    (None, None) => AuthMethod::Agent {
                        vault_id: vault_id.to_string(),
                        key_item_id: String::new(),
                    },
                },
                hop_ref: j.hop_ref.map(|hr| HopRef {
                    vault_id: hr.vault_id,
                    profile_uid: hr.profile_uid,
                }),
            })
            .collect(),
    }
}

/// Resolves a bastion profile by (vault_id, profile_uid) for a host-chain (B2.2):
/// scans the vault's connection profiles and finds the one with a matching immutable uid.
/// Does not recurse along the reference chain (only the hop profile itself is taken).
fn resolve_profile_by_uid(
    state: &CoreState,
    vault_id: &str,
    profile_uid: &str,
) -> Result<ConnectionProfile, FfiError> {
    let vault = Vault::open(
        &state.storage,
        &state.keyset,
        &resolve_vid(&state.storage, vault_id),
    )
    .map_err(FfiError::other)?;
    for m in vault.list_items().map_err(FfiError::other)? {
        if m.item_type != ITEM_TYPE_CONNECTION {
            continue;
        }
        if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
            if let Ok(sp) = serde_json::from_slice::<StoredProfile>(&item.content) {
                let prof = stored_to_profile(
                    vault_id,
                    String::from_utf8_lossy(&m.item_id).to_string(),
                    sp,
                );
                if prof.uid == profile_uid {
                    return Ok(prof);
                }
            }
        }
    }
    Err(FfiError::NotFound)
}

/// Magic of a vault backup file.
const BACKUP_MAGIC: &[u8; 4] = b"UNVB";
/// Version of the backup format.
const BACKUP_VERSION: u8 = 1;

/// Backup AAD: binds the ciphertext to the vault_id and the header (magic+version+
/// kdf_blob) so that tampering with the KDF params/version is detected on decryption.
fn backup_aad(vault_id: &[u8], kdf_blob: &[u8]) -> AssociatedData {
    let mut tag = Vec::with_capacity(BACKUP_MAGIC.len() + 1 + kdf_blob.len());
    tag.extend_from_slice(BACKUP_MAGIC);
    tag.push(BACKUP_VERSION);
    tag.extend_from_slice(kdf_blob);
    AssociatedData::new(vault_id.to_vec(), tag, BACKUP_VERSION as u64)
}

/// Appends a length-prefixed (u32 BE) blob.
fn put_len_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// Reader of the backup's length-prefixed framing (with bounds checking).
struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], FfiError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| FfiError::other("backup overflow"))?;
        if end > self.buf.len() {
            return Err(FfiError::other("truncated backup"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, FfiError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, FfiError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn bytes(&mut self) -> Result<&'a [u8], FfiError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// A parsed PuTTY session (internal representation).
#[derive(Default)]
struct PuttySession {
    name: String,
    host: String,
    port: u32,
    user: String,
    protocol: String,
    proxy_method: u32,
    proxy_host: String,
    proxy_port: u32,
    proxy_user: String,
}

/// Parses a PuTTY export (`.reg`) into a list of sessions. A block starts with the line
/// `[...\Sessions\<name>]` (the name is url-encoded), followed by `"Key"="value"` /
/// `"Key"=dword:hex`.
fn parse_putty_reg(text: &str) -> Vec<PuttySession> {
    let mut out = Vec::new();
    let mut cur: Option<PuttySession> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(s) = cur.take() {
                out.push(s);
            }
            if let Some(idx) = rest.find("\\Sessions\\") {
                let name_enc = rest[idx + "\\Sessions\\".len()..].trim_end_matches(']');
                cur = Some(PuttySession {
                    name: putty_unescape(name_enc),
                    ..Default::default()
                });
            }
            continue;
        }
        let Some(s) = cur.as_mut() else {
            continue;
        };
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        let val = val.trim();
        match key {
            "HostName" => s.host = unquote_reg(val),
            "PortNumber" => s.port = parse_dword(val),
            "UserName" => s.user = unquote_reg(val),
            "Protocol" => s.protocol = unquote_reg(val),
            "ProxyMethod" => s.proxy_method = parse_dword(val),
            "ProxyHost" => s.proxy_host = unquote_reg(val),
            "ProxyPort" => s.proxy_port = parse_dword(val),
            "ProxyUsername" => s.proxy_user = unquote_reg(val),
            _ => {}
        }
    }
    if let Some(s) = cur.take() {
        out.push(s);
    }
    out
}

/// Strips the quotes from a `.reg` string value.
fn unquote_reg(v: &str) -> String {
    v.trim().trim_matches('"').to_string()
}

/// Parses `dword:0000XXXX` (hex) into `u32`; otherwise 0.
fn parse_dword(v: &str) -> u32 {
    v.trim()
        .strip_prefix("dword:")
        .and_then(|h| u32::from_str_radix(h.trim(), 16).ok())
        .unwrap_or(0)
}

/// Decodes the `%XX` escaping of a PuTTY session name.
fn putty_unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Renders a jump host into a `ProxyJump` element (`user@host:port`, IPv6 in brackets).
/// Reversible with [`parse_proxy_jump`].
fn format_proxy_hop(j: &JumpHost) -> String {
    let hostport = if j.host.contains(':') && !j.host.starts_with('[') {
        format!("[{}]:{}", j.host, j.port)
    } else {
        format!("{}:{}", j.host, j.port)
    };
    if j.user.is_empty() {
        hostport
    } else {
        format!("{}@{hostport}", j.user)
    }
}

/// Parses `ProxyJump` (`a,b,c`, elements of the form `user@host:port`) into jump hosts.
/// We leave authentication unassigned — the key/password is assigned by the UI (the import does not
/// know the vault's items).
fn parse_proxy_jump(spec: Option<&str>) -> Vec<StoredJump> {
    let mut out = Vec::new();
    let Some(spec) = spec else {
        return out;
    };
    for hop in spec.split(',') {
        let hop = hop.trim();
        if hop.is_empty() {
            continue;
        }
        let (user, hostport) = match hop.split_once('@') {
            Some((u, hp)) => (u.to_string(), hp),
            None => (String::new(), hop),
        };
        let (host, port) = split_host_port(hostport);
        out.push(StoredJump {
            host,
            port,
            user,
            key_item_id: None,
            password_item_id: None,
            extra: std::collections::BTreeMap::new(),
            hop_ref: None,
        });
    }
    out
}

/// Parses `host[:port]` with IPv6 support: `[2001:db8::1]:2222`, `[2001:db8::1]`,
/// a bare `2001:db8::1` (several `:` without brackets → the whole thing as host), otherwise
/// `host:port`. The default port is 22.
///
/// IPv6 brackets are always stripped: the same "bare" host string goes both into the connect
/// (`russh`) and into the known_hosts lookup/pin — the host identity for pinning
/// is preserved (it's important not to mix `[ip]` and `ip` across different paths).
fn split_host_port(s: &str) -> (String, u16) {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once("]:") {
            return (h.to_string(), p.parse().unwrap_or(22));
        }
        if let Some(h) = rest.strip_suffix(']') {
            return (h.to_string(), 22);
        }
    }
    // A bare IPv6 literal (>1 colon, no brackets) — no port specified.
    if s.matches(':').count() > 1 {
        return (s.to_string(), 22);
    }
    match s.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(22)),
        None => (s.to_string(), 22),
    }
}

/// Observer of an interactive session (implemented by the UI; a UniFFI callback interface).
#[uniffi::export(with_foreign)]
pub trait SessionObserver: Send + Sync {
    /// Data from the session (terminal output).
    fn on_data(&self, data: Vec<u8>);
    /// The session is closed; the exit code (or -1).
    fn on_close(&self, exit_status: i32);
}

struct ObserverSink(Arc<dyn SessionObserver>);

impl OutputSink for ObserverSink {
    fn on_data(&self, data: Vec<u8>) {
        self.0.on_data(data);
    }
    fn on_close(&self, exit_status: Option<u32>) {
        self.0.on_close(exit_status.map(|c| c as i32).unwrap_or(-1));
    }
}

/// Observer of a streaming exec: stdout/stderr separately + the exit code.
#[uniffi::export(with_foreign)]
pub trait ExecObserver: Send + Sync {
    /// stdout data.
    fn on_stdout(&self, data: Vec<u8>);
    /// stderr data.
    fn on_stderr(&self, data: Vec<u8>);
    /// The command finished; the exit code (or -1).
    fn on_exit(&self, exit_status: i32);
}

struct ExecSinkBridge(Arc<dyn ExecObserver>);

impl unissh_ssh_transport::ExecSink for ExecSinkBridge {
    fn on_stdout(&self, data: Vec<u8>) {
        self.0.on_stdout(data);
    }
    fn on_stderr(&self, data: Vec<u8>) {
        self.0.on_stderr(data);
    }
    fn on_exit(&self, exit_status: Option<u32>) {
        self.0.on_exit(exit_status.map(|c| c as i32).unwrap_or(-1));
    }
}

/// Observer of a broadcast session: each host's output is tagged with its index
/// (position in `targets`). Implemented by the UI.
#[uniffi::export(with_foreign)]
pub trait BroadcastObserver: Send + Sync {
    /// Data from the session of host `host_index`.
    fn on_data(&self, host_index: u32, data: Vec<u8>);
    /// The session of host `host_index` is closed; the exit code (or -1).
    fn on_close(&self, host_index: u32, exit_status: i32);
}

/// A sink that tags one host's output with its index and delegates to
/// [`BroadcastObserver`]. Attached per-client in the ffi — the transport crate knows
/// nothing about broadcast.
struct TaggedSink {
    observer: Arc<dyn BroadcastObserver>,
    index: u32,
}

impl OutputSink for TaggedSink {
    fn on_data(&self, data: Vec<u8>) {
        self.observer.on_data(self.index, data);
    }
    fn on_close(&self, exit_status: Option<u32>) {
        self.observer
            .on_close(self.index, exit_status.map(|c| c as i32).unwrap_or(-1));
    }
}

/// An interactive SSH session (PTY). Manages input/resize/close; output
/// goes to the registered observer. Does not hold the Core lock.
#[derive(uniffi::Object)]
pub struct SshSession {
    _client: Mutex<SshClient>,
    shell: ShellHandle,
    rt: Arc<tokio::runtime::Runtime>,
}

#[uniffi::export]
impl SshSession {
    /// Sends input (keystrokes) to the session.
    pub fn write(&self, data: Vec<u8>) -> Result<(), FfiError> {
        self.rt
            .block_on(self.shell.write(&data))
            .map_err(FfiError::ssh)
    }

    /// Changes the terminal window size. `cols`/`rows` must be > 0.
    ///
    /// Best-effort: `window-change` is sent to the server without acknowledgement, so
    /// `Ok(())` means "the notification was sent", not "the server applied the size".
    /// An error is returned only on a channel/transport drop. The UI must not wait for an ack.
    pub fn resize(&self, cols: u32, rows: u32) -> Result<(), FfiError> {
        check_term_size(cols, rows)?;
        self.rt
            .block_on(self.shell.resize(cols, rows))
            .map_err(FfiError::ssh)
    }

    /// Closes the session.
    pub fn close(&self) -> Result<(), FfiError> {
        self.rt.block_on(self.shell.close()).map_err(FfiError::ssh)
    }
}

/// Handle of a streaming exec: stdin, completion polling, close. Output goes to
/// `ExecObserver`. Does not hold the Core lock.
#[derive(uniffi::Object)]
pub struct ExecHandleFfi {
    _client: Mutex<SshClient>,
    handle: ExecHandle,
    rt: Arc<tokio::runtime::Runtime>,
}

#[uniffi::export]
impl ExecHandleFfi {
    /// Writes to the command's stdin.
    pub fn write_stdin(&self, data: Vec<u8>) -> Result<(), FfiError> {
        self.rt
            .block_on(self.handle.write_stdin(&data))
            .map_err(FfiError::ssh)
    }

    /// Waits for the command to finish for up to `timeout_ms` ms. `true` — it finished (and
    /// `on_exit` was delivered), `false` — a timeout.
    pub fn wait_exit(&self, timeout_ms: u32) -> Result<bool, FfiError> {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
        loop {
            if self.handle.has_exited() {
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Closes the channel (EOF stdin + close).
    pub fn close(&self) -> Result<(), FfiError> {
        self.rt.block_on(self.handle.close()).map_err(FfiError::ssh)
    }
}

/// An interactive PTY session with auto-reconnect. Stores the connection parameters and
/// on a drop (a `write` error) or on an explicit `reconnect()` re-establishes
/// the session with backoff. `Agent`/`VaultPassword` credentials are re-resolved from the vault on
/// each attempt (plaintext is not cached); an inline `Password` (if the session was opened
/// with it) is kept in `auth` for the session's lifetime — for reconnects.
/// `HostKeyMismatch` is NOT reconnected (a possible MITM → stop).
#[derive(uniffi::Object)]
pub struct ReconnectingSession {
    state: Arc<Mutex<Option<CoreState>>>,
    rt: Arc<tokio::runtime::Runtime>,
    host: String,
    port: u16,
    user: String,
    auth: AuthMethod,
    jumps: Vec<JumpHost>,
    term: String,
    cols: u32,
    rows: u32,
    max_retries: u32,
    backoff_ms: u32,
    observer: Arc<dyn SessionObserver>,
    current: Mutex<Option<(SshClient, ShellHandle)>>,
    // Serializes reconnect: two concurrent reconnect() calls (e.g. from a race
    // on write-fail) must not create an extra orphan connection.
    reconnect_lock: Mutex<()>,
}

impl ReconnectingSession {
    fn connect_once(&self) -> Result<(), FfiError> {
        let client = connect_with_state(
            &self.state,
            &self.rt,
            &self.auth,
            &self.jumps,
            self.host.clone(),
            self.port,
            self.user.clone(),
        )?;
        let sink: Arc<dyn OutputSink> = Arc::new(ObserverSink(self.observer.clone()));
        let shell = self
            .rt
            .block_on(client.open_shell(&self.term, self.cols, self.rows, sink))
            .map_err(FfiError::ssh)?;
        *lock_recover(&self.current) = Some((client, shell));
        Ok(())
    }

    fn connect_with_retry(&self) -> Result<(), FfiError> {
        let mut last = FfiError::other("no connection attempt");
        for attempt in 0..=self.max_retries {
            match self.connect_once() {
                Ok(()) => return Ok(()),
                // A MITM is not cured by reconnecting — we return the error immediately.
                Err(e @ FfiError::HostKeyMismatch { .. }) => return Err(e),
                Err(e) => {
                    last = e;
                    if attempt < self.max_retries {
                        std::thread::sleep(std::time::Duration::from_millis(retry_backoff_ms(
                            attempt,
                            self.backoff_ms,
                        )));
                    }
                }
            }
        }
        Err(last)
    }

    fn try_write(&self, data: &[u8]) -> Result<(), FfiError> {
        let guard = lock_recover(&self.current);
        match guard.as_ref() {
            Some((_client, shell)) => self.rt.block_on(shell.write(data)).map_err(FfiError::ssh),
            None => Err(FfiError::other("not connected")),
        }
    }

    fn teardown(&self) {
        let _enter = self.rt.enter();
        let mut guard = lock_recover(&self.current);
        if let Some((client, shell)) = guard.take() {
            let _ = self.rt.block_on(shell.close());
            let _ = self.rt.block_on(client.disconnect());
        }
    }
}

#[uniffi::export]
impl ReconnectingSession {
    /// Whether there is a live session right now.
    pub fn is_connected(&self) -> bool {
        lock_recover(&self.current).is_some()
    }

    /// Sends input; on an error (drop) it auto-reconnects and retries.
    pub fn write(&self, data: Vec<u8>) -> Result<(), FfiError> {
        if self.try_write(&data).is_ok() {
            return Ok(());
        }
        self.reconnect()?;
        self.try_write(&data)
    }

    /// Resizes the current session (`cols`/`rows` > 0).
    pub fn resize(&self, cols: u32, rows: u32) -> Result<(), FfiError> {
        check_term_size(cols, rows)?;
        let guard = lock_recover(&self.current);
        match guard.as_ref() {
            Some((_client, shell)) => self
                .rt
                .block_on(shell.resize(cols, rows))
                .map_err(FfiError::ssh),
            None => Err(FfiError::other("not connected")),
        }
    }

    /// Explicitly recreates the session (tears down the old one, reconnects with backoff).
    pub fn reconnect(&self) -> Result<(), FfiError> {
        // We serialize: concurrent reconnect() calls don't create orphan connections.
        let _g = lock_recover(&self.reconnect_lock);
        self.teardown();
        self.connect_with_retry()
    }

    /// Closes the session and tears down the connection.
    pub fn close(&self) {
        self.teardown();
    }
}

impl Drop for ReconnectingSession {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// A broadcast session (cluster-ssh): holds PTY sessions of several hosts; input
/// is fanned out to all. Does not hold the Core lock. Output goes to `BroadcastObserver` with
/// the host index.
#[derive(uniffi::Object)]
pub struct BroadcastSession {
    inner: Mutex<Vec<(SshClient, ShellHandle)>>,
    statuses: Vec<BroadcastHostStatus>,
    rt: Arc<tokio::runtime::Runtime>,
}

#[uniffi::export]
impl BroadcastSession {
    /// Statuses of all targets (including those that didn't connect).
    pub fn statuses(&self) -> Vec<BroadcastHostStatus> {
        self.statuses.clone()
    }

    /// Sends input to all active sessions (best-effort: a dead host does not
    /// block the others).
    pub fn write_all(&self, data: Vec<u8>) -> Result<(), FfiError> {
        let guard = lock_recover(&self.inner);
        for (_client, shell) in guard.iter() {
            let _ = self.rt.block_on(shell.write(&data));
        }
        Ok(())
    }

    /// Resizes all active sessions (`cols`/`rows` > 0). Best-effort.
    pub fn resize_all(&self, cols: u32, rows: u32) -> Result<(), FfiError> {
        check_term_size(cols, rows)?;
        let guard = lock_recover(&self.inner);
        for (_client, shell) in guard.iter() {
            let _ = self.rt.block_on(shell.resize(cols, rows));
        }
        Ok(())
    }

    /// Closes all sessions and tears down the connections.
    pub fn close(&self) {
        // block_on enters the runtime context (Drop of a russh channel may
        // tokio::spawn — without enter a drop outside the runtime panics).
        let _enter = self.rt.enter();
        let mut guard = lock_recover(&self.inner);
        for (client, shell) in guard.drain(..) {
            let _ = self.rt.block_on(shell.close());
            let _ = self.rt.block_on(client.disconnect());
        }
    }
}

impl Drop for BroadcastSession {
    fn drop(&mut self) {
        let _enter = self.rt.enter();
        let mut guard = lock_recover(&self.inner);
        guard.clear();
    }
}

/// An active tunnel (port forwarding). Keeps the SSH connection alive. `close()` — a
/// clean disconnect; on Drop without `close()` the listener deterministically
/// stops (ForwardGuard) and the connection is torn down (without a polite disconnect).
#[derive(uniffi::Object)]
pub struct SshTunnel {
    client: Mutex<Option<SshClient>>,
    guard: Mutex<Option<ForwardGuard>>,
    rt: Arc<tokio::runtime::Runtime>,
    bind_addr: String,
}

#[uniffi::export]
impl SshTunnel {
    /// The address the forward listens on: `host:port` (local/dynamic) or
    /// `remote_bind:assigned_port` (remote).
    pub fn bind_address(&self) -> String {
        self.bind_addr.clone()
    }

    /// Closes the tunnel and the connection.
    pub fn close(&self) {
        // Stop the listener (Drop of ForwardGuard), then tear down the connection normally.
        // SshClient/ForwardGuard drop safely outside the runtime; block_on itself
        // enters the runtime context (so no separate enter — otherwise a nested
        // block_on panics).
        let _ = lock_recover(&self.guard).take();
        if let Some(c) = lock_recover(&self.client).take() {
            let _ = self.rt.block_on(c.disconnect());
        }
    }
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        // Deterministically stop the listener (ForwardGuard.abort on Drop).
        // SshClient (= Arc<Handle>) drops safely outside the runtime; a clean
        // disconnect is done only by close() (we don't call block_on in Drop here).
        let _ = lock_recover(&self.guard).take();
        let _ = lock_recover(&self.client).take();
    }
}

/// Progress callback of an SFTP transfer (implemented by the UI).
#[uniffi::export(with_foreign)]
pub trait SftpProgressObserver: Send + Sync {
    /// `transferred` bytes of `total` (0 if the size is unknown).
    fn on_progress(&self, transferred: u64, total: u64);
}

struct ProgressBridge(Arc<dyn SftpProgressObserver>);

impl unissh_ssh_transport::SftpProgress for ProgressBridge {
    fn on_progress(&self, transferred: u64, total: u64) {
        self.0.on_progress(transferred, total);
    }
}

/// A cooperative cancellation token for a transfer. Created by the UI, passed to
/// `sftp_download`/`sftp_upload`, cancelled from another thread.
#[derive(uniffi::Object)]
pub struct CancelToken {
    flag: Arc<std::sync::atomic::AtomicBool>,
}

#[uniffi::export]
impl CancelToken {
    /// A new (uncancelled) token.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Requests cancellation (the transfer will stop between chunks).
    pub fn cancel(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }
}

struct CancelBridge(Arc<std::sync::atomic::AtomicBool>);

impl unissh_ssh_transport::SftpCancel for CancelBridge {
    fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// === Milestone 2: sync via a callback interface ===

/// **Sync callback interface** (implemented by the app — server-tz §3.1): a narrow
/// contract of an "untrusted box of blobs". The core does NOT trust the order, nor
/// `server_seq`, nor the contents — `sync_now` verifies every object before
/// applying it. Objects cross the boundary as opaque bytes
/// (`SyncObject::to_bytes`); the core serializes/deserializes on its own side.
#[uniffi::export(with_foreign)]
pub trait FfiSyncTransport: Send + Sync {
    /// Hands objects to the server; returns the assigned `server_seq` in input order.
    fn push_objects(&self, objects: Vec<Vec<u8>>) -> Result<Vec<u64>, FfiError>;
    /// Returns everything with `server_seq > cursor` (order not guaranteed — the core sorts).
    fn delta_since(&self, cursor: u64) -> Vec<SyncDeltaItem>;
    /// Reports the maximum assigned `server_seq` (informational, not trusted).
    fn report_version(&self) -> u64;
}

/// Adapter: a foreign `FfiSyncTransport` → `unissh_sync::SyncTransport`. Serializes
/// `SyncObject` to bytes at the FFI boundary and maps errors. A broken object from the delta →
/// is skipped (the engine verifies every object before applying it anyway).
struct ForeignTransportAdapter {
    inner: Arc<dyn FfiSyncTransport>,
    /// The last push error (the callback may throw) — propagated out of sync_push.
    push_err: Mutex<Option<FfiError>>,
}

impl SyncTransport for ForeignTransportAdapter {
    fn push_objects(&mut self, objects: &[SyncObject]) -> Result<Vec<u64>, unissh_sync::SyncError> {
        let mut blobs = Vec::with_capacity(objects.len());
        for o in objects {
            blobs.push(o.to_bytes().map_err(|_| unissh_sync::SyncError::Format)?);
        }
        match self.inner.push_objects(blobs) {
            Ok(seqs) => Ok(seqs),
            Err(e) => {
                *lock_recover(&self.push_err) = Some(e);
                Err(unissh_sync::SyncError::Format)
            }
        }
    }
    fn delta_since(&self, cursor: u64) -> Vec<(u64, SyncObject)> {
        self.inner
            .delta_since(cursor)
            .into_iter()
            .filter_map(|item| {
                SyncObject::from_bytes(&item.object)
                    .ok()
                    .map(|o| (item.server_seq, o))
            })
            .collect()
    }
    fn report_version(&self) -> u64 {
        self.inner.report_version()
    }
}

// === Milestone 2: onboarding Path B (PAKE device-to-device) ===
//
// Design note (uniffi 0.31): `#[uniffi::constructor]` must return
// `Self`/`Arc<Self>`/`Result<Arc<Self>>` — NOT an arbitrary Record. Therefore
// the constructor immediately performs the PAKE step and places the outgoing message (`msg1`/
// `msg2`) INSIDE the handle; the relay blob is exposed via a separate getter `msg()`. This
// is an agreed fallback to the planned "handle + bytes" pair without changing the semantics
// (the messages are still opaque relay blobs; the state is one-shot).

/// Handle of the initiator side of PAKE onboarding (Path B). One-shot: `start` creates
/// the state + `msg1` (getter `msg()`); `Core::onboard_confirm_and_seal`
/// consumes the state.
#[derive(uniffi::Object)]
pub struct OnboardInitiatorHandle {
    inner: Mutex<Option<OnboardInitiator>>,
    msg1: Vec<u8>,
}

#[uniffi::export]
impl OnboardInitiatorHandle {
    /// Starts onboarding on the existing device using the OOB code. Returns a handle
    /// holding the initiator state and `msg1` (obtain it via the getter [`Self::msg`]).
    #[uniffi::constructor]
    pub fn start(code: Vec<u8>) -> Arc<Self> {
        let code = Zeroizing::new(code);
        let (init, msg1) = OnboardInitiator::start(&code);
        Arc::new(OnboardInitiatorHandle {
            inner: Mutex::new(Some(init)),
            msg1,
        })
    }

    /// `msg1` — an opaque relay blob for the responder.
    pub fn msg(&self) -> Vec<u8> {
        self.msg1.clone()
    }
}

/// Handle of the responder side of PAKE onboarding (the new device). One-shot:
/// `respond` creates the state + `msg2` (getter `msg()`); `Core::
/// onboard_finish_install` consumes the state.
#[derive(uniffi::Object)]
pub struct OnboardResponderHandle {
    inner: Mutex<Option<OnboardResponder>>,
    msg2: Vec<u8>,
}

#[uniffi::export]
impl OnboardResponderHandle {
    /// The new device accepts `msg1` via the OOB code and forms `msg2` (relayed
    /// back to the initiator; obtain it via the getter [`Self::msg`]).
    #[uniffi::constructor]
    pub fn respond(code: Vec<u8>, msg1: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        let code = Zeroizing::new(code);
        let (resp, msg2) = OnboardResponder::respond(&code, &msg1).map_err(map_keychain_err)?;
        Ok(Arc::new(OnboardResponderHandle {
            inner: Mutex::new(Some(resp)),
            msg2,
        }))
    }

    /// `msg2` — an opaque relay blob back to the initiator.
    pub fn msg(&self) -> Vec<u8> {
        self.msg2.clone()
    }
}

/// A pool of idle SFTP channels over a SINGLE SSH connection. russh multiplexes
/// many channels over one transport, so parallel file transfers do not
/// require new handshakes/authentications — only new channels.
///
/// Invariant: `created` = idle + leased. Grows lazily up to `max`:
/// the first channel is opened at connect, the rest — on demand. `generation`
/// grows on a full `reconnect()`; a channel of an old generation, when returned from a lease,
/// is not put back into the pool but discarded (its transport is already dead). `closed`
/// (close/Drop) makes a lease fail immediately.
///
/// `max` — the cap on the number of channels (K from settings). It may **decrease** during
/// operation: if the server rejects opening a new channel (e.g. `MaxSessions` →
/// `AdministrativelyProhibited`), the pool shrinks to the actually permitted number and
/// reuses the already-open channels (degrading to a less parallel/
/// sequential mode) instead of failing the transfer.
struct SftpPool {
    idle: Vec<SftpSession>,
    created: usize,
    max: usize,
    generation: u64,
    closed: bool,
}

/// An SFTP connection: a single SSH connection + a channel pool ([`SftpPool`]). Operations
/// lease a channel from the pool, so up to `SftpPool::max` of them run in parallel
/// (the main lever for the "many files" scenario); with `max == 1` the behavior
/// is equivalent to the previous strictly sequential session.
///
/// Channels are closed under `rt.enter()` (in `close`/Drop/on discard): the internal
/// russh channel thread does a `tokio::spawn` on Drop, which needs a runtime
/// context — otherwise a panic on a drop outside the runtime.
#[derive(uniffi::Object)]
pub struct SftpFfi {
    client: Mutex<Option<SshClient>>,
    /// A channel pool + a condition variable for a blocking lease: the lease is called
    /// from Tauri's blocking threads (`spawn_blocking`), so we wait via a `Condvar`,
    /// not via an async semaphore.
    pool: Mutex<SftpPool>,
    pool_cv: Condvar,
    rt: Arc<tokio::runtime::Runtime>,
    // Reconnect inputs (mirror ReconnectingSession): when the whole SSH connection
    // dies on a long-idle session, `reopen()` rebuilds the client from these — a
    // bare channel reopen can't help once the transport itself is gone (russh then
    // surfaces "Channel send error" on every channel_open). `Agent`/`VaultPassword`
    // creds are re-resolved from the vault on each reconnect (plaintext isn't
    // cached); an inline `Password` lives in `auth` for the session's lifetime.
    state: Arc<Mutex<Option<CoreState>>>,
    host: String,
    port: u16,
    user: String,
    auth: AuthMethod,
    jumps: Vec<JumpHost>,
    // Serializes reopen(): two racing callers must not fan out into two full
    // reconnects (would orphan a connection). Mirrors ReconnectingSession.
    reconnect_lock: Mutex<()>,
}

/// Fast-path channel-reopen bound: if the server never OPEN-CONFIRMs (a silently
/// dead TCP with keepalive off never surfaces an error on its own), fail fast and
/// fall through to the timeout-bounded full reconnect instead of hanging forever
/// while holding the session locks.
const REOPEN_CHANNEL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// How many times to retry opening a channel when NOT a single
/// live channel is left in the pool to fall back to, and the server refused a new one. The refusal is usually transient:
/// the session slot of the just-closed (discarded) channel is not yet freed on the
/// server (`MaxSessions` → `AdministrativelyProhibited`). Retries with backoff
/// survive this; a truly dead connection exhausts them and the error surfaces.
const OPEN_RETRY_MAX: u32 = 6;
/// Linear backoff step between open retries (attempt * step). In total, with
/// OPEN_RETRY_MAX=6 the wait is ~0.15+0.3+…+0.9 ≈ 3.1 s before giving up.
const OPEN_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(150);

impl SftpFfi {
    /// Leases a channel from the pool, runs `f`, returns the channel. Up to `SftpPool::max`
    /// operations run in parallel; when saturated it blocks the calling blocking thread
    /// until a channel is freed. The channel is returned to the pool if its thread is not
    /// desynchronized (`!is_poisoned`) and its generation is current — including after
    /// a CLEAN file error. A spoiled one (drop/timeout/interrupted pipeline)
    /// is discarded; the pool self-heals by opening a fresh one on the next lease.
    fn with_sftp<T, F>(&self, f: F) -> Result<T, FfiError>
    where
        F: FnOnce(&Arc<tokio::runtime::Runtime>, &mut SftpSession) -> Result<T, FfiError>,
    {
        let (mut ch, gen) = self.lease()?;
        let r = f(&self.rt, &mut ch);
        // Return the channel to the pool while its thread is NOT desynchronized — even on
        // an operation error. A clean file error (no permission/file, directory already
        // exists) does not spoil the channel, and there's no reason to discard it: it was precisely
        // discarding good channels (with reopening) that created channel churn
        // hitting the server's `MaxSessions`. A spoiled one (drop/timeout/
        // interrupted pipeline) channel is discarded — it cannot be reused.
        let healthy = !ch.is_poisoned();
        self.giveback(ch, gen, healthy);
        r
    }

    /// Blocking channel lease. Returns the channel and its generation (to check
    /// currency on return).
    fn lease(&self) -> Result<(SftpSession, u64), FfiError> {
        let mut open_retries: u32 = 0;
        let mut p = lock_recover(&self.pool);
        loop {
            if p.closed {
                return Err(FfiError::other("sftp session closed"));
            }
            if let Some(ch) = p.idle.pop() {
                return Ok((ch, p.generation));
            }
            if p.created < p.max {
                // We reserve a slot and open the channel OUTSIDE the pool lock: opening does a
                // block_on and locks the client — we must not hold the pool lock at the same time (otherwise
                // we'd serialize all leases for the duration of the open).
                p.created += 1;
                let gen = p.generation;
                drop(p);
                match self.open_channel() {
                    Ok(ch) => return Ok((ch, gen)),
                    Err(e) => {
                        p = lock_recover(&self.pool);
                        p.created -= 1;
                        if p.created > 0 {
                            // There is a live channel to fall back to. The server refused a NEW one
                            // (typically `MaxSessions` → `AdministrativelyProhibited`):
                            // we shrink the cap to the permitted value and reuse
                            // the existing ones — degradation, not a transfer failure. We do NOT wait
                            // here directly: while the channel was being opened (the lock was released),
                            // another thread may have returned its own and its notify went to waste
                            // — we go back to the start of the loop, where idle.pop() under the same
                            // lock either takes a channel or goes into wait without a race.
                            if p.max > p.created {
                                p.max = p.created;
                            }
                            continue;
                        }
                        // Not a single live channel to fall back to. Usually the refusal is transient:
                        // the slot of the just-discarded channel is not yet freed on the
                        // server. We retry opening with backoff; having exhausted the retries (a truly
                        // dead connection) — we return the error.
                        open_retries += 1;
                        if open_retries > OPEN_RETRY_MAX {
                            drop(p);
                            self.pool_cv.notify_one();
                            return Err(e);
                        }
                        drop(p);
                        std::thread::sleep(OPEN_RETRY_BACKOFF * open_retries);
                        p = lock_recover(&self.pool);
                    }
                }
            } else {
                // All channels are created and busy — we wait until someone returns theirs.
                p = self.pool_cv.wait(p).unwrap_or_else(|e| e.into_inner());
            }
        }
    }

    /// Returns the channel to the pool (success) or discards it (error / close /
    /// stale generation), decrementing `created`. In both cases it wakes one
    /// waiter for a lease.
    fn giveback(&self, ch: SftpSession, gen: u64, healthy: bool) {
        let mut p = lock_recover(&self.pool);
        if healthy && !p.closed && gen == p.generation {
            p.idle.push(ch);
            drop(p);
            self.pool_cv.notify_one();
        } else {
            p.created = p.created.saturating_sub(1);
            drop(p);
            self.pool_cv.notify_one();
            // A dead/stale channel is dropped under rt.enter() — the channel teardown
            // does a tokio::spawn.
            let _enter = self.rt.enter();
            drop(ch);
        }
    }

    /// Opens one new SFTP channel on the current connection. block_on must not be called
    /// within a runtime context (panic) — here we are on a blocking thread, there is no context.
    /// Bounded by a timeout: a silently-dead connection (keepalive off, no RST) would otherwise
    /// wait for OPEN-CONFIRM forever.
    fn open_channel(&self) -> Result<SftpSession, FfiError> {
        let client_guard = lock_recover(&self.client);
        let client = client_guard
            .as_ref()
            .ok_or_else(|| FfiError::other("sftp client closed"))?;
        self.rt
            .block_on(async {
                tokio::time::timeout(REOPEN_CHANNEL_TIMEOUT, client.open_sftp()).await
            })
            .map_err(|_| FfiError::other("sftp channel open timed out"))?
            .map_err(map_transport_err)
    }

    /// Full reconnect: rebuilds the SSH connection from the saved parameters
    /// (credentials are re-resolved from the vault). Needed when an idle connection
    /// has died entirely — opening a channel on a dead `Handle` won't help (russh returns
    /// "Channel send error"). Bumps `generation`, so leased channels
    /// of the old generation are discarded on return, and idle channels are dropped here.
    fn reconnect(&self) -> Result<(), FfiError> {
        // Network/handshake outside the runtime context (inside block_on connect_with_state).
        let client = connect_with_state(
            &self.state,
            &self.rt,
            &self.auth,
            &self.jumps,
            self.host.clone(),
            self.port,
            self.user.clone(),
        )?;
        let old_idle = {
            let mut p = lock_recover(&self.pool);
            let old_idle = std::mem::take(&mut p.idle);
            p.created = p.created.saturating_sub(old_idle.len());
            p.generation = p.generation.wrapping_add(1);
            p.closed = false;
            old_idle
        };
        let old_client = lock_recover(&self.client).replace(client);
        // Wake all lease waiters: slots have freed up (created was decremented).
        self.pool_cv.notify_all();
        // The old idle channels and the client are dropped under rt.enter() (teardown → spawn).
        let _enter = self.rt.enter();
        drop(old_idle);
        drop(old_client);
        Ok(())
    }

    /// Closes the pool and the connection: marks `closed`, drops all idle channels
    /// (leased ones will close on return, seeing `closed`) and the client — all under
    /// `rt.enter()`. Shared implementation for [`Self::close`] and `Drop`.
    fn teardown(&self) {
        let _enter = self.rt.enter();
        let old_idle = {
            let mut p = lock_recover(&self.pool);
            p.closed = true;
            let old_idle = std::mem::take(&mut p.idle);
            p.created = p.created.saturating_sub(old_idle.len());
            old_idle
        };
        self.pool_cv.notify_all();
        drop(old_idle);
        let _ = lock_recover(&self.client).take();
    }
}

#[uniffi::export]
impl SftpFfi {
    /// Directory listing.
    pub fn list_dir(&self, path: String) -> Result<Vec<SftpEntry>, FfiError> {
        self.with_sftp(|rt, s| {
            let entries = rt.block_on(s.list_dir(&path)).map_err(map_transport_err)?;
            Ok(entries
                .into_iter()
                .map(|e| SftpEntry {
                    filename: e.filename,
                    is_dir: e.is_dir,
                    size: e.size,
                    mode: e.mode,
                    mtime: e.mtime,
                })
                .collect())
        })
    }

    /// Downloads the whole file.
    pub fn read_file(&self, path: String) -> Result<Vec<u8>, FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.read_file(&path)).map_err(map_transport_err))
    }

    /// Uploads a file (creates/overwrites).
    pub fn write_file(&self, path: String, data: Vec<u8>) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| {
            rt.block_on(s.write_file(&path, &data))
                .map_err(map_transport_err)
        })
    }

    /// Deletes a file.
    pub fn remove(&self, path: String) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.remove(&path)).map_err(map_transport_err))
    }

    /// Creates a directory.
    pub fn mkdir(&self, path: String) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.mkdir(&path)).map_err(map_transport_err))
    }

    /// Resumable download of `remote_path` → local `local_path` from `offset`
    /// (for resuming), with progress and cancellation. Returns `true` if completed;
    /// `false` — if interrupted by cancellation (can be continued from a new offset).
    /// `known_size` — the size of the remote file, if it is already known to the caller
    /// (e.g. from a listing during a recursive folder download): lets the core
    /// skip the `stat` and save a round-trip per file. `None` → the core will do
    /// the `stat` itself.
    pub fn sftp_download(
        &self,
        remote_path: String,
        local_path: String,
        offset: u64,
        known_size: Option<u64>,
        progress: Option<Arc<dyn SftpProgressObserver>>,
        cancel: Option<Arc<CancelToken>>,
    ) -> Result<bool, FfiError> {
        let prog = progress
            .map(|p| Arc::new(ProgressBridge(p)) as Arc<dyn unissh_ssh_transport::SftpProgress>);
        let canc = cancel.map(|c| {
            Arc::new(CancelBridge(c.flag.clone())) as Arc<dyn unissh_ssh_transport::SftpCancel>
        });
        self.with_sftp(move |rt, s| {
            let outcome = rt
                .block_on(s.download_to(&remote_path, &local_path, offset, known_size, prog, canc))
                .map_err(map_transport_err)?;
            Ok(outcome == unissh_ssh_transport::TransferOutcome::Completed)
        })
    }

    /// Resumable upload of local `local_path` → `remote_path` from `offset`,
    /// with progress and cancellation. Does not use TRUNC — resuming does not overwrite the prefix.
    pub fn sftp_upload(
        &self,
        local_path: String,
        remote_path: String,
        offset: u64,
        progress: Option<Arc<dyn SftpProgressObserver>>,
        cancel: Option<Arc<CancelToken>>,
    ) -> Result<bool, FfiError> {
        let prog = progress
            .map(|p| Arc::new(ProgressBridge(p)) as Arc<dyn unissh_ssh_transport::SftpProgress>);
        let canc = cancel.map(|c| {
            Arc::new(CancelBridge(c.flag.clone())) as Arc<dyn unissh_ssh_transport::SftpCancel>
        });
        self.with_sftp(move |rt, s| {
            let outcome = rt
                .block_on(s.upload_from(&local_path, &remote_path, offset, prog, canc))
                .map_err(map_transport_err)?;
            Ok(outcome == unissh_ssh_transport::TransferOutcome::Completed)
        })
    }

    /// Deletes a directory.
    pub fn rmdir(&self, path: String) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.rmdir(&path)).map_err(map_transport_err))
    }

    /// Recursively deletes a directory with all its contents (like `rm -rf`).
    pub fn rmdir_recursive(&self, path: String) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.remove_tree(&path)).map_err(map_transport_err))
    }

    /// Renames/moves.
    pub fn rename(&self, from: String, to: String) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.rename(&from, &to)).map_err(map_transport_err))
    }

    /// chmod: changes the permissions (the low 12 bits of st_mode).
    pub fn chmod(&self, path: String, mode: u32) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.chmod(&path, mode)).map_err(map_transport_err))
    }

    /// stat by path.
    pub fn stat(&self, path: String) -> Result<SftpFileStat, FfiError> {
        self.with_sftp(|rt, s| {
            let st = rt.block_on(s.stat(&path)).map_err(map_transport_err)?;
            Ok(SftpFileStat {
                size: st.size,
                is_dir: st.is_dir,
                mode: st.mode,
                mtime: st.mtime,
            })
        })
    }

    /// Canonicalizes a path.
    pub fn realpath(&self, path: String) -> Result<String, FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.realpath(&path)).map_err(map_transport_err))
    }

    /// Restores a working SFTP session. First it cheaply tries to reopen a
    /// channel over the live connection (the server killed the idle channel); if
    /// the connection itself is dead — the typical case of a long idle when the transport
    /// has already died and russh returns "Channel send error" — it rebuilds the connection from
    /// scratch and opens a new channel. `HostKeyMismatch` is NOT cured by reconnecting
    /// (a possible MITM → stop), it is propagated as-is.
    pub fn reopen(&self) -> Result<(), FfiError> {
        // Serialize concurrent reopens so two racing callers can't each rebuild the
        // connection (one would be orphaned). Held across the whole escalation.
        let _g = lock_recover(&self.reconnect_lock);
        // Fast path: open a fresh channel on the current connection — this is both a check
        // of transport liveness and a "warm-up" of the pool. On success we put it into the pool as idle.
        match self.open_channel() {
            Ok(ch) => {
                let mut p = lock_recover(&self.pool);
                if p.closed {
                    drop(p);
                    let _enter = self.rt.enter();
                    drop(ch);
                    return Ok(());
                }
                p.created += 1;
                p.idle.push(ch);
                drop(p);
                self.pool_cv.notify_one();
                Ok(())
            }
            // The channel didn't open — the connection itself is probably dead: a full reconnect
            // (which also propagates HostKeyMismatch on the rebuild).
            Err(_) => self.reconnect(),
        }
    }

    /// Closes the channel pool and the connection.
    pub fn close(&self) {
        self.teardown();
    }
}

impl Drop for SftpFfi {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// A key identifier in the embedded agent, NAMESPACED by `(vault_id, item_id)`
/// (A4, sec-review): the agent survives vault switches and connects, while item_ids are not
/// unique across vaults (e.g. everyone names a key `id_ed25519`). Without a namespace the second
/// `load` would short-circuit on `contains()` and sign with the WRONG key. The length
/// prefix on vault_id guarantees uniqueness. The same id builds `Auth::Agent`.
fn agent_key_id(vault_id: &str, key_item_id: &str) -> Vec<u8> {
    let v = vault_id.as_bytes();
    let k = key_item_id.as_bytes();
    let mut out = Vec::with_capacity(4 + v.len() + k.len());
    out.extend_from_slice(&(v.len() as u32).to_be_bytes());
    out.extend_from_slice(v);
    out.extend_from_slice(k);
    out
}

fn load_key_into_agent(
    state: &mut CoreState,
    vault_id: &str,
    key_item_id: &str,
) -> Result<(), FfiError> {
    let akid = agent_key_id(vault_id, key_item_id);
    if state.agent.contains(&akid) {
        return Ok(());
    }
    // We fetch the key and (if any) the certificate within a single vault scope,
    // so that the borrow of storage/keyset ends before the &mut agent below.
    let (key_item, cert_str) = {
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, vault_id),
        )
        .map_err(FfiError::other)?;
        let key_item = vault
            .get_item(key_item_id.as_bytes())
            .map_err(FfiError::other)?
            .ok_or(FfiError::NotFound)?;
        let cert_str = vault
            .get_item(cert_item_id(key_item_id).as_bytes())
            .map_err(FfiError::other)?
            .map(|c| String::from_utf8_lossy(c.content.as_slice()).to_string());
        (key_item, cert_str)
    };

    state
        .agent
        .add_from_item(akid.clone(), &key_item)
        .map_err(FfiError::ssh)?;
    if let Some(cert) = cert_str {
        state
            .agent
            .attach_certificate(&akid, &cert)
            .map_err(FfiError::ssh)?;
    }
    Ok(())
}

/// The SQLCipher key is derived from the keyset secrets (an unlock is needed to
/// open the DB). HKDF-SHA256 over the private X25519+Ed25519. All intermediate
/// copies of the secrets and the key itself are in `Zeroizing`, zeroized on exit/Drop.
fn derive_db_key(keyset: &unissh_keychain::UnlockedKeyset) -> Zeroizing<[u8; 32]> {
    let x_secret = Zeroizing::new(keyset.encryption.secret.expose_to_bytes());
    let e_secret = Zeroizing::new(keyset.signing.signing.expose_to_bytes());
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(x_secret.as_ref());
    ikm.extend_from_slice(e_secret.as_ref());

    let hk = Hkdf::<Sha256>::new(Some(b"unissh-db-key-salt-v1"), ikm.as_ref());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"unissh-db-key-v1", key.as_mut())
        .expect("32 is a valid HKDF length");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `derive_escrow_credentials` returns a 256-bit K_auth, a 16-byte salt and the
    /// recommended Argon2id params; and re-deriving K_auth from the RETURNED params
    /// (same salt) + the Secret Key reproduces the same bytes — exactly what a fresh
    /// device does on escrow fetch.
    #[test]
    fn derive_escrow_credentials_shape_and_rederivable() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        let sk_hex = core.create_account(Some("password".into())).unwrap();

        let creds = core
            .derive_escrow_credentials(Some("password".into()), sk_hex.clone())
            .unwrap();

        assert_eq!(creds.k_auth.len(), 32, "K_auth is a 256-bit HKDF output");
        assert_eq!(creds.argon_salt.len(), 16, "fresh 16-byte salt");
        assert_eq!(creds.argon_mem_kib, 65536);
        assert_eq!(creds.argon_iterations, 3);
        assert_eq!(creds.argon_parallelism, 1);

        // Re-derive with the returned params (same salt) → identical K_auth.
        let params = KdfParams {
            mem_kib: creds.argon_mem_kib,
            iterations: creds.argon_iterations,
            parallelism: creds.argon_parallelism,
            salt: creds.argon_salt.clone(),
        };
        let argon_key = derive_key(b"password", &params).unwrap();
        let sk_bytes = hex::decode(sk_hex.trim()).unwrap();
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let rederived = derive_escrow_auth_key(Some(&argon_key), &sk);
        assert_eq!(
            &rederived.expose_bytes()[..],
            &creds.k_auth[..],
            "re-deriving with the returned params reproduces K_auth"
        );
    }

    /// Passwordless (SecretKeyOnly / SSO) accounts pass `password = None`: K_auth is
    /// derived from the Secret Key alone and is still a 256-bit credential.
    #[test]
    fn derive_escrow_credentials_passwordless_returns_k_auth() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        let sk_hex = core.create_account(None).unwrap();

        let creds = core.derive_escrow_credentials(None, sk_hex).unwrap();
        assert_eq!(creds.k_auth.len(), 32);
        assert_eq!(creds.argon_salt.len(), 16);
        assert_eq!(creds.argon_mem_kib, 65536);
    }

    /// Enroll/fetch symmetry: the `K_auth` minted by `derive_escrow_credentials`
    /// (fresh params) is reproduced BIT-FOR-BIT by `derive_escrow_auth_with_params`
    /// fed those SAME params — exactly what a fresh device does on escrow fetch after
    /// reading the stored params from `GET /v1/escrow/params`. This is the invariant
    /// the server relies on (it gates the fetch on `sha256(K_auth)`).
    #[test]
    fn escrow_enroll_fetch_kauth_symmetry() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        let sk_hex = core.create_account(Some("hunter2".into())).unwrap();

        // ENROLL: mint fresh params + K_auth (what server_keyset_push uploads).
        let creds = core
            .derive_escrow_credentials(Some("hunter2".into()), sk_hex.clone())
            .unwrap();

        // FETCH: re-derive K_auth from the SAME params (what the server echoes back).
        let refetched = core
            .derive_escrow_auth_with_params(
                Some("hunter2".into()),
                sk_hex.clone(),
                creds.argon_salt.clone(),
                creds.argon_mem_kib,
                creds.argon_iterations,
                creds.argon_parallelism,
            )
            .unwrap();
        assert_eq!(
            refetched, creds.k_auth,
            "enroll and fetch must derive the same K_auth"
        );

        // A wrong password must NOT reproduce K_auth (the server fetch would 403).
        let wrong = core
            .derive_escrow_auth_with_params(
                Some("wrong".into()),
                sk_hex,
                creds.argon_salt.clone(),
                creds.argon_mem_kib,
                creds.argon_iterations,
                creds.argon_parallelism,
            )
            .unwrap();
        assert_ne!(
            wrong, creds.k_auth,
            "a wrong password must not reproduce K_auth"
        );
    }

    /// Passwordless (SSO) symmetry: with `password = None`, `K_auth` derives from the
    /// Secret Key alone and the params-taking variant reproduces it regardless of the
    /// (ignored) Argon2id params.
    #[test]
    fn escrow_passwordless_kauth_symmetry() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        let sk_hex = core.create_account(None).unwrap();
        let creds = core
            .derive_escrow_credentials(None, sk_hex.clone())
            .unwrap();
        let refetched = core
            .derive_escrow_auth_with_params(
                None,
                sk_hex,
                creds.argon_salt.clone(),
                creds.argon_mem_kib,
                creds.argon_iterations,
                creds.argon_parallelism,
            )
            .unwrap();
        assert_eq!(refetched, creds.k_auth);
    }

    #[test]
    fn backup_keyset_sidecar_copies_and_is_noop_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyset");
        let bak = {
            let mut p = path.as_os_str().to_owned();
            p.push(".pre-migration.bak");
            std::path::PathBuf::from(p)
        };
        // No sidecar → no-op (no panic, no .bak).
        backup_keyset_sidecar(&path);
        assert!(!bak.exists(), "no backup if there is no sidecar yet");
        // A sidecar exists → a .bak is created with the same content.
        std::fs::write(&path, b"OLD-KEYSET-BLOB").unwrap();
        backup_keyset_sidecar(&path);
        assert_eq!(std::fs::read(&bak).unwrap(), b"OLD-KEYSET-BLOB");
    }

    #[test]
    fn account_state_payload_roundtrip_and_reject_malformed() {
        let p = AccountStatePayload {
            personal_vault_id: vec![1, 2, 3, 4],
            default_username: "deploy".into(),
        };
        let dec = AccountStatePayload::decode(&p.encode()).unwrap();
        assert_eq!(dec.personal_vault_id, p.personal_vault_id);
        assert_eq!(dec.default_username, "deploy");

        // Empty fields = "not set".
        let de = AccountStatePayload::decode(&AccountStatePayload::default().encode()).unwrap();
        assert!(de.personal_vault_id.is_empty() && de.default_username.is_empty());

        // Broken input is rejected (does not panic).
        assert!(AccountStatePayload::decode(&[0, 0, 0, 9, 1, 2, 3]).is_err()); // len>data
        assert!(AccountStatePayload::decode(&[]).is_err());
        let mut trailing = p.encode();
        trailing.push(0xFF);
        assert!(AccountStatePayload::decode(&trailing).is_err());
    }

    #[test]
    fn agent_key_id_namespaces_by_vault_and_item() {
        // The same item_id in DIFFERENT vaults → different agent-ids (no aliasing).
        assert_ne!(
            agent_key_id("vaultA", "id_ed25519"),
            agent_key_id("vaultB", "id_ed25519")
        );
        // One pair → one id (load and Auth::Agent match).
        assert_eq!(agent_key_id("v", "k"), agent_key_id("v", "k"));
        // The length prefix rules out concatenation: ("v","aultk") != ("va","ultk").
        assert_ne!(agent_key_id("v", "aultk"), agent_key_id("va", "ultk"));
    }

    /// Regression (A4a namespace): delete_item and replacing key material MUST
    /// unload the private key from the in-memory agent under the same namespaced key
    /// agent_key_id(vault,item) it was loaded with — otherwise remove is a no-op and
    /// a revoked/replaced key stays alive and signing until the end of the session.
    #[test]
    fn revoking_key_evicts_it_from_agent() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();

        // delete_item unloads the loaded key.
        core.generate_ssh_key("v".into(), "k".into()).unwrap();
        let akid = agent_key_id("v", "k");
        {
            let mut guard = core.locked_state();
            load_key_into_agent(guard.as_mut().unwrap(), "v", "k").unwrap();
            assert!(
                guard.as_ref().unwrap().agent.contains(&akid),
                "the key is loaded under the namespaced id"
            );
        }
        core.delete_item("v".into(), "k".into()).unwrap();
        assert!(
            !core.locked_state().as_ref().unwrap().agent.contains(&akid),
            "delete_item must unload the key from the agent (otherwise revocation is bypassed)"
        );

        // Replacing the material under the same id (generate over it) also unloads the old one.
        core.generate_ssh_key("v".into(), "k2".into()).unwrap();
        let akid2 = agent_key_id("v", "k2");
        {
            let mut guard = core.locked_state();
            load_key_into_agent(guard.as_mut().unwrap(), "v", "k2").unwrap();
            assert!(guard.as_ref().unwrap().agent.contains(&akid2));
        }
        core.generate_ssh_key("v".into(), "k2".into()).unwrap();
        assert!(
            !core.locked_state().as_ref().unwrap().agent.contains(&akid2),
            "replacing the material must unload the previous key"
        );
    }

    /// #9: a repeated import_ssh_config preserves the profile's immutable uid —
    /// bindings and hop_refs are tied to it, a fresh uid on overwrite
    /// would orphan them.
    #[test]
    fn import_ssh_config_preserves_uid_on_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();

        core.import_ssh_config(
            "v".into(),
            "Host web\n  HostName web.example\n  Port 22\n  User deploy\n".into(),
        )
        .unwrap();
        let uid1 = core.get_connection("v".into(), "web".into()).unwrap().uid;
        assert!(!uid1.is_empty());

        // Overwriting with the same alias (the port changed) — the uid must be preserved.
        core.import_ssh_config(
            "v".into(),
            "Host web\n  HostName web.example\n  Port 2222\n  User deploy\n".into(),
        )
        .unwrap();
        let p2 = core.get_connection("v".into(), "web".into()).unwrap();
        assert_eq!(p2.uid, uid1, "the uid is preserved on overwrite (#9)");
        assert_eq!(p2.port, 2222, "the other fields were updated");
    }

    /// A legacy profile (before password items): `key_item_id` as a flat field, and for a jump —
    /// as a mandatory string (possibly empty). Must be readable without migration.
    #[test]
    fn legacy_stored_profile_deserializes() {
        let legacy = r#"{
            "label":"L","host":"h","port":22,"user":"u",
            "key_item_id":"k1",
            "jumps":[{"host":"j","port":2200,"user":"ju","key_item_id":"k2"},
                     {"host":"j2","port":22,"user":"","key_item_id":""}]
        }"#;
        let stored: StoredProfile = serde_json::from_str(legacy).unwrap();
        let prof = stored_to_profile("vaultA", "p1".to_string(), stored);
        assert!(matches!(
            &prof.auth,
            ProfileAuth::Key { key_item_id } if key_item_id == "k1"
        ));
        // A profile's hop is vault-qualified by the profile's vault.
        assert!(matches!(
            &prof.jumps[0].auth,
            AuthMethod::Agent { vault_id, key_item_id } if vault_id == "vaultA" && key_item_id == "k2"
        ));
        // an empty key_item_id (ssh-config import) — the "not assigned" semantics
        assert!(matches!(
            &prof.jumps[1].auth,
            AuthMethod::Agent { vault_id, key_item_id } if vault_id == "vaultA" && key_item_id.is_empty()
        ));

        // a legacy "password" profile: key_item_id = null → prompt at connect time
        let legacy_pw = r#"{"label":"L","host":"h","port":22,"user":"u",
                            "key_item_id":null,"jumps":[]}"#;
        let stored: StoredProfile = serde_json::from_str(legacy_pw).unwrap();
        let prof = stored_to_profile("vaultA", "p2".to_string(), stored);
        assert!(matches!(prof.auth, ProfileAuth::PromptPassword));
    }

    /// New format: a reference to a password item takes priority over a key and survives
    /// a round-trip serialization.
    #[test]
    fn vault_password_profile_roundtrip() {
        let prof = ConnectionProfile {
            profile_id: "p".to_string(),
            uid: "uid-fixed".to_string(),
            label: "L".to_string(),
            host: "h".to_string(),
            port: 22,
            user: "u".to_string(),
            auth: ProfileAuth::VaultPassword {
                password_item_id: "pw1".to_string(),
            },
            username_template: None,
            jumps: vec![JumpHost {
                host: "j".to_string(),
                port: 22,
                user: "ju".to_string(),
                auth: AuthMethod::VaultPassword {
                    vault_id: "vp".to_string(),
                    password_item_id: "pw2".to_string(),
                },
                hop_ref: None,
            }],
            tags: vec!["prod".to_string()],
        };
        let (key_item_id, password_item_id) = match prof.auth.clone() {
            ProfileAuth::Key { key_item_id } => (Some(key_item_id), None),
            ProfileAuth::VaultPassword { password_item_id } => (None, Some(password_item_id)),
            ProfileAuth::PromptPassword | ProfileAuth::Personal => (None, None),
        };
        let stored = StoredProfile {
            uid: Some(prof.uid.clone()),
            label: prof.label.clone(),
            host: prof.host.clone(),
            port: prof.port,
            user: prof.user.clone(),
            key_item_id,
            password_item_id,
            personal: false,
            username_template: None,
            jumps: prof
                .jumps
                .clone()
                .into_iter()
                .map(|j| jump_to_stored(j).unwrap())
                .collect(),
            tags: prof.tags.clone(),
            extra: std::collections::BTreeMap::new(),
        };
        let json = serde_json::to_string(&stored).unwrap();
        let back: StoredProfile = serde_json::from_str(&json).unwrap();
        let prof2 = stored_to_profile("vp", "p".to_string(), back);
        assert!(matches!(
            &prof2.auth,
            ProfileAuth::VaultPassword { password_item_id } if password_item_id == "pw1"
        ));
        // The hop is restored with the profile's vault (vault-relative storage).
        assert!(matches!(
            &prof2.jumps[0].auth,
            AuthMethod::VaultPassword { vault_id, password_item_id }
                if vault_id == "vp" && password_item_id == "pw2"
        ));
        // The uid survives the round-trip (not re-minted when reading a saved one).
        assert_eq!(prof2.uid, "uid-fixed");
        assert_eq!(prof2.tags, vec!["prod".to_string()]);
    }

    /// An inline password in a jump host is not serialized into a profile — an error.
    #[test]
    fn inline_jump_password_is_rejected() {
        let jump = JumpHost {
            host: "j".to_string(),
            port: 22,
            user: "u".to_string(),
            auth: AuthMethod::Password {
                password: "sekret".to_string(),
            },
            hop_ref: None,
        };
        assert!(jump_to_stored(jump).is_err());
    }

    /// A4b: a profile's credential reference gets the `vault_id` of the vault where the
    /// profile lives — so the target and hops can resolve against DIFFERENT vaults.
    #[test]
    fn profile_auth_is_vault_qualified() {
        assert!(matches!(
            profile_auth_to_method("teamvault", ProfileAuth::Key { key_item_id: "k".into() }),
            AuthMethod::Agent { vault_id, key_item_id } if vault_id == "teamvault" && key_item_id == "k"
        ));
        assert!(matches!(
            profile_auth_to_method(
                "personal",
                ProfileAuth::VaultPassword { password_item_id: "pw".into() }
            ),
            AuthMethod::VaultPassword { vault_id, password_item_id }
                if vault_id == "personal" && password_item_id == "pw"
        ));
        // PromptPassword is not tied to a vault (inline, prompted at connect time).
        assert!(matches!(
            profile_auth_to_method("any", ProfileAuth::PromptPassword),
            AuthMethod::Password { password } if password.is_empty()
        ));
    }

    /// B2.2: a hop's host-chain reference survives jump_to_stored → stored_to_profile.
    #[test]
    fn hop_ref_roundtrip() {
        let j = JumpHost {
            host: String::new(),
            port: 0,
            user: String::new(),
            auth: AuthMethod::Agent {
                vault_id: String::new(),
                key_item_id: String::new(),
            },
            hop_ref: Some(HopRef {
                vault_id: "teamvault".into(),
                profile_uid: "uid-bastion".into(),
            }),
        };
        let stored = jump_to_stored(j).unwrap();
        assert!(stored.hop_ref.is_some());
        let sp = StoredProfile {
            uid: Some("u".into()),
            label: "L".into(),
            host: "h".into(),
            port: 22,
            user: "x".into(),
            key_item_id: None,
            password_item_id: None,
            personal: false,
            username_template: None,
            jumps: vec![stored],
            tags: vec![],
            extra: std::collections::BTreeMap::new(),
        };
        let prof = stored_to_profile("va", "p".into(), sp);
        let hr = prof.jumps[0].hop_ref.as_ref().unwrap();
        assert_eq!(hr.vault_id, "teamvault");
        assert_eq!(hr.profile_uid, "uid-bastion");
    }

    /// B2.2: resolve_profile_by_uid finds a bastion profile by its uid.
    #[test]
    fn resolve_profile_by_uid_finds_bastion() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();
        core.save_connection(
            "v".into(),
            ConnectionProfile {
                profile_id: "bastion".into(),
                uid: String::new(),
                label: "B".into(),
                host: "gw.example".into(),
                port: 2222,
                user: "jump".into(),
                auth: ProfileAuth::PromptPassword,
                username_template: None,
                jumps: vec![],
                tags: vec![],
            },
        )
        .unwrap();
        let bastion = core.get_connection("v".into(), "bastion".into()).unwrap();
        // We find the bastion by uid.
        {
            let guard = core.locked_state();
            let state = guard.as_ref().unwrap();
            let found = resolve_profile_by_uid(state, "v", &bastion.uid).unwrap();
            assert_eq!(found.host, "gw.example");
            assert_eq!(found.port, 2222);
            assert_eq!(found.user, "jump");
        }
        // An unknown uid → NotFound.
        {
            let guard = core.locked_state();
            let state = guard.as_ref().unwrap();
            assert!(resolve_profile_by_uid(state, "v", "nope").is_err());
        }
    }

    /// B1: the identity body round-trips through serialization; missing
    /// optional references read as `None` (forward compatibility).
    #[test]
    fn stored_identity_roundtrip_and_into() {
        let stored = StoredIdentity {
            label: "Prod login".into(),
            user: "alice".into(),
            key_item_id: Some("id_ed25519".into()),
            password_item_id: None,
            extra: std::collections::BTreeMap::new(),
        };
        let json = serde_json::to_string(&stored).unwrap();
        let back: StoredIdentity = serde_json::from_str(&json).unwrap();
        let id = back.into_identity("ident1".into());
        assert_eq!(id.identity_id, "ident1");
        assert_eq!(id.user, "alice");
        assert_eq!(id.key_item_id.as_deref(), Some("id_ed25519"));
        assert!(id.password_item_id.is_none());
        // a minimal body (no references) — both references None.
        let minimal = r#"{"label":"L","user":"bob"}"#;
        let m: StoredIdentity = serde_json::from_str(minimal).unwrap();
        assert!(m.key_item_id.is_none() && m.password_item_id.is_none());
    }

    /// B2: a profile's uid. The legacy fallback is deterministic (stable across
    /// devices and calls); a freshly minted one is unique and non-empty.
    #[test]
    fn profile_uid_legacy_deterministic_and_mint_unique() {
        let a = legacy_profile_uid("vault1", "prod-web");
        assert_eq!(a, legacy_profile_uid("vault1", "prod-web"));
        assert_eq!(a.len(), 32); // 16 bytes in hex
                                 // The length prefix on vault_id rules out concatenation of adjacent fields.
        assert_ne!(
            legacy_profile_uid("vault1", "prod-web"),
            legacy_profile_uid("vault", "1prod-web")
        );
        assert_ne!(
            legacy_profile_uid("vault1", "prod-web"),
            legacy_profile_uid("vault1", "prod-db")
        );
        // Mint: non-empty, unique between calls (with overwhelming probability).
        let m1 = mint_profile_uid();
        assert_eq!(m1.len(), 32);
        assert_ne!(m1, mint_profile_uid());
    }

    /// B3.1: anti-redirect logic. A destination mismatch is NEVER silently
    /// "learned" — always `Redirected` (an explicit re-bind is required).
    #[test]
    fn resolve_binding_anti_redirect() {
        let b = IdentityBinding {
            team_vault_id: "team".into(),
            profile_uid: "uid1".into(),
            identity_item_id: "ident1".into(),
            destination_pin: "prod-web:22".into(),
        };
        // No binding → fallback.
        assert_eq!(
            resolve_binding(None, "prod-web:22"),
            BindingResolution::Unbound
        );
        // Matched → one may log in with the personal identity.
        assert_eq!(
            resolve_binding(Some(&b), "prod-web:22"),
            BindingResolution::Matched {
                identity_item_id: "ident1".into()
            }
        );
        // The host was re-pointed (host in-place) → refusal, not a silent re-send of credentials.
        assert_eq!(
            resolve_binding(Some(&b), "evil-host:22"),
            BindingResolution::Redirected {
                pinned: "prod-web:22".into(),
                current: "evil-host:22".into()
            }
        );
        // A port change also counts as a redirect.
        assert!(matches!(
            resolve_binding(Some(&b), "prod-web:2222"),
            BindingResolution::Redirected { .. }
        ));
    }

    /// B3.1: a binding's item_id is derived from (team_vault_id, profile_uid) and
    /// does not concatenate adjacent fields (length prefix).
    #[test]
    fn binding_item_id_deterministic_and_unambiguous() {
        assert_eq!(
            binding_item_id("team", "uid1"),
            binding_item_id("team", "uid1")
        );
        assert_ne!(
            binding_item_id("team", "uid1"),
            binding_item_id("team", "uid2")
        );
        // ("team","1uid1") != ("team1","uid1") — thanks to the len prefix.
        assert_ne!(
            binding_item_id("team", "1uid1"),
            binding_item_id("team1", "uid1")
        );
        assert!(binding_item_id("team", "uid1").starts_with("binding:"));
    }

    /// B3.1: the binding body survives a round-trip serialization.
    #[test]
    fn stored_binding_roundtrip() {
        let stored = StoredBinding {
            team_vault_id: "team".into(),
            profile_uid: "uid1".into(),
            identity_item_id: "ident1".into(),
            destination_pin: "h:22".into(),
            extra: std::collections::BTreeMap::new(),
        };
        let json = serde_json::to_string(&stored).unwrap();
        let back: StoredBinding = serde_json::from_str(&json).unwrap();
        let b = back.into_binding();
        assert_eq!(b.team_vault_id, "team");
        assert_eq!(b.profile_uid, "uid1");
        assert_eq!(b.identity_item_id, "ident1");
        assert_eq!(b.destination_pin, "h:22");
    }

    /// B7: forward-compat. An unknown field (from a future version) is captured in
    /// `extra` and survives deserialize→serialize; an empty `extra` adds no
    /// keys (existing signed items do not change byte-for-byte).
    #[test]
    fn stored_profile_preserves_unknown_fields() {
        let json = r#"{"uid":"u","label":"L","host":"h","port":22,"user":"x",
                       "jumps":[],"tags":[],"future_field":"keep","future_num":7}"#;
        let sp: StoredProfile = serde_json::from_str(json).unwrap();
        assert_eq!(
            sp.extra.get("future_field").and_then(|v| v.as_str()),
            Some("keep")
        );
        assert_eq!(sp.extra.get("future_num").and_then(|v| v.as_i64()), Some(7));
        let out = serde_json::to_string(&sp).unwrap();
        assert!(out.contains("future_field") && out.contains("future_num"));
        // Empty extra → no extra keys.
        let sp0: StoredProfile = serde_json::from_str(
            r#"{"label":"L","host":"h","port":22,"user":"x","jumps":[],"tags":[]}"#,
        )
        .unwrap();
        assert!(sp0.extra.is_empty());
        assert!(!serde_json::to_string(&sp0).unwrap().contains("extra"));
    }

    /// B7: an edit of a profile by a client that does NOT know a future-version field PRESERVES it
    /// (merge-on-save) — no silent LWW downgrade.
    #[test]
    fn save_connection_preserves_future_fields_on_edit() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();
        core.save_connection(
            "v".into(),
            ConnectionProfile {
                profile_id: "p".into(),
                uid: String::new(),
                label: "L".into(),
                host: "h".into(),
                port: 22,
                user: "x".into(),
                auth: ProfileAuth::PromptPassword,
                username_template: None,
                jumps: vec![],
                tags: vec![],
            },
        )
        .unwrap();
        // We inject a "future-version field" straight into the saved JSON (like a newer
        // client), bypassing the public API.
        let read_future = || -> Option<String> {
            let mut guard = core.locked_state();
            let st = guard.as_mut().unwrap();
            let vid = resolve_vid(&st.storage, "v");
            let vault = Vault::open(&st.storage, &st.keyset, &vid).unwrap();
            let item = vault.get_item(b"p").unwrap().unwrap();
            let sp: StoredProfile = serde_json::from_slice(&item.content).unwrap();
            sp.extra
                .get("future")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        {
            let mut guard = core.locked_state();
            let st = guard.as_mut().unwrap();
            let vid = resolve_vid(&st.storage, "v");
            let vault = Vault::open(&st.storage, &st.keyset, &vid).unwrap();
            let item = vault.get_item(b"p").unwrap().unwrap();
            let mut sp: StoredProfile = serde_json::from_slice(&item.content).unwrap();
            sp.extra.insert("future".into(), serde_json::json!("keep"));
            let json = serde_json::to_vec(&sp).unwrap();
            vault.put_item(b"p", ITEM_TYPE_CONNECTION, &json).unwrap();
        }
        assert_eq!(read_future(), Some("keep".to_string()));
        // The current client (which doesn't know "future") edits the profile.
        let mut p = core.get_connection("v".into(), "p".into()).unwrap();
        p.label = "renamed".into();
        core.save_connection("v".into(), p).unwrap();
        // The field survived the edit.
        assert_eq!(read_future(), Some("keep".to_string()));
    }

    /// B3.1/B3.2: binding CRUD against a live Core + first-bind guard (a silent
    /// re-pin to a different destination without allow_rebind is rejected).
    #[test]
    fn binding_crud_and_first_bind_guard() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("personal".into(), "Personal".into())
            .unwrap();
        let b = IdentityBinding {
            team_vault_id: "team".into(),
            profile_uid: "uid1".into(),
            identity_item_id: "ident1".into(),
            destination_pin: "prod-web:22".into(),
        };
        // The first binding — ok.
        core.set_binding("personal".into(), b.clone(), false)
            .unwrap();
        let got = core
            .get_binding("personal".into(), "team".into(), "uid1".into())
            .unwrap()
            .unwrap();
        assert_eq!(got.identity_item_id, "ident1");
        assert_eq!(got.destination_pin, "prod-web:22");
        // An idempotent re-pin (the same destination, changing only the identity) —
        // ok without the flag.
        let mut b2 = b.clone();
        b2.identity_item_id = "ident2".into();
        core.set_binding("personal".into(), b2, false).unwrap();
        // A re-pin to a DIFFERENT destination without allow_rebind — refused.
        let mut b3 = b.clone();
        b3.destination_pin = "evil:22".into();
        assert!(core
            .set_binding("personal".into(), b3.clone(), false)
            .is_err());
        // With allow_rebind=true — ok.
        core.set_binding("personal".into(), b3, true).unwrap();
        // resolve_host_binding reflects the pin: matched → Matched, otherwise → Redirected.
        assert!(matches!(
            core.resolve_host_binding(
                "personal".into(),
                "team".into(),
                "uid1".into(),
                "evil:22".into()
            )
            .unwrap(),
            BindingResolution::Matched { .. }
        ));
        assert!(matches!(
            core.resolve_host_binding(
                "personal".into(),
                "team".into(),
                "uid1".into(),
                "prod-web:22".into()
            )
            .unwrap(),
            BindingResolution::Redirected { .. }
        ));
        assert_eq!(core.list_bindings("personal".into()).unwrap().len(), 1);
        // Deletion.
        core.delete_binding("personal".into(), "team".into(), "uid1".into())
            .unwrap();
        assert!(core
            .get_binding("personal".into(), "team".into(), "uid1".into())
            .unwrap()
            .is_none());
    }

    /// Username template: `%u` → the identity's username; the template is part of the destination pin
    /// (editing the template → changing the destination → anti-redirect). Gateway-agnostic.
    #[test]
    fn username_template_render_destination_and_username() {
        let nj: &[JumpHost] = &[];
        // Without a template: plain host:port and the base username.
        assert_eq!(personal_destination("h", 22, None, nj), "h:22");
        assert_eq!(personal_destination("h", 22, Some(""), nj), "h:22");
        assert_eq!(apply_username_template("alice", None), "alice");
        // With a template: it is part of the destination, and %u expands into the username.
        assert_eq!(
            personal_destination("gw", 22, Some("%u:prod-db"), nj),
            "gw:22#%u:prod-db"
        );
        assert_eq!(
            apply_username_template("alice", Some("%u:prod-db")),
            "alice:prod-db"
        );
        // A different gateway format also works (not only warpgate `:`).
        assert_eq!(
            apply_username_template("alice", Some("%u@edge")),
            "alice@edge"
        );
        // Different templates → different destinations (an edit is caught by anti-redirect).
        assert_ne!(
            personal_destination("gw", 22, Some("%u:prod-db"), nj),
            personal_destination("gw", 22, Some("%u:prod-web"), nj)
        );
        // trim at the edges.
        assert_eq!(apply_username_template("alice", Some("  %u:x ")), "alice:x");

        // Anti-redirect over the JUMP CHAIN (#1): inserting a jump changes the destination
        // even with the same host:port — otherwise an admin could siphon off the personal credential via
        // a MITM hop. A host without jumps yields the previous string (backward compatibility).
        let jump = JumpHost {
            host: "attacker.com".into(),
            port: 22,
            user: "x".into(),
            auth: AuthMethod::Agent {
                vault_id: "v".into(),
                key_item_id: "k".into(),
            },
            hop_ref: None,
        };
        assert_eq!(personal_destination("h", 22, None, nj), "h:22");
        assert_ne!(
            personal_destination("h", 22, None, nj),
            personal_destination("h", 22, None, std::slice::from_ref(&jump)),
            "the appearance of a jump must change the pin (fail-safe anti-redirect)"
        );
        assert!(
            personal_destination("h", 22, None, std::slice::from_ref(&jump))
                .starts_with("h:22|via=")
        );
    }

    /// B4: the username chain. The first non-empty (trimmed) of
    /// identity → profile fallback → account-default.
    #[test]
    fn pick_username_chain() {
        assert_eq!(pick_username("alice", "prof", Some("acct")), "alice");
        assert_eq!(pick_username("  ", "prof", Some("acct")), "prof");
        assert_eq!(pick_username("", "", Some("acct")), "acct");
        assert_eq!(pick_username("", "", None), "");
        assert_eq!(pick_username("", "", Some("  ")), "");
    }

    /// Co-location / multi-vault: the identity + binding may live in ANY private
    /// vault, NOT in the "personal" pointer (which we don't set here at all). resolve searches across
    /// the account's vaults and finds it — this way different hosts log in from different vaults.
    #[test]
    fn resolve_personal_auth_finds_binding_in_any_private_vault() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        // A working private vault — NOT assigned as the personal one (we don't call set_personal_vault).
        let work = "aabbccddeeff00112233445566778899";
        core.create_vault(work.into(), "Work".into()).unwrap();
        core.save_identity(
            work.into(),
            Identity {
                identity_id: "work-id".into(),
                label: "Work".into(),
                user: "alice-work".into(),
                key_item_id: Some("workkey".into()),
                password_item_id: None,
            },
        )
        .unwrap();
        core.set_binding(
            work.into(),
            IdentityBinding {
                team_vault_id: "team".into(),
                profile_uid: "uidW".into(),
                identity_item_id: "work-id".into(),
                destination_pin: "corp:22".into(),
            },
            false,
        )
        .unwrap();
        let pa = core
            .resolve_personal_auth("team".into(), "uidW".into(), "corp:22".into(), "fb".into())
            .unwrap();
        assert_eq!(pa.user, "alice-work");
        match &pa.auth {
            AuthMethod::Agent {
                vault_id,
                key_item_id,
            } => {
                assert_eq!(
                    vault_id, work,
                    "creds from the Work vault, not a 'personal' one"
                );
                assert_eq!(key_item_id, "workkey");
            }
            _ => panic!("expected Agent auth"),
        }
    }

    /// B4: resolve_personal_auth unwraps the personal credential ONLY for
    /// the pinned destination; on a redirect/without a binding — an error (the credential does not
    /// go to a re-pointed host).
    #[test]
    fn resolve_personal_auth_enforces_anti_redirect() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        // The personal vault is a cloud vault (hex id); set_personal_vault expects hex.
        let pv = "00112233445566778899aabbccddeeff";
        core.create_vault(pv.into(), "Personal".into()).unwrap();
        core.set_personal_vault(pv.into()).unwrap();
        core.save_identity(
            pv.into(),
            Identity {
                identity_id: "ident1".into(),
                label: "L".into(),
                user: "alice".into(),
                key_item_id: Some("mykey".into()),
                password_item_id: None,
            },
        )
        .unwrap();
        core.set_binding(
            pv.into(),
            IdentityBinding {
                team_vault_id: "team".into(),
                profile_uid: "uid1".into(),
                identity_item_id: "ident1".into(),
                destination_pin: "prod-web:22".into(),
            },
            false,
        )
        .unwrap();
        // The destination matched → the personal credential + the username from the identity.
        let pa = core
            .resolve_personal_auth(
                "team".into(),
                "uid1".into(),
                "prod-web:22".into(),
                "fallbackuser".into(),
            )
            .unwrap();
        assert_eq!(pa.user, "alice");
        if let AuthMethod::Agent {
            vault_id,
            key_item_id,
        } = &pa.auth
        {
            assert_eq!(vault_id.as_str(), pv);
            assert_eq!(key_item_id.as_str(), "mykey");
        } else {
            panic!("expected Agent auth from personal vault");
        }
        // The host was re-pointed → ERROR (the credential is not unwrapped for the wrong host).
        assert!(core
            .resolve_personal_auth(
                "team".into(),
                "uid1".into(),
                "evil:22".into(),
                "fallbackuser".into(),
            )
            .is_err());
        // No binding for this uid → the error "linking is required".
        assert!(core
            .resolve_personal_auth(
                "team".into(),
                "uid-unbound".into(),
                "prod-web:22".into(),
                "fallbackuser".into(),
            )
            .is_err());
    }

    /// B4.3-fix: a Personal host does NOT go into fan-out with an empty password — it is excluded
    /// from the tag and group paths (otherwise there would be a live connect without a binding/anti-redirect).
    #[test]
    fn personal_host_excluded_from_fanout() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();
        let mk = |id: &str, host: &str, auth: ProfileAuth| ConnectionProfile {
            profile_id: id.into(),
            uid: String::new(),
            label: id.into(),
            host: host.into(),
            port: 22,
            user: "u".into(),
            auth,
            username_template: None,
            jumps: vec![],
            tags: vec!["prod".into()],
        };
        core.save_connection("v".into(), mk("personal-host", "gw", ProfileAuth::Personal))
            .unwrap();
        core.save_connection(
            "v".into(),
            mk(
                "key-host",
                "web",
                ProfileAuth::Key {
                    key_item_id: "k".into(),
                },
            ),
        )
        .unwrap();
        // Tag fan-out: Personal is excluded → only the key host among the targets.
        let targets = core
            .select_targets_by_tags("v".into(), vec!["prod".into()], false)
            .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "web");
        // Group fan-out: the dry-run marks a Personal member with the Personal status (excluded).
        core.save_group(
            "v".into(),
            ServerGroup {
                group_id: "g".into(),
                label: "G".into(),
                member_ids: vec!["personal-host".into(), "key-host".into()],
                parent_id: None,
            },
        )
        .unwrap();
        let plans = core.dry_run_group("v".into(), "g".into()).unwrap();
        let personal = plans
            .iter()
            .find(|p| p.member_id == "personal-host")
            .unwrap();
        assert_eq!(personal.status, ResolveStatus::Personal);
        let keyh = plans.iter().find(|p| p.member_id == "key-host").unwrap();
        assert_eq!(keyh.status, ResolveStatus::Ok);
    }

    /// B6: a BOUND Personal host makes it into fan-out with the RESOLVED user+auth
    /// (the personal identity from the binding); an unbound one is excluded.
    #[test]
    fn personal_host_bound_included_in_fanout() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "Team".into()).unwrap();
        let pv = "00112233445566778899aabbccddeeff";
        core.create_vault(pv.into(), "Personal".into()).unwrap();
        core.set_personal_vault(pv.into()).unwrap();
        core.save_identity(
            pv.into(),
            Identity {
                identity_id: "ident1".into(),
                label: "L".into(),
                user: "alice".into(),
                key_item_id: Some("k".into()),
                password_item_id: None,
            },
        )
        .unwrap();
        let mk = |id: &str, host: &str, auth: ProfileAuth| ConnectionProfile {
            profile_id: id.into(),
            uid: String::new(),
            label: id.into(),
            host: host.into(),
            port: 22,
            user: "u".into(),
            auth,
            username_template: None,
            jumps: vec![],
            tags: vec!["prod".into()],
        };
        core.save_connection("v".into(), mk("personal-host", "gw", ProfileAuth::Personal))
            .unwrap();
        core.save_connection(
            "v".into(),
            mk(
                "key-host",
                "web",
                ProfileAuth::Key {
                    key_item_id: "kk".into(),
                },
            ),
        )
        .unwrap();
        // Bind the personal identity to the Personal host (the pin = its destination).
        let ph = core
            .get_connection("v".into(), "personal-host".into())
            .unwrap();
        let dest = core.personal_destination(
            ph.host.clone(),
            ph.port,
            ph.username_template.clone(),
            ph.jumps.clone(),
        );
        core.set_binding(
            pv.into(),
            IdentityBinding {
                team_vault_id: "v".into(),
                profile_uid: ph.uid.clone(),
                identity_item_id: "ident1".into(),
                destination_pin: dest,
            },
            false,
        )
        .unwrap();
        // Tag fan-out: the bound Personal host is included with the resolved user+auth.
        let targets = core
            .select_targets_by_tags("v".into(), vec!["prod".into()], false)
            .unwrap();
        assert_eq!(targets.len(), 2);
        let pt = targets.iter().find(|t| t.host == "gw").unwrap();
        assert_eq!(pt.user, "alice");
        assert!(matches!(
            &pt.auth,
            AuthMethod::Agent { vault_id, key_item_id }
                if vault_id.as_str() == pv && key_item_id == "k"
        ));
        // Group fan-out: the dry-run marks the bound Personal host as Ok.
        core.save_group(
            "v".into(),
            ServerGroup {
                group_id: "g".into(),
                label: "G".into(),
                member_ids: vec!["personal-host".into(), "key-host".into()],
                parent_id: None,
            },
        )
        .unwrap();
        let plans = core.dry_run_group("v".into(), "g".into()).unwrap();
        assert_eq!(
            plans
                .iter()
                .find(|p| p.member_id == "personal-host")
                .unwrap()
                .status,
            ResolveStatus::Ok
        );
    }

    #[test]
    fn retry_backoff_is_linear() {
        assert_eq!(retry_backoff_ms(0, 100), 100);
        assert_eq!(retry_backoff_ms(1, 100), 200);
        assert_eq!(retry_backoff_ms(2, 50), 150);
        assert_eq!(retry_backoff_ms(0, 0), 0);
    }

    #[test]
    fn tags_default_to_empty_for_legacy_profile() {
        // A profile without a tags field (legacy) is read, tags are empty.
        let legacy = r#"{"label":"L","host":"h","port":22,"user":"u",
                         "key_item_id":"k","jumps":[]}"#;
        let stored: StoredProfile = serde_json::from_str(legacy).unwrap();
        let prof = stored_to_profile("v", "p".to_string(), stored);
        assert!(prof.tags.is_empty());
    }

    #[test]
    fn tag_matching_any_and_all() {
        let host = ["prod".to_string(), "web".to_string(), "eu".to_string()];
        // any: the intersection is non-empty
        assert!(tags_match(&host, &["prod".to_string()], false));
        assert!(tags_match(
            &host,
            &["x".to_string(), "web".to_string()],
            false
        ));
        assert!(!tags_match(&host, &["x".to_string()], false));
        // all: query ⊆ the host's tags
        assert!(tags_match(
            &host,
            &["prod".to_string(), "web".to_string()],
            true
        ));
        assert!(!tags_match(
            &host,
            &["prod".to_string(), "db".to_string()],
            true
        ));
        // an empty query → we select nothing (protection against "exec on everything")
        assert!(!tags_match(&host, &[], false));
        assert!(!tags_match(&host, &[], true));
    }

    /// Pure flatten of nested groups: deduplication, cycle protection, a depth
    /// limit. The graph is given by maps without a DB.
    #[test]
    fn flatten_group_members_respects_depth_limit() {
        use std::collections::{HashMap, HashSet};
        // A chain g0->g1->...->g40, each with the next group + a terminal profile.
        let profiles: HashSet<String> = ["p_end".to_string()].into_iter().collect();
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for i in 0..40 {
            groups.insert(format!("g{i}"), vec![format!("g{}", i + 1)]);
        }
        groups.insert("g40".to_string(), vec!["p_end".to_string()]);
        // must not overflow the stack; beyond the limit — CycleSkipped, not a panic.
        let (members, issues) = flatten_group_members(&groups, &profiles, "g0", GROUP_MAX_DEPTH);
        assert!(issues
            .iter()
            .any(|(_, st)| *st == ResolveStatus::CycleSkipped));
        // a profile beyond the depth limit is not expanded
        assert!(members.is_empty());
    }

    #[test]
    fn flatten_group_members_dedup_cycle_depth() {
        use std::collections::HashMap;
        let profiles: std::collections::HashSet<String> =
            ["p1", "p2", "p3"].iter().map(|s| s.to_string()).collect();
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        // A → [p1, B, p2]; B → [p2, p3, A(cycle)]
        groups.insert("A".to_string(), vec!["p1".into(), "B".into(), "p2".into()]);
        groups.insert("B".to_string(), vec!["p2".into(), "p3".into(), "A".into()]);

        let (members, issues) = flatten_group_members(&groups, &profiles, "A", GROUP_MAX_DEPTH);
        // profiles are expanded once each, in traversal order
        assert_eq!(members, vec!["p1", "p2", "p3"]);
        // the cycle A→B→A is marked but did not loop
        assert!(issues
            .iter()
            .any(|(_, s)| *s == ResolveStatus::CycleSkipped));

        // a dangling member and a member that is neither a group nor a profile
        let mut g2: HashMap<String, Vec<String>> = HashMap::new();
        g2.insert("G".to_string(), vec!["p1".into(), "ghost".into()]);
        let (m2, iss2) = flatten_group_members(&g2, &profiles, "G", GROUP_MAX_DEPTH);
        assert_eq!(m2, vec!["p1"]);
        assert!(iss2
            .iter()
            .any(|(id, s)| id == "ghost" && *s == ResolveStatus::Dangling));
    }
}
