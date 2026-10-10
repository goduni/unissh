//! Storage data model.
//!
//! Storage operates on **already-encrypted** blobs (`name_blob`, `content_blob`,
//! `wrapped_vk`, `wrapped_item_key`) + open metadata. Encryption is the `vault`
//! layer, not here. The version/signature/tombstone fields are laid down for future sync
//! (spec 9, 5.4), though there is no sync yet.

/// Vault sync target (spec §13 item 5). In Milestone 1 only `Local`; `Cloud`
/// is laid down for server-side sync (there is no server in this repository — only
/// storing the label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncTarget {
    /// Local vault: never leaves for a server ("instance without a server").
    Local,
    /// Cloud vault: syncs with a server (sync is Milestone 2+, outside this repository).
    Cloud,
}

impl SyncTarget {
    pub(crate) fn to_i64(self) -> i64 {
        match self {
            Self::Local => 0,
            Self::Cloud => 1,
        }
    }
    pub(crate) fn from_i64(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::Local),
            1 => Some(Self::Cloud),
            _ => None,
        }
    }
}

/// Policy for caching vault content offline (spec §13 item 11). Storage stores the label
/// as-is; enforcing the policy (wiping the cache / refusing to read offline) is a higher layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CachePolicy {
    /// Content may be kept in the local (encrypted) DB for offline access.
    OfflineAllowed,
    /// Content is available online only (offline caching is not allowed).
    OnlineOnly,
}

impl CachePolicy {
    pub(crate) fn to_i64(self) -> i64 {
        match self {
            Self::OfflineAllowed => 0,
            Self::OnlineOnly => 1,
        }
    }
    pub(crate) fn from_i64(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::OfflineAllowed),
            1 => Some(Self::OnlineOnly),
            _ => None,
        }
    }
}

/// Vault record (metadata + wrapped VK). Content fields (`name_blob`) are
/// ciphertext from the `vault` layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRecord {
    /// Vault identifier (open metadata).
    pub vault_id: Vec<u8>,
    /// Sync target.
    pub sync_target: SyncTarget,
    /// Encrypted vault name/metadata (ciphertext of the vault layer).
    pub name_blob: Vec<u8>,
    /// Wrapped Vault Key (e.g. `Enc(VK, owner pubkey)`).
    pub wrapped_vk: Vec<u8>,
    /// Monotonic record version.
    pub version: u64,
    /// Deletion marker (tombstone).
    pub tombstone: bool,
    /// Signature of the change author (Ed25519 crypto blob).
    pub signature: Vec<u8>,
    /// Public key of the change author.
    pub author_pubkey: Vec<u8>,
    /// Current vault key epoch (spec §13 item 9). Open metadata; VK rotation and
    /// epoch enforcement are done by the `vault` layer (P3/P4) — storage stores the value as-is.
    pub key_epoch: u64,
    /// Vault offline-cache policy (spec §13 item 11).
    pub cache_policy: CachePolicy,
    /// **1:1 binding of a cloud vault to a server:** the `tenant_id` of the server this
    /// cloud vault syncs with (the same identifier that keys the
    /// sync transport). An open client-side routing label — NOT part of the
    /// signed content (like `sync_target`/`key_epoch`/`cache_policy`).
    /// Empty (`Vec::new()`) = unbound/legacy or a local vault (never
    /// syncs). Sync pushes a cloud vault ONLY to the server with a matching
    /// `sync_tenant`, so that with several servers the vault does not go to the wrong one.
    pub sync_tenant: Vec<u8>,
}

/// Item record. The unit of sync (spec 9.1). Content (`content_blob`) is ciphertext
/// of the `vault` layer, wrapped by `wrapped_item_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRecord {
    /// Vault that owns the item.
    pub vault_id: Vec<u8>,
    /// Item identifier within the vault.
    pub item_id: Vec<u8>,
    /// Item type (open metadata: e.g. SSH key/note). The name is in the content.
    pub item_type: u32,
    /// Encrypted item content (ciphertext of the vault layer).
    pub content_blob: Vec<u8>,
    /// Per-item key, wrapped by VK.
    pub wrapped_item_key: Vec<u8>,
    /// Monotonic item version.
    pub version: u64,
    /// Deletion marker (tombstone) — a first-class sync event (spec 9.4).
    pub tombstone: bool,
    /// Signature of the change author.
    pub signature: Vec<u8>,
    /// Public key of the change author.
    pub author_pubkey: Vec<u8>,
    /// When the item was created (unix seconds). **Open metadata, not signed and not
    /// synced**: set by `storage` on first insert (the value in
    /// the passed record is ignored), on read it is filled with the actual value.
    pub created_at: i64,
    /// When the item was last modified (unix seconds). Also storage-owned: set
    /// on every write; on read it is filled with the actual value.
    pub updated_at: i64,
    /// Vault key epoch under which `wrapped_item_key` is wrapped (spec §13 item 9).
    /// Open metadata; epoch rotation and re-wrapping are done by the `vault` layer
    /// (P3/P4) — storage stores the value as-is, does not verify.
    pub key_epoch: u64,
}

/// Vault member role (spec §13, sharing). Storage stores the role as an open label
/// inside the grant; authorization and signature verification are done by the `vault` layer (P3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberRole {
    /// Read only.
    Viewer,
    /// Read and write items.
    Editor,
    /// Membership management (issuing/revoking grants).
    Admin,
}

impl MemberRole {
    pub(crate) fn to_i64(self) -> i64 {
        match self {
            Self::Viewer => 0,
            Self::Editor => 1,
            Self::Admin => 2,
        }
    }
    /// Decodes the role from the DB integer representation. `None` = unknown
    /// value (rejected, not a panic).
    pub fn from_i64(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::Viewer),
            1 => Some(Self::Editor),
            2 => Some(Self::Admin),
            _ => None,
        }
    }
}

/// Signed vault membership manifest for a specific key epoch (storage for
/// sharing, spec §13). Storage keeps `manifest_blob`/`signature` as-is and does **not**
/// verify the signature/membership set — that is the `vault` layer (P3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipManifest {
    /// Vault the manifest belongs to.
    pub vault_id: Vec<u8>,
    /// Vault key epoch.
    pub key_epoch: u64,
    /// Serialized signed manifest (ciphertext/blob of the `vault` layer).
    pub manifest_blob: Vec<u8>,
    /// Author signature (Ed25519 crypto blob).
    pub signature: Vec<u8>,
    /// Public key of the manifest author.
    pub author_pubkey: Vec<u8>,
}

/// Member access grant to a vault for a key epoch: wrapped VK for the member + role
/// (storage for sharing, spec §13). Storage stores `wrapped_vk`/`signature` as-is
/// and does **not** check the signature/right to issue — that is the `vault` layer (P3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipGrant {
    /// Vault access was granted to.
    pub vault_id: Vec<u8>,
    /// Member public key (grant recipient).
    pub member_pubkey: Vec<u8>,
    /// Vault key epoch the grant was issued for.
    pub key_epoch: u64,
    /// Member role.
    pub role: MemberRole,
    /// Grant expiry time (unix seconds). Sentinel `<= 0` = no expiry.
    /// Part of the grant's signed content (authenticated). Read enforcement is
    /// on the server (`member_has_active_grant`).
    pub not_after: i64,
    /// Vault VK wrapped under `member_pubkey` (HPKE blob of the `vault`/`crypto` layer).
    pub wrapped_vk: Vec<u8>,
    /// Signature of the grant author.
    pub signature: Vec<u8>,
    /// Public key of the grant author.
    pub author_pubkey: Vec<u8>,
}

/// Append-only audit-log record (storage of signed events, spec §13). Storage
/// stores `entry_blob`/`signature` as-is and does **not** sign and does **not**
/// verify — the blob arrives already signed (the `vault`/higher layer). The log
/// is only appended to at the end: there are no update/delete methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Monotonic sequence number (autoincrement, assigned by storage).
    pub seq: u64,
    /// Serialized signed audit event (blob of a higher layer).
    pub entry_blob: Vec<u8>,
    /// Signature of the event author (Ed25519 crypto blob).
    pub signature: Vec<u8>,
    /// Public key of the event author.
    pub author_pubkey: Vec<u8>,
    /// When recorded (unix seconds). Storage-owned: set on `append_audit`.
    pub recorded_at: i64,
}

/// Pinned member public key (anti-spoof pinning, spec §13 item 12). Storage
/// stores it as open metadata; key changes (re-pinning) are controlled by the
/// `vault` layer (P3) — here it is only storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedMemberKey {
    /// Member account identifier (open metadata).
    pub account_id: Vec<u8>,
    /// Pinned member public key.
    pub member_pubkey: Vec<u8>,
    /// Key fingerprint (for display/comparison), e.g. `SHA256:...`.
    pub fingerprint: String,
    /// When pinned (unix seconds). Storage-owned: set on `pin_member_key`.
    pub added_at: i64,
}

/// Trusted per-vault anchor: the genesis-owner (creator-pubkey) of a vault created
/// by another account. Pinned TOFU on share-accept; absence of a row = own
/// vault (fallback to the local keyset). Storage stores it as open metadata;
/// TOFU control of re-pinning is the `vault` layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultTrustAnchor {
    /// Vault the anchor belongs to (open metadata).
    pub vault_id: Vec<u8>,
    /// Pinned genesis-owner (Ed25519 vault creator-pubkey).
    pub genesis_owner_pubkey: Vec<u8>,
    /// When pinned (unix seconds). Storage-owned.
    pub pinned_at: i64,
}

/// Per-account state (A3): a signed+versioned, HPKE-self-sealed blob
/// (pointer to the personal vault + account-default username). Storage stores the open
/// fields + the opaque `payload`; LWW by `version` is enforced by the sync/ffi layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStateRecord {
    /// Ed25519 pubkey of the author account (row key).
    pub author_pubkey: Vec<u8>,
    /// Signed version (LWW).
    pub version: u64,
    /// HPKE-self-sealed payload.
    pub payload: Vec<u8>,
    /// Ed25519 signature over (domain || marker || version || payload).
    pub signature: Vec<u8>,
    /// When updated (unix seconds). Storage-owned.
    pub updated_at: i64,
}

/// Pinned host key (SSH TOFU/pinning, spec 10.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHost {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Pinned public host key (OpenSSH bytes).
    pub host_key: Vec<u8>,
    /// When pinned (unix time, seconds).
    pub added_at: i64,
}

/// Category of a DB structural-integrity violation (for [`crate::Storage::check_consistency`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsistencyKind {
    /// Item references a vault_id that has no record in `vaults`.
    OrphanItem,
    /// Record version < 1 (monotonic versions start at 1).
    BadVersion,
    /// Length of `author_pubkey` does not equal the Ed25519 key length (32).
    BadAuthorLen,
    /// Signature length is below the minimum allowed.
    BadSignatureLen,
    /// Tombstone record with a non-empty `content_blob` (deletion must clear the content).
    TombstoneNotEmpty,
    /// Version history exists for an item that is deleted (tombstone) or absent —
    /// old plaintext must not outlive deletion of the secret.
    StaleHistory,
}

/// A single integrity violation. Identifiers are hex (open metadata), no secrets.
#[derive(Debug, Clone)]
pub struct ConsistencyIssue {
    /// Category.
    pub kind: ConsistencyKind,
    /// Record vault_id (hex).
    pub vault_id_hex: String,
    /// Record item_id (hex); empty for vault-level issues.
    pub item_id_hex: String,
    /// Machine-readable detail (lengths/versions), no plaintext/cipher blobs.
    pub detail: String,
}

/// DB structural-check report (no secrets).
#[derive(Debug, Clone)]
pub struct ConsistencyReport {
    /// `integrity_ok && issues.is_empty()`.
    pub ok: bool,
    /// `PRAGMA integrity_check` returned `ok` (the B-tree structure is intact).
    pub integrity_ok: bool,
    /// Violations found.
    pub issues: Vec<ConsistencyIssue>,
}
