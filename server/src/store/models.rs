//! Row structs (`FromRow` — generic, works for both SQLite and Postgres). Open
//! columns mirror the core's record contract. All integers are decoded as i64.

use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct AccountRow {
    pub account_id: Vec<u8>,
    pub display_name: Option<String>,
    pub handle: Option<String>,
    pub is_owner: i64,
    pub ed25519_pub: Option<Vec<u8>>,
    pub x25519_pub: Option<Vec<u8>>,
    pub status: String,
    /// SSO seam (Phase 5): the IdP issuer + subject this account is bound to.
    /// NULL for keyset (non-SSO) accounts.
    pub external_issuer: Option<String>,
    pub external_subject: Option<String>,
}

/// Account + device count (for admin listing).
#[derive(Debug, Clone, FromRow)]
pub struct AccountListRow {
    pub account_id: Vec<u8>,
    pub display_name: Option<String>,
    pub handle: Option<String>,
    pub is_owner: i64,
    pub ed25519_pub: Option<Vec<u8>>,
    pub x25519_pub: Option<Vec<u8>>,
    pub status: String,
    pub device_count: i64,
    /// Self-attested registration (M14): canonical payload + signature, for the
    /// panel's x25519<->ed25519 binding check. NULL for pre-M14 accounts.
    pub reg_payload: Option<Vec<u8>>,
    pub reg_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct DeviceRow {
    pub account_id: Vec<u8>,
    pub device_id: Vec<u8>,
    pub ed25519_pub: Vec<u8>,
    pub x25519_pub: Vec<u8>,
    pub registered_at: i64,
    pub status: String,
    /// Web/panel devices auto-expire; NULL for app devices (never expire).
    pub expires_at: Option<i64>,
}

/// One delta element: `(server_seq, object_bytes)` (§5.1).
#[derive(Debug, Clone, FromRow)]
pub struct DeltaRow {
    pub server_seq: i64,
    pub object_bytes: Vec<u8>,
}

#[derive(Debug, Clone, FromRow)]
pub struct VaultRow {
    pub vault_id: Vec<u8>,
    pub owner_pubkey: Vec<u8>,
    pub latest_version: i64,
    pub latest_epoch: i64,
    pub sync_target: i64,
    pub cache_policy: i64,
    pub tombstone: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct ManifestRow {
    pub vault_id: Vec<u8>,
    pub key_epoch: i64,
    pub manifest_blob: Vec<u8>,
    pub signature: Vec<u8>,
    pub author_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, FromRow)]
pub struct GrantRow {
    pub vault_id: Vec<u8>,
    pub member_pubkey: Vec<u8>,
    pub key_epoch: i64,
    pub role: i64,
    pub wrapped_vk: Vec<u8>,
    pub signature: Vec<u8>,
    pub author_pubkey: Vec<u8>,
    pub not_after: Option<i64>,
    pub revoked: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditRow {
    pub seq: i64,
    pub source: String,
    pub entry_blob: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub author_pubkey: Option<Vec<u8>>,
    pub recorded_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct KeysetRow {
    pub generation: i64,
    pub keyset_bytes: Vec<u8>,
}

/// A keyset blob + its escrow credentials (Phase 2 escrow sign-in): the encrypted
/// keyset a fresh device downloads, plus `sha256(K_auth)` and the Argon2id
/// salt/params it needs to re-derive `K_auth` from password+SecretKey. The escrow
/// fields are NULL until a client enables escrow via `set_escrow`.
#[derive(Debug, Clone, FromRow)]
pub struct EscrowRow {
    pub keyset_bytes: Vec<u8>,
    pub generation: i64,
    pub account_id: Vec<u8>,
    pub k_auth_hash: Option<Vec<u8>>,
    pub argon_salt: Option<Vec<u8>>,
    pub argon_mem_kib: Option<i64>,
    pub argon_iterations: Option<i64>,
    pub argon_parallelism: Option<i64>,
}

#[derive(Debug, Clone, FromRow)]
pub struct SessionRow {
    pub session_id: Vec<u8>,
    pub account_id: Vec<u8>,
    pub device_id: Vec<u8>,
    pub access_hash: Vec<u8>,
    pub refresh_hash: Vec<u8>,
    pub access_expires: i64,
    pub refresh_expires: i64,
    /// How this session was authenticated: 'keyset' (default) | 'oidc' (Phase 5).
    pub auth_source: String,
    /// When the OIDC assertion must be re-checked; NULL for keyset sessions.
    pub reassert_expires: Option<i64>,
    pub revoked: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct IdempotencyRow {
    pub request_hash: Vec<u8>,
    pub response_blob: Vec<u8>,
    pub status_code: i64,
}

/// A single blob column (for the ZK dump test §15.3).
#[derive(Debug, Clone, FromRow)]
pub struct BlobRow {
    pub b: Vec<u8>,
}

#[derive(Debug, Clone, FromRow)]
pub struct RelayRow {
    pub msg1: Option<Vec<u8>>,
    pub msg2: Option<Vec<u8>>,
    pub msg3: Option<Vec<u8>>,
    pub state: String,
    pub expires_at: i64,
}

// ---- Admin/ops read-projection rows (open metadata; NOT content blobs) ----

/// An account's device + count of active sessions (admin device listing).
#[derive(Debug, Clone, FromRow)]
pub struct AdminDeviceRow {
    pub device_id: Vec<u8>,
    pub status: String,
    pub registered_at: i64,
    pub session_count: i64,
}

/// An active session (admin session listing). Token hashes are NOT exported.
#[derive(Debug, Clone, FromRow)]
pub struct AdminSessionRow {
    pub session_id: Vec<u8>,
    pub account_id: Vec<u8>,
    pub device_id: Vec<u8>,
    pub access_expires: i64,
    pub refresh_expires: i64,
    pub revoked: i64,
    pub created_at: i64,
}

/// An invite (admin listing, v2 shape). token_hash is NOT exported.
#[derive(Debug, Clone, FromRow)]
pub struct AdminInviteRow {
    pub invite_id: Vec<u8>,
    pub state: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub redeemed_at: Option<i64>,
}

/// Metadata of a sync object (WITHOUT object_bytes — ZK boundary ARCH §5.4). blob_len is
/// only the ciphertext size.
#[derive(Debug, Clone, FromRow)]
pub struct ObjectMetaRow {
    pub server_seq: i64,
    pub object_tag: i64,
    pub vault_id: Option<Vec<u8>>,
    pub item_id: Option<Vec<u8>>,
    pub obj_version: Option<i64>,
    pub key_epoch: Option<i64>,
    pub tombstone: Option<i64>,
    pub author_pubkey: Option<Vec<u8>>,
    pub received_at: i64,
    pub blob_len: i64,
}

/// PAKE channel (admin observation of onboarding). Messages msg1..3 are NOT exported.
#[derive(Debug, Clone, FromRow)]
pub struct AdminRelayRow {
    pub channel_id: Vec<u8>,
    pub state: String,
    pub expires_at: i64,
    pub created_at: i64,
}

/// Keyset generation (admin observation). keyset_bytes is NOT exported.
#[derive(Debug, Clone, FromRow)]
pub struct AdminKeysetRow {
    pub generation: i64,
    pub uploaded_at: i64,
}

/// An applied migration (from `_sqlx_migrations`, instance-global).
#[derive(Debug, Clone, FromRow)]
pub struct MigrationRow {
    pub version: i64,
    pub description: String,
}

/// A full audit record for verifying the hash chain (§11.2 tamper-evidence).
#[derive(Debug, Clone, FromRow)]
pub struct AuditChainRow {
    pub seq: i64,
    pub source: String,
    pub entry_blob: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub author_pubkey: Option<Vec<u8>>,
    pub vault_id: Option<Vec<u8>>,
    pub recorded_at: i64,
    pub server_seq: Option<i64>,
    pub prev_hash: Option<Vec<u8>>,
}

// ---- v2 (redesign/server-v2): singleton instance row ----

/// The singleton `instance` row (v2 schema): this server's identity, claim
/// state, setup code, and instance-wide `next_seq`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InstanceRow {
    pub instance_id: Vec<u8>,
    pub name: Option<String>,
    pub claimed: i64,
    pub owner_account_id: Option<Vec<u8>>,
    pub setup_code_hash: Option<Vec<u8>>,
    pub next_seq: i64,
    pub created_at: i64,
}

// ---- v2 (redesign/server-v2): spaces, memberships, shared directory ----

/// A space (server-trusted grouping of accounts; v2 schema).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceRow {
    pub space_id: Vec<u8>,
    pub name: String,
    pub status: String,
    pub created_by: Option<Vec<u8>>,
    pub created_at: i64,
}

/// A membership edge (`account_id` in `space_id`) with a server-trusted role.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceMemberRow {
    pub space_id: Vec<u8>,
    pub account_id: Vec<u8>,
    pub role: String,
    pub added_by: Option<Vec<u8>>,
    pub added_at: i64,
}

/// A shared people-directory entry (open metadata; any member may read).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DirectoryRow {
    pub account_id: Vec<u8>,
    pub handle: Option<String>,
    pub display_name: Option<String>,
    pub ed25519_pub: Vec<u8>,
    pub x25519_pub: Vec<u8>,
    pub status: String,
}

// ---- v2 (redesign/server-v2): invites (intents inside) + pending_actions ----

/// A v2 invite: one join mechanism with space + selective-vault intents stored as
/// JSON text; only `sha256(token)` is stored (never the token itself).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InviteV2Row {
    pub invite_id: Vec<u8>,
    pub token_hash: Vec<u8>,
    pub space_intents: String,
    pub vault_intents: String,
    pub expires_at: i64,
    pub state: String,
    pub redeemed_by: Option<Vec<u8>>,
    pub redeemed_at: Option<i64>,
    pub created_by: Option<Vec<u8>>,
    pub created_at: i64,
}

/// A pending crypto action (vault-admin to-do): grant/revoke fulfilment the server
/// marks done itself by observing published manifests/grants.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingActionRow {
    pub action_id: Vec<u8>,
    pub kind: String,
    pub vault_id: Vec<u8>,
    pub account_id: Vec<u8>,
    pub crypto_role: Option<i64>,
    pub source: String,
    pub proof: Option<Vec<u8>>,
    pub state: String,
    pub created_at: i64,
    pub done_at: Option<i64>,
    pub done_epoch: Option<i64>,
}

/// Tiny helper row: an account's ed25519 pubkey (for ed → account_id resolution
/// during done-marking).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EdOnly {
    pub ed25519_pub: Vec<u8>,
}

/// Tiny helper row: the instance's server-PRIVATE escrow-decoy secret. Kept OUT
/// of `InstanceRow` on purpose — it must never ride along on the widely-used
/// instance read, and no endpoint ever returns it. Option because the column is
/// NULL only transiently before `ensure_instance` backfills it on first boot.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DecoySecretRow {
    pub escrow_decoy_secret: Option<Vec<u8>>,
}

// ---- v2 (redesign/server-v2): key-binding attestations ----

/// A key-binding attestation (Task 10): a space admin's signed statement about a
/// target account's key binding. `blob` + `signature` are opaque — the server
/// stores them VERBATIM and never verifies them (clients do; ZK discipline).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AttestationRow {
    pub account_id: Vec<u8>,
    pub attestor_pubkey: Vec<u8>,
    pub blob: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at: i64,
}
