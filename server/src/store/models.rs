//! Row structs (`FromRow` — generic, works for both SQLite and Postgres). Open
//! columns mirror the core's record contract. All integers are decoded as i64.

use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct TenantRow {
    pub tenant_id: Vec<u8>,
    pub tier: String,
    pub display_name: Option<String>,
    pub next_seq: i64,
    pub genesis_owner_pubkey: Option<Vec<u8>>,
    pub created_at: i64,
    pub status: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct AccountRow {
    pub account_id: Vec<u8>,
    pub display_name: Option<String>,
    pub handle: Option<String>,
    pub is_admin: i64,
    pub ed25519_pub: Option<Vec<u8>>,
    pub x25519_pub: Option<Vec<u8>>,
    pub status: String,
}

/// Account + device count (for admin listing).
#[derive(Debug, Clone, FromRow)]
pub struct AccountListRow {
    pub account_id: Vec<u8>,
    pub display_name: Option<String>,
    pub handle: Option<String>,
    pub is_admin: i64,
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
    pub tenant_id: Vec<u8>,
    pub account_id: Vec<u8>,
    pub device_id: Vec<u8>,
    pub ed25519_pub: Vec<u8>,
    pub x25519_pub: Vec<u8>,
    pub registered_at: i64,
    pub status: String,
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

#[derive(Debug, Clone, FromRow)]
pub struct InviteRow {
    pub invite_id: Vec<u8>,
    pub role: i64,
    pub scope: Option<String>,
    pub expires_at: i64,
    pub state: String,
}

/// Enrollment grant for listing to the operator (token_hash is NOT exported).
#[derive(Debug, Clone, FromRow)]
pub struct EnrollGrantRow {
    pub grant_id: Vec<u8>,
    pub label: String,
    pub tier: Option<String>,
    pub state: String,
    pub expires_at: Option<i64>,
    pub redeemed_tenant: Option<Vec<u8>>,
    pub redeemed_at: Option<i64>,
    pub created_at: i64,
}

/// Internal read of a grant for classification during CAS-redeem.
#[derive(Debug, Clone, FromRow)]
pub struct EnrollGrantState {
    pub tier: Option<String>,
    pub state: String,
    pub expires_at: Option<i64>,
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

/// An invite (admin listing). token_hash is NOT exported.
#[derive(Debug, Clone, FromRow)]
pub struct AdminInviteRow {
    pub invite_id: Vec<u8>,
    pub role: i64,
    pub scope: Option<String>,
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

/// A tenant for cross-tenant ops listing (`/v1/ops/tenants`).
#[derive(Debug, Clone, FromRow)]
pub struct OpsTenantRow {
    pub tenant_id: Vec<u8>,
    pub tier: String,
    pub display_name: Option<String>,
    pub status: String,
    pub next_seq: i64,
    pub created_at: i64,
    pub account_count: i64,
    /// Genesis-owner (Ed25519) — open metadata for the ops list (personal/org +
    /// who the owner is). NULL before bootstrap.
    pub genesis_owner_pubkey: Option<Vec<u8>>,
}

/// An account for cross-tenant ops discoverability (`/v1/ops/account?handle=`).
/// Open metadata — helps the operator find the account_id before Bearer (§ chicken/egg).
#[derive(Debug, Clone, FromRow)]
pub struct OpsAccountRow {
    pub tenant_id: Vec<u8>,
    pub account_id: Vec<u8>,
    pub display_name: Option<String>,
    pub handle: Option<String>,
    pub is_admin: i64,
    pub status: String,
}

/// A device for ops discoverability (no pubkey — only identifier/state).
#[derive(Debug, Clone, FromRow)]
pub struct OpsDeviceRow {
    pub device_id: Vec<u8>,
    pub status: String,
    pub registered_at: i64,
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
