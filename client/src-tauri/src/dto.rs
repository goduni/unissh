//! Serde DTOs mirroring the core's `uniffi` types for Tauri IPC.
//!
//! The core's records/enums derive `uniffi::Record`/`uniffi::Enum` but NOT
//! `serde::Serialize`/`Deserialize`, so they can't cross the Tauri IPC boundary
//! directly. These mirrors carry the same data with `camelCase` JSON, plus
//! `From` conversions in both directions.

use serde::{Deserialize, Serialize};
use unissh_ffi as ffi;

// ---------- inputs (frontend -> core) ----------

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AuthMethod {
    /// Key from the vault via the embedded agent. Vault-qualified: `vault_id`
    /// names the vault holding the key, so target and each jump hop can draw
    /// credentials from different vaults.
    #[serde(rename_all = "camelCase")]
    Agent {
        vault_id: String,
        key_item_id: String,
    },
    /// Inline password entered now (never stored).
    Password { password: String },
    /// Password item from the vault, decrypted in-core at connect.
    #[serde(rename_all = "camelCase")]
    VaultPassword {
        vault_id: String,
        password_item_id: String,
    },
}

impl From<AuthMethod> for ffi::AuthMethod {
    fn from(a: AuthMethod) -> Self {
        match a {
            AuthMethod::Agent {
                vault_id,
                key_item_id,
            } => ffi::AuthMethod::Agent {
                vault_id,
                key_item_id,
            },
            AuthMethod::Password { password } => ffi::AuthMethod::Password { password },
            AuthMethod::VaultPassword {
                vault_id,
                password_item_id,
            } => ffi::AuthMethod::VaultPassword {
                vault_id,
                password_item_id,
            },
        }
    }
}
// Reverse: needed to surface a core-resolved AuthMethod (e.g. PersonalAuth) back
// to the frontend. An inline `Password` here would carry no secret in practice
// (resolve_personal_auth only ever returns Agent/VaultPassword refs).
impl From<ffi::AuthMethod> for AuthMethod {
    fn from(a: ffi::AuthMethod) -> Self {
        match a {
            ffi::AuthMethod::Agent {
                vault_id,
                key_item_id,
            } => AuthMethod::Agent {
                vault_id,
                key_item_id,
            },
            ffi::AuthMethod::Password { password } => AuthMethod::Password { password },
            ffi::AuthMethod::VaultPassword {
                vault_id,
                password_item_id,
            } => AuthMethod::VaultPassword {
                vault_id,
                password_item_id,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ProfileAuth {
    #[serde(rename_all = "camelCase")]
    Key {
        key_item_id: String,
    },
    #[serde(rename_all = "camelCase")]
    VaultPassword {
        password_item_id: String,
    },
    PromptPassword,
    /// No stored creds in the (shared) vault — log in with a personal identity
    /// via a binding (B4).
    Personal,
}

impl From<ProfileAuth> for ffi::ProfileAuth {
    fn from(a: ProfileAuth) -> Self {
        match a {
            ProfileAuth::Key { key_item_id } => ffi::ProfileAuth::Key { key_item_id },
            ProfileAuth::VaultPassword { password_item_id } => {
                ffi::ProfileAuth::VaultPassword { password_item_id }
            }
            ProfileAuth::PromptPassword => ffi::ProfileAuth::PromptPassword,
            ProfileAuth::Personal => ffi::ProfileAuth::Personal,
        }
    }
}
impl From<ffi::ProfileAuth> for ProfileAuth {
    fn from(a: ffi::ProfileAuth) -> Self {
        match a {
            ffi::ProfileAuth::Key { key_item_id } => ProfileAuth::Key { key_item_id },
            ffi::ProfileAuth::VaultPassword { password_item_id } => {
                ProfileAuth::VaultPassword { password_item_id }
            }
            ffi::ProfileAuth::PromptPassword => ProfileAuth::PromptPassword,
            ffi::ProfileAuth::Personal => ProfileAuth::Personal,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HopRef {
    pub vault_id: String,
    pub profile_uid: String,
}
impl From<HopRef> for ffi::HopRef {
    fn from(h: HopRef) -> Self {
        ffi::HopRef {
            vault_id: h.vault_id,
            profile_uid: h.profile_uid,
        }
    }
}
impl From<ffi::HopRef> for HopRef {
    fn from(h: ffi::HopRef) -> Self {
        HopRef {
            vault_id: h.vault_id,
            profile_uid: h.profile_uid,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JumpHost {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    #[serde(default)]
    pub hop_ref: Option<HopRef>,
}

impl From<JumpHost> for ffi::JumpHost {
    fn from(j: JumpHost) -> Self {
        ffi::JumpHost {
            host: j.host,
            port: j.port,
            user: j.user,
            auth: j.auth.into(),
            hop_ref: j.hop_ref.map(Into::into),
        }
    }
}
// core JumpHost -> dto: needed for reading profiles back. Maps stored AuthMethod
// (only Agent/VaultPassword are persistable) onto the dto AuthMethod.
impl From<ffi::JumpHost> for JumpHost {
    fn from(j: ffi::JumpHost) -> Self {
        JumpHost {
            host: j.host,
            port: j.port,
            user: j.user,
            auth: match j.auth {
                ffi::AuthMethod::Agent {
                    vault_id,
                    key_item_id,
                } => AuthMethodOut::Agent {
                    vault_id,
                    key_item_id,
                },
                ffi::AuthMethod::VaultPassword {
                    vault_id,
                    password_item_id,
                } => AuthMethodOut::VaultPassword {
                    vault_id,
                    password_item_id,
                },
                ffi::AuthMethod::Password { .. } => AuthMethodOut::Password,
            }
            .into(),
            hop_ref: j.hop_ref.map(Into::into),
        }
    }
}

/// `AuthMethod` as read back from a stored profile/jump — inline passwords are
/// never stored, so this is a lossless view that elides any password value.
enum AuthMethodOut {
    Agent {
        vault_id: String,
        key_item_id: String,
    },
    Password,
    VaultPassword {
        vault_id: String,
        password_item_id: String,
    },
}
impl From<AuthMethodOut> for AuthMethod {
    fn from(a: AuthMethodOut) -> Self {
        match a {
            AuthMethodOut::Agent {
                vault_id,
                key_item_id,
            } => AuthMethod::Agent {
                vault_id,
                key_item_id,
            },
            AuthMethodOut::Password => AuthMethod::Password {
                password: String::new(),
            },
            AuthMethodOut::VaultPassword {
                vault_id,
                password_item_id,
            } => AuthMethod::VaultPassword {
                vault_id,
                password_item_id,
            },
        }
    }
}
// dto AuthMethod is Deserialize-only above; add Serialize so it can round-trip in JumpHost.
impl Serialize for AuthMethod {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        match self {
            AuthMethod::Agent {
                vault_id,
                key_item_id,
            } => {
                let mut st = s.serialize_struct("AuthMethod", 3)?;
                st.serialize_field("type", "agent")?;
                st.serialize_field("vaultId", vault_id)?;
                st.serialize_field("keyItemId", key_item_id)?;
                st.end()
            }
            AuthMethod::Password { .. } => {
                let mut st = s.serialize_struct("AuthMethod", 1)?;
                st.serialize_field("type", "password")?;
                st.end()
            }
            AuthMethod::VaultPassword {
                vault_id,
                password_item_id,
            } => {
                let mut st = s.serialize_struct("AuthMethod", 3)?;
                st.serialize_field("type", "vaultPassword")?;
                st.serialize_field("vaultId", vault_id)?;
                st.serialize_field("passwordItemId", password_item_id)?;
                st.end()
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionProfile {
    pub profile_id: String,
    /// Immutable profile uid (minted by core on create; preserved on edit).
    /// Empty on a fresh create.
    #[serde(default)]
    pub uid: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: ProfileAuth,
    #[serde(default)]
    pub username_template: Option<String>,
    #[serde(default)]
    pub jumps: Vec<JumpHost>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl From<ConnectionProfile> for ffi::ConnectionProfile {
    fn from(p: ConnectionProfile) -> Self {
        ffi::ConnectionProfile {
            profile_id: p.profile_id,
            uid: p.uid,
            label: p.label,
            host: p.host,
            port: p.port,
            user: p.user,
            auth: p.auth.into(),
            username_template: p.username_template,
            jumps: p.jumps.into_iter().map(Into::into).collect(),
            tags: p.tags,
        }
    }
}
impl From<ffi::ConnectionProfile> for ConnectionProfile {
    fn from(p: ffi::ConnectionProfile) -> Self {
        ConnectionProfile {
            profile_id: p.profile_id,
            uid: p.uid,
            label: p.label,
            host: p.host,
            port: p.port,
            user: p.user,
            auth: p.auth.into(),
            username_template: p.username_template,
            jumps: p.jumps.into_iter().map(Into::into).collect(),
            tags: p.tags,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerGroup {
    pub group_id: String,
    pub label: String,
    #[serde(default)]
    pub member_ids: Vec<String>,
    #[serde(default)]
    pub parent_id: Option<String>,
}
impl From<ServerGroup> for ffi::ServerGroup {
    fn from(g: ServerGroup) -> Self {
        ffi::ServerGroup {
            group_id: g.group_id,
            label: g.label,
            member_ids: g.member_ids,
            parent_id: g.parent_id,
        }
    }
}
impl From<ffi::ServerGroup> for ServerGroup {
    fn from(g: ffi::ServerGroup) -> Self {
        ServerGroup {
            group_id: g.group_id,
            label: g.label,
            member_ids: g.member_ids,
            parent_id: g.parent_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub identity_id: String,
    pub label: String,
    pub user: String,
    #[serde(default)]
    pub key_item_id: Option<String>,
    #[serde(default)]
    pub password_item_id: Option<String>,
}
impl From<Identity> for ffi::Identity {
    fn from(i: Identity) -> Self {
        ffi::Identity {
            identity_id: i.identity_id,
            label: i.label,
            user: i.user,
            key_item_id: i.key_item_id,
            password_item_id: i.password_item_id,
        }
    }
}
impl From<ffi::Identity> for Identity {
    fn from(i: ffi::Identity) -> Self {
        Identity {
            identity_id: i.identity_id,
            label: i.label,
            user: i.user,
            key_item_id: i.key_item_id,
            password_item_id: i.password_item_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityBinding {
    pub team_vault_id: String,
    pub profile_uid: String,
    pub identity_item_id: String,
    pub destination_pin: String,
}
impl From<IdentityBinding> for ffi::IdentityBinding {
    fn from(b: IdentityBinding) -> Self {
        ffi::IdentityBinding {
            team_vault_id: b.team_vault_id,
            profile_uid: b.profile_uid,
            identity_item_id: b.identity_item_id,
            destination_pin: b.destination_pin,
        }
    }
}
impl From<ffi::IdentityBinding> for IdentityBinding {
    fn from(b: ffi::IdentityBinding) -> Self {
        IdentityBinding {
            team_vault_id: b.team_vault_id,
            profile_uid: b.profile_uid,
            identity_item_id: b.identity_item_id,
            destination_pin: b.destination_pin,
        }
    }
}

/// Anti-redirect binding-resolution result (core → frontend).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BindingResolution {
    Unbound,
    #[serde(rename_all = "camelCase")]
    Matched {
        identity_item_id: String,
    },
    #[serde(rename_all = "camelCase")]
    Redirected {
        pinned: String,
        current: String,
    },
}
impl From<ffi::BindingResolution> for BindingResolution {
    fn from(r: ffi::BindingResolution) -> Self {
        match r {
            ffi::BindingResolution::Unbound => BindingResolution::Unbound,
            ffi::BindingResolution::Matched { identity_item_id } => {
                BindingResolution::Matched { identity_item_id }
            }
            ffi::BindingResolution::Redirected { pinned, current } => {
                BindingResolution::Redirected { pinned, current }
            }
        }
    }
}

/// Personal auth resolved by the core (post anti-redirect) for a connect.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonalAuth {
    pub user: String,
    pub auth: AuthMethod,
}
impl From<ffi::PersonalAuth> for PersonalAuth {
    fn from(p: ffi::PersonalAuth) -> Self {
        PersonalAuth {
            user: p.user,
            auth: p.auth.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiExecTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    #[serde(default)]
    pub jumps: Vec<JumpHost>,
}
impl From<MultiExecTarget> for ffi::MultiExecTarget {
    fn from(t: MultiExecTarget) -> Self {
        ffi::MultiExecTarget {
            host: t.host,
            port: t.port,
            user: t.user,
            auth: t.auth.into(),
            jumps: t.jumps.into_iter().map(Into::into).collect(),
        }
    }
}

// ---------- outputs (core -> frontend) ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub vault_id: String,
    pub name: String,
    /// Local vault (offline only) or Cloud vault (syncs with the server). Drives
    /// the Local/Cloud badge and gates cloud-only operations in the UI.
    pub sync_target: SyncTarget,
    /// For a cloud vault, the `tenant_id` (base64) of the server it is bound 1:1
    /// to. `None` for local vaults and not-yet-bound legacy cloud vaults. Lets the
    /// UI show which linked server a cloud vault syncs with.
    pub sync_tenant: Option<String>,
}
impl From<ffi::VaultInfo> for VaultInfo {
    fn from(v: ffi::VaultInfo) -> Self {
        VaultInfo {
            vault_id: v.vault_id,
            name: v.name,
            sync_target: v.sync_target.into(),
            sync_tenant: v.sync_tenant,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncTarget {
    Local,
    Cloud,
}
impl From<ffi::FfiSyncTarget> for SyncTarget {
    fn from(t: ffi::FfiSyncTarget) -> Self {
        match t {
            ffi::FfiSyncTarget::Local => SyncTarget::Local,
            ffi::FfiSyncTarget::Cloud => SyncTarget::Cloud,
        }
    }
}

/// Result of a sync pass (FFI mirror of `FfiSyncReport`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    pub applied: u64,
    pub skipped_stale: u64,
    pub conflicts: u32,
    pub rejected: u32,
    pub pushed: u64,
}
impl From<ffi::FfiSyncReport> for SyncReport {
    fn from(r: ffi::FfiSyncReport) -> Self {
        SyncReport {
            applied: r.applied,
            skipped_stale: r.skipped_stale,
            conflicts: r.conflicts,
            rejected: r.rejected,
            pushed: r.pushed,
        }
    }
}

// ---------- membership / sharing ----------

/// Cryptographic vault role (mirror of `ffi::FfiMemberRole`). Used both as input
/// (add_member / rotate_vk) and output (list_members).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MemberRole {
    Viewer,
    Editor,
    Admin,
}
impl From<MemberRole> for ffi::FfiMemberRole {
    fn from(r: MemberRole) -> Self {
        match r {
            MemberRole::Viewer => ffi::FfiMemberRole::Viewer,
            MemberRole::Editor => ffi::FfiMemberRole::Editor,
            MemberRole::Admin => ffi::FfiMemberRole::Admin,
        }
    }
}
impl From<ffi::FfiMemberRole> for MemberRole {
    fn from(r: ffi::FfiMemberRole) -> Self {
        match r {
            ffi::FfiMemberRole::Viewer => MemberRole::Viewer,
            ffi::FfiMemberRole::Editor => MemberRole::Editor,
            ffi::FfiMemberRole::Admin => MemberRole::Admin,
        }
    }
}

/// A vault member: public keys (hex) + role + OOB fingerprint. No secrets.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberInfo {
    pub ed25519_pub_hex: String,
    pub role: MemberRole,
    pub fingerprint: String,
}
impl From<ffi::MemberInfo> for MemberInfo {
    fn from(m: ffi::MemberInfo) -> Self {
        MemberInfo {
            ed25519_pub_hex: m.ed25519_pub_hex,
            role: m.role.into(),
            fingerprint: m.fingerprint,
        }
    }
}

/// A member that survives a VK rotation: public keys (hex) + role.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemainingMember {
    pub ed25519_pub_hex: String,
    pub x25519_pub_hex: String,
    pub role: MemberRole,
}
impl From<RemainingMember> for ffi::RemainingMember {
    fn from(r: RemainingMember) -> Self {
        ffi::RemainingMember {
            ed25519_pub_hex: r.ed25519_pub_hex,
            x25519_pub_hex: r.x25519_pub_hex,
            role: r.role.into(),
        }
    }
}

/// An account as seen by an instance-admin via `/v1/accounts`. Pubkeys are hex
/// (converted from the server's base64) so they feed `add_member` directly.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub account_id: String,
    pub display_name: Option<String>,
    pub handle: Option<String>,
    pub is_admin: bool,
    pub ed25519_pub_hex: Option<String>,
    pub x25519_pub_hex: Option<String>,
    pub status: String,
    pub device_count: i64,
}

/// A device under the caller's own account, from `GET /v1/devices`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub device_id: String,
    pub status: String,
    pub registered_at: i64,
    pub active_sessions: i64,
}

/// Public, session-less probe of a server instance (`GET /v1/instance`). Drives the
/// Add-server flow's branch: `!claimed` → setup-code (claim); claimed → invite/sign-in.
/// `name` is flattened to `""` when the instance is unclaimed/unnamed (the frontend
/// `InstanceInfo.name` is a plain string), unlike the server-facing `Option` form.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceInfoDto {
    pub claimed: bool,
    pub name: String,
    pub version: String,
    pub instance_id: String,
    pub auth: Vec<String>,
}

// ---------- spaces / directory / pending / invites (server-v2) ----------

/// One space the caller is a member of, from `GET /v1/spaces`. `role` is the
/// caller's server-trusted role in that space (`admin`|`member`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceInfo {
    pub space_id: String,
    pub name: String,
    pub role: String,
}

/// A freshly-minted invite from `POST /v1/invite`. `token` is returned exactly
/// once (only its hash is stored server-side); `url` is the shareable join link
/// when the server has a `public_url` configured, else `None`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteInfo {
    pub invite_id: String,
    pub token: String,
    pub url: Option<String>,
    pub expires_at: i64,
}

/// One person in the shared directory (`GET /v1/directory`). Pubkeys are hex
/// (converted from the server's base64) so they feed `server_add_member` /
/// `server_add_space_member` directly, matching [`AccountInfo`]'s convention.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryEntry {
    pub account_id: String,
    pub handle: Option<String>,
    pub display_name: Option<String>,
    pub ed25519_pub_hex: String,
    pub x25519_pub_hex: String,
    pub status: String,
}

/// One outstanding crypto action a vault-admin must fulfil (`GET /v1/pending`):
/// a `grant` or `revoke` for `account_id` on `vault_id`. `vault_id_hex` and the
/// target pubkeys are hex (from the server's base64) so they feed `server_add_member`
/// / `server_rotate_vk`; the server ids (`action_id`, `account_id`) and the opaque
/// binding `proof` stay base64 as the server sends them.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAction {
    pub action_id: String,
    pub kind: String,
    pub vault_id_hex: String,
    pub account_id: String,
    pub ed25519_pub_hex: Option<String>,
    pub x25519_pub_hex: Option<String>,
    pub crypto_role: Option<i64>,
    pub source: String,
    pub proof: Option<String>,
    pub created_at: i64,
}

/// One key-binding attestation about an account (`GET /v1/attestations`). The
/// `blob` + `signature` are opaque base64 the CLIENT verifies (the server never
/// interprets them); `attestor_pubkey` is the attesting device's Ed25519 (base64).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationInfo {
    pub attestor_pubkey: String,
    pub blob: String,
    pub signature: String,
    pub created_at: i64,
}

/// The Argon2id params for keyless-escrow `K_auth` re-derivation (`GET /v1/escrow/params`).
/// `argon_salt` is base64. NOTE: for an unknown/unenrolled handle the server returns a
/// shaped decoy of the same form — this is NOT an existence oracle.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EscrowParamsInfo {
    pub argon_salt: String,
    pub argon_mem_kib: u32,
    pub argon_iterations: u32,
    pub argon_parallelism: u32,
}

// ---------- device-to-device onboarding (Path B) ----------

/// Everything a new device needs to join, produced by the existing device. It is
/// transferred over a TRUSTED side channel (QR / read-aloud) — the `oob_code` is
/// the PAKE secret, so the relay never sees it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingPayload {
    pub base_url: String,
    /// Opaque server-instance id (base64) — used to key the new device's link.
    pub instance_id: String,
    /// Cloud-vault binding label (space id, base64) the new device inherits.
    pub space_id: String,
    pub account_id: String,
    /// The new device's id, pre-created on the server by the existing device.
    pub device_id: String,
    /// Relay channel for the PAKE message exchange.
    pub channel_id: String,
    /// PAKE OOB secret (base64). Transferred only over the trusted side channel.
    pub oob_code: String,
}

// ---------- audit (read-only) ----------

/// A server audit-log entry (observed event). Opaque blobs are omitted.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub seq: i64,
    pub source: String,
    pub recorded_at: i64,
    pub author_pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemInfo {
    pub item_id: String,
    pub item_type: u32,
    pub version: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub has_certificate: bool,
}
impl From<ffi::ItemInfo> for ItemInfo {
    fn from(i: ffi::ItemInfo) -> Self {
        ItemInfo {
            item_id: i.item_id,
            item_type: i.item_type,
            version: i.version,
            created_at: i.created_at,
            updated_at: i.updated_at,
            has_certificate: i.has_certificate,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyInfo {
    pub openssh: String,
    pub fingerprint: String,
}
impl From<ffi::PublicKeyInfo> for PublicKeyInfo {
    fn from(p: ffi::PublicKeyInfo) -> Self {
        PublicKeyInfo {
            openssh: p.openssh,
            fingerprint: p.fingerprint,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownHostInfo {
    pub host: String,
    pub port: u16,
    pub key: String,
    pub added_at: i64,
}
impl From<ffi::KnownHostInfo> for KnownHostInfo {
    fn from(k: ffi::KnownHostInfo) -> Self {
        KnownHostInfo {
            host: k.host,
            port: k.port,
            key: k.key,
            added_at: k.added_at,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownHostsImport {
    pub imported: u32,
    pub skipped_hashed: u32,
    pub skipped_invalid: u32,
}
impl From<ffi::KnownHostsImport> for KnownHostsImport {
    fn from(k: ffi::KnownHostsImport) -> Self {
        KnownHostsImport {
            imported: k.imported,
            skipped_hashed: k.skipped_hashed,
            skipped_invalid: k.skipped_invalid,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostImportReport {
    pub created_ids: Vec<String>,
    pub skipped: u32,
}
impl From<ffi::HostImportReport> for HostImportReport {
    fn from(h: ffi::HostImportReport) -> Self {
        HostImportReport {
            created_ids: h.created_ids,
            skipped: h.skipped,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_status: i32,
}
impl From<ffi::SshExecResult> for SshExecResult {
    fn from(r: ffi::SshExecResult) -> Self {
        SshExecResult {
            stdout: r.stdout,
            stderr: r.stderr,
            exit_status: r.exit_status,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiExecResult {
    pub host: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_status: i32,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub timed_out: bool,
}
impl From<ffi::MultiExecResult> for MultiExecResult {
    fn from(r: ffi::MultiExecResult) -> Self {
        MultiExecResult {
            host: r.host,
            stdout: r.stdout,
            stderr: r.stderr,
            exit_status: r.exit_status,
            error: r.error,
            duration_ms: r.duration_ms,
            timed_out: r.timed_out,
        }
    }
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum ResolveStatus {
    Ok,
    Dangling,
    PromptPassword,
    CycleSkipped,
    Personal,
}
impl From<ffi::ResolveStatus> for ResolveStatus {
    fn from(s: ffi::ResolveStatus) -> Self {
        match s {
            ffi::ResolveStatus::Ok => ResolveStatus::Ok,
            ffi::ResolveStatus::Dangling => ResolveStatus::Dangling,
            ffi::ResolveStatus::PromptPassword => ResolveStatus::PromptPassword,
            ffi::ResolveStatus::CycleSkipped => ResolveStatus::CycleSkipped,
            ffi::ResolveStatus::Personal => ResolveStatus::Personal,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupTargetPlan {
    pub member_id: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub status: ResolveStatus,
}
impl From<ffi::GroupTargetPlan> for GroupTargetPlan {
    fn from(p: ffi::GroupTargetPlan) -> Self {
        GroupTargetPlan {
            member_id: p.member_id,
            host: p.host,
            port: p.port,
            user: p.user,
            status: p.status.into(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastHostStatus {
    pub host: String,
    pub index: u32,
    pub connected: bool,
    pub error: Option<String>,
}
impl From<ffi::BroadcastHostStatus> for BroadcastHostStatus {
    fn from(s: ffi::BroadcastHostStatus) -> Self {
        BroadcastHostStatus {
            host: s.host,
            index: s.index,
            connected: s.connected,
            error: s.error,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpEntry {
    pub filename: String,
    pub is_dir: bool,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
}
impl From<ffi::SftpEntry> for SftpEntry {
    fn from(e: ffi::SftpEntry) -> Self {
        SftpEntry {
            filename: e.filename,
            is_dir: e.is_dir,
            size: e.size,
            mode: e.mode,
            mtime: e.mtime,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpFileStat {
    pub size: u64,
    pub is_dir: bool,
    pub mode: u32,
    pub mtime: u64,
}

/// One entry of a LOCAL directory listing (size + mtime in one read, so the
/// client doesn't fan out a stat IPC per file).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: u64,
}
impl From<ffi::SftpFileStat> for SftpFileStat {
    fn from(s: ffi::SftpFileStat) -> Self {
        SftpFileStat {
            size: s.size,
            is_dir: s.is_dir,
            mode: s.mode,
            mtime: s.mtime,
        }
    }
}

/// Result of opening a long-lived object (session/tunnel/sftp/broadcast): an id
/// the frontend uses for follow-up commands, plus any immediately-useful data.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedTunnel {
    pub id: String,
    pub bind_address: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedBroadcast {
    pub id: String,
    pub statuses: Vec<BroadcastHostStatus>,
}

// ---------- vault integrity (verify_vault_integrity) ----------
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IntegrityFailureKind {
    SignatureInvalid,
    AuthorMismatch,
    Malformed,
}
impl From<ffi::IntegrityFailureKind> for IntegrityFailureKind {
    fn from(k: ffi::IntegrityFailureKind) -> Self {
        match k {
            ffi::IntegrityFailureKind::SignatureInvalid => Self::SignatureInvalid,
            ffi::IntegrityFailureKind::AuthorMismatch => Self::AuthorMismatch,
            ffi::IntegrityFailureKind::Malformed => Self::Malformed,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityIssue {
    pub item_id: String,
    pub version: u64,
    pub tombstone: bool,
    pub failure: IntegrityFailureKind,
}
impl From<ffi::IntegrityIssueInfo> for IntegrityIssue {
    fn from(i: ffi::IntegrityIssueInfo) -> Self {
        IntegrityIssue {
            item_id: i.item_id,
            version: i.version,
            tombstone: i.tombstone,
            failure: i.failure.into(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultIntegrityReport {
    pub ok: bool,
    pub checked: u64,
    pub issues: Vec<IntegrityIssue>,
}
impl From<ffi::VaultIntegrityReport> for VaultIntegrityReport {
    fn from(r: ffi::VaultIntegrityReport) -> Self {
        VaultIntegrityReport {
            ok: r.ok,
            checked: r.checked,
            issues: r.issues.into_iter().map(Into::into).collect(),
        }
    }
}

// ---------- db consistency (check_consistency) ----------
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DbConsistencyKind {
    OrphanItem,
    BadVersion,
    BadAuthorLen,
    BadSignatureLen,
    TombstoneNotEmpty,
    StaleHistory,
}
impl From<ffi::DbConsistencyKind> for DbConsistencyKind {
    fn from(k: ffi::DbConsistencyKind) -> Self {
        match k {
            ffi::DbConsistencyKind::OrphanItem => Self::OrphanItem,
            ffi::DbConsistencyKind::BadVersion => Self::BadVersion,
            ffi::DbConsistencyKind::BadAuthorLen => Self::BadAuthorLen,
            ffi::DbConsistencyKind::BadSignatureLen => Self::BadSignatureLen,
            ffi::DbConsistencyKind::TombstoneNotEmpty => Self::TombstoneNotEmpty,
            ffi::DbConsistencyKind::StaleHistory => Self::StaleHistory,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbConsistencyIssue {
    pub kind: DbConsistencyKind,
    pub vault_id_hex: String,
    pub item_id_hex: String,
    pub detail: String,
}
impl From<ffi::DbConsistencyIssue> for DbConsistencyIssue {
    fn from(i: ffi::DbConsistencyIssue) -> Self {
        DbConsistencyIssue {
            kind: i.kind.into(),
            vault_id_hex: i.vault_id_hex,
            item_id_hex: i.item_id_hex,
            detail: i.detail,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbConsistencyReport {
    pub ok: bool,
    pub integrity_ok: bool,
    pub issues: Vec<DbConsistencyIssue>,
}
impl From<ffi::DbConsistencyReport> for DbConsistencyReport {
    fn from(r: ffi::DbConsistencyReport) -> Self {
        DbConsistencyReport {
            ok: r.ok,
            integrity_ok: r.integrity_ok,
            issues: r.issues.into_iter().map(Into::into).collect(),
        }
    }
}
