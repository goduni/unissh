//! [`SyncObject`] — a tagged serializable representation of syncable objects.
//!
//! Carries **already-encrypted/signed** blobs (the ciphertext of the `vault`/
//! `crypto`/`keychain` layers) + open metadata. No crypto is performed here —
//! the engine only transports and verifies (through `vault`/`crypto`). Serialization
//! is a hand-written length-prefixed byte codec (like `EncryptedKeyset`/
//! `AssociatedData`), without `serde`.

use unissh_storage::{
    CachePolicy, ItemRecord, MemberRole, MembershipGrant, MembershipManifest, SyncTarget,
    VaultRecord,
};

use crate::error::SyncError;

/// The type of a syncable object (one tag byte in the codec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectTag {
    /// A vault record.
    Vault,
    /// An item record.
    Item,
    /// An epoch's membership manifest.
    MembershipManifest,
    /// A per-member grant.
    MembershipGrant,
    /// An audit record.
    Audit,
    /// A serialized `EncryptedKeyset` blob (server-tz §9 Path A).
    Keyset,
    /// Per-account state (A3): a signed+versioned, HPKE-self-sealed
    /// blob (pointer to the personal vault + account-default username). Account-scoped:
    /// delivered only to the account's own devices (author == device keyset).
    AccountState,
}

impl ObjectTag {
    pub(crate) fn to_u8(self) -> u8 {
        match self {
            Self::Vault => 1,
            Self::Item => 2,
            Self::MembershipManifest => 3,
            Self::MembershipGrant => 4,
            Self::Audit => 5,
            Self::Keyset => 6,
            Self::AccountState => 7,
        }
    }
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Vault),
            2 => Some(Self::Item),
            3 => Some(Self::MembershipManifest),
            4 => Some(Self::MembershipGrant),
            5 => Some(Self::Audit),
            6 => Some(Self::Keyset),
            7 => Some(Self::AccountState),
            _ => None,
        }
    }
}

/// An audit record as a sync object. (The storage `AuditEntry` carries `seq`/`recorded_at`
/// — storage-owned fields that are NOT synced: on receipt storage assigns
/// its own. So we sync only the signed triple.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditObject {
    /// The vault the event relates to (for routing/filtering).
    pub vault_id: Vec<u8>,
    /// The serialized signed event (a blob of the layer above).
    pub entry_blob: Vec<u8>,
    /// The event author's signature.
    pub signature: Vec<u8>,
    /// The author's public key.
    pub author_pubkey: Vec<u8>,
}

/// Per-account state (A3) as a sync object. Signed by the account's Ed25519 key
/// (`author_pubkey`, an open column — by which the delta filter addresses the object only
/// to the account's own devices), versioned (LWW by `version`), and the
/// payload (`payload`) is HPKE-self-sealed under the account's x25519 (the server does not read it).
/// Signed content: domain || `ACCOUNT_STATE_MARKER` || version_be || payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStateObject {
    /// The author account's Ed25519 pubkey (== the device keyset). An open column.
    pub author_pubkey: Vec<u8>,
    /// The signed version (client clock, LWW; NOT server_seq).
    pub version: u64,
    /// The HPKE-self-sealed payload (pointer to the personal vault + username).
    pub payload: Vec<u8>,
    /// The Ed25519 signature over the signed content.
    pub signature: Vec<u8>,
}

/// A syncable object. The variants carry already-encrypted/signed blobs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncObject {
    /// A vault record.
    Vault(VaultRecord),
    /// An item record.
    Item(ItemRecord),
    /// A membership manifest.
    MembershipManifest(MembershipManifest),
    /// A per-member grant.
    MembershipGrant(MembershipGrant),
    /// An audit record.
    Audit(AuditObject),
    /// A serialized keyset blob (Path A).
    Keyset(Vec<u8>),
    /// Per-account state (A3).
    AccountState(AccountStateObject),
}

impl SyncObject {
    /// The object's type tag.
    pub fn tag(&self) -> ObjectTag {
        match self {
            Self::Vault(_) => ObjectTag::Vault,
            Self::Item(_) => ObjectTag::Item,
            Self::MembershipManifest(_) => ObjectTag::MembershipManifest,
            Self::MembershipGrant(_) => ObjectTag::MembershipGrant,
            Self::Audit(_) => ObjectTag::Audit,
            Self::Keyset(_) => ObjectTag::Keyset,
            Self::AccountState(_) => ObjectTag::AccountState,
        }
    }

    /// The object's `vault_id` (open metadata), if applicable. `Keyset` is an
    /// instance-level object with no `vault_id` → `None`.
    pub fn vault_id(&self) -> Option<&[u8]> {
        match self {
            Self::Vault(v) => Some(&v.vault_id),
            Self::Item(i) => Some(&i.vault_id),
            Self::MembershipManifest(m) => Some(&m.vault_id),
            Self::MembershipGrant(g) => Some(&g.vault_id),
            Self::Audit(a) => Some(&a.vault_id),
            Self::Keyset(_) => None,
            Self::AccountState(_) => None,
        }
    }

    /// The object's `key_epoch` (open metadata), if applicable. `Item`/`Vault`/
    /// `MembershipGrant`/`MembershipManifest` carry an epoch; `Audit`/`Keyset` do not.
    pub fn key_epoch(&self) -> Option<u64> {
        match self {
            Self::Vault(v) => Some(v.key_epoch),
            Self::Item(i) => Some(i.key_epoch),
            Self::MembershipManifest(m) => Some(m.key_epoch),
            Self::MembershipGrant(g) => Some(g.key_epoch),
            Self::Audit(_) | Self::Keyset(_) | Self::AccountState(_) => None,
        }
    }
}

/// Length-prefixed write of a slice: `len:u32 be || bytes`.
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), SyncError> {
    let len = u32::try_from(b.len()).map_err(|_| SyncError::Format)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

/// A cursor parser over a slice (does NOT panic on short input).
struct Reader<'a> {
    b: &'a [u8],
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b }
    }
    fn u8(&mut self) -> Result<u8, SyncError> {
        let (h, t) = self.b.split_first().ok_or(SyncError::Format)?;
        self.b = t;
        Ok(*h)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], SyncError> {
        if self.b.len() < n {
            return Err(SyncError::Format);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u32(&mut self) -> Result<u32, SyncError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, SyncError> {
        let s = self.take(8)?;
        let mut a = [0_u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, SyncError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn finish(self) -> Result<(), SyncError> {
        if self.b.is_empty() {
            Ok(())
        } else {
            Err(SyncError::Format)
        }
    }
}

fn sync_target_u8(t: SyncTarget) -> u8 {
    match t {
        SyncTarget::Local => 0,
        SyncTarget::Cloud => 1,
        _ => 0,
    }
}
fn sync_target_from(v: u8) -> Result<SyncTarget, SyncError> {
    match v {
        0 => Ok(SyncTarget::Local),
        1 => Ok(SyncTarget::Cloud),
        _ => Err(SyncError::Format),
    }
}
fn cache_policy_u8(c: CachePolicy) -> u8 {
    match c {
        CachePolicy::OfflineAllowed => 0,
        CachePolicy::OnlineOnly => 1,
        _ => 0,
    }
}
fn cache_policy_from(v: u8) -> Result<CachePolicy, SyncError> {
    match v {
        0 => Ok(CachePolicy::OfflineAllowed),
        1 => Ok(CachePolicy::OnlineOnly),
        _ => Err(SyncError::Format),
    }
}
fn role_u8(r: MemberRole) -> u8 {
    match r {
        MemberRole::Viewer => 0,
        MemberRole::Editor => 1,
        MemberRole::Admin => 2,
        _ => 0,
    }
}
fn role_from(v: u8) -> Result<MemberRole, SyncError> {
    MemberRole::from_i64(i64::from(v)).ok_or(SyncError::Format)
}

impl SyncObject {
    /// Serializes the object into self-describing bytes (tag + length-prefixed fields).
    pub fn to_bytes(&self) -> Result<Vec<u8>, SyncError> {
        let mut out = Vec::new();
        out.push(self.tag().to_u8());
        match self {
            Self::Vault(v) => {
                put_bytes(&mut out, &v.vault_id)?;
                out.push(sync_target_u8(v.sync_target));
                put_bytes(&mut out, &v.name_blob)?;
                put_bytes(&mut out, &v.wrapped_vk)?;
                out.extend_from_slice(&v.version.to_be_bytes());
                out.push(u8::from(v.tombstone));
                put_bytes(&mut out, &v.signature)?;
                put_bytes(&mut out, &v.author_pubkey)?;
                out.extend_from_slice(&v.key_epoch.to_be_bytes());
                out.push(cache_policy_u8(v.cache_policy));
                // sync_tenant is NOT serialized: it is a local routing label
                // (which server a cloud vault is bound to), and the server is already
                // unambiguously determined by the transport's tenant. Sending it is pointless and undesirable
                // (we do not hand the server the binding map). from_bytes restores it empty.
            }
            Self::Item(i) => {
                put_bytes(&mut out, &i.vault_id)?;
                put_bytes(&mut out, &i.item_id)?;
                out.extend_from_slice(&i.item_type.to_be_bytes());
                put_bytes(&mut out, &i.content_blob)?;
                put_bytes(&mut out, &i.wrapped_item_key)?;
                out.extend_from_slice(&i.version.to_be_bytes());
                out.push(u8::from(i.tombstone));
                put_bytes(&mut out, &i.signature)?;
                put_bytes(&mut out, &i.author_pubkey)?;
                out.extend_from_slice(&i.key_epoch.to_be_bytes());
                // created_at/updated_at are storage-owned, NOT synced.
            }
            Self::MembershipManifest(m) => {
                put_bytes(&mut out, &m.vault_id)?;
                out.extend_from_slice(&m.key_epoch.to_be_bytes());
                put_bytes(&mut out, &m.manifest_blob)?;
                put_bytes(&mut out, &m.signature)?;
                put_bytes(&mut out, &m.author_pubkey)?;
            }
            Self::MembershipGrant(g) => {
                put_bytes(&mut out, &g.vault_id)?;
                put_bytes(&mut out, &g.member_pubkey)?;
                out.extend_from_slice(&g.key_epoch.to_be_bytes());
                out.push(role_u8(g.role));
                // not_after:i64be (8) — per-grant expiry (sentinel <=0 = no expiry).
                // Fixed-width: it is also in the unprefixed signed content.
                out.extend_from_slice(&g.not_after.to_be_bytes());
                put_bytes(&mut out, &g.wrapped_vk)?;
                put_bytes(&mut out, &g.signature)?;
                put_bytes(&mut out, &g.author_pubkey)?;
            }
            Self::Audit(a) => {
                put_bytes(&mut out, &a.vault_id)?;
                put_bytes(&mut out, &a.entry_blob)?;
                put_bytes(&mut out, &a.signature)?;
                put_bytes(&mut out, &a.author_pubkey)?;
            }
            Self::Keyset(b) => {
                put_bytes(&mut out, b)?;
            }
            Self::AccountState(a) => {
                // version:u64be (fixed, also in the signed content) || payload ||
                // signature || author_pubkey (open column for the delta filter).
                out.extend_from_slice(&a.version.to_be_bytes());
                put_bytes(&mut out, &a.payload)?;
                put_bytes(&mut out, &a.signature)?;
                put_bytes(&mut out, &a.author_pubkey)?;
            }
        }
        Ok(out)
    }

    /// Parses the object from bytes. Broken/unknown → [`SyncError::Format`]
    /// (the calling engine turns this into a `rejected` entry, not a crash).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SyncError> {
        let mut r = Reader::new(bytes);
        let tag = ObjectTag::from_u8(r.u8()?).ok_or(SyncError::Format)?;
        let obj = match tag {
            ObjectTag::Vault => {
                let vault_id = r.bytes()?;
                let sync_target = sync_target_from(r.u8()?)?;
                let name_blob = r.bytes()?;
                let wrapped_vk = r.bytes()?;
                let version = r.u64()?;
                let tombstone = r.u8()? != 0;
                let signature = r.bytes()?;
                let author_pubkey = r.bytes()?;
                let key_epoch = r.u64()?;
                let cache_policy = cache_policy_from(r.u8()?)?;
                Self::Vault(VaultRecord {
                    vault_id,
                    sync_target,
                    name_blob,
                    wrapped_vk,
                    version,
                    tombstone,
                    signature,
                    author_pubkey,
                    key_epoch,
                    cache_policy,
                    // sync_tenant is a client routing label, NOT sent over
                    // the wire (the server is already identified by the transport's tenant).
                    // Records received from the server carry no binding → empty; the local
                    // binding is held by put_vault/bind_unbound_cloud_vaults.
                    sync_tenant: Vec::new(),
                })
            }
            ObjectTag::Item => {
                let vault_id = r.bytes()?;
                let item_id = r.bytes()?;
                let item_type = r.u32()?;
                let content_blob = r.bytes()?;
                let wrapped_item_key = r.bytes()?;
                let version = r.u64()?;
                let tombstone = r.u8()? != 0;
                let signature = r.bytes()?;
                let author_pubkey = r.bytes()?;
                let key_epoch = r.u64()?;
                Self::Item(ItemRecord {
                    vault_id,
                    item_id,
                    item_type,
                    content_blob,
                    wrapped_item_key,
                    version,
                    tombstone,
                    signature,
                    author_pubkey,
                    created_at: 0,
                    updated_at: 0,
                    key_epoch,
                })
            }
            ObjectTag::MembershipManifest => {
                let vault_id = r.bytes()?;
                let key_epoch = r.u64()?;
                let manifest_blob = r.bytes()?;
                let signature = r.bytes()?;
                let author_pubkey = r.bytes()?;
                Self::MembershipManifest(MembershipManifest {
                    vault_id,
                    key_epoch,
                    manifest_blob,
                    signature,
                    author_pubkey,
                })
            }
            ObjectTag::MembershipGrant => {
                let vault_id = r.bytes()?;
                let member_pubkey = r.bytes()?;
                let key_epoch = r.u64()?;
                let role = role_from(r.u8()?)?;
                let not_after = r.u64()? as i64; // 8 BE bytes (see serialize)
                let wrapped_vk = r.bytes()?;
                let signature = r.bytes()?;
                let author_pubkey = r.bytes()?;
                Self::MembershipGrant(MembershipGrant {
                    vault_id,
                    member_pubkey,
                    key_epoch,
                    role,
                    not_after,
                    wrapped_vk,
                    signature,
                    author_pubkey,
                })
            }
            ObjectTag::Audit => {
                let vault_id = r.bytes()?;
                let entry_blob = r.bytes()?;
                let signature = r.bytes()?;
                let author_pubkey = r.bytes()?;
                Self::Audit(AuditObject {
                    vault_id,
                    entry_blob,
                    signature,
                    author_pubkey,
                })
            }
            ObjectTag::Keyset => Self::Keyset(r.bytes()?),
            ObjectTag::AccountState => {
                let version = r.u64()?;
                let payload = r.bytes()?;
                let signature = r.bytes()?;
                let author_pubkey = r.bytes()?;
                Self::AccountState(AccountStateObject {
                    author_pubkey,
                    version,
                    payload,
                    signature,
                })
            }
        };
        r.finish()?;
        Ok(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unissh_storage::{CachePolicy, SyncTarget, VaultRecord};

    fn vrec() -> VaultRecord {
        VaultRecord {
            vault_id: b"v1".to_vec(),
            sync_target: SyncTarget::Cloud,
            name_blob: vec![1, 2, 3],
            wrapped_vk: vec![4, 5, 6],
            version: 7,
            tombstone: false,
            signature: vec![9_u8; 67],
            author_pubkey: vec![0_u8; 32],
            key_epoch: 2,
            cache_policy: CachePolicy::OfflineAllowed,
            // sync_tenant does not go over the wire → the round-trip restores it empty.
            sync_tenant: Vec::new(),
        }
    }

    fn irec() -> ItemRecord {
        ItemRecord {
            vault_id: b"v1".to_vec(),
            item_id: b"i1".to_vec(),
            item_type: 42,
            content_blob: vec![1, 2, 3, 4],
            wrapped_item_key: vec![5, 6],
            version: 9,
            tombstone: true,
            signature: vec![7_u8; 67],
            author_pubkey: vec![8_u8; 32],
            created_at: 0,
            updated_at: 0,
            key_epoch: 3,
        }
    }

    #[test]
    fn tag_and_ids() {
        let o = SyncObject::Vault(vrec());
        assert_eq!(o.tag(), ObjectTag::Vault);
        assert_eq!(o.vault_id(), Some(b"v1".as_slice()));
        assert_eq!(o.key_epoch(), Some(2));
    }

    #[test]
    fn roundtrip_vault_item_audit_keyset() {
        for o in [
            SyncObject::Vault(vrec()),
            SyncObject::Item(irec()),
            SyncObject::Audit(AuditObject {
                vault_id: b"v1".to_vec(),
                entry_blob: vec![1, 2, 3],
                signature: vec![4_u8; 67],
                author_pubkey: vec![5_u8; 32],
            }),
            SyncObject::Keyset(vec![9, 9, 9]),
            SyncObject::AccountState(AccountStateObject {
                author_pubkey: vec![0xA_u8; 32],
                version: 12345,
                payload: vec![1, 2, 3, 4, 5],
                signature: vec![0xB_u8; 67],
            }),
        ] {
            let bytes = o.to_bytes().unwrap();
            let back = SyncObject::from_bytes(&bytes).unwrap();
            assert_eq!(o, back);
        }
    }

    #[test]
    fn account_state_tag_is_account_scoped() {
        let o = SyncObject::AccountState(AccountStateObject {
            author_pubkey: vec![7_u8; 32],
            version: 1,
            payload: vec![9],
            signature: vec![8_u8; 67],
        });
        assert_eq!(o.tag(), ObjectTag::AccountState);
        // account-scoped: NOT vault-scoped and does NOT carry an epoch.
        assert_eq!(o.vault_id(), None);
        assert_eq!(o.key_epoch(), None);
    }

    #[test]
    fn from_bytes_rejects_truncated_and_unknown_tag() {
        assert!(SyncObject::from_bytes(&[]).is_err());
        assert!(SyncObject::from_bytes(&[99, 0, 0]).is_err()); // unknown tag
        let mut good = SyncObject::Keyset(vec![1, 2, 3]).to_bytes().unwrap();
        good.truncate(good.len() - 1);
        assert!(SyncObject::from_bytes(&good).is_err());
    }
}
