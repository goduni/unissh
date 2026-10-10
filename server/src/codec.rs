//! Byte codec for objects (spec §5.2). The server stores `object_bytes` verbatim,
//! but parses the **open columns** with EXACTLY the same manual length-prefixed
//! codec as the core (`crates/sync/src/object.rs:130-387`). No serde/bincode.
//!
//! Strict decoder: trailing bytes / truncation / unknown tag → `Format`. The buffer
//! must be fully consumed (mirror of `Reader::finish`).

use crate::error::AppError;

/// Object type tag (byte 0 of the blob).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectTag {
    Vault = 1,
    Item = 2,
    MembershipManifest = 3,
    MembershipGrant = 4,
    Audit = 5,
    Keyset = 6,
    AccountState = 7,
}

impl ObjectTag {
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
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
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Cursor parser (does not panic on short input) — mirror of `object.rs::Reader`.
struct Reader<'a> {
    b: &'a [u8],
}
impl<'a> Reader<'a> {
    const fn new(b: &'a [u8]) -> Self {
        Reader { b }
    }
    fn u8(&mut self) -> Result<u8, AppError> {
        let (h, t) = self.b.split_first().ok_or_else(fmt_err)?;
        self.b = t;
        Ok(*h)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], AppError> {
        if self.b.len() < n {
            return Err(fmt_err());
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u32(&mut self) -> Result<u32, AppError> {
        let s = self.take(4)?;
        let mut a = [0_u8; 4];
        a.copy_from_slice(s);
        Ok(u32::from_be_bytes(a))
    }
    fn u64(&mut self) -> Result<u64, AppError> {
        let s = self.take(8)?;
        let mut a = [0_u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, AppError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn finish(self) -> Result<(), AppError> {
        if self.b.is_empty() {
            Ok(())
        } else {
            Err(fmt_err())
        }
    }
}

fn fmt_err() -> AppError {
    AppError::malformed("object codec: format error")
}

/// Open columns parsed from the blob (§4.3). `None` for tags without the field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedObject {
    pub tag_u8: u8,
    pub vault_id: Option<Vec<u8>>,
    pub item_id: Option<Vec<u8>>,
    pub member_pubkey: Option<Vec<u8>>,
    /// signed version (CLIENT-side, NOT server_seq) — tag 1,2.
    pub obj_version: Option<u64>,
    /// key_epoch — tag 1-4.
    pub key_epoch: Option<u64>,
    /// tombstone — tag 1,2.
    pub tombstone: Option<bool>,
    /// item_type — tag 2.
    pub item_type: Option<u32>,
    /// sync_target (0=Local/1=Cloud) — tag 1.
    pub sync_target: Option<u8>,
    /// cache_policy (0=OfflineAllowed/1=OnlineOnly) — tag 1.
    pub cache_policy: Option<u8>,
    /// role (0=Viewer/1=Editor/2=Admin) — tag 4.
    pub role: Option<u8>,
    /// not_after (unix seconds; sentinel <=0 = no expiry) — tag 4. Lives inside
    /// the grant's signed content; persisted in materialize, enforced on read.
    pub not_after: Option<i64>,
    /// Author's Ed25519 (32 bytes) — tag 1-5.
    pub author_pubkey: Option<Vec<u8>>,
    /// blob signature (67 bytes) — tag 1-5 (for optional validation §2.4).
    pub signature: Option<Vec<u8>>,
    /// Signed (NOT encrypted) member-set — tag 3 (for materialize/GET grants).
    pub manifest_blob: Option<Vec<u8>>,
    /// HPKE wrapper of the grant's VK — tag 4 (for materialize ACL / GET grants).
    pub wrapped_vk: Option<Vec<u8>>,
    /// Audit-event body — tag 5 (for /v1/audit append).
    pub entry_blob: Option<Vec<u8>>,
}

impl ParsedObject {
    pub const fn tag(&self) -> Option<ObjectTag> {
        ObjectTag::from_u8(self.tag_u8)
    }
}

/// Parse the open columns with the strict codec. Does not reconstruct the payload —
/// it extracts the indexable/filterable fields; the source of truth is the bytes themselves.
pub fn parse_open(bytes: &[u8]) -> Result<ParsedObject, AppError> {
    let mut r = Reader::new(bytes);
    let tag_u8 = r.u8()?;
    let tag = ObjectTag::from_u8(tag_u8).ok_or_else(fmt_err)?;
    let mut p = ParsedObject {
        tag_u8,
        ..Default::default()
    };

    match tag {
        ObjectTag::Vault => {
            // [1] put(vault_id) [sync_target:u8] put(name_blob) put(wrapped_vk)
            // [version:u64] [tombstone:u8] put(sig) put(author) [key_epoch:u64] [cache_policy:u8]
            p.vault_id = Some(r.bytes()?);
            let st = r.u8()?;
            if st > 1 {
                return Err(fmt_err());
            }
            p.sync_target = Some(st);
            let _name_blob = r.bytes()?;
            let _wrapped_vk = r.bytes()?;
            p.obj_version = Some(r.u64()?);
            p.tombstone = Some(r.u8()? != 0);
            p.signature = Some(r.bytes()?);
            p.author_pubkey = Some(r.bytes()?);
            p.key_epoch = Some(r.u64()?);
            let cp = r.u8()?;
            if cp > 1 {
                return Err(fmt_err());
            }
            p.cache_policy = Some(cp);
        }
        ObjectTag::Item => {
            // [2] put(vault_id) put(item_id) [item_type:u32] put(content) put(wrapped_item_key)
            // [version:u64] [tombstone:u8] put(sig) put(author) [key_epoch:u64]
            p.vault_id = Some(r.bytes()?);
            p.item_id = Some(r.bytes()?);
            p.item_type = Some(r.u32()?);
            let _content = r.bytes()?;
            let _wrapped_item_key = r.bytes()?;
            p.obj_version = Some(r.u64()?);
            p.tombstone = Some(r.u8()? != 0);
            p.signature = Some(r.bytes()?);
            p.author_pubkey = Some(r.bytes()?);
            p.key_epoch = Some(r.u64()?);
        }
        ObjectTag::MembershipManifest => {
            // [3] put(vault_id) [key_epoch:u64] put(manifest_blob) put(sig) put(author)
            p.vault_id = Some(r.bytes()?);
            p.key_epoch = Some(r.u64()?);
            p.manifest_blob = Some(r.bytes()?);
            p.signature = Some(r.bytes()?);
            p.author_pubkey = Some(r.bytes()?);
        }
        ObjectTag::MembershipGrant => {
            // [4] put(vault_id) put(member_pubkey) [key_epoch:u64] [role:u8]
            // [not_after:i64] put(wrapped_vk) put(sig) put(author)
            p.vault_id = Some(r.bytes()?);
            p.member_pubkey = Some(r.bytes()?);
            p.key_epoch = Some(r.u64()?);
            let role = r.u8()?;
            if role > 2 {
                return Err(fmt_err());
            }
            p.role = Some(role);
            // 8 BE bytes after role, read as a two's-complement i64.
            p.not_after = Some(i64::from_be_bytes(r.u64()?.to_be_bytes()));
            p.wrapped_vk = Some(r.bytes()?);
            p.signature = Some(r.bytes()?);
            p.author_pubkey = Some(r.bytes()?);
        }
        ObjectTag::Audit => {
            // [5] put(vault_id) put(entry_blob) put(sig) put(author)
            p.vault_id = Some(r.bytes()?);
            p.entry_blob = Some(r.bytes()?);
            p.signature = Some(r.bytes()?);
            p.author_pubkey = Some(r.bytes()?);
        }
        ObjectTag::Keyset => {
            // [6] put(keyset_blob)
            let _keyset_blob = r.bytes()?;
        }
        ObjectTag::AccountState => {
            // [7] [version:u64] put(payload) put(sig) put(author). author_pubkey —
            // an open column; the delta filter uses it to address the object to the
            // devices of its own account; the payload (HPKE-self-sealed) is NOT read by the server.
            p.obj_version = Some(r.u64()?);
            let _payload = r.bytes()?;
            p.signature = Some(r.bytes()?);
            p.author_pubkey = Some(r.bytes()?);
        }
    }
    r.finish()?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid Keyset blob: tag(6) + put(len-prefixed payload).
    fn keyset_blob() -> Vec<u8> {
        let mut b = vec![6_u8];
        let payload = [1_u8, 2, 3];
        b.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        b.extend_from_slice(&payload);
        b
    }

    #[test]
    fn parses_keyset_and_enforces_full_consume() {
        let b = keyset_blob();
        let p = parse_open(&b).unwrap();
        assert_eq!(p.tag(), Some(ObjectTag::Keyset));
        // trailing byte → format error
        let mut bad = b.clone();
        bad.push(0);
        assert!(parse_open(&bad).is_err());
        // truncation → format error
        let mut trunc = b;
        trunc.truncate(trunc.len() - 1);
        assert!(parse_open(&trunc).is_err());
    }

    fn put(b: &mut Vec<u8>, v: &[u8]) {
        b.extend_from_slice(&u32::try_from(v.len()).unwrap().to_be_bytes());
        b.extend_from_slice(v);
    }

    /// Valid grant blob (tag 4): exercises the u8, u32-length, u64 and i64 readers.
    fn grant_blob() -> Vec<u8> {
        let mut b = vec![4_u8];
        put(&mut b, &[0xaa; 16]); // vault_id
        put(&mut b, &[0xbb; 32]); // member_pubkey
        b.extend_from_slice(&3_u64.to_be_bytes()); // key_epoch
        b.push(1); // role
        b.extend_from_slice(&(-1_i64).to_be_bytes()); // not_after
        put(&mut b, &[0xcc; 8]); // wrapped_vk
        put(&mut b, &[0xdd; 67]); // sig
        put(&mut b, &[0xee; 32]); // author
        b
    }

    #[test]
    fn truncated_blob_is_format_error() {
        let full = grant_blob();
        let p = parse_open(&full).unwrap();
        assert_eq!(p.not_after, Some(-1), "not_after keeps its sign");
        assert_eq!(p.key_epoch, Some(3), "key_epoch is read big-endian");
        for cut in 0..full.len() {
            let err = parse_open(&full[..cut]).unwrap_err();
            assert_eq!(
                err.code,
                crate::error::ErrorCode::Malformed,
                "cut at {cut}: {err}"
            );
        }
    }

    #[test]
    fn rejects_unknown_tag_and_empty() {
        assert!(parse_open(&[]).is_err());
        assert!(parse_open(&[99, 0, 0, 0, 0]).is_err());
    }
}
