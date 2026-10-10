//! Parse the `manifest_blob` member-set (spec §8.1) — mirror of
//! `crates/vault/src/membership.rs::canonical_member_payload`. Used by the
//! server for the author∈members@epoch predicate on write-accept (§9.4) and RBAC.
//!
//! Format: `"unissh-manifest-v1" || key_epoch:u64BE || count:u32BE ||
//! repeated{ role:u8, ed_len:u16BE, ed25519_pub }`, members sorted by
//! ed25519_pub ASC, no duplicates.

use crate::domain::rbac::Role;
use crate::error::AppError;

pub const MANIFEST_DOMAIN: &[u8] = b"unissh-manifest-v1";

/// Parsed manifest member-set.
#[derive(Debug, Clone)]
pub struct MemberSet {
    pub key_epoch: u64,
    pub members: Vec<(Vec<u8>, Role)>,
}

impl MemberSet {
    pub fn role_of(&self, ed25519_pub: &[u8]) -> Option<Role> {
        self.members
            .iter()
            .find(|(p, _)| p == ed25519_pub)
            .map(|(_, r)| *r)
    }
    pub fn contains(&self, ed25519_pub: &[u8]) -> bool {
        self.role_of(ed25519_pub).is_some()
    }
}

/// Strict parse of manifest_blob → member-set.
pub fn parse_member_set(blob: &[u8]) -> Result<MemberSet, AppError> {
    let err = || AppError::malformed("manifest: format error");
    let dl = MANIFEST_DOMAIN.len();
    if blob.len() < dl + 8 + 4 {
        return Err(err());
    }
    let (domain, rest) = blob.split_at_checked(dl).ok_or_else(err)?;
    if domain != MANIFEST_DOMAIN {
        return Err(err());
    }
    let (epoch, rest) = rest.split_first_chunk::<8>().ok_or_else(err)?;
    let key_epoch = u64::from_be_bytes(*epoch);
    let (cnt, mut rest) = rest.split_first_chunk::<4>().ok_or_else(err)?;
    let count = u32::from_be_bytes(*cnt) as usize;

    let mut members = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let (&[role_byte, l0, l1], tail) = rest.split_first_chunk::<3>().ok_or_else(err)?;
        let role = Role::from_u8(role_byte).ok_or_else(err)?;
        let ed_len = usize::from(u16::from_be_bytes([l0, l1]));
        let (ed, tail) = tail.split_at_checked(ed_len).ok_or_else(err)?;
        members.push((ed.to_vec(), role));
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(err()); // trailing bytes
    }
    Ok(MemberSet { key_epoch, members })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_blob() -> Vec<u8> {
        let mut b = MANIFEST_DOMAIN.to_vec();
        b.extend_from_slice(&9_u64.to_be_bytes()); // key_epoch
        b.extend_from_slice(&2_u32.to_be_bytes()); // count
        for (role, ed) in [(2_u8, [0x01_u8; 32]), (0, [0x02; 32])] {
            b.push(role);
            b.extend_from_slice(&32_u16.to_be_bytes());
            b.extend_from_slice(&ed);
        }
        b
    }

    #[test]
    fn truncated_manifest_is_format_error() {
        let full = manifest_blob();
        let set = parse_member_set(&full).unwrap();
        assert_eq!(set.key_epoch, 9, "key_epoch is read big-endian");
        assert_eq!(
            set.role_of(&[0x01; 32]),
            Some(Role::Admin),
            "first member is admin"
        );
        assert_eq!(
            set.role_of(&[0x02; 32]),
            Some(Role::Viewer),
            "second member is viewer"
        );
        for cut in 0..full.len() {
            let err = parse_member_set(&full[..cut]).unwrap_err();
            assert_eq!(
                err.code,
                crate::error::ErrorCode::Malformed,
                "cut at {cut}: {err}"
            );
        }
    }
}
