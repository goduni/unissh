//! Device-local pins for the public encryption keys explicitly supplied when
//! granting access. A fresh membership epoch needs a fresh grant for EVERY
//! remaining member, not only the one being added. Never fill missing pins
//! from an untrusted server directory behind the operator's back.

use std::collections::BTreeMap;

use unissh_storage::Storage;
use unissh_vault::Member;

use crate::{decode_pubkey32, FfiError};

fn slot(vault_id: &[u8]) -> String {
    format!("membership.recipient-keys.v1:{}", hex::encode(vault_id))
}

/// Remember the operator-confirmed recipient key even if other legacy pins
/// are still missing. No membership changes until every recipient is known;
/// re-granting each missing member progressively repairs an older device.
pub(crate) fn recipients(
    storage: &Storage,
    vault_id: &[u8],
    members: &[Member],
    owner: (Vec<u8>, Vec<u8>),
    supplied: (Vec<u8>, Vec<u8>),
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, FfiError> {
    let key = slot(vault_id);
    let mut pins: BTreeMap<String, String> = match storage.get_meta(&key)? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(FfiError::other)?,
        None => BTreeMap::new(),
    };
    for (ed, x) in [owner, supplied] {
        let ed = hex::encode(ed);
        let x = hex::encode(x);
        if pins.get(&ed).is_some_and(|previous| previous != &x) {
            return Err(FfiError::other(
                "member encryption key changed; verify the member's identity before granting access",
            ));
        }
        pins.insert(ed, x);
    }
    storage.set_meta(&key, &serde_json::to_vec(&pins).map_err(FfiError::other)?)?;
    let mut out = Vec::with_capacity(members.len());
    let mut missing = Vec::new();
    for member in members {
        let ed = hex::encode(&member.ed25519_pub);
        match pins.get(&ed) {
            Some(x) => out.push((
                member.ed25519_pub.clone(),
                decode_pubkey32("member encryption key", x)?,
            )),
            None => missing.push(ed),
        }
    }
    if !missing.is_empty() {
        return Err(FfiError::other(format!(
            "recipient key remembered on this device; membership unchanged. Re-grant these existing members with their verified encryption keys, then retry: {}",
            missing.join(", ")
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use unissh_storage::MemberRole;

    #[test]
    fn legacy_recipient_keys_are_collected_without_changing_membership() {
        let storage = Storage::open_in_memory(&[7; 32]).unwrap();
        let members: Vec<Member> = [1, 2, 3]
            .map(|id| Member {
                ed25519_pub: vec![id; 32],
                role: MemberRole::Editor,
            })
            .into();
        let owner = || (vec![1; 32], vec![11; 32]);
        let result = recipients(
            &storage,
            b"vault",
            &members,
            owner(),
            (vec![3; 32], vec![33; 32]),
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("membership unchanged"));
        assert!(storage.latest_membership_epoch(b"vault").unwrap().is_none());
        let all = recipients(
            &storage,
            b"vault",
            &members,
            owner(),
            (vec![2; 32], vec![22; 32]),
        )
        .unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[1], (vec![2; 32], vec![22; 32]));
        assert!(recipients(
            &storage,
            b"vault",
            &members,
            owner(),
            (vec![2; 32], vec![99; 32]),
        )
        .unwrap_err()
        .to_string()
        .contains("encryption key changed"));
    }
}
