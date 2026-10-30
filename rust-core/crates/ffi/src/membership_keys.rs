//! Device-local cache of public encryption keys explicitly supplied when
//! granting access. A fresh membership epoch needs a fresh grant for EVERY
//! remaining member, not only the one being added. Never fill missing keys
//! from an untrusted server directory behind the operator's back.

use std::collections::BTreeMap;

use unissh_storage::Storage;
use unissh_vault::Member;

use crate::{decode_pubkey32, FfiError};

/// A member's public signing key and public encryption key, in that order.
pub(crate) type RecipientKey = (Vec<u8>, Vec<u8>);

fn slot(vault_id: &[u8]) -> String {
    format!("membership.recipient-keys.v1:{}", hex::encode(vault_id))
}

/// Remember the operator-confirmed recipient key even if other legacy keys
/// are still missing. No membership changes until every recipient is known;
/// re-granting each missing member progressively repairs an older device.
/// An explicit re-grant updates its supplied recipient, as the API has always
/// allowed; other recipients' keys are never silently refreshed from a server.
pub(crate) fn recipients(
    storage: &Storage,
    vault_id: &[u8],
    members: &[Member],
    owner: RecipientKey,
    supplied: RecipientKey,
) -> Result<Vec<RecipientKey>, FfiError> {
    let key = slot(vault_id);
    let mut pins: BTreeMap<String, String> = match storage.get_meta(&key)? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(FfiError::other)?,
        None => BTreeMap::new(),
    };
    for (ed, x) in [owner, supplied] {
        let ed = hex::encode(ed);
        let x = hex::encode(x);
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

/// A VK rotation explicitly supplies every remaining recipient's verified
/// keys. Remember the exact keys that received the new VK, atomically with
/// that rotation, so a later grant cannot fall back to an obsolete X25519 key.
pub(crate) fn remember_rotation(
    storage: &Storage,
    vault_id: &[u8],
    grants: &[(Vec<u8>, Vec<u8>, unissh_storage::MemberRole)],
) -> Result<(), FfiError> {
    let keys: BTreeMap<String, String> = grants
        .iter()
        .map(|(x, ed, _)| (hex::encode(ed), hex::encode(x)))
        .collect();
    storage.set_meta(
        &slot(vault_id),
        &serde_json::to_vec(&keys).map_err(FfiError::other)?,
    )?;
    Ok(())
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
        let updated = recipients(
            &storage,
            b"vault",
            &members,
            owner(),
            (vec![2; 32], vec![99; 32]),
        )
        .unwrap();
        assert_eq!(updated[1], (vec![2; 32], vec![99; 32]));
        assert_eq!(updated[2], (vec![3; 32], vec![33; 32]));
    }

    #[test]
    fn a_grant_after_vk_rotation_uses_the_updated_recipient_key() {
        use crate::{Core, FfiMemberRole, RemainingMember};
        use unissh_keychain::{create_account, KdfParams};
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().into_owned(),
            dir.path().join("i.keyset").to_string_lossy().into_owned(),
        );
        core.create_account(None).unwrap();
        let vault = core
            .create_cloud_vault("Team".into(), "dGVuYW50LXRlc3Q=".into())
            .unwrap();
        let old = create_account(None, KdfParams::recommended()).unwrap().2;
        let updated = create_account(None, KdfParams::recommended()).unwrap().2;
        let added = create_account(None, KdfParams::recommended()).unwrap().2;
        let member_ed = old.signing.verifying.to_bytes().to_vec();
        core.add_member(
            vault.clone(),
            hex::encode(&member_ed),
            hex::encode(old.encryption.public.to_bytes()),
            FfiMemberRole::Editor,
        )
        .unwrap();
        core.rotate_vk(
            vault.clone(),
            vec![RemainingMember {
                ed25519_pub_hex: hex::encode(&member_ed),
                x25519_pub_hex: hex::encode(updated.encryption.public.to_bytes()),
                role: FfiMemberRole::Editor,
            }],
        )
        .unwrap();
        core.add_member(
            vault.clone(),
            hex::encode(added.signing.verifying.to_bytes()),
            hex::encode(added.encryption.public.to_bytes()),
            FfiMemberRole::Editor,
        )
        .unwrap();
        let vid = hex::decode(&vault).unwrap();
        let (grant, members) = core
            .with_state(|state| {
                let members = unissh_vault::verify_chain_to_epoch(
                    &state.storage,
                    &vid,
                    3,
                    &state.keyset.signing.verifying.to_bytes(),
                )
                .map_err(FfiError::other)?;
                let grant = state
                    .storage
                    .list_membership_grants(&vid, 3)?
                    .into_iter()
                    .find(|g| g.member_pubkey == member_ed)
                    .unwrap();
                Ok((grant, members))
            })
            .unwrap();
        unissh_vault::verify_grant(&grant, &vid, &members).unwrap();
        assert!(unissh_vault::open_grant(
            &grant,
            &vid,
            &updated.encryption.secret,
            &member_ed,
            3,
            0
        )
        .is_ok());
        assert!(
            unissh_vault::open_grant(&grant, &vid, &old.encryption.secret, &member_ed, 3, 0)
                .is_err(),
            "an obsolete recipient key must not receive the current VK"
        );
    }
}
