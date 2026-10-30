//! BLOCKER regression (data-loss): records created AFTER a vault transitions into
//! membership mode must carry the current `key_epoch` (>= floor, manifest@epoch),
//! otherwise `verify_record_authority` rejects them as a downgrade (`EpochInvalid`)
//! and the item is permanently unreadable. Before the fix, `put_item`/
//! `put_item_keep_history`/`tombstone_record` hard-stamped `key_epoch=0`.
#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use unissh_keychain::{create_account, KdfParams, UnlockedKeyset};
use unissh_storage::{MemberRole, Storage};
use unissh_vault::{Member, Vault};

fn keyset() -> UnlockedKeyset {
    let (_sk, _rec, unlocked) = create_account(None, KdfParams::recommended()).unwrap();
    unlocked
}
fn storage() -> Storage {
    Storage::open_in_memory(&[7_u8; 32]).unwrap()
}
fn ed_of(ks: &UnlockedKeyset) -> Vec<u8> {
    ks.signing.verifying.to_bytes().to_vec()
}
fn x_of(ks: &UnlockedKeyset) -> Vec<u8> {
    ks.encryption.public.to_bytes().to_vec()
}

/// BLOCKER: after membership is established (owner=Admin) and the vault reopened, a
/// new `put_item` must round-trip through `get_item`. Before the fix it returned
/// `EpochInvalid` (item at key_epoch=0 while membership@1).
#[test]
fn put_item_after_membership_roundtrips() {
    let st = storage();
    let owner = keyset();
    let owner_ed = ed_of(&owner);
    let owner_x = x_of(&owner);

    let v = Vault::create(&st, &owner, b"mv".to_vec(), b"shared").unwrap();
    let vid = v.vault_id().to_vec();

    let members = vec![Member {
        ed25519_pub: owner_ed.clone(),
        role: MemberRole::Admin,
    }];
    let xkeys = vec![(owner_ed, owner_x)];
    let epoch = v
        .establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();
    assert_eq!(epoch, 1);
    drop(v);

    // Reopen the vault and put a NEW item — it must land on the current epoch
    // and read back.
    let v2 = Vault::open(&st, &owner, &vid).unwrap();
    v2.put_item(b"secret", 1, b"top-secret").unwrap();
    let got = v2
        .get_item(b"secret")
        .expect("get_item must not error")
        .expect("item must exist");
    assert_eq!(got.content.as_slice(), b"top-secret");

    // put_item_keep_history too.
    v2.put_item_keep_history(b"pwd", 2, b"hunter2").unwrap();
    let pwd = v2.get_item(b"pwd").unwrap().unwrap();
    assert_eq!(pwd.content.as_slice(), b"hunter2");

    // tombstone (delete_item) must also be authorized (verify_chain green).
    v2.delete_item(b"secret").unwrap();
    let report = v2.verify_chain().unwrap();
    assert!(report.ok, "verify_chain must be green: {:?}", report);
}

/// After `rotate_vk`, a NEW `put_item` (on a vault reopened under VK') must
/// round-trip. Before the fix it was written at key_epoch=0 < floor → EpochInvalid.
#[test]
fn put_item_after_rotate_vk_roundtrips() {
    let st = storage();
    let owner = keyset();
    let owner_ed = ed_of(&owner);
    let owner_x = x_of(&owner);

    let v = Vault::create(&st, &owner, b"mv".to_vec(), b"shared").unwrap();
    let vid = v.vault_id().to_vec();

    let members = vec![Member {
        ed25519_pub: owner_ed.clone(),
        role: MemberRole::Admin,
    }];
    let xkeys = vec![(owner_ed.clone(), owner_x.clone())];
    v.establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();

    let grants = vec![(owner_x, owner_ed, MemberRole::Admin)];
    let new_epoch = v.rotate_vk(&owner, &members, &grants).unwrap();
    assert_eq!(new_epoch, 2);
    drop(v);

    // Reopen under VK' (the owner's current wrap at epoch 2) and put a new
    // item — it must land on epoch 2 (>= floor=2, manifest@2) and read back.
    let v2 = Vault::open(&st, &owner, &vid).unwrap();
    v2.put_item(b"fresh", 1, b"after-rotation").unwrap();
    let got = v2.get_item(b"fresh").unwrap().unwrap();
    assert_eq!(got.content.as_slice(), b"after-rotation");

    // The written item carries key_epoch=2 (the vault's current epoch), not 0.
    let rec = st.get_item(&vid, b"fresh").unwrap().unwrap();
    assert_eq!(rec.key_epoch, 2);

    let report = v2.verify_chain().unwrap();
    assert!(report.ok, "verify_chain must be green: {:?}", report);
}

#[test]
fn sharing_reanchors_existing_items_and_keeps_deleted_items_deleted() {
    let st = storage();
    let owner = keyset();
    let v = Vault::create(&st, &owner, b"share-old".to_vec(), b"shared").unwrap();
    v.put_item(b"before-share", 6, b"existing note").unwrap();
    v.put_item(b"deleted", 6, b"do not resurrect").unwrap();
    v.delete_item(b"deleted").unwrap();
    let members = [Member {
        ed25519_pub: ed_of(&owner),
        role: MemberRole::Admin,
    }];
    let xkeys = [(ed_of(&owner), x_of(&owner))];
    for epoch in [1, 2] {
        assert_eq!(
            v.establish_or_extend_membership(&owner, &members, &xkeys)
                .unwrap(),
            epoch
        );
        assert_eq!(
            v.get_item(b"before-share")
                .unwrap()
                .unwrap()
                .content
                .as_slice(),
            b"existing note"
        );
        let record = st.get_item(v.vault_id(), b"before-share").unwrap().unwrap();
        assert_eq!(record.key_epoch, epoch);
        assert_eq!(record.version, epoch + 1);
        assert!(
            st.get_item(v.vault_id(), b"deleted")
                .unwrap()
                .unwrap()
                .tombstone
        );
        assert!(v.verify_chain().unwrap().ok);
    }
}

#[test]
fn sharing_does_not_promote_a_record_with_a_tampered_signature() {
    let st = storage();
    let owner = keyset();
    let v = Vault::create(&st, &owner, b"bad-share".to_vec(), b"shared").unwrap();
    v.put_item(b"note", 6, b"existing note").unwrap();
    let mut record = st.get_item(v.vault_id(), b"note").unwrap().unwrap();
    record.version += 1;
    record.signature[0] ^= 1;
    st.put_item(&record).unwrap();
    let members = [Member {
        ed25519_pub: ed_of(&owner),
        role: MemberRole::Admin,
    }];
    let xkeys = [(ed_of(&owner), x_of(&owner))];
    assert!(v
        .establish_or_extend_membership(&owner, &members, &xkeys)
        .is_err());
    assert!(st.latest_membership_epoch(v.vault_id()).unwrap().is_none());
    assert_eq!(
        st.get_item(v.vault_id(), b"note").unwrap().unwrap().version,
        2
    );
}

#[test]
fn membership_change_does_not_launder_a_viewers_signed_edit() {
    use unissh_crypto::{sign_version, AssociatedData, VersionedObject};
    let st = storage();
    let owner = keyset();
    let viewer = keyset();
    let v = Vault::create(&st, &owner, b"viewer-share".to_vec(), b"shared").unwrap();
    let members = [
        Member {
            ed25519_pub: ed_of(&owner),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: ed_of(&viewer),
            role: MemberRole::Viewer,
        },
    ];
    let xkeys = [
        (ed_of(&owner), x_of(&owner)),
        (ed_of(&viewer), x_of(&viewer)),
    ];
    v.establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();
    v.put_item(b"note", 6, b"owner's note").unwrap();
    let mut record = st.get_item(v.vault_id(), b"note").unwrap().unwrap();
    record.version += 1;
    record.author_pubkey = ed_of(&viewer);
    let aad = AssociatedData::new(
        v.vault_id().to_vec(),
        record.item_id.clone(),
        record.version,
    );
    record.signature = sign_version(
        &viewer.signing.signing,
        &VersionedObject::from_content(aad, &record.content_blob),
    )
    .unwrap();
    st.put_item(&record).unwrap();
    assert!(matches!(
        v.establish_or_extend_membership(&owner, &members, &xkeys),
        Err(unissh_vault::VaultError::AuthorityInvalid)
    ));
    assert_eq!(st.latest_membership_epoch(v.vault_id()).unwrap(), Some(1));
    assert_eq!(
        st.get_item(v.vault_id(), b"note")
            .unwrap()
            .unwrap()
            .author_pubkey,
        ed_of(&viewer)
    );
}

#[test]
fn vault_key_rotation_keeps_deleted_records_current_and_deleted() {
    let st = storage();
    let owner = keyset();
    let v = Vault::create(&st, &owner, b"rotate-deleted".to_vec(), b"shared").unwrap();
    let members = [Member {
        ed25519_pub: ed_of(&owner),
        role: MemberRole::Admin,
    }];
    let xkeys = [(ed_of(&owner), x_of(&owner))];
    v.establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();
    v.put_item(b"deleted", 6, b"never resurrect").unwrap();
    v.delete_item(b"deleted").unwrap();
    let grants = [(x_of(&owner), ed_of(&owner), MemberRole::Admin)];
    v.rotate_vk(&owner, &members, &grants).unwrap();
    let reopened = Vault::open(&st, &owner, v.vault_id()).unwrap();
    let record = st.get_item(v.vault_id(), b"deleted").unwrap().unwrap();
    assert!(record.tombstone);
    assert_eq!(record.key_epoch, 2);
    assert!(reopened.verify_chain().unwrap().ok);
    // Simulate an older client's signed deletion left below the trusted floor.
    signed_stale_delete(&st, v.vault_id(), &owner, 1);
    reopened
        .establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();
    assert!(reopened.get_item(b"deleted").unwrap().is_none());
    assert_eq!(
        st.get_item(v.vault_id(), b"deleted")
            .unwrap()
            .unwrap()
            .key_epoch,
        3
    );
    assert!(reopened.verify_chain().unwrap().ok);
}

/// Reconstruct an older client's below-floor row without weakening the
/// ordinary read path. A membership-only update retains the VK; rotation does not.
#[test]
fn legacy_live_reissue_requires_the_current_vault_key() {
    for rotated in [false, true] {
        let st = storage();
        let owner = keyset();
        let v = Vault::create(&st, &owner, b"legacy-live".to_vec(), b"shared").unwrap();
        let members = [Member {
            ed25519_pub: ed_of(&owner),
            role: MemberRole::Admin,
        }];
        let xkeys = [(ed_of(&owner), x_of(&owner))];
        v.establish_or_extend_membership(&owner, &members, &xkeys)
            .unwrap();
        v.put_item(b"note", 6, b"existing note").unwrap();
        let legacy = st.get_item(v.vault_id(), b"note").unwrap().unwrap();
        if rotated {
            v.rotate_vk(
                &owner,
                &members,
                &[(x_of(&owner), ed_of(&owner), MemberRole::Admin)],
            )
            .unwrap();
        } else {
            v.establish_or_extend_membership(&owner, &members, &xkeys)
                .unwrap();
        }
        let current = st.get_item(v.vault_id(), b"note").unwrap().unwrap();
        assert!(st
            .discard_unpushed_item(v.vault_id(), b"note", current.version, &ed_of(&owner))
            .unwrap());
        st.put_item(&legacy).unwrap();
        st.set_vault_epoch_floor(v.vault_id(), 2).unwrap();
        let reopened = Vault::open(&st, &owner, v.vault_id()).unwrap();
        assert!(matches!(
            reopened.get_item(b"note"),
            Err(unissh_vault::VaultError::EpochInvalid)
        ));
        let repaired = reopened.establish_or_extend_membership(&owner, &members, &xkeys);
        if rotated {
            assert!(
                repaired.is_err(),
                "old-VK ciphertext must never be reissued under VK prime"
            );
            assert_eq!(st.latest_membership_epoch(v.vault_id()).unwrap(), Some(2));
        } else {
            assert_eq!(repaired.unwrap(), 3);
            assert_eq!(
                reopened
                    .get_item(b"note")
                    .unwrap()
                    .unwrap()
                    .content
                    .as_slice(),
                b"existing note"
            );
            assert!(reopened.verify_chain().unwrap().ok);
        }
        assert!(
            unissh_vault::verify_record_authority(
                &st,
                v.vault_id(),
                &ed_of(&owner),
                1,
                &ed_of(&owner)
            )
            .is_err(),
            "ordinary authority checks must still enforce the floor"
        );
    }
}

fn signed_stale_delete(st: &Storage, vault_id: &[u8], signer: &UnlockedKeyset, epoch: u64) {
    use unissh_crypto::{sign_version, AssociatedData, VersionedObject};
    let mut record = st.get_item(vault_id, b"deleted").unwrap().unwrap();
    assert!(
        record.tombstone && record.content_blob.is_empty() && record.wrapped_item_key.is_empty()
    );
    record.version += 1;
    record.key_epoch = epoch;
    record.author_pubkey = ed_of(signer);
    let aad = AssociatedData::new(vault_id.to_vec(), record.item_id.clone(), record.version);
    record.signature = sign_version(
        &signer.signing.signing,
        &VersionedObject::from_content(aad, &record.content_blob),
    )
    .unwrap();
    st.put_item(&record).unwrap();
}

#[test]
fn old_epoch_deletes_from_revoked_or_demoted_signers_are_not_promoted() {
    for remaining_role in [None, Some(MemberRole::Viewer)] {
        let st = storage();
        let owner = keyset();
        let writer = keyset();
        let v = Vault::create(&st, &owner, b"revoked-delete".to_vec(), b"shared").unwrap();
        let members = [
            Member {
                ed25519_pub: ed_of(&owner),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: ed_of(&writer),
                role: MemberRole::Editor,
            },
        ];
        let xkeys = [
            (ed_of(&owner), x_of(&owner)),
            (ed_of(&writer), x_of(&writer)),
        ];
        v.establish_or_extend_membership(&owner, &members, &xkeys)
            .unwrap();
        v.put_item(b"deleted", 6, b"deleted").unwrap();
        v.delete_item(b"deleted").unwrap();
        let mut remaining = vec![members[0].clone()];
        let mut grants = vec![(x_of(&owner), ed_of(&owner), MemberRole::Admin)];
        if let Some(role) = remaining_role {
            remaining.push(Member {
                ed25519_pub: ed_of(&writer),
                role,
            });
            grants.push((x_of(&writer), ed_of(&writer), role));
        }
        v.rotate_vk(&owner, &remaining, &grants).unwrap();
        signed_stale_delete(&st, v.vault_id(), &writer, 1);
        for floor in [0, 2] {
            // Older owner clients could leave the floor unarmed. Current
            // permission is still required before reissuing their snapshot.
            st.set_vault_epoch_floor(v.vault_id(), floor).unwrap();
            let reopened = Vault::open(&st, &owner, v.vault_id()).unwrap();
            assert!(matches!(
                reopened.establish_or_extend_membership(&owner, &remaining, &xkeys),
                Err(unissh_vault::VaultError::AuthorityInvalid)
            ));
            assert!(matches!(
                reopened.rotate_vk(&owner, &remaining, &grants),
                Err(unissh_vault::VaultError::AuthorityInvalid)
            ));
        }
        assert_eq!(st.latest_membership_epoch(v.vault_id()).unwrap(), Some(2));
    }
}

#[test]
fn reissuing_a_snapshot_refuses_an_unsigned_flip_of_the_deleted_flag() {
    let st = storage();
    let owner = keyset();
    let v = Vault::create(&st, &owner, b"flipped-delete".to_vec(), b"shared").unwrap();
    v.put_item(b"note", 6, b"keep this note").unwrap();
    let mut record = st.get_item(v.vault_id(), b"note").unwrap().unwrap();
    assert!(st
        .discard_unpushed_item(v.vault_id(), b"note", record.version, &ed_of(&owner))
        .unwrap());
    // The signature covers the ciphertext, not this clear metadata flag.
    record.tombstone = true;
    st.put_item(&record).unwrap();
    let members = [Member {
        ed25519_pub: ed_of(&owner),
        role: MemberRole::Admin,
    }];
    assert!(matches!(
        v.establish_or_extend_membership(&owner, &members, &[(ed_of(&owner), x_of(&owner))]),
        Err(unissh_vault::VaultError::Format)
    ));
    assert!(st.latest_membership_epoch(v.vault_id()).unwrap().is_none());
}

#[test]
fn owner_repair_cannot_replace_a_missing_manifest_at_the_trusted_floor() {
    let st = storage();
    let owner = keyset();
    let v = Vault::create(&st, &owner, b"missing-manifest".to_vec(), b"shared").unwrap();
    let members = [Member {
        ed25519_pub: ed_of(&owner),
        role: MemberRole::Admin,
    }];
    let xkeys = [(ed_of(&owner), x_of(&owner))];
    v.establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();
    v.put_item(b"note", 6, b"existing note").unwrap();
    // A trusted floor says epoch 2 has already been seen, but its manifest
    // is missing. Neither owner operation may invent a replacement epoch 2.
    st.set_vault_epoch_floor(v.vault_id(), 2).unwrap();
    assert!(matches!(
        v.establish_or_extend_membership(&owner, &members, &xkeys),
        Err(unissh_vault::VaultError::EpochInvalid)
    ));
    assert!(matches!(
        v.rotate_vk(
            &owner,
            &members,
            &[(x_of(&owner), ed_of(&owner), MemberRole::Admin)]
        ),
        Err(unissh_vault::VaultError::EpochInvalid)
    ));
    assert!(st
        .get_membership_manifest(v.vault_id(), 2)
        .unwrap()
        .is_none());
    assert_eq!(st.get_vault_epoch_floor(v.vault_id()).unwrap(), Some(2));
}

#[test]
fn membership_changes_arm_the_owners_floor_without_a_sync_round_trip() {
    let st = storage();
    let owner = keyset();
    let editor = keyset();
    let v = Vault::create(&st, &owner, b"owner-floor".to_vec(), b"shared").unwrap();
    let mut members = [
        Member {
            ed25519_pub: ed_of(&owner),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: ed_of(&editor),
            role: MemberRole::Editor,
        },
    ];
    let xkeys = [
        (ed_of(&owner), x_of(&owner)),
        (ed_of(&editor), x_of(&editor)),
    ];
    v.establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();
    assert_eq!(st.get_vault_epoch_floor(v.vault_id()).unwrap(), Some(1));
    members[1].role = MemberRole::Viewer;
    v.establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();
    assert_eq!(st.get_vault_epoch_floor(v.vault_id()).unwrap(), Some(2));
    assert!(matches!(
        unissh_vault::verify_record_authority(
            &st,
            v.vault_id(),
            &ed_of(&editor),
            1,
            &ed_of(&owner)
        ),
        Err(unissh_vault::VaultError::EpochInvalid)
    ));
    // A legacy owner can have the manifest but no persisted floor. Reads
    // must enforce known membership even before the server echoes it.
    st.set_vault_epoch_floor(v.vault_id(), 0).unwrap();
    assert!(matches!(
        unissh_vault::verify_record_authority(
            &st,
            v.vault_id(),
            &ed_of(&editor),
            1,
            &ed_of(&owner)
        ),
        Err(unissh_vault::VaultError::EpochInvalid)
    ));
}
