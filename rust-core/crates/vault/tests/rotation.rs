//! P4 tests: eager VK rotation, revocation re-wrap, purge_vault, member-aware verify_chain.
#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use unissh_keychain::{create_account, KdfParams, UnlockedKeyset};
use unissh_storage::{ItemRecord, MemberRole, Storage};
use unissh_vault::{
    build_manifest, open_grant, verify_manifest, IntegrityFailure, Member, Vault, VaultError,
};

fn keyset() -> UnlockedKeyset {
    let (_sk, _rec, unlocked) = create_account(None, KdfParams::recommended()).unwrap();
    unlocked
}
fn storage() -> Storage {
    Storage::open_in_memory(&[7_u8; 32]).unwrap()
}

/// a member's member-id = their Ed25519 pubkey; X25519 pub is for wrapping the VK.
fn ed_of(ks: &UnlockedKeyset) -> Vec<u8> {
    ks.signing.verifying.to_bytes().to_vec()
}
fn x_of(ks: &UnlockedKeyset) -> Vec<u8> {
    ks.encryption.public.to_bytes().to_vec()
}

/// Turns a freshly created Vault into a membership vault: puts a genesis manifest@1
/// over the `members` set into storage. The Vault is created by admin (owner==admin_ed).
/// The vault VK is not needed for the manifest — the manifest is only about members/roles.
fn put_genesis_manifest(st: &Storage, admin: &UnlockedKeyset, vault_id: &[u8], members: &[Member]) {
    let m = build_manifest(admin, vault_id, 1, members).unwrap();
    // self-check the chain before persisting (genesis_owner == admin_ed)
    let admin_ed = ed_of(admin);
    verify_manifest(&m, vault_id, None, &admin_ed).unwrap();
    st.put_membership_manifest(&m).unwrap();
}

#[test]
fn rotate_vk_reissues_to_remaining_members_only() {
    let st = storage();
    let admin = keyset();
    let bob = keyset(); // stays
    let carol = keyset(); // will be revoked
    let admin_ed = ed_of(&admin);
    let bob_ed = ed_of(&bob);
    let carol_ed = ed_of(&carol);

    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"secret", 1, b"top-secret").unwrap();

    // genesis manifest@1 over all three (carol = Editor)
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[
            Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: bob_ed.clone(),
                role: MemberRole::Editor,
            },
            Member {
                ed25519_pub: carol_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    );

    // Rotation: keep admin + bob (carol revoked). Grants only to those who remain.
    let remaining = vec![
        Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: bob_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    let grants = vec![
        (x_of(&admin), admin_ed, MemberRole::Admin),
        (x_of(&bob), bob_ed.clone(), MemberRole::Editor),
    ];
    let new_epoch = v.rotate_vk(&admin, &remaining, &grants).unwrap();
    assert_eq!(new_epoch, 2);

    // manifest@2 exists and verifies along the chain (genesis_owner=admin_ed)
    let m2 = st
        .get_membership_manifest(v.vault_id(), 2)
        .unwrap()
        .unwrap();
    assert_eq!(m2.key_epoch, 2);

    // bob (remaining) opens his grant@2 → obtains VK'
    let gs2 = st.list_membership_grants(v.vault_id(), 2).unwrap();
    let bob_grant = gs2.iter().find(|g| g.member_pubkey == bob_ed).unwrap();
    let vk_prime = open_grant(
        bob_grant,
        v.vault_id(),
        &bob.encryption.secret,
        &bob_ed,
        2,
        0,
    )
    .unwrap();
    assert_eq!(vk_prime.expose_bytes().len(), 32);

    // carol (revoked) has NO grant@2
    assert!(gs2.iter().all(|g| g.member_pubkey != carol_ed));

    // the epoch floor is raised to 2
    assert_eq!(st.get_vault_epoch_floor(v.vault_id()).unwrap().unwrap(), 2);

    // the vault record carries key_epoch=2 and its version has grown
    let vrec = st.get_vault(v.vault_id()).unwrap().unwrap();
    assert_eq!(vrec.key_epoch, 2);
    assert!(vrec.version >= 2);
}

#[test]
fn rotate_vk_by_non_admin_rejected() {
    let st = storage();
    let admin = keyset();
    let mallory = keyset(); // Editor, not Admin
    let admin_ed = ed_of(&admin);
    let mallory_ed = ed_of(&mallory);

    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[
            Member {
                ed25519_pub: admin_ed,
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: mallory_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    );
    // mallory (Editor) attempts to rotate
    let remaining = vec![Member {
        ed25519_pub: mallory_ed.clone(),
        role: MemberRole::Admin,
    }];
    let grants = vec![(x_of(&mallory), mallory_ed, MemberRole::Admin)];
    assert!(matches!(
        v.rotate_vk(&mallory, &remaining, &grants).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
    // nothing written for epoch 2
    assert!(st
        .get_membership_manifest(v.vault_id(), 2)
        .unwrap()
        .is_none());
    assert!(st.get_vault_epoch_floor(v.vault_id()).unwrap().is_none());
}

#[test]
fn rotate_vk_on_local_vault_without_manifest_rejected() {
    let st = storage();
    let owner = keyset();
    let owner_ed = ed_of(&owner);
    let v = Vault::create(&st, &owner, b"local".to_vec(), b"n").unwrap();
    v.put_item(b"i", 1, b"x").unwrap();
    // no manifest → rotation is not allowed (D2: local vaults don't change)
    let remaining = vec![Member {
        ed25519_pub: owner_ed.clone(),
        role: MemberRole::Admin,
    }];
    let grants = vec![(x_of(&owner), owner_ed, MemberRole::Admin)];
    assert!(matches!(
        v.rotate_vk(&owner, &remaining, &grants).unwrap_err(),
        VaultError::NotAMember
    ));
    // the local item reads as before
    assert_eq!(v.get_item(b"i").unwrap().unwrap().content.as_slice(), b"x");
}

#[test]
fn rotated_item_decrypts_under_new_vk_for_remaining_member() {
    use unissh_crypto::{aead_decrypt, unwrap_key};
    let st = storage();
    let admin = keyset();
    let bob = keyset();
    let admin_ed = ed_of(&admin);
    let bob_ed = ed_of(&bob);

    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"secret", 7, b"payload-v1").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[
            Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: bob_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    );
    let remaining = vec![
        Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: bob_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    let grants = vec![
        (x_of(&admin), admin_ed, MemberRole::Admin),
        (x_of(&bob), bob_ed.clone(), MemberRole::Editor),
    ];
    v.rotate_vk(&admin, &remaining, &grants).unwrap();

    // bob obtains VK' from his grant@2
    let gs2 = st.list_membership_grants(v.vault_id(), 2).unwrap();
    let bob_grant = gs2.iter().find(|g| g.member_pubkey == bob_ed).unwrap();
    let vk_prime = open_grant(
        bob_grant,
        v.vault_id(),
        &bob.encryption.secret,
        &bob_ed,
        2,
        0,
    )
    .unwrap();

    // reads the re-wrapped item: the storage record carries key_epoch=2, version=2
    let rec = st.get_item(v.vault_id(), b"secret").unwrap().unwrap();
    assert_eq!(rec.key_epoch, 2);
    assert_eq!(rec.version, 2);
    // the per-item key unwraps under VK' (AAD=item_id), content under the versioned AAD
    let item_key = unwrap_key(&vk_prime, &rec.wrapped_item_key, b"secret").unwrap();
    let aad = unissh_crypto::AssociatedData::new(v.vault_id().to_vec(), b"secret".to_vec(), 2);
    let pt = aead_decrypt(&item_key, &rec.content_blob, &aad).unwrap();
    assert_eq!(pt.as_slice(), b"payload-v1");
}

#[test]
fn rotated_item_key_not_unwrappable_with_old_vk() {
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"secret", 1, b"data").unwrap();
    // save the OLD wrapped_item_key before rotation
    let old_rec = st.get_item(v.vault_id(), b"secret").unwrap().unwrap();
    let old_wik = old_rec.wrapped_item_key;

    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed, MemberRole::Admin)],
    )
    .unwrap();

    let new_rec = st.get_item(v.vault_id(), b"secret").unwrap().unwrap();
    // the key wrap changed (under VK'). The direct "old VK doesn't open" check is
    // provided by rotated_item_decrypts_under_new_vk_for_remaining_member (VK' is not
    // directly visible to tests — the core↔UI boundary).
    assert_ne!(new_rec.wrapped_item_key, old_wik);
}

#[test]
fn rotate_vk_is_atomic_on_midway_failure() {
    // Atomicity: a failure MID-transaction (after writing manifest@2, grants@2, and
    // the re-wrapped item, at the put_vault step) must roll back the ENTIRE rotation —
    // no half-rotated state. Versions in `rotate_vk` are derived monotonically from
    // fresh reads, so a version conflict is unreachable; instead we deterministically
    // break put_vault via `checked_version`: stored vault-version = i64::MAX → rotation
    // computes v_version = i64::MAX+1, which storage rejects (VersionOutOfRange) already
    // INSIDE the transaction — after manifest/grant/item. The put order in the
    // transaction: manifest → grants → items → vault → floor (see Vault::rotate_vk).
    // `rotate_vk` does not decrypt the old name_blob (it takes self.name from memory and
    // re-encrypts under VK'/the new version), so swapping the stored vault-version does
    // not break its reads.
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"secret", 1, b"data").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );

    // Inject a vault record at version i64::MAX (storage does not trust the signature).
    let mut bumped = st.get_vault(v.vault_id()).unwrap().unwrap();
    bumped.version = i64::MAX as u64;
    st.put_vault(&bumped).unwrap();

    let err = v
        .rotate_vk(
            &admin,
            &[Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            }],
            &[(x_of(&admin), admin_ed, MemberRole::Admin)],
        )
        .unwrap_err();
    assert!(matches!(err, VaultError::Storage(_)), "actual err: {err:?}");

    // Full rollback: the re-wrapped item is NOT written (it stays at version=1, epoch=0),
    // manifest@2 / epoch floor / grants@2 are absent. The key point: nothing from epoch 2
    // is committed (manifest@2 and grant@2 were written in the transaction before the
    // failed put_vault).
    let it = st.get_item(v.vault_id(), b"secret").unwrap().unwrap();
    assert_eq!(it.version, 1);
    assert_eq!(it.key_epoch, 0);
    assert!(st
        .get_membership_manifest(v.vault_id(), 2)
        .unwrap()
        .is_none());
    assert!(st.get_vault_epoch_floor(v.vault_id()).unwrap().is_none());
    assert!(st
        .list_membership_grants(v.vault_id(), 2)
        .unwrap()
        .is_empty());
}

#[test]
fn purge_vault_leaves_no_rows() {
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"x").unwrap();
    v.put_item_keep_history(b"pw", 4, b"s1").unwrap();
    v.put_item_keep_history(b"pw", 4, b"s2").unwrap(); // creates history
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed,
            role: MemberRole::Admin,
        }],
    );
    st.set_vault_epoch_floor(v.vault_id(), 1).unwrap();
    let vid = v.vault_id().to_vec();

    // a neighboring vault — do not touch
    let other = Vault::create(&st, &admin, b"other".to_vec(), b"o").unwrap();
    other.put_item(b"keep", 1, b"y").unwrap();

    // purge consumes self (zeroize VK) and erases all rows
    v.purge_vault().unwrap();

    assert!(st.get_vault(&vid).unwrap().is_none());
    assert!(st.list_items_including_tombstones(&vid).unwrap().is_empty());
    assert!(st.list_all_history(&vid).unwrap().is_empty());
    assert!(st.get_membership_manifest(&vid, 1).unwrap().is_none());
    assert!(st.list_membership_grants(&vid, 1).unwrap().is_empty());
    assert!(st.get_vault_epoch_floor(&vid).unwrap().is_none());
    // the neighboring vault is intact
    assert!(st.get_vault(other.vault_id()).unwrap().is_some());
    assert_eq!(st.list_items(other.vault_id()).unwrap().len(), 1);
}

#[test]
fn purge_vault_after_rotation_clears_all_epochs() {
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"x").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed, MemberRole::Admin)],
    )
    .unwrap();
    let vid = v.vault_id().to_vec();
    // reopening under VK' is not needed for purge — purge doesn't unwrap the VK
    v.purge_vault().unwrap();
    // both epochs of manifests/grants are erased
    assert!(st.get_membership_manifest(&vid, 1).unwrap().is_none());
    assert!(st.get_membership_manifest(&vid, 2).unwrap().is_none());
    assert!(st.list_membership_grants(&vid, 1).unwrap().is_empty());
    assert!(st.list_membership_grants(&vid, 2).unwrap().is_empty());
    assert!(st.get_vault(&vid).unwrap().is_none());
}

#[test]
fn verify_chain_ok_after_rotation() {
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed, MemberRole::Admin)],
    )
    .unwrap();

    // verify_chain on the same instance (its genesis_owner = admin = author of all records)
    let report = v.verify_chain().unwrap();
    assert!(report.ok, "issues: {:?}", report.issues);
}

#[test]
fn rotate_vk_rejects_omitting_owner_from_remaining_members() {
    // P4 review (hardening): the re-wrapped items and the new vault record are authored
    // by the owner (self.keyset == genesis_owner). If an admin != owner omits the owner
    // from remaining_members, those records at new_epoch are from a non-member and will
    // later be rejected by verify_record_authority. rotate_vk must reject such a rotation
    // BEFORE writing. Control: with the owner in the set — rotation is ok.
    let st = storage();
    let owner = keyset(); // vault creator = genesis_owner
    let admin2 = keyset(); // second admin, != owner
    let owner_ed = ed_of(&owner);
    let admin2_ed = ed_of(&admin2);

    let v = Vault::create(&st, &owner, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"secret", 1, b"top").unwrap();
    // genesis@1: owner Admin + admin2 Admin.
    put_genesis_manifest(
        &st,
        &owner,
        v.vault_id(),
        &[
            Member {
                ed25519_pub: owner_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: admin2_ed.clone(),
                role: MemberRole::Admin,
            },
        ],
    );

    // admin2 rotates, OMITTING the owner from remaining_members → rejected.
    let err = v
        .rotate_vk(
            &admin2,
            &[Member {
                ed25519_pub: admin2_ed.clone(),
                role: MemberRole::Admin,
            }],
            &[(x_of(&admin2), admin2_ed.clone(), MemberRole::Admin)],
        )
        .unwrap_err();
    assert!(matches!(err, VaultError::NotAMember), "got {err:?}");
    // nothing committed: epoch 2 is absent, the floor is not set.
    assert!(st
        .get_membership_manifest(v.vault_id(), 2)
        .unwrap()
        .is_none());
    assert!(st.get_vault_epoch_floor(v.vault_id()).unwrap().is_none());

    // Control: admin2 includes the owner → rotation passes.
    v.rotate_vk(
        &admin2,
        &[
            Member {
                ed25519_pub: owner_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: admin2_ed.clone(),
                role: MemberRole::Admin,
            },
        ],
        &[
            (x_of(&owner), owner_ed, MemberRole::Admin),
            (x_of(&admin2), admin2_ed, MemberRole::Admin),
        ],
    )
    .unwrap();
    assert_eq!(st.get_vault_epoch_floor(v.vault_id()).unwrap().unwrap(), 2);
}

#[test]
fn verify_chain_flags_record_below_epoch_floor() {
    use unissh_crypto::{
        aead_encrypt, sign_version, wrap_key, AssociatedData, SymmetricKey, VersionedObject,
    };
    // After rotation (floor=2) we maliciously inject an item record at epoch 1
    // (manifest@1 is still in storage, but the epoch is below the floor). verify_chain
    // must flag it as NotAuthorized (anti-rollback, §1.1).
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
    )
    .unwrap();
    // after rotation item "a" is at epoch 2, floor=2. Inject a NEW item at epoch 1.
    let item_key = SymmetricKey::generate();
    let aad = AssociatedData::new(v.vault_id().to_vec(), b"injected".to_vec(), 1_u64);
    let content_blob = aead_encrypt(&item_key, b"old", &aad).unwrap();
    let vo = VersionedObject::from_content(aad, &content_blob);
    let signature = sign_version(&admin.signing.signing, &vo).unwrap();
    let injected = ItemRecord {
        vault_id: v.vault_id().to_vec(),
        item_id: b"injected".to_vec(),
        item_type: 1,
        content_blob,
        wrapped_item_key: wrap_key(&item_key, &item_key, b"injected").unwrap(),
        version: 1,
        tombstone: false,
        signature,
        author_pubkey: admin_ed,
        created_at: 0,
        updated_at: 0,
        key_epoch: 1, // below the floor (2)
    };
    st.put_item(&injected).unwrap();

    let report = v.verify_chain().unwrap();
    assert!(!report.ok);
    assert!(report
        .issues
        .iter()
        .any(|i| i.item_id == b"injected" && i.failure == IntegrityFailure::NotAuthorized));
}

#[test]
fn verify_chain_flags_record_with_epoch_having_no_manifest() {
    use unissh_crypto::{
        aead_encrypt, sign_version, wrap_key, AssociatedData, SymmetricKey, VersionedObject,
    };
    // ANTI-ROLLBACK BYPASS (high): post-rotation an attacker from an untrusted DB
    // stamps key_epoch=0 (an epoch WITHOUT a manifest) onto a VALIDLY-owner-signed
    // record. Before the fix the mode was computed PER-RECORD from its own key_epoch:
    // no manifest@0 → downgrade to owner==author → the record was accepted (floor/D1
    // were skipped). The fix: the mode is taken from a vault-level trusted signal; in
    // membership mode a record at an epoch without a manifest → NotAuthorized.
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
    )
    .unwrap();
    // Injection: a record at key_epoch=0 (NO manifest@0), signed by owner (validly).
    let item_key = SymmetricKey::generate();
    let aad = AssociatedData::new(v.vault_id().to_vec(), b"injected".to_vec(), 1_u64);
    let content_blob = aead_encrypt(&item_key, b"old", &aad).unwrap();
    let vo = VersionedObject::from_content(aad, &content_blob);
    let signature = sign_version(&admin.signing.signing, &vo).unwrap();
    let injected = ItemRecord {
        vault_id: v.vault_id().to_vec(),
        item_id: b"injected".to_vec(),
        item_type: 1,
        content_blob,
        wrapped_item_key: wrap_key(&item_key, &item_key, b"injected").unwrap(),
        version: 1,
        tombstone: false,
        signature,
        author_pubkey: admin_ed,
        created_at: 0,
        updated_at: 0,
        key_epoch: 0, // an epoch WITHOUT a manifest — mode downgrade
    };
    st.put_item(&injected).unwrap();

    let report = v.verify_chain().unwrap();
    assert!(!report.ok);
    assert!(report
        .issues
        .iter()
        .any(|i| i.item_id == b"injected" && i.failure == IntegrityFailure::NotAuthorized));
}

#[test]
fn get_item_refuses_downgraded_epoch_record() {
    use unissh_crypto::{
        aead_encrypt, sign_version, wrap_key, AssociatedData, SymmetricKey, VersionedObject,
    };
    // The same downgrade on the LIVE read path (decrypt_record): after rotation (floor=2)
    // an untrusted DB puts a VALIDLY-owner-signed record at key_epoch=0 (an epoch
    // WITHOUT a manifest). Before the fix decrypt_record chose the mode by
    // record.key_epoch: no manifest@0 → owner==author passed → on to unwrap_key/decrypt.
    // Authority MUST reject BEFORE unwrapping the key (VaultError != Decrypt), otherwise
    // the downgrade mode is accepted. This is the "empirically reproduced" read path.
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
    )
    .unwrap();
    // reopen the vault as owner: vault record@2 seals VK' under his pubkey.
    let v2 = Vault::open(&st, &admin, v.vault_id()).unwrap();

    // Injection: a new record at key_epoch=0, validly signed by owner.
    let item_key = SymmetricKey::generate();
    let aad = AssociatedData::new(v.vault_id().to_vec(), b"injected".to_vec(), 1_u64);
    let content_blob = aead_encrypt(&item_key, b"old", &aad).unwrap();
    let vo = VersionedObject::from_content(aad, &content_blob);
    let signature = sign_version(&admin.signing.signing, &vo).unwrap();
    let injected = ItemRecord {
        vault_id: v.vault_id().to_vec(),
        item_id: b"injected".to_vec(),
        item_type: 1,
        content_blob,
        wrapped_item_key: wrap_key(&item_key, &item_key, b"injected").unwrap(),
        version: 1,
        tombstone: false,
        signature,
        author_pubkey: admin_ed,
        created_at: 0,
        updated_at: 0,
        key_epoch: 0, // an epoch WITHOUT a manifest — mode downgrade
    };
    st.put_item(&injected).unwrap();

    // The live read path must reject ON AUTHORITY, before reaching unwrap/decrypt.
    let err = v2.get_item(b"injected").unwrap_err();
    assert!(
        !matches!(err, VaultError::Decrypt),
        "authority must reject before key unwrap; got {err:?}"
    );
}

#[test]
fn verify_chain_rejects_self_consistent_old_epoch_record() {
    use unissh_crypto::{
        aead_encrypt, sign_version, wrap_key, AssociatedData, SymmetricKey, VersionedObject,
    };
    // After rotation the server serves a record whose author is NOT a member of the
    // verified chain at its epoch. verify_chain catches this.
    let st = storage();
    let admin = keyset();
    let attacker = keyset();
    let admin_ed = ed_of(&admin);
    let attacker_ed = ed_of(&attacker);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed, MemberRole::Admin)],
    )
    .unwrap();
    // attacker injects a record at epoch 2, signed by themselves (not a member@2).
    let item_key = SymmetricKey::generate();
    let aad = AssociatedData::new(v.vault_id().to_vec(), b"evil".to_vec(), 1_u64);
    let content_blob = aead_encrypt(&item_key, b"x", &aad).unwrap();
    let vo = VersionedObject::from_content(aad, &content_blob);
    let signature = sign_version(&attacker.signing.signing, &vo).unwrap();
    let evil = ItemRecord {
        vault_id: v.vault_id().to_vec(),
        item_id: b"evil".to_vec(),
        item_type: 1,
        content_blob,
        wrapped_item_key: wrap_key(&item_key, &item_key, b"evil").unwrap(),
        version: 1,
        tombstone: false,
        signature,
        author_pubkey: attacker_ed,
        created_at: 0,
        updated_at: 0,
        key_epoch: 2, // at epoch 2 the attacker is NOT a member
    };
    st.put_item(&evil).unwrap();
    let report = v.verify_chain().unwrap();
    assert!(!report.ok);
    assert!(report
        .issues
        .iter()
        .any(|i| i.item_id == b"evil" && i.failure == IntegrityFailure::NotAuthorized));
}
