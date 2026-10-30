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
