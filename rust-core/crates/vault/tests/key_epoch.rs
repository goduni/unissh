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
