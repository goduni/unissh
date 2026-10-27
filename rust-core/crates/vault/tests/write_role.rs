//! A member's role gates item writes in a shared vault: a Viewer's write is
//! refused before anything is stored (the server and every other member would
//! refuse the record anyway), an Editor's goes through. Own vaults (local or
//! cloud, the account is the owner) are covered by every other vault test.
#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use unissh_keychain::{create_account, KdfParams, UnlockedKeyset};
use unissh_storage::{MemberRole, Storage};
use unissh_vault::{Member, Vault, VaultError};

fn keyset() -> UnlockedKeyset {
    let (_sk, _rec, unlocked) = create_account(None, KdfParams::recommended()).unwrap();
    unlocked
}
fn ed_of(ks: &UnlockedKeyset) -> Vec<u8> {
    ks.signing.verifying.to_bytes().to_vec()
}
fn x_of(ks: &UnlockedKeyset) -> Vec<u8> {
    ks.encryption.public.to_bytes().to_vec()
}

/// The owner shares vault `sv` with `member` as `role` and stores item `host`
/// in it; the member's device has pinned the owner as the vault's genesis owner
/// (as sync does). Returns the storage the member opens the vault from.
fn shared_with(owner: &UnlockedKeyset, member: &UnlockedKeyset, role: MemberRole) -> Storage {
    let st = Storage::open_in_memory(&[7_u8; 32]).unwrap();
    let v = Vault::create(&st, owner, b"sv".to_vec(), b"shared").unwrap();
    let members = vec![
        Member {
            ed25519_pub: ed_of(owner),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: ed_of(member),
            role,
        },
    ];
    let xkeys = vec![(ed_of(owner), x_of(owner)), (ed_of(member), x_of(member))];
    v.establish_or_extend_membership(owner, &members, &xkeys)
        .unwrap();
    drop(v);
    Vault::open(&st, owner, b"sv")
        .unwrap()
        .put_item(b"host", 1, b"owner's host")
        .unwrap();
    st.set_vault_trust_anchor(b"sv", &ed_of(owner)).unwrap();
    st
}

#[test]
fn viewer_item_writes_are_refused_and_store_nothing() {
    let (owner, viewer) = (keyset(), keyset());
    let st = shared_with(&owner, &viewer, MemberRole::Viewer);
    let host_before = st.get_item(b"sv", b"host").unwrap().unwrap();

    let v = Vault::open(&st, &viewer, b"sv").unwrap();
    assert!(!v.can_write());
    // The Viewer still reads.
    assert_eq!(
        v.get_item(b"host").unwrap().unwrap().content.as_slice(),
        b"owner's host"
    );
    assert!(matches!(
        v.put_item(b"new", 1, b"x"),
        Err(VaultError::ReadOnly)
    ));
    assert!(matches!(
        v.put_item_keep_history(b"host", 1, b"edited"),
        Err(VaultError::ReadOnly)
    ));
    assert!(matches!(v.delete_item(b"host"), Err(VaultError::ReadOnly)));
    assert!(matches!(
        v.rename_item(b"host", b"moved"),
        Err(VaultError::ReadOnly)
    ));

    // Nothing was written: no new item, the owner's item untouched (same version,
    // same author, not a tombstone).
    assert!(st.get_item(b"sv", b"new").unwrap().is_none());
    assert!(st.get_item(b"sv", b"moved").unwrap().is_none());
    let host_after = st.get_item(b"sv", b"host").unwrap().unwrap();
    assert_eq!(host_after.version, host_before.version);
    assert_eq!(host_after.author_pubkey, host_before.author_pubkey);
    assert!(!host_after.tombstone);
}

#[test]
fn editor_item_write_goes_through_and_reads_back() {
    let (owner, editor) = (keyset(), keyset());
    let st = shared_with(&owner, &editor, MemberRole::Editor);

    let v = Vault::open(&st, &editor, b"sv").unwrap();
    v.put_item(b"host", 1, b"editor's edit").unwrap();
    // Read back through the authority check every other member applies.
    assert_eq!(
        v.get_item(b"host").unwrap().unwrap().content.as_slice(),
        b"editor's edit"
    );
}
