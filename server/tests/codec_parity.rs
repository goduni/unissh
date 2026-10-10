//! Byte-parity §15.2: the open columns parsed by the server MUST match
//! what the core (`unissh-sync::SyncObject::to_bytes`) puts in the blob. The core is
//! the reference oracle. Any deviation = a bug (spec preamble).

use unissh_server::codec::{ObjectTag, parse_open};
use unissh_storage::{
    CachePolicy, ItemRecord, MemberRole, MembershipGrant, MembershipManifest, SyncTarget,
    VaultRecord,
};
use unissh_sync::{AccountStateObject, AuditObject, SyncObject};

fn vault() -> VaultRecord {
    VaultRecord {
        vault_id: b"vault-uuid-1".to_vec(),
        sync_target: SyncTarget::Cloud,
        name_blob: vec![1, 2, 3, 4],
        wrapped_vk: vec![5, 6, 7],
        version: 7,
        tombstone: true,
        signature: vec![9_u8; 67],
        author_pubkey: vec![0xaa; 32],
        key_epoch: 5,
        cache_policy: CachePolicy::OnlineOnly,
        sync_tenant: Vec::new(),
    }
}

fn item() -> ItemRecord {
    ItemRecord {
        vault_id: b"vault-uuid-1".to_vec(),
        item_id: b"item-1".to_vec(),
        item_type: 42,
        content_blob: vec![1, 2, 3, 4, 5],
        wrapped_item_key: vec![6, 7],
        version: 9,
        tombstone: false,
        signature: vec![8_u8; 67],
        author_pubkey: vec![0xbb; 32],
        created_at: 0,
        updated_at: 0,
        key_epoch: 3,
    }
}

#[test]
fn vault_open_columns_match_core() {
    let bytes = SyncObject::Vault(vault()).to_bytes().unwrap();
    let p = parse_open(&bytes).unwrap();
    assert_eq!(p.tag(), Some(ObjectTag::Vault));
    assert_eq!(p.vault_id.as_deref(), Some(b"vault-uuid-1".as_slice()));
    assert_eq!(p.obj_version, Some(7));
    assert_eq!(p.key_epoch, Some(5));
    assert_eq!(p.tombstone, Some(true));
    assert_eq!(p.sync_target, Some(1)); // Cloud
    assert_eq!(p.cache_policy, Some(1)); // OnlineOnly
    assert_eq!(p.author_pubkey.as_deref(), Some([0xaa; 32].as_slice()));
    assert_eq!(p.signature.as_deref(), Some([9_u8; 67].as_slice()));
    assert_eq!(p.item_id, None);
    assert_eq!(p.member_pubkey, None);
    assert_eq!(p.role, None);
}

#[test]
fn item_open_columns_match_core() {
    let bytes = SyncObject::Item(item()).to_bytes().unwrap();
    let p = parse_open(&bytes).unwrap();
    assert_eq!(p.tag(), Some(ObjectTag::Item));
    assert_eq!(p.vault_id.as_deref(), Some(b"vault-uuid-1".as_slice()));
    assert_eq!(p.item_id.as_deref(), Some(b"item-1".as_slice()));
    assert_eq!(p.item_type, Some(42));
    assert_eq!(p.obj_version, Some(9));
    assert_eq!(p.key_epoch, Some(3));
    assert_eq!(p.tombstone, Some(false));
    assert_eq!(p.author_pubkey.as_deref(), Some([0xbb; 32].as_slice()));
    assert_eq!(p.sync_target, None);
    assert_eq!(p.cache_policy, None);
}

#[test]
fn manifest_open_columns_match_core() {
    let m = MembershipManifest {
        vault_id: b"vault-uuid-1".to_vec(),
        key_epoch: 6,
        manifest_blob: vec![1, 2, 3],
        signature: vec![4_u8; 67],
        author_pubkey: vec![0xcc; 32],
    };
    let bytes = SyncObject::MembershipManifest(m).to_bytes().unwrap();
    let p = parse_open(&bytes).unwrap();
    assert_eq!(p.tag(), Some(ObjectTag::MembershipManifest));
    assert_eq!(p.vault_id.as_deref(), Some(b"vault-uuid-1".as_slice()));
    assert_eq!(p.key_epoch, Some(6));
    assert_eq!(p.author_pubkey.as_deref(), Some([0xcc; 32].as_slice()));
    assert_eq!(p.obj_version, None);
    assert_eq!(p.role, None);
}

#[test]
fn grant_open_columns_match_core() {
    let g = MembershipGrant {
        vault_id: b"vault-uuid-1".to_vec(),
        member_pubkey: vec![0xdd; 32],
        key_epoch: 6,
        role: MemberRole::Editor,
        not_after: 0,
        wrapped_vk: vec![1, 2, 3],
        signature: vec![4_u8; 67],
        author_pubkey: vec![0xee; 32],
    };
    let bytes = SyncObject::MembershipGrant(g).to_bytes().unwrap();
    let p = parse_open(&bytes).unwrap();
    assert_eq!(p.tag(), Some(ObjectTag::MembershipGrant));
    assert_eq!(p.vault_id.as_deref(), Some(b"vault-uuid-1".as_slice()));
    assert_eq!(p.member_pubkey.as_deref(), Some([0xdd; 32].as_slice()));
    assert_eq!(p.key_epoch, Some(6));
    assert_eq!(p.role, Some(1)); // Editor
    assert_eq!(p.author_pubkey.as_deref(), Some([0xee; 32].as_slice()));
}

#[test]
fn audit_and_keyset_open_columns_match_core() {
    let a = AuditObject {
        vault_id: vec![],
        entry_blob: vec![1, 2, 3],
        signature: vec![4_u8; 67],
        author_pubkey: vec![0x11; 32],
    };
    let bytes = SyncObject::Audit(a).to_bytes().unwrap();
    let p = parse_open(&bytes).unwrap();
    assert_eq!(p.tag(), Some(ObjectTag::Audit));
    assert_eq!(p.vault_id.as_deref(), Some([].as_slice()));
    assert_eq!(p.author_pubkey.as_deref(), Some([0x11; 32].as_slice()));
    assert_eq!(p.key_epoch, None);

    let ks = SyncObject::Keyset(vec![9, 9, 9, 9]).to_bytes().unwrap();
    let pk = parse_open(&ks).unwrap();
    assert_eq!(pk.tag(), Some(ObjectTag::Keyset));
    assert_eq!(pk.vault_id, None);
    assert_eq!(pk.author_pubkey, None);
}

#[test]
fn account_state_open_columns_match_core() {
    // A3: parse_open should extract author_pubkey (delta filter) + obj_version (LWW)
    // + signature; vault_id/key_epoch — None (account-scoped, not vault-scoped).
    let a = AccountStateObject {
        author_pubkey: vec![0x33; 32],
        version: 77,
        payload: vec![1, 2, 3, 4, 5],
        signature: vec![0x44; 67],
    };
    let bytes = SyncObject::AccountState(a).to_bytes().unwrap();
    let p = parse_open(&bytes).unwrap();
    assert_eq!(p.tag(), Some(ObjectTag::AccountState));
    assert_eq!(p.author_pubkey.as_deref(), Some([0x33; 32].as_slice()));
    assert_eq!(p.obj_version, Some(77));
    assert_eq!(p.signature.as_deref(), Some([0x44; 67].as_slice()));
    assert_eq!(p.vault_id, None);
    assert_eq!(p.key_epoch, None);
}

#[test]
fn account_state_core_signature_verifies_on_server() {
    // A3 byte-parity: a signature produced by rust-core (`sign_account_state`)
    // MUST pass the server's `verify_record_sig` — otherwise the client can't
    // sync account-state with validate_signatures=true.
    use unissh_crypto::KdfParams;
    use unissh_keychain::create_account;
    let params = KdfParams {
        mem_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
        salt: vec![1_u8; 16],
    };
    let (_sk, _enc, keyset) = create_account(Some(b"pw"), params).unwrap();
    let author = keyset.signing.verifying.to_bytes().to_vec();
    let payload = b"hpke-self-sealed-blob".to_vec();
    let sig = unissh_vault::sign_account_state(&keyset, 9, &payload).unwrap();
    let obj = SyncObject::AccountState(AccountStateObject {
        author_pubkey: author,
        version: 9,
        payload,
        signature: sig,
    });
    let bytes = obj.to_bytes().unwrap();
    unissh_server::crypto::verify_record_sig(&bytes)
        .expect("core-signed account-state must verify server-side (byte-parity)");

    // Corrupting the payload → the signature doesn't match (verify rejects).
    let mut tampered = obj;
    if let SyncObject::AccountState(a) = &mut tampered {
        a.payload[0] ^= 0xFF;
    }
    let tb = tampered.to_bytes().unwrap();
    assert!(
        unissh_server::crypto::verify_record_sig(&tb).is_err(),
        "tampered payload must fail server verify"
    );
}

#[test]
fn rejects_trailing_truncation_unknown_tag() {
    let good = SyncObject::Vault(vault()).to_bytes().unwrap();
    // trailing byte
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(parse_open(&trailing).is_err(), "trailing bytes must reject");
    // truncation
    let mut trunc = good.clone();
    trunc.truncate(good.len() - 1);
    assert!(parse_open(&trunc).is_err(), "truncation must reject");
    // unknown tag
    assert!(
        parse_open(&[99, 0, 0, 0, 0]).is_err(),
        "unknown tag must reject"
    );
}
