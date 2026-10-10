//! P5: identity (account-id, registration, server-auth, generation-floor, unlock-from-blob).

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use unissh_keychain::{
    generate_account_id, load_account_id, store_account_id, KeychainError, ACCOUNT_ID_LEN,
};
use unissh_storage::Storage;

fn st() -> Storage {
    Storage::open_in_memory(&[7_u8; 32]).unwrap()
}

#[test]
fn account_id_generate_store_load() {
    let s = st();
    let id = generate_account_id();
    assert_eq!(id.len(), ACCOUNT_ID_LEN);
    // before any write — empty
    assert!(load_account_id(&s).unwrap().is_none());
    store_account_id(&s, &id).unwrap();
    assert_eq!(load_account_id(&s).unwrap(), Some(id));
}

#[test]
fn account_id_idempotent_same_value() {
    let s = st();
    let id = generate_account_id();
    store_account_id(&s, &id).unwrap();
    // rewriting the same id — ok (idempotent)
    store_account_id(&s, &id).unwrap();
    assert_eq!(load_account_id(&s).unwrap(), Some(id));
}

#[test]
fn account_id_conflict_rejected() {
    let s = st();
    let a = generate_account_id();
    let b = generate_account_id();
    assert_ne!(a, b);
    store_account_id(&s, &a).unwrap();
    assert_eq!(
        store_account_id(&s, &b).unwrap_err(),
        KeychainError::AccountIdConflict
    );
    // the original id is not overwritten
    assert_eq!(load_account_id(&s).unwrap(), Some(a));
}

#[test]
fn account_id_two_generations_differ() {
    assert_ne!(generate_account_id(), generate_account_id());
}

use unissh_keychain::{build_registration, create_account, verify_registration, KdfParams};

fn fast_params() -> KdfParams {
    // ≥ OWASP minimum (19 MiB / t=2) — below the hard floor from_blob rejects the keyset.
    KdfParams {
        mem_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
        salt: vec![5_u8; 16],
    }
}

#[test]
fn registration_build_and_self_verify() {
    let (_sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let acc = generate_account_id();
    let blob = build_registration(&unlocked, &acc).unwrap();

    let x_pub = unlocked.encryption.public.to_bytes();
    let ed_pub = unlocked.signing.verifying.to_bytes();
    // self-verify passes with the correct expected keys/account-id
    verify_registration(&blob, &acc, &x_pub, &ed_pub).unwrap();
}

#[test]
fn registration_rejects_wrong_expected_pubkey() {
    let (_sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let acc = generate_account_id();
    let blob = build_registration(&unlocked, &acc).unwrap();

    let x_pub = unlocked.encryption.public.to_bytes();
    let mut wrong_ed = unlocked.signing.verifying.to_bytes();
    wrong_ed[0] ^= 0x01;
    assert_eq!(
        verify_registration(&blob, &acc, &x_pub, &wrong_ed).unwrap_err(),
        KeychainError::RegistrationInvalid
    );
}

#[test]
fn registration_rejects_wrong_expected_account_id() {
    let (_sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let acc = generate_account_id();
    let blob = build_registration(&unlocked, &acc).unwrap();

    let x_pub = unlocked.encryption.public.to_bytes();
    let ed_pub = unlocked.signing.verifying.to_bytes();
    let other = generate_account_id();
    assert_eq!(
        verify_registration(&blob, &other, &x_pub, &ed_pub).unwrap_err(),
        KeychainError::RegistrationInvalid
    );
}

#[test]
fn registration_rejects_tampered_signature() {
    let (_sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let acc = generate_account_id();
    let mut blob = build_registration(&unlocked, &acc).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;

    let x_pub = unlocked.encryption.public.to_bytes();
    let ed_pub = unlocked.signing.verifying.to_bytes();
    assert_eq!(
        verify_registration(&blob, &acc, &x_pub, &ed_pub).unwrap_err(),
        KeychainError::RegistrationInvalid
    );
}

use unissh_crypto::{verify_server_auth, ServerAuthChallenge};
use unissh_keychain::sign_server_challenge;

fn challenge() -> ServerAuthChallenge {
    ServerAuthChallenge {
        host: b"prod.example".to_vec(),
        account_id: b"acc-1".to_vec(),
        device_id: b"dev-1".to_vec(),
        key_id: b"key-1".to_vec(),
        nonce: b"nonce-abc".to_vec(),
        expiry: 1_900_000_000,
    }
}

#[test]
fn server_challenge_sign_roundtrip() {
    let (_sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let c = challenge();
    let sig = sign_server_challenge(&unlocked, &c).unwrap();
    // the server verifies with the keyset's public Ed25519 key
    verify_server_auth(&unlocked.signing.verifying, &c, &sig).unwrap();
}

#[test]
fn server_challenge_wrong_key_rejected() {
    let (_sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let (_sk2, _rec2, other) = create_account(Some(b"pw2"), fast_params()).unwrap();
    let c = challenge();
    let sig = sign_server_challenge(&unlocked, &c).unwrap();
    // a foreign public key → the signature does not verify
    assert!(verify_server_auth(&other.signing.verifying, &c, &sig).is_err());
}

#[test]
fn server_challenge_tampered_rejected() {
    let (_sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let c = challenge();
    let sig = sign_server_challenge(&unlocked, &c).unwrap();
    let mut tampered = c;
    tampered.nonce = b"nonce-xyz".to_vec();
    assert!(verify_server_auth(&unlocked.signing.verifying, &tampered, &sig).is_err());
}

use unissh_keychain::{
    keyset_gen_floor, raise_keyset_gen_floor, unlock_account_checked, EncryptedKeyset,
};

#[test]
fn unlock_from_server_blob_roundtrips() {
    // server-tz §9 Path A: bytes arrive "from the server" and are unpacked as usual.
    let (sk, record, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let server_bytes = record.to_bytes().unwrap();

    let parsed = EncryptedKeyset::from_bytes(&server_bytes).unwrap();
    let reopened = unlock_account_checked(&parsed, Some(b"pw"), &sk, &st()).unwrap();
    assert_eq!(
        reopened.signing.verifying.to_bytes(),
        unlocked.signing.verifying.to_bytes()
    );
}

#[test]
fn checked_unlock_raises_floor_to_record_generation() {
    let s = st();
    let (sk, record, _) = create_account(Some(b"pw"), fast_params()).unwrap();
    assert!(keyset_gen_floor(&s).unwrap().is_none()); // no floor → TOFU
    unlock_account_checked(&record, Some(b"pw"), &sk, &s).unwrap();
    // floor raised to the record's generation (=1)
    assert_eq!(
        keyset_gen_floor(&s).unwrap(),
        Some(u64::from(record.generation))
    );
}

#[test]
fn checked_unlock_rejects_generation_below_floor() {
    let s = st();
    let (sk, record, _) = create_account(Some(b"pw"), fast_params()).unwrap();
    // artificially raise the floor above the record's generation
    raise_keyset_gen_floor(&s, u64::from(record.generation) + 5).unwrap();
    let err = unlock_account_checked(&record, Some(b"pw"), &sk, &s).unwrap_err();
    assert_eq!(
        err,
        KeychainError::GenerationRollback {
            attempted: u64::from(record.generation),
            floor: u64::from(record.generation) + 5,
        }
    );
}

#[test]
fn checked_unlock_wrong_password_does_not_raise_floor() {
    let s = st();
    let (sk, record, _) = create_account(Some(b"pw"), fast_params()).unwrap();
    assert!(unlock_account_checked(&record, Some(b"wrong"), &sk, &s).is_err());
    // an unsuccessful unlock does not move the floor
    assert!(keyset_gen_floor(&s).unwrap().is_none());
}

#[test]
fn raise_floor_is_monotonic() {
    let s = st();
    raise_keyset_gen_floor(&s, 5).unwrap();
    raise_keyset_gen_floor(&s, 3).unwrap(); // lower — does not lower it
    assert_eq!(keyset_gen_floor(&s).unwrap(), Some(5));
    raise_keyset_gen_floor(&s, 9).unwrap();
    assert_eq!(keyset_gen_floor(&s).unwrap(), Some(9));
}

use unissh_keychain::{change_password, raise_floor_after_change_password};

#[test]
fn change_password_raises_floor_blocks_old_blob() {
    let s = st();
    let (sk, record, _) = create_account(Some(b"old"), fast_params()).unwrap();
    // first unlock on the device → floor = generation(record) = 1
    unlock_account_checked(&record, Some(b"old"), &sk, &s).unwrap();

    // changed the password → new record with generation+1; raise the floor to match it
    let rotated = change_password(&record, Some(b"old"), Some(b"new"), &sk, fast_params()).unwrap();
    raise_floor_after_change_password(&s, &rotated).unwrap();
    assert_eq!(
        keyset_gen_floor(&s).unwrap(),
        Some(u64::from(rotated.generation))
    );

    // the OLD blob (password downgrade) no longer opens on this device
    let err = unlock_account_checked(&record, Some(b"old"), &sk, &s).unwrap_err();
    assert!(matches!(err, KeychainError::GenerationRollback { .. }));

    // the new blob — opens
    unlock_account_checked(&rotated, Some(b"new"), &sk, &s).unwrap();
}
