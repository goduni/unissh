//! Key-hierarchy tests: unlock round-trip, negative scenarios.

use unissh_keychain::{
    change_password, create_account, unlock_account, EncryptedKeyset, KdfParams, KeychainError,
    SecretKey, UnlockMode,
};

fn fast_params() -> KdfParams {
    // At the OWASP minimum (19 MiB / t=2): below the hard floor `from_blob` rejects the
    // keyset, so the create→unlock round-trip requires params ≥ the floor (still faster
    // than the production 64 MiB).
    KdfParams {
        mem_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
        salt: vec![5_u8; 16],
    }
}

#[test]
fn create_and_unlock_with_password() {
    let (sk, record, unlocked) = create_account(Some(b"master-pw"), fast_params()).unwrap();
    assert_eq!(record.mode, UnlockMode::Password);

    let reopened = unlock_account(&record, Some(b"master-pw"), &sk).unwrap();
    // same keyset: the public keys match
    assert_eq!(
        reopened.encryption.public.to_bytes(),
        unlocked.encryption.public.to_bytes()
    );
    assert_eq!(
        reopened.signing.verifying.to_bytes(),
        unlocked.signing.verifying.to_bytes()
    );
}

#[test]
fn change_password_rotates_wrapping_keeps_identity() {
    let (sk, record, unlocked) = create_account(Some(b"old-pw"), fast_params()).unwrap();

    let rotated = change_password(
        &record,
        Some(b"old-pw"),
        Some(b"new-pw"),
        &sk,
        fast_params(),
    )
    .expect("change password");
    // generation increases (anti-replay of the old blob).
    assert_eq!(rotated.generation, record.generation + 1);
    assert_eq!(rotated.mode, UnlockMode::Password);

    // Opens with the new password and yields the same identity.
    let reopened = unlock_account(&rotated, Some(b"new-pw"), &sk).unwrap();
    assert_eq!(
        reopened.signing.verifying.to_bytes(),
        unlocked.signing.verifying.to_bytes()
    );
    // The old password no longer works on the new record.
    assert_eq!(
        unlock_account(&rotated, Some(b"old-pw"), &sk).unwrap_err(),
        KeychainError::InvalidCredentials
    );
}

#[test]
fn change_password_can_remove_and_set_password() {
    let (sk, record, _) = create_account(Some(b"pw"), fast_params()).unwrap();
    // Remove the password → SecretKeyOnly mode.
    let no_pw = change_password(&record, Some(b"pw"), None, &sk, fast_params()).unwrap();
    assert_eq!(no_pw.mode, UnlockMode::SecretKeyOnly);
    unlock_account(&no_pw, None, &sk).unwrap();
    // Set a password again.
    let with_pw = change_password(&no_pw, None, Some(b"pw2"), &sk, fast_params()).unwrap();
    assert_eq!(with_pw.mode, UnlockMode::Password);
    unlock_account(&with_pw, Some(b"pw2"), &sk).unwrap();
}

#[test]
fn change_password_wrong_old_creds_does_not_rewrap() {
    let (sk, record, _) = create_account(Some(b"right"), fast_params()).unwrap();
    // Wrong old password → error, no re-wrapping (protection against bricking).
    assert_eq!(
        change_password(&record, Some(b"wrong"), Some(b"new"), &sk, fast_params()).unwrap_err(),
        KeychainError::InvalidCredentials
    );
    // Wrong Secret Key → also an error.
    let other = SecretKey::generate();
    assert_eq!(
        change_password(&record, Some(b"right"), Some(b"new"), &other, fast_params()).unwrap_err(),
        KeychainError::InvalidCredentials
    );
}

#[test]
fn wrong_password_fails() {
    let (sk, record, _) = create_account(Some(b"right"), fast_params()).unwrap();
    assert_eq!(
        unlock_account(&record, Some(b"wrong"), &sk).unwrap_err(),
        KeychainError::InvalidCredentials
    );
}

#[test]
fn wrong_secret_key_fails() {
    let (_sk, record, _) = create_account(Some(b"pw"), fast_params()).unwrap();
    let other_sk = SecretKey::generate();
    assert_eq!(
        unlock_account(&record, Some(b"pw"), &other_sk).unwrap_err(),
        KeychainError::InvalidCredentials
    );
}

#[test]
fn password_required_when_missing() {
    let (sk, record, _) = create_account(Some(b"pw"), fast_params()).unwrap();
    assert_eq!(
        unlock_account(&record, None, &sk).unwrap_err(),
        KeychainError::PasswordRequired
    );
}

#[test]
fn secret_key_only_mode() {
    let (sk, record, unlocked) = create_account(None, fast_params()).unwrap();
    assert_eq!(record.mode, UnlockMode::SecretKeyOnly);
    assert!(record.kdf_params.is_none());

    // unlock without a password, Secret Key only
    let reopened = unlock_account(&record, None, &sk).unwrap();
    assert_eq!(
        reopened.encryption.public.to_bytes(),
        unlocked.encryption.public.to_bytes()
    );

    // a foreign Secret Key does not work
    assert!(unlock_account(&record, None, &SecretKey::generate()).is_err());
}

#[test]
fn record_serialization_roundtrip_password() {
    let (_sk, record, _) = create_account(Some(b"pw"), fast_params()).unwrap();
    let bytes = record.to_bytes().unwrap();
    let parsed = EncryptedKeyset::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, record);
}

#[test]
fn record_serialization_roundtrip_sso() {
    let (_sk, record, _) = create_account(None, fast_params()).unwrap();
    let bytes = record.to_bytes().unwrap();
    let parsed = EncryptedKeyset::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, record);
}

#[test]
fn unlock_after_serialization_roundtrip() {
    let (sk, record, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let bytes = record.to_bytes().unwrap();
    let parsed = EncryptedKeyset::from_bytes(&bytes).unwrap();
    let reopened = unlock_account(&parsed, Some(b"pw"), &sk).unwrap();
    assert_eq!(
        reopened.signing.verifying.to_bytes(),
        unlocked.signing.verifying.to_bytes()
    );
}

#[test]
fn corrupted_record_fails() {
    let (_sk, record, _) = create_account(Some(b"pw"), fast_params()).unwrap();
    let mut bytes = record.to_bytes().unwrap();
    // corrupt the format version
    bytes[0] = 0xff;
    assert_eq!(
        EncryptedKeyset::from_bytes(&bytes).unwrap_err(),
        KeychainError::Format
    );
}

#[test]
fn tampered_generation_fails_unlock() {
    // generation is part of the AAD → tampering with the generation breaks the unlock.
    let (sk, record, _) = create_account(Some(b"pw"), fast_params()).unwrap();
    let mut tampered = record.clone();
    tampered.generation = tampered.generation.wrapping_add(1);
    assert!(unlock_account(&tampered, Some(b"pw"), &sk).is_err());
}

#[test]
fn tampered_wrapped_keyset_fails_unlock() {
    let (sk, record, _) = create_account(Some(b"pw"), fast_params()).unwrap();
    let mut tampered = record.clone();
    let last = tampered.wrapped_keyset.len() - 1;
    tampered.wrapped_keyset[last] ^= 0x01;
    assert!(unlock_account(&tampered, Some(b"pw"), &sk).is_err());
}
