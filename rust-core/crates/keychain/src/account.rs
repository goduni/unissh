//! Identity layer (server-tz §2.1, §13.3): local account-id and self-attested
//! registration binding of the keyset public keys.
//!
//! ## account-id
//! 16 random bytes (a public identifier, NOT a secret). Persisted in storage-meta
//! under the key `"account_id"`. server-tz §2.1: the final account-id is assigned
//! by the server when the pubkeys are published; here we generate a local candidate
//! and build the self-attested binding — server-side issuance/verification lives in the server repo.

use rand_core::{OsRng, RngCore};

use unissh_crypto::{
    sign_registration as crypto_sign_registration,
    verify_registration as crypto_verify_registration, Ed25519VerifyingKey, RegistrationPayload,
};
use unissh_storage::Storage;

use crate::error::KeychainError;
use crate::keyset::UnlockedKeyset;

/// Length of the account-id in bytes (128 bits, a public identifier).
pub const ACCOUNT_ID_LEN: usize = 16;

/// storage-meta key for the account-id.
const META_ACCOUNT_ID: &str = "account_id";

/// Generates a new random account-id (a public identifier).
pub fn generate_account_id() -> [u8; ACCOUNT_ID_LEN] {
    let mut id = [0_u8; ACCOUNT_ID_LEN];
    OsRng.fill_bytes(&mut id);
    id
}

/// Stores the account-id in storage-meta. Idempotent for the same value; writing
/// a different id → [`KeychainError::AccountIdConflict`] (the account-id is
/// immutable within an instance).
pub fn store_account_id(
    storage: &Storage,
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> Result<(), KeychainError> {
    if let Some(existing) = storage.get_meta(META_ACCOUNT_ID)? {
        if existing.as_slice() != account_id.as_slice() {
            return Err(KeychainError::AccountIdConflict);
        }
        return Ok(());
    }
    storage.set_meta(META_ACCOUNT_ID, account_id)?;
    Ok(())
}

/// Reads the account-id from storage-meta (if set).
pub fn load_account_id(storage: &Storage) -> Result<Option<[u8; ACCOUNT_ID_LEN]>, KeychainError> {
    match storage.get_meta(META_ACCOUNT_ID)? {
        Some(v) => {
            let arr: [u8; ACCOUNT_ID_LEN] =
                v.as_slice().try_into().map_err(|_| KeychainError::Format)?;
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

/// Builds a self-attested registration blob: binds `account_id` to the keyset
/// public keys (X25519 + Ed25519) and signs it with the keyset Ed25519 key
/// (domain `unissh-registration-v1`). Returns the signature blob — published to
/// the server together with the public keys (server-tz §2.1).
pub fn build_registration(
    unlocked: &UnlockedKeyset,
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> Result<Vec<u8>, KeychainError> {
    let payload = RegistrationPayload {
        account_id: account_id.to_vec(),
        x25519_pub: unlocked.encryption.public.to_bytes(),
        ed25519_pub: unlocked.signing.verifying.to_bytes(),
    };
    Ok(crypto_sign_registration(
        &unlocked.signing.signing,
        &payload,
    )?)
}

/// Like [`build_registration`], but returns BOTH the canonical payload AND the
/// signature. The server (`/v1/bootstrap`, `/v1/register`) accepts two base64 fields —
/// `registration_payload` and `registration_signature`; the payload is built here,
/// in one place with the signature, so the canonical form is not reassembled in
/// FFI/UI (risk of byte desync → verification failure on the server). Returns
/// `(canonical_payload, signature)`. Both are public data (account-id + pubkeys
/// + signature), not a secret.
pub fn build_registration_request(
    unlocked: &UnlockedKeyset,
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> Result<(Vec<u8>, Vec<u8>), KeychainError> {
    let payload = RegistrationPayload {
        account_id: account_id.to_vec(),
        x25519_pub: unlocked.encryption.public.to_bytes(),
        ed25519_pub: unlocked.signing.verifying.to_bytes(),
    };
    let canonical = payload.canonical()?;
    let signature = crypto_sign_registration(&unlocked.signing.signing, &payload)?;
    Ok((canonical, signature))
}

/// Verifies a registration blob: (1) the signature is valid under `expected_ed25519_pub`,
/// (2) the signed payload binds exactly `(expected_account_id, expected_x25519_pub,
/// expected_ed25519_pub)`. Any mismatch → [`KeychainError::RegistrationInvalid`].
///
/// Self-verify: the device verifies its own blob before publishing; server-side
/// verification on receipt lives in the server repo.
pub fn verify_registration(
    sig_blob: &[u8],
    expected_account_id: &[u8; ACCOUNT_ID_LEN],
    expected_x25519_pub: &[u8; 32],
    expected_ed25519_pub: &[u8; 32],
) -> Result<(), KeychainError> {
    let payload = RegistrationPayload {
        account_id: expected_account_id.to_vec(),
        x25519_pub: *expected_x25519_pub,
        ed25519_pub: *expected_ed25519_pub,
    };
    let verifying = Ed25519VerifyingKey::from_bytes(expected_ed25519_pub)
        .map_err(|_| KeychainError::RegistrationInvalid)?;
    crypto_verify_registration(&verifying, &payload, sig_blob)
        .map_err(|_| KeychainError::RegistrationInvalid)
}
