//! The frozen pre-agility AEAD codec (the format before round 2: the blob header is NOT
//! bound to the AAD) and its incompatibility with the current scheme.
//!
//! `current_and_pre_agility_are_incompatible` is the "canary" that was missing
//! in round 2: binding the header into the AAD changed the ciphertext authentication, i.e.
//! this is a FORMAT change, not just an internal detail. Had such a test been on the
//! keyset path — round 2 would have caught the lockout at commit time.

use unissh_crypto::{
    aead_decrypt, aead_decrypt_pre_agility, aead_encrypt, aead_encrypt_pre_agility, unwrap_key,
    unwrap_key_pre_agility, wrap_key, wrap_key_pre_agility, AssociatedData, SymmetricKey,
};

fn key() -> SymmetricKey {
    SymmetricKey::from_bytes([0x42u8; 32])
}
fn aad() -> AssociatedData {
    AssociatedData::new(b"vault".to_vec(), b"item".to_vec(), 7)
}

#[test]
fn pre_agility_roundtrips() {
    let k = key();
    let blob = aead_encrypt_pre_agility(&k, b"secret payload", &aad()).unwrap();
    assert_eq!(
        aead_decrypt_pre_agility(&k, &blob, &aad()).unwrap(),
        b"secret payload"
    );
}

#[test]
fn current_and_pre_agility_are_incompatible() {
    let k = key();
    let current = aead_encrypt(&k, b"x", &aad()).unwrap();
    let legacy = aead_encrypt_pre_agility(&k, b"x", &aad()).unwrap();
    // The current reader does not open a legacy blob and vice versa: the AAD differs by
    // the 3-byte header (round-2 crypto-agility binding).
    assert!(aead_decrypt(&k, &legacy, &aad()).is_err());
    assert!(aead_decrypt_pre_agility(&k, &current, &aad()).is_err());
}

#[test]
fn pre_agility_rejects_wrong_aad() {
    let k = key();
    let blob = aead_encrypt_pre_agility(&k, b"x", &aad()).unwrap();
    let other = AssociatedData::new(b"vault".to_vec(), b"item".to_vec(), 8);
    assert!(aead_decrypt_pre_agility(&k, &blob, &other).is_err());
}

#[test]
fn keywrap_pre_agility_roundtrips() {
    let kek = SymmetricKey::from_bytes([0x55u8; 32]);
    let k = SymmetricKey::from_bytes([0x66u8; 32]);
    let blob = wrap_key_pre_agility(&kek, &k, b"item-1").unwrap();
    let got = unwrap_key_pre_agility(&kek, &blob, b"item-1").unwrap();
    assert_eq!(got.expose_bytes(), k.expose_bytes());
}

/// GOLDEN. A `wrap_key_pre_agility` wrapper captured once and frozen thereafter.
///
/// Everything else in this file round-trips: it wraps and unwraps in the same run,
/// which is self-consistent and therefore CANNOT detect drift — change both halves
/// together and the test still passes. `keychain` already pins the legacy AEAD path
/// this way (`FROZEN_LEGACY_RECORD`), but the legacy *keywrap* codec had no captured
/// bytes of its own, so a change to `KEYWRAP_DOMAIN`, to the AAD layout, or to the
/// header would have gone unnoticed here.
///
/// Captured with kek=[0x55;32], key=[0x66;32], aad=b"item-1". If this stops
/// unwrapping, the pre-agility keywrap format changed — that is a format break
/// needing a new version, not an edit to these bytes (see `SECURITY.md`,
/// "On-disk format changes").
const FROZEN_PRE_AGILITY_WRAPPER: &[u8] = &[
    0x01, 0x00, 0x01, 0xe9, 0x3d, 0xde, 0x23, 0x60, 0x99, 0x60, 0xff, 0xca, 0xec, 0xac, 0x3b, 0xc3,
    0x3d, 0xb1, 0xf4, 0xb9, 0x0c, 0xf1, 0x88, 0xee, 0x06, 0x95, 0x4d, 0x4f, 0xb6, 0x9e, 0x3e, 0x04,
    0x04, 0xcd, 0x30, 0xc3, 0x9f, 0x18, 0x3f, 0x21, 0xc3, 0x9b, 0x24, 0x09, 0x9f, 0xa2, 0x30, 0xcc,
    0x67, 0x3d, 0xe1, 0xc6, 0x93, 0x8f, 0xba, 0xb2, 0xc2, 0xb1, 0xf8, 0x47, 0x48, 0x44, 0x74, 0x7d,
    0x7c, 0x43, 0x04, 0x9b, 0x24, 0x07, 0x67, 0xe6, 0x1f, 0x6f, 0x82,
];

#[test]
fn frozen_pre_agility_wrapper_still_unwraps() {
    let kek = SymmetricKey::from_bytes([0x55u8; 32]);
    let got = unwrap_key_pre_agility(&kek, FROZEN_PRE_AGILITY_WRAPPER, b"item-1")
        .expect("the frozen pre-agility wrapper must keep unwrapping");
    assert_eq!(got.expose_bytes(), &[0x66u8; 32]);
}

#[test]
fn frozen_pre_agility_wrapper_is_bound_to_its_aad() {
    // The other half of the guarantee: the captured bytes decode under the AAD they
    // were sealed with and no other, so the vector pins the binding, not just the key.
    let kek = SymmetricKey::from_bytes([0x55u8; 32]);
    assert!(unwrap_key_pre_agility(&kek, FROZEN_PRE_AGILITY_WRAPPER, b"item-2").is_err());
}

#[test]
fn keywrap_current_and_pre_agility_incompatible() {
    // Canary for keywrap: round 2 added the KEYWRAP_DOMAIN domain tag and header
    // binding — this is a change to the wrapped-key format. The current unwrap does not open
    // a pre-round-2 wrapper and vice versa.
    let kek = SymmetricKey::from_bytes([0x55u8; 32]);
    let k = SymmetricKey::from_bytes([0x66u8; 32]);
    let current = wrap_key(&kek, &k, b"item-1").unwrap();
    let legacy = wrap_key_pre_agility(&kek, &k, b"item-1").unwrap();
    assert!(unwrap_key(&kek, &legacy, b"item-1").is_err());
    assert!(unwrap_key_pre_agility(&kek, &current, b"item-1").is_err());
}
