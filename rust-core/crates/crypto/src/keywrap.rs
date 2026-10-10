//! Symmetric wrapping of a key by another key (key-encryption-key).
//!
//! Used for the envelope-encryption hierarchy: the per-item key is wrapped by VK, VK
//! is wrapped by the unlock key, and so on (the hierarchy details are in the `keychain` crate).
//!
//! Technically this is AEAD over the 32 bytes of the key, so the blob format matches
//! [`crate::aead`] (`alg_id = 0x0001`): a wrapped key is an ordinary AEAD ciphertext.

use zeroize::Zeroize;

use crate::aead::{open_xchacha, open_xchacha_bare, seal_xchacha, seal_xchacha_bare};
use crate::error::CryptoError;
use crate::keys::{SymmetricKey, SYMMETRIC_KEY_LEN};

/// Domain tag of a wrapped key. The keywrap blob and the item-content blob use the same
/// AlgId (0x0001) and the same `seal_xchacha` — without the tag, a caller with an empty/matching
/// AAD could allow an item blob to be slipped in where a wrapped key is expected.
/// The tag makes wrapped keys cryptographically distinct regardless of caller
/// discipline (fixed length → the prefix is unambiguous).
const KEYWRAP_DOMAIN: &[u8] = b"unissh-keywrap-v1";

fn keywrap_aad(aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEYWRAP_DOMAIN.len().saturating_add(aad.len()));
    out.extend_from_slice(KEYWRAP_DOMAIN);
    out.extend_from_slice(aad);
    out
}

/// Wraps `key` with the wrapping key `kek`, binding it to `aad`. Returns a blob.
///
/// `aad` is an arbitrary context binding (for example, the key owner's
/// identifier). May be empty (the keywrap domain tag is embedded regardless).
pub fn wrap_key(
    kek: &SymmetricKey,
    key: &SymmetricKey,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    seal_xchacha(kek.expose_bytes(), key.expose_bytes(), &keywrap_aad(aad))
}

/// Unwraps a wrapped key. A wrong `kek`/`aad`/corruption → `Decrypt`.
pub fn unwrap_key(
    kek: &SymmetricKey,
    blob: &[u8],
    aad: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    let plaintext = open_xchacha(kek.expose_bytes(), blob, &keywrap_aad(aad))?;
    finish_unwrap(plaintext)
}

/// **FROZEN. Pre-round-2 ("pre-crypto-agility") unwrapping of a wrapped key.**
/// Without the domain tag [`KEYWRAP_DOMAIN`] and without binding the 3-byte header in the AAD
/// (`seal_xchacha` did not bind the header before round 2). Its sole purpose is to
/// read keys wrapped before round 2 (read-fallback in `vault`); new data
/// uses [`unwrap_key`]. The scheme is frozen — pinned by a golden vector.
pub fn unwrap_key_pre_agility(
    kek: &SymmetricKey,
    blob: &[u8],
    aad: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    let plaintext = open_xchacha_bare(kek.expose_bytes(), blob, aad)?;
    finish_unwrap(plaintext)
}

/// **FROZEN.** The seal counterpart of [`unwrap_key_pre_agility`] — reproduces the pre-round-2
/// wrapped-key format. Only for golden vectors of the migration and for tests; new
/// data must not be written this way.
pub fn wrap_key_pre_agility(
    kek: &SymmetricKey,
    key: &SymmetricKey,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    seal_xchacha_bare(kek.expose_bytes(), key.expose_bytes(), aad)
}

/// Common unwrap tail: length check and key assembly (with zeroization of temporary bytes).
fn finish_unwrap(mut plaintext: Vec<u8>) -> Result<SymmetricKey, CryptoError> {
    if plaintext.len() != SYMMETRIC_KEY_LEN {
        plaintext.zeroize();
        return Err(CryptoError::InvalidLength);
    }
    let key = SymmetricKey::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(key)
}
