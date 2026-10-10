//! Envelope wrapping under a public key: HPKE (RFC 9180), DHKEM(X25519,
//! HKDF-SHA256) + ChaCha20-Poly1305.
//!
//! Used to hand someone a symmetric key by encrypting it under their
//! X25519 public key (for example, `Enc(VK, member_pubkey)` during sharing —
//! the sharing flow itself is not implemented in this repository, but the wrapper is needed right away).
//!
//! Blob format (`alg_id = 0x0010`):
//! ```text
//! header(3) || enc(32) || ciphertext+tag
//! ```
//! `enc` is the encapsulated key (ephemeral X25519, 32 bytes). `info` binds the
//! context in the HPKE key schedule (domain separation/binding).

use hpke::aead::ChaCha20Poly1305 as HpkeAead;
use hpke::kdf::HkdfSha256;
use hpke::{
    single_shot_open, single_shot_seal, Deserializable, Kem as KemTrait, OpModeR, OpModeS,
    Serializable,
};
use rand_core::OsRng;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::keys::{HpkeKem, SymmetricKey, X25519PublicKey, X25519SecretKey, SYMMETRIC_KEY_LEN};
use crate::version::{parse_expecting, write_header, AlgId, HEADER_LEN};

/// Length of the encapsulated key for DHKEM(X25519).
const ENC_LEN: usize = 32;

/// Wraps a symmetric key under the recipient's X25519 public key.
///
/// `info` is the HPKE context binding (may be empty).
pub fn seal_key_to_public(
    recipient: &X25519PublicKey,
    key: &SymmetricKey,
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (encapped, ciphertext) = single_shot_seal::<HpkeAead, HkdfSha256, HpkeKem, _>(
        &OpModeS::Base,
        &recipient.0,
        info,
        key.expose_bytes(),
        &[],
        &mut OsRng,
    )
    .map_err(|_| CryptoError::Hpke)?;

    let enc = encapped.to_bytes();
    let mut out = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(enc.len())
            .saturating_add(ciphertext.len()),
    );
    write_header(&mut out, AlgId::HpkeX25519HkdfSha256ChaCha20);
    out.extend_from_slice(enc.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unwraps a symmetric key with one's own X25519 private key.
///
/// `info` must match the one used at `seal`. A foreign private key, corruption of
/// `enc`/the ciphertext, or a wrong `info` → `Hpke`.
pub fn open_key_with_secret(
    recipient: &X25519SecretKey,
    blob: &[u8],
    info: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    let body = parse_expecting(blob, AlgId::HpkeX25519HkdfSha256ChaCha20)?;
    if body.len() < ENC_LEN {
        return Err(CryptoError::Format);
    }
    let (enc_bytes, ciphertext) = body.split_at(ENC_LEN);

    let encapped = <HpkeKem as KemTrait>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|_| CryptoError::Format)?;

    let mut plaintext = single_shot_open::<HpkeAead, HkdfSha256, HpkeKem>(
        &OpModeR::Base,
        &recipient.0,
        &encapped,
        info,
        ciphertext,
        &[],
    )
    .map_err(|_| CryptoError::Hpke)?;

    if plaintext.len() != SYMMETRIC_KEY_LEN {
        plaintext.zeroize();
        return Err(CryptoError::InvalidLength);
    }
    let key = SymmetricKey::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(key)
}

/// Canonical HPKE `info` for the VK wrapper: binds the wrapper to the vault,
/// the recipient, and the **key epoch** (spec §1.1, anti-replay on VK rotation).
/// Without the epoch the server could pass off an old `Enc(VK_old, member_pub)` as a fresh one.
///
/// `b"unissh-vkwrap-v1" || len(vault_id):u16 || vault_id ||
///  len(member_pubkey):u16 || member_pubkey || key_epoch:u64 be`.
///
/// Passed as `info` to [`seal_key_to_public`]/[`open_key_with_secret`];
/// any mismatch (vault/recipient/epoch) → `Hpke` on open.
pub fn vk_wrap_info(
    vault_id: &[u8],
    member_pubkey: &[u8],
    key_epoch: u64,
) -> Result<Vec<u8>, CryptoError> {
    const DOMAIN: &[u8] = b"unissh-vkwrap-v1";
    if vault_id.len() > u16::MAX as usize || member_pubkey.len() > u16::MAX as usize {
        return Err(CryptoError::InvalidLength);
    }
    let mut out = Vec::with_capacity(
        DOMAIN
            .len()
            .saturating_add(2 + 2 + 8)
            .saturating_add(vault_id.len())
            .saturating_add(member_pubkey.len()),
    );
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(
        &u16::try_from(vault_id.len())
            .map_err(|_| CryptoError::InvalidLength)?
            .to_be_bytes(),
    );
    out.extend_from_slice(vault_id);
    out.extend_from_slice(
        &u16::try_from(member_pubkey.len())
            .map_err(|_| CryptoError::InvalidLength)?
            .to_be_bytes(),
    );
    out.extend_from_slice(member_pubkey);
    out.extend_from_slice(&key_epoch.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::X25519Keypair;

    #[test]
    fn vk_wrap_roundtrip_same_epoch() {
        let recipient = X25519Keypair::generate();
        let member_pub = recipient.public.to_bytes();
        let vk = SymmetricKey::generate();
        let info = vk_wrap_info(b"vault-1", &member_pub, 1).unwrap();
        let blob = seal_key_to_public(&recipient.public, &vk, &info).unwrap();
        let opened = open_key_with_secret(&recipient.secret, &blob, &info).unwrap();
        assert_eq!(opened.expose_bytes(), vk.expose_bytes());
    }

    #[test]
    fn vk_wrap_rejects_rotated_epoch() {
        // Replay of an old epoch: open with a different key_epoch breaks authentication.
        let recipient = X25519Keypair::generate();
        let member_pub = recipient.public.to_bytes();
        let vk = SymmetricKey::generate();
        let info_e1 = vk_wrap_info(b"vault-1", &member_pub, 1).unwrap();
        let blob = seal_key_to_public(&recipient.public, &vk, &info_e1).unwrap();
        let info_e2 = vk_wrap_info(b"vault-1", &member_pub, 2).unwrap();
        assert_eq!(
            open_key_with_secret(&recipient.secret, &blob, &info_e2).unwrap_err(),
            CryptoError::Hpke
        );
    }

    #[test]
    fn vk_wrap_rejects_wrong_member_binding() {
        let recipient = X25519Keypair::generate();
        let vk = SymmetricKey::generate();
        let info = vk_wrap_info(b"vault-1", b"member-A", 1).unwrap();
        let blob = seal_key_to_public(&recipient.public, &vk, &info).unwrap();
        let info_other = vk_wrap_info(b"vault-1", b"member-B", 1).unwrap();
        assert_eq!(
            open_key_with_secret(&recipient.secret, &blob, &info_other).unwrap_err(),
            CryptoError::Hpke
        );
    }
}
