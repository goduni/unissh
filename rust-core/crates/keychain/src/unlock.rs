//! Unlock Key derivation: `combine(Argon2id(password), Secret Key)`.
//!
//! The Unlock Key is a 256-bit symmetric key that encrypts the personal keyset.
//! The combining is done via HKDF-SHA256 (extract+expand), with domain separation.
//!
//! The passwordless mode (SSO + trusted devices, spec 5.1/12) is laid out as an
//! extension point: when `argon_key = None` the root becomes the Secret Key
//! (+ in the future a device secret from the Secure Enclave, the `device_secret`
//! parameter). The biometrics themselves are not implemented here — that is the
//! platform layer of the UI project.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use unissh_crypto::SymmetricKey;

use crate::secret_key::SecretKey;

/// HKDF salt (domain separation of the scheme).
const UNLOCK_HKDF_SALT: &[u8] = b"unissh-unlock-salt-v1";
/// HKDF `info` (binding to the key's purpose).
const UNLOCK_HKDF_INFO: &[u8] = b"unissh-unlock-key-v1";

/// Derives the Unlock Key from the (optional) Argon2id key, the Secret Key and
/// the (optional, for the future) device secret.
///
/// IKM = `argon_key? || secret_key || device_secret?`. The order and the domain
/// labels are fixed — they cannot change without bumping the keyset format version.
pub(crate) fn derive_unlock_key(
    argon_key: Option<&SymmetricKey>,
    secret_key: &SecretKey,
    device_secret: Option<&[u8]>,
) -> SymmetricKey {
    // We keep IKM and OKM in Zeroizing — they are zeroized even during stack unwinding.
    // Each component is length-framed: `present:u8 || len:u32be || data`. Without
    // framing, different input triples with the same concatenation would yield ONE
    // Unlock Key (ambiguous IKM) — critical before enabling the device_secret mode.
    fn push_field(ikm: &mut Vec<u8>, present: bool, data: &[u8]) {
        ikm.push(present as u8);
        ikm.extend_from_slice(&(data.len() as u32).to_be_bytes());
        ikm.extend_from_slice(data);
    }
    let mut ikm = Zeroizing::new(Vec::new());
    match argon_key {
        Some(ak) => push_field(&mut ikm, true, ak.expose_bytes()),
        None => push_field(&mut ikm, false, &[]),
    }
    push_field(&mut ikm, true, secret_key.expose_bytes());
    match device_secret {
        Some(ds) => push_field(&mut ikm, true, ds),
        None => push_field(&mut ikm, false, &[]),
    }

    let hk = Hkdf::<Sha256>::new(Some(UNLOCK_HKDF_SALT), ikm.as_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(UNLOCK_HKDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    SymmetricKey::from_bytes(*okm)
}

/// HKDF `info` for the escrow retrieval credential (K_auth). A distinct label →
/// an independent key: K_auth cannot recover the Unlock Key (K_unlock).
const ESCROW_AUTH_HKDF_INFO: &[u8] = b"unissh-escrow-auth-v1";

/// Derives the escrow **auth** credential `K_auth` from the (optional) Argon2id key
/// and the Secret Key. Same IKM framing and salt as the Unlock Key, but a distinct
/// HKDF `info`, so K_auth is domain-separated from K_unlock. The server stores only
/// `sha256(K_auth)` and never sees K_unlock. Passwordless (SSO) accounts pass
/// `argon_key = None` (their escrow fetch is authorized by the OIDC session, not K_auth).
///
/// The IKM framing below deliberately duplicates [`derive_unlock_key`]'s framing
/// instead of factoring it out, to keep that format-frozen function byte-untouched.
pub fn derive_escrow_auth_key(
    argon_key: Option<&SymmetricKey>,
    secret_key: &SecretKey,
) -> SymmetricKey {
    fn push_field(ikm: &mut Vec<u8>, present: bool, data: &[u8]) {
        ikm.push(present as u8);
        ikm.extend_from_slice(&(data.len() as u32).to_be_bytes());
        ikm.extend_from_slice(data);
    }
    let mut ikm = Zeroizing::new(Vec::new());
    match argon_key {
        Some(ak) => push_field(&mut ikm, true, ak.expose_bytes()),
        None => push_field(&mut ikm, false, &[]),
    }
    push_field(&mut ikm, true, secret_key.expose_bytes());
    // device_secret slot kept absent, mirroring derive_unlock_key's IKM shape.
    push_field(&mut ikm, false, &[]);

    let hk = Hkdf::<Sha256>::new(Some(UNLOCK_HKDF_SALT), ikm.as_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(ESCROW_AUTH_HKDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SymmetricKey::from_bytes(*okm)
}

/// **FROZEN. Pre-round-2 ("pre-crypto-agility") Unlock Key derivation.** IKM is a
/// RAW concatenation without length-framing: `argon_key? || secret_key || device_secret?`.
/// The salt/`info` are the same as in the current [`derive_unlock_key`] — the ONLY
/// difference is the absence of framing.
///
/// Its sole purpose is to open a keyset created before round 2, in
/// `migrate-on-open` (the keyset is migrated to the current scheme right after a
/// successful unlock). It cannot change: the bytes are pinned by a golden vector in
/// `tests/`. See `SECURITY.md`, the "On-disk format changes" section.
pub(crate) fn derive_unlock_key_legacy_v1(
    argon_key: Option<&SymmetricKey>,
    secret_key: &SecretKey,
    device_secret: Option<&[u8]>,
) -> SymmetricKey {
    let mut ikm = Zeroizing::new(Vec::new());
    if let Some(ak) = argon_key {
        ikm.extend_from_slice(ak.expose_bytes());
    }
    ikm.extend_from_slice(secret_key.expose_bytes());
    if let Some(ds) = device_secret {
        ikm.extend_from_slice(ds);
    }

    let hk = Hkdf::<Sha256>::new(Some(UNLOCK_HKDF_SALT), ikm.as_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(UNLOCK_HKDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    SymmetricKey::from_bytes(*okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed inputs → the K_auth bytes are pinned (frozen once established).
    #[test]
    fn escrow_auth_key_is_deterministic_and_independent_of_unlock() {
        let argon = SymmetricKey::from_bytes([7u8; 32]);
        let sk = SecretKey::from_bytes([9u8; 16]);
        let a1 = derive_escrow_auth_key(Some(&argon), &sk);
        let a2 = derive_escrow_auth_key(Some(&argon), &sk);
        assert_eq!(a1.expose_bytes(), a2.expose_bytes(), "deterministic");
        // Must NOT equal the Unlock Key from the same material (domain separation).
        let uk = derive_unlock_key(Some(&argon), &sk, None);
        assert_ne!(a1.expose_bytes(), uk.expose_bytes(), "K_auth != K_unlock");
    }

    /// GOLDEN: pin the exact bytes so a future edit to the derivation is caught.
    /// If this vector breaks — the K_auth derivation changed; that is a format
    /// break for the escrow retrieval credential, requiring a new `info` label
    /// and a versioned migration, not an edit to these bytes.
    #[test]
    fn escrow_auth_key_golden() {
        let argon = SymmetricKey::from_bytes([7u8; 32]);
        let sk = SecretKey::from_bytes([9u8; 16]);
        let got = derive_escrow_auth_key(Some(&argon), &sk);
        // Captured on first green run; frozen thereafter (info = b"unissh-escrow-auth-v1").
        const FROZEN_ESCROW_AUTH_KEY: [u8; 32] = [
            0xb9, 0xd6, 0xbf, 0x86, 0x91, 0xa8, 0x4d, 0x5b, 0x12, 0x90, 0x5f, 0xc6, 0xb5, 0xfa,
            0xd5, 0x9e, 0x7e, 0x9a, 0xdd, 0x07, 0xb4, 0xdb, 0xb6, 0x52, 0xaf, 0x9e, 0xf3, 0x27,
            0xfb, 0x4e, 0x47, 0xc2,
        ];
        assert_eq!(got.expose_bytes(), &FROZEN_ESCROW_AUTH_KEY);
    }
}
