//! Device-bound wrapping of stored unlock material (desktop biometric unlock).
//!
//! Biometric unlock remembers the master password on a device, and this module
//! is the part of that which does not depend on any platform: the material is
//! sealed under a key derived from a **device secret**, and only the resulting
//! blob is written anywhere. Where the device secret comes from is the platform
//! adapter's business — a Keychain item gated by the current Touch ID set on
//! macOS, the signature of a Windows Hello credential on Windows. Without that
//! secret the blob is useless; with it, it opens to exactly the bytes sealed.
//!
//! This is deliberately **outside the key hierarchy**: the Unlock Key derivation
//! and the keyset format are untouched, and the reserved `device_secret` input of
//! `derive_unlock_key` stays unused. The password alone always
//! unlocks; this only decides whether the device may type it for the user.
//!
//! Blob format (version 1):
//! ```text
//! wrap_version(1) || unissh-crypto AEAD blob
//!                    = format_version(1) || alg_id(2) || nonce(24) || ciphertext || tag(16)
//! ```
//! The AEAD key is `HKDF-SHA256(ikm = device_secret, info = "unissh-device-wrap-v1")`.
//! The associated data binds the blob to this purpose and to `wrap_version`, so a
//! blob cannot be replayed into another AEAD context nor relabelled to a
//! different version. The nonce is random per wrap (XChaCha20's 192 bits).

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use unissh_crypto::{aead_decrypt, aead_encrypt, AssociatedData, CryptoError, SymmetricKey};

/// The only blob version this build writes and reads.
pub const DEVICE_WRAP_VERSION: u8 = 1;

/// Shortest device secret accepted. Both adapters produce more (macOS: 32 random
/// bytes; Windows: a Hello signature), so this only catches an adapter bug that
/// would hand over an empty or truncated secret.
pub const DEVICE_SECRET_MIN_LEN: usize = 32;

/// HKDF `info`: the device secret is used for this purpose and no other.
const DEVICE_WRAP_HKDF_INFO: &[u8] = b"unissh-device-wrap-v1";
/// Associated-data domain label (the `vault_id` slot of [`AssociatedData`]).
const DEVICE_WRAP_AAD_DOMAIN: &[u8] = b"unissh-device-wrap";

/// Why material could not be wrapped or unwrapped.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceWrapError {
    /// Nothing to store: an empty password would unlock nothing.
    #[error("refusing to wrap empty material")]
    EmptyMaterial,
    /// The device secret is shorter than [`DEVICE_SECRET_MIN_LEN`].
    #[error("device secret too short")]
    ShortSecret,
    /// The blob was written by a format this build does not know.
    #[error("unsupported device-wrap version {0}")]
    UnsupportedVersion(u8),
    /// The blob is structurally broken (truncated, wrong inner header).
    #[error("malformed device-wrap blob")]
    Malformed,
    /// The blob does not open under this device secret: a different secret
    /// (re-enrolled device, another machine) or a tampered blob.
    #[error("device-wrap blob does not open under this device secret")]
    Unwrap,
}

/// Seals `material` under `device_secret`. Returns the versioned blob.
pub fn wrap(material: &[u8], device_secret: &[u8]) -> Result<Vec<u8>, DeviceWrapError> {
    if material.is_empty() {
        return Err(DeviceWrapError::EmptyMaterial);
    }
    let key = derive_wrap_key(device_secret)?;
    let sealed = aead_encrypt(&key, material, &aad(DEVICE_WRAP_VERSION))
        .map_err(|_| DeviceWrapError::Malformed)?;
    let mut out = Vec::with_capacity(1 + sealed.len());
    out.push(DEVICE_WRAP_VERSION);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a blob written by [`wrap`]. The material comes back in a zeroizing
/// buffer; callers keep it there until it is handed to the unlock.
pub fn unwrap(blob: &[u8], device_secret: &[u8]) -> Result<Zeroizing<Vec<u8>>, DeviceWrapError> {
    let (&version, sealed) = blob.split_first().ok_or(DeviceWrapError::Malformed)?;
    if version != DEVICE_WRAP_VERSION {
        return Err(DeviceWrapError::UnsupportedVersion(version));
    }
    let key = derive_wrap_key(device_secret)?;
    let material = aead_decrypt(&key, sealed, &aad(version)).map_err(|e| match e {
        CryptoError::Decrypt => DeviceWrapError::Unwrap,
        _ => DeviceWrapError::Malformed,
    })?;
    Ok(Zeroizing::new(material))
}

fn derive_wrap_key(device_secret: &[u8]) -> Result<SymmetricKey, DeviceWrapError> {
    if device_secret.len() < DEVICE_SECRET_MIN_LEN {
        return Err(DeviceWrapError::ShortSecret);
    }
    let hk = Hkdf::<Sha256>::new(None, device_secret);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(DEVICE_WRAP_HKDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(SymmetricKey::from_bytes(*okm))
}

fn aad(version: u8) -> AssociatedData {
    AssociatedData::new(DEVICE_WRAP_AAD_DOMAIN, Vec::new(), u64::from(version))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7u8; 32];
    const PASSWORD: &[u8] = b"correct horse battery staple";

    #[test]
    fn round_trip_returns_the_material() {
        let blob = wrap(PASSWORD, &SECRET).unwrap();
        assert_eq!(unwrap(&blob, &SECRET).unwrap().as_slice(), PASSWORD);
    }

    #[test]
    fn wrong_device_secret_fails() {
        let blob = wrap(PASSWORD, &SECRET).unwrap();
        assert_eq!(
            unwrap(&blob, &[8u8; 32]).unwrap_err(),
            DeviceWrapError::Unwrap
        );
    }

    #[test]
    fn tampered_blob_fails() {
        let mut blob = wrap(PASSWORD, &SECRET).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(unwrap(&blob, &SECRET).unwrap_err(), DeviceWrapError::Unwrap);
    }

    #[test]
    fn unknown_version_is_refused() {
        let mut blob = wrap(PASSWORD, &SECRET).unwrap();
        blob[0] = DEVICE_WRAP_VERSION + 1;
        assert_eq!(
            unwrap(&blob, &SECRET).unwrap_err(),
            DeviceWrapError::UnsupportedVersion(DEVICE_WRAP_VERSION + 1)
        );
    }

    #[test]
    fn empty_material_is_refused() {
        assert_eq!(
            wrap(b"", &SECRET).unwrap_err(),
            DeviceWrapError::EmptyMaterial
        );
    }
}
