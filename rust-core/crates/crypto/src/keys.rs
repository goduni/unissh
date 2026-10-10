//! Key types with secret zeroization.
//!
//! Secret types (`SymmetricKey`, `X25519SecretKey`, `Ed25519SigningKey`)
//! are zeroized when they leave scope. Access to a secret's raw bytes is
//! only through explicit `expose_*` methods (so that a leak into a log/serialization is
//! visible in the code). The `Debug` of secrets is redacted.
//!
//! X25519 is represented via the `hpke` KEM types so that the public/private key are
//! guaranteed compatible with the `hpke_seal` wrappers (the same DHKEM).

use core::fmt;

use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, Serializable};
use rand_core::{OsRng, RngCore};
use zeroize::ZeroizeOnDrop;

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::error::CryptoError;

/// The concrete DHKEM used throughout the crate.
pub(crate) type HpkeKem = X25519HkdfSha256;

/// Length of the symmetric key (256 bits).
pub const SYMMETRIC_KEY_LEN: usize = 32;
/// Length of a serialized X25519 key (public and private).
pub const X25519_KEY_LEN: usize = 32;
/// Length of a serialized Ed25519 key.
pub const ED25519_KEY_LEN: usize = 32;

/// Returns `N` cryptographically random bytes from the system CSPRNG. For unguessable,
/// non-recyclable identifiers (for example an immutable profile uid).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0_u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

// ---------------------------------------------------------------------------
// Symmetric key
// ---------------------------------------------------------------------------

/// 256-bit symmetric key (VK, per-item, KEK, etc.). Zeroized on Drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; SYMMETRIC_KEY_LEN]);

impl SymmetricKey {
    /// Generates a random key from the system CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0_u8; SYMMETRIC_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Constructs a key from ready bytes.
    pub fn from_bytes(bytes: [u8; SYMMETRIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Constructs a key from a slice; the length must be exactly [`SYMMETRIC_KEY_LEN`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; SYMMETRIC_KEY_LEN] =
            bytes.try_into().map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self(arr))
    }

    /// Explicit access to the key's raw bytes. Use with care: do not log,
    /// do not serialize in the clear.
    pub fn expose_bytes(&self) -> &[u8; SYMMETRIC_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// X25519 (via the HPKE KEM)
// ---------------------------------------------------------------------------

/// Recipient's X25519 public key (for `seal_key_to_public`).
#[derive(Clone)]
pub struct X25519PublicKey(pub(crate) <HpkeKem as KemTrait>::PublicKey);

/// X25519 private key (for `open_key_with_secret`). The inner secret
/// (`x25519`-dalek) is zeroized on Drop.
pub struct X25519SecretKey(pub(crate) <HpkeKem as KemTrait>::PrivateKey);

/// X25519 key pair.
pub struct X25519Keypair {
    /// Private key.
    pub secret: X25519SecretKey,
    /// Public key.
    pub public: X25519PublicKey,
}

impl X25519Keypair {
    /// Generates a new X25519 pair.
    pub fn generate() -> Self {
        let (sk, pk) = <HpkeKem as KemTrait>::gen_keypair(&mut OsRng);
        Self {
            secret: X25519SecretKey(sk),
            public: X25519PublicKey(pk),
        }
    }
}

impl X25519PublicKey {
    /// Serializes the public key into 32 bytes.
    pub fn to_bytes(&self) -> [u8; X25519_KEY_LEN] {
        let ga = self.0.to_bytes();
        let mut out = [0_u8; X25519_KEY_LEN];
        out.copy_from_slice(ga.as_slice());
        out
    }

    /// Reconstructs the public key from 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        <HpkeKem as KemTrait>::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::Format)
    }
}

impl X25519SecretKey {
    /// Serializes the private key into 32 bytes. A secret — access explicitly and with care.
    pub fn expose_to_bytes(&self) -> [u8; X25519_KEY_LEN] {
        let ga = self.0.to_bytes();
        let mut out = [0_u8; X25519_KEY_LEN];
        out.copy_from_slice(ga.as_slice());
        out
    }

    /// Reconstructs the private key from 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        <HpkeKem as KemTrait>::PrivateKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::Format)
    }

    /// Derives the corresponding public key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(<HpkeKem as KemTrait>::sk_to_pk(&self.0))
    }
}

impl fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519SecretKey(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

/// Ed25519 private signing key. `ed25519-dalek` zeroizes the secret on Drop.
pub struct Ed25519SigningKey(pub(crate) SigningKey);

/// Ed25519 public verifying key.
#[derive(Clone)]
pub struct Ed25519VerifyingKey(pub(crate) VerifyingKey);

/// Ed25519 key pair.
pub struct Ed25519Keypair {
    /// Private signing key.
    pub signing: Ed25519SigningKey,
    /// Public verifying key.
    pub verifying: Ed25519VerifyingKey,
}

impl Ed25519Keypair {
    /// Generates a new Ed25519 pair.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self {
            signing: Ed25519SigningKey(signing),
            verifying: Ed25519VerifyingKey(verifying),
        }
    }
}

impl Ed25519SigningKey {
    /// Serializes the private key into 32 bytes (seed). A secret — access with care.
    pub fn expose_to_bytes(&self) -> [u8; ED25519_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Reconstructs the private key from a 32-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; ED25519_KEY_LEN] =
            bytes.try_into().map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self(SigningKey::from_bytes(&arr)))
    }

    /// The corresponding public key.
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey(self.0.verifying_key())
    }
}

impl Ed25519VerifyingKey {
    /// Serializes the public key into 32 bytes.
    pub fn to_bytes(&self) -> [u8; ED25519_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Reconstructs the public key from 32 bytes. An invalid point → error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; ED25519_KEY_LEN] =
            bytes.try_into().map_err(|_| CryptoError::InvalidLength)?;
        VerifyingKey::from_bytes(&arr)
            .map(Self)
            .map_err(|_| CryptoError::Format)
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519SigningKey(<redacted>)")
    }
}
