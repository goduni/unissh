//! Secret Key — a high-entropy key (~128 bits), generated on the device.
//!
//! It never leaves for the server (there is no server in this crate anyway). It
//! makes an offline brute-force of the password impossible even with a full DB
//! dump: the Unlock Key is derived from `combine(Argon2id(password), Secret Key)`,
//! and the Secret Key is absent from the DB.
//!
//! Per-instance: each instance has its own Secret Key (see spec 2A).

use core::fmt;

use rand_core::{OsRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::error::KeychainError;

/// Length of the Secret Key in bytes (128 bits of entropy).
pub const SECRET_KEY_LEN: usize = 16;

/// Secret Key. Zeroized on Drop. Shown to the user in the Emergency Kit
/// (formatting the Kit is the job of the `recovery` crate, Milestone 2).
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_LEN]);

impl SecretKey {
    /// Generates a new Secret Key from the system CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0_u8; SECRET_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Constructs from ready-made bytes.
    pub fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Constructs from a slice; the length must be exactly [`SECRET_KEY_LEN`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self, KeychainError> {
        let arr: [u8; SECRET_KEY_LEN] = bytes.try_into().map_err(|_| KeychainError::Format)?;
        Ok(Self(arr))
    }

    /// Explicit access to the raw bytes. Do not log, do not store in the clear.
    pub fn expose_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}
