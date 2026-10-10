//! KDF: Argon2id with configurable (adaptive) parameters.
//!
//! The crate owns the primitive for deriving a key from a password and the serialization
//! of the parameters (salt, memory, iterations, parallelism). Where to store the parameters
//! (per-account in the envelope) and how to combine them with the Secret Key is the job of
//! the `keychain` crate.
//!
//! Parameter blob format (`alg_id = 0x0030`):
//! ```text
//! header(3) || kdf_id:u8(=1 Argon2id) || mem_kib:u32 be || iterations:u32 be
//!           || parallelism:u32 be || salt_len:u8 || salt
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::keys::{SymmetricKey, SYMMETRIC_KEY_LEN};
use crate::version::{parse_expecting, read_u32_be, write_header, AlgId};

/// KDF identifier in the parameter blob.
const KDF_ID_ARGON2ID: u8 = 1;

/// Upper bounds on Argon2 parameters when parsing an untrusted blob (DoS protection).
/// 1 GiB of memory / 64 iterations / 64 lanes — clearly above any reasonable settings.
const MAX_MEM_KIB: u32 = 1024 * 1024;
const MAX_ITERATIONS: u32 = 64;
const MAX_PARALLELISM: u32 = 64;

/// Recommended salt length.
pub const DEFAULT_SALT_LEN: usize = 16;

/// Hard strength floor for Argon2id (OWASP minimum: 19 MiB / t=2 / p=1, salt ≥ 16).
/// `recommended()` (64 MiB / t=3) is noticeably HIGHER; this is the lower bound below which
/// a keyset is not created and not parsed from a blob — protection against a buggy/compromised
/// client (or server) trying to enroll/slip in a weak KDF.
/// Minimum memory (KiB) — 19 MiB (OWASP m=19456, t=2).
pub const MIN_MEM_KIB: u32 = 19 * 1024;
/// Minimum iterations (time cost).
pub const MIN_ITERATIONS: u32 = 2;
/// Minimum parallelism (lanes).
pub const MIN_PARALLELISM: u32 = 1;
/// Minimum salt length (bytes).
pub const MIN_SALT_LEN: usize = 16;

/// Argon2id parameters. Adaptive: tuned to the device, stored next to
/// the encrypted keyset (per-account) and serialized into a blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB (spec: ≥ 64 MiB = 65536 KiB).
    pub mem_kib: u32,
    /// Number of iterations (time cost).
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
    /// Salt (unique per account).
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// Recommended parameters with a fresh random salt: 64 MiB, t=3, p=1.
    pub fn recommended() -> Self {
        Self::with_random_salt(64 * 1024, 3, 1, DEFAULT_SALT_LEN)
    }

    /// Whether the parameters meet the hard strength floor (OWASP minimum). UI/callers
    /// can check the user's choice before enrollment.
    pub fn meets_minimum(&self) -> bool {
        self.mem_kib >= MIN_MEM_KIB
            && self.iterations >= MIN_ITERATIONS
            && self.parallelism >= MIN_PARALLELISM
            && self.salt.len() >= MIN_SALT_LEN
    }

    /// Parameters with the given cost and a fresh random salt.
    pub fn with_random_salt(
        mem_kib: u32,
        iterations: u32,
        parallelism: u32,
        salt_len: usize,
    ) -> Self {
        let mut salt = vec![0_u8; salt_len];
        OsRng.fill_bytes(&mut salt);
        Self {
            mem_kib,
            iterations,
            parallelism,
            salt,
        }
    }

    /// Serializes the parameters into a versioned blob (`alg_id = 0x0030`).
    pub fn to_blob(&self) -> Result<Vec<u8>, CryptoError> {
        if self.salt.len() > u8::MAX as usize {
            return Err(CryptoError::InvalidLength);
        }
        let mut out = Vec::with_capacity(
            (crate::version::HEADER_LEN + 1 + 12 + 1).saturating_add(self.salt.len()),
        );
        write_header(&mut out, AlgId::Argon2idParams);
        out.push(KDF_ID_ARGON2ID);
        out.extend_from_slice(&self.mem_kib.to_be_bytes());
        out.extend_from_slice(&self.iterations.to_be_bytes());
        out.extend_from_slice(&self.parallelism.to_be_bytes());
        out.push(u8::try_from(self.salt.len()).map_err(|_| CryptoError::InvalidLength)?);
        out.extend_from_slice(&self.salt);
        Ok(out)
    }

    /// Parses the parameter blob.
    pub fn from_blob(blob: &[u8]) -> Result<Self, CryptoError> {
        // kdf_id(1) + mem(4) + iter(4) + par(4) + salt_len(1) = 14
        const FIXED: usize = 1 + 4 + 4 + 4 + 1;
        let body = parse_expecting(blob, AlgId::Argon2idParams)?;
        if body.len() < FIXED {
            return Err(CryptoError::Format);
        }
        if body.first() != Some(&KDF_ID_ARGON2ID) {
            return Err(CryptoError::UnsupportedAlgorithm(
                AlgId::Argon2idParams.to_u16(),
            ));
        }
        let mem_kib = read_u32_be(body.get(1..5).ok_or(CryptoError::Format)?)?;
        let iterations = read_u32_be(body.get(5..9).ok_or(CryptoError::Format)?)?;
        let parallelism = read_u32_be(body.get(9..13).ok_or(CryptoError::Format)?)?;
        let salt_len = usize::from(*body.get(13).ok_or(CryptoError::Format)?);
        if body.len() != FIXED + salt_len {
            return Err(CryptoError::Format);
        }
        // Upper bounds against DoS: the blob may come from an untrusted source
        // (e.g. a backup file), and Argon2 allocates ~`mem_kib` KiB BEFORE any
        // AEAD authentication. The recommended parameters (64 MiB, t=3, p=1) and
        // any reasonable ones fit with a large margin.
        if mem_kib > MAX_MEM_KIB || iterations > MAX_ITERATIONS || parallelism > MAX_PARALLELISM {
            return Err(CryptoError::Format);
        }
        let params = Self {
            mem_kib,
            iterations,
            parallelism,
            salt: body.get(FIXED..).ok_or(CryptoError::Format)?.to_vec(),
        };
        // We do NOT apply the hard strength floor (`meets_minimum`) here: this is a READ path
        // (unlock/import of a foreign keyset or backup). Refusing to parse a blob with weak but
        // valid parameters does not improve security (the key is still derived from
        // exactly these parameters, and AEAD authentication will fail on a wrong
        // password), but it turns a legitimate keyset/backup from an old/light profile
        // into an un-openable one (lockout). The strength floor is enforced at ENROLL — all
        // keyset-creation paths take `KdfParams::recommended()` (64 MiB / t=3). The upper
        // DoS bounds (see above) remain — they protect against allocation before auth.
        Ok(params)
    }
}

/// Derives a 256-bit symmetric key from a password via Argon2id with the given parameters.
pub fn derive_key(password: &[u8], params: &KdfParams) -> Result<SymmetricKey, CryptoError> {
    let p = Params::new(
        params.mem_kib,
        params.iterations,
        params.parallelism,
        Some(SYMMETRIC_KEY_LEN),
    )
    .map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut out = [0_u8; SYMMETRIC_KEY_LEN];
    argon
        .hash_password_into(password, &params.salt, &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    let key = SymmetricKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_blob_is_format_error() {
        let full = KdfParams::recommended().to_blob().unwrap();
        for cut in 0..full.len() {
            let err = KdfParams::from_blob(&full[..cut]).unwrap_err();
            assert!(matches!(err, CryptoError::Format), "cut at {cut}: {err:?}");
        }
        assert!(KdfParams::from_blob(&full).is_ok(), "the full blob parses");
    }
}
