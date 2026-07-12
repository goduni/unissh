//! Server id/token generation (OsRng), hashing, base64 (STANDARD, with
//! padding — spec §5.0). The server does no payload crypto by design; here
//! only id/token/hash utilities.

use crate::error::AppError;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

/// Fill the buffer with cryptographically-random bytes from OsRng. An OS-RNG
/// failure is an unrecoverable process condition.
pub fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS RNG failure");
}

/// 16 random bytes (account-id, tenant-id, device-id, invite-id, channel-id …).
pub fn random_id16() -> [u8; 16] {
    let mut b = [0u8; 16];
    fill_random(&mut b);
    b
}

/// 32 random bytes (session access/refresh, nonce, invite random part).
pub fn random_bytes32() -> [u8; 32] {
    let mut b = [0u8; 32];
    fill_random(&mut b);
    b
}

/// N random bytes.
pub fn random_vec(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    fill_random(&mut v);
    v
}

/// SHA-256 (for storing only token hashes: invite/access/refresh).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// base64 STANDARD (with padding).
pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode base64 STANDARD; error → 400 malformed.
pub fn unb64(s: &str) -> Result<Vec<u8>, AppError> {
    STANDARD
        .decode(s.as_bytes())
        .map_err(|_| AppError::malformed("invalid base64"))
}

/// Decode base64 with an exact-length check (for id/pubkey/signature).
pub fn unb64_exact(s: &str, len: usize, what: &str) -> Result<Vec<u8>, AppError> {
    let v = unb64(s)?;
    if v.len() != len {
        return Err(AppError::malformed(format!(
            "{what}: expected {len} bytes, got {}",
            v.len()
        )));
    }
    Ok(v)
}

/// Human setup code from 6 random bytes: "XXXX-XXXX-XXXX" (uppercase hex).
pub fn generate_setup_code(bytes: &[u8; 6]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!("{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12])
}
