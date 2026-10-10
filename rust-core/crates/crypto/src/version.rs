//! Blob versioning and the algorithm registry (crypto agility).
//!
//! Each encrypted/signed blob begins with a 3-byte header:
//!
//! ```text
//! [0]      format_version : u8           (current = 0x01)
//! [1..3]   alg_id         : u16 big-endian
//! [3..]    body, algorithm-dependent
//! ```
//!
//! This allows rotating the crypto later: add a new `AlgId`, read old
//! blobs by their id, write new ones by the new id. The format version changes only on
//! an incompatible change to the layout of the header itself.

use crate::error::CryptoError;

/// Current blob format version (the first byte of every blob).
pub const FORMAT_VERSION: u8 = 0x01;

/// Length of the common header: version(1) + alg_id(2).
pub const HEADER_LEN: usize = 3;

/// Algorithm identifiers. Values are stable forever — do not reuse.
///
/// Reserved (not yet implemented) extension points:
/// - `0x0002` AES-256-GCM (FIPS/compliance option),
/// - `0x0011` HPKE hybrid X25519+ML-KEM (post-quantum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlgId {
    /// The default symmetric AEAD.
    XChaCha20Poly1305 = 0x0001,
    /// Wrapping of a symmetric key under an X25519 public key (HPKE).
    HpkeX25519HkdfSha256ChaCha20 = 0x0010,
    /// Ed25519 signature.
    Ed25519 = 0x0020,
    /// Serialized Argon2id parameters.
    Argon2idParams = 0x0030,
}

impl AlgId {
    /// Numeric identifier.
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Parses an identifier. An unknown/reserved id → error.
    pub const fn from_u16(v: u16) -> Result<Self, CryptoError> {
        Ok(match v {
            0x0001 => Self::XChaCha20Poly1305,
            0x0010 => Self::HpkeX25519HkdfSha256ChaCha20,
            0x0020 => Self::Ed25519,
            0x0030 => Self::Argon2idParams,
            other => return Err(CryptoError::UnsupportedAlgorithm(other)),
        })
    }
}

/// Prepends the header (version + alg_id) to the start of the buffer.
pub(crate) fn write_header(out: &mut Vec<u8>, alg: AlgId) {
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&alg.to_u16().to_be_bytes());
}

/// Header bytes `[format_version, alg_id_be]` — for cryptographically binding the version and
/// algorithm into the AEAD associated data (protection against downgrade/confusion when adding
/// new AlgIds).
pub(crate) const fn header_bytes(alg: AlgId) -> [u8; HEADER_LEN] {
    let a = alg.to_u16().to_be_bytes();
    [FORMAT_VERSION, a[0], a[1]]
}

/// Parses the header: checks the version, parses the alg_id, returns `(alg, body)`.
pub(crate) fn parse_header(blob: &[u8]) -> Result<(AlgId, &[u8]), CryptoError> {
    let [version, alg_hi, alg_lo, body @ ..] = blob else {
        return Err(CryptoError::Format);
    };
    if *version != FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(*version));
    }
    let alg = AlgId::from_u16(u16::from_be_bytes([*alg_hi, *alg_lo]))?;
    Ok((alg, body))
}

/// Parses the header and requires a specific algorithm; otherwise `UnsupportedAlgorithm`.
pub(crate) fn parse_expecting(blob: &[u8], expected: AlgId) -> Result<&[u8], CryptoError> {
    let (alg, body) = parse_header(blob)?;
    if alg != expected {
        return Err(CryptoError::UnsupportedAlgorithm(alg.to_u16()));
    }
    Ok(body)
}

/// Reads a big-endian u32 from an exactly 4-byte slice.
pub(crate) fn read_u32_be(b: &[u8]) -> Result<u32, CryptoError> {
    let arr: [u8; 4] = b.try_into().map_err(|_| CryptoError::Format)?;
    Ok(u32::from_be_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let mut buf = Vec::new();
        write_header(&mut buf, AlgId::Ed25519);
        buf.extend_from_slice(b"body");
        let (alg, body) = parse_header(&buf).unwrap();
        assert_eq!(alg, AlgId::Ed25519);
        assert_eq!(body, b"body");
    }

    #[test]
    fn rejects_short_blob() {
        assert_eq!(
            parse_header(&[0x01, 0x00]).unwrap_err(),
            CryptoError::Format
        );
    }

    #[test]
    fn truncated_header_is_format_error() {
        let mut full = Vec::new();
        write_header(&mut full, AlgId::Ed25519);
        for cut in 0..full.len() {
            let err = parse_header(&full[..cut]).unwrap_err();
            assert!(matches!(err, CryptoError::Format), "cut at {cut}: {err:?}");
        }
        assert!(parse_header(&full).is_ok(), "a bare header parses");
    }

    #[test]
    fn rejects_bad_version() {
        let blob = [0x02, 0x00, 0x01];
        assert_eq!(
            parse_header(&blob).unwrap_err(),
            CryptoError::UnsupportedVersion(0x02)
        );
    }

    #[test]
    fn rejects_unknown_alg() {
        let blob = [FORMAT_VERSION, 0xff, 0xff];
        assert_eq!(
            parse_header(&blob).unwrap_err(),
            CryptoError::UnsupportedAlgorithm(0xffff)
        );
    }

    #[test]
    fn parse_expecting_mismatch() {
        let mut blob = Vec::new();
        write_header(&mut blob, AlgId::XChaCha20Poly1305);
        assert_eq!(
            parse_expecting(&blob, AlgId::Ed25519).unwrap_err(),
            CryptoError::UnsupportedAlgorithm(AlgId::XChaCha20Poly1305.to_u16())
        );
    }
}
