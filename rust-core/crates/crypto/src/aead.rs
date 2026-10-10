//! Symmetric AEAD (XChaCha20-Poly1305) with associated data.
//!
//! Blob format (`alg_id = 0x0001`):
//! ```text
//! header(3) || nonce(24) || ciphertext || tag(16)
//! ```
//! `ciphertext || tag` is what the RustCrypto implementation returns (the tag is already
//! appended at the end). The `nonce` is stored in the blob; the associated data is NOT written
//! into the blob — it is reconstructed by the caller and binds the blob to a context.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};

use crate::error::CryptoError;
use crate::keys::{SymmetricKey, SYMMETRIC_KEY_LEN};
use crate::version::{header_bytes, parse_expecting, write_header, AlgId};

/// Length of the XChaCha20 nonce (192 bits).
pub const NONCE_LEN: usize = 24;
/// Length of the Poly1305 tag.
pub const TAG_LEN: usize = 16;

/// Binding of a cipher blob to a context: `vault_id + item_id + version`.
///
/// Fed into AEAD as associated data and included in the signed object
/// ([`crate::signature`]). The server cannot silently substitute/reorder blobs:
/// decryption of a foreign/reordered blob will fail authentication.
///
/// `vault_id`/`item_id` are raw bytes (the crate does not depend on the id types from storage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociatedData {
    /// Vault identifier (raw bytes).
    pub vault_id: Vec<u8>,
    /// Item identifier (raw bytes).
    pub item_id: Vec<u8>,
    /// Monotonic version of the object.
    pub version: u64,
}

impl AssociatedData {
    /// Creates a new binding context.
    pub fn new(vault_id: impl Into<Vec<u8>>, item_id: impl Into<Vec<u8>>, version: u64) -> Self {
        Self {
            vault_id: vault_id.into(),
            item_id: item_id.into(),
            version,
        }
    }

    /// Canonical length-prefixed serialization:
    /// ```text
    /// len(vault_id):u16 || vault_id || len(item_id):u16 || item_id || version:u64 be
    /// ```
    /// Length prefixes eliminate any ambiguity in concatenating fields. An identifier
    /// longer than 65535 bytes is not allowed (`InvalidLength`).
    pub fn canonical(&self) -> Result<Vec<u8>, CryptoError> {
        if self.vault_id.len() > u16::MAX as usize || self.item_id.len() > u16::MAX as usize {
            return Err(CryptoError::InvalidLength);
        }
        let mut out = Vec::with_capacity(2 + self.vault_id.len() + 2 + self.item_id.len() + 8);
        out.extend_from_slice(&(self.vault_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&(self.item_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.item_id);
        out.extend_from_slice(&self.version.to_be_bytes());
        Ok(out)
    }
}

/// Encrypts `plaintext` with a symmetric key, binding it to `aad`. Returns a blob.
pub fn aead_encrypt(
    key: &SymmetricKey,
    plaintext: &[u8],
    aad: &AssociatedData,
) -> Result<Vec<u8>, CryptoError> {
    let aad_bytes = aad.canonical()?;
    seal_xchacha(key.expose_bytes(), plaintext, &aad_bytes)
}

/// Decrypts a blob, verifying the binding to `aad`. Any corruption/mismatch → `Decrypt`.
pub fn aead_decrypt(
    key: &SymmetricKey,
    blob: &[u8],
    aad: &AssociatedData,
) -> Result<Vec<u8>, CryptoError> {
    let aad_bytes = aad.canonical()?;
    open_xchacha(key.expose_bytes(), blob, &aad_bytes)
}

/// **FROZEN. Pre-agility (pre round 2) AEAD codec: the blob header is NOT bound to
/// the AAD.** Its sole purpose is `migrate-on-open` of artifacts written before
/// the `crypto-agility binding` (when `seal_xchacha` started binding the `header` into the AAD).
/// New data MUST use [`aead_decrypt`]. The scheme is frozen —
/// its bytes are pinned by a golden vector; it must not be changed (see `SECURITY.md`, section
/// "On-disk format changes").
pub fn aead_decrypt_pre_agility(
    key: &SymmetricKey,
    blob: &[u8],
    aad: &AssociatedData,
) -> Result<Vec<u8>, CryptoError> {
    let aad_bytes = aad.canonical()?;
    open_xchacha_inner(key.expose_bytes(), blob, &aad_bytes, false)
}

/// **FROZEN.** The seal counterpart of [`aead_decrypt_pre_agility`] — reproduces the pre-agility
/// format (header not in the AAD). Only for golden vectors of the migration and for emergency
/// re-encoding of old backups; **new data must not be written this way.**
pub fn aead_encrypt_pre_agility(
    key: &SymmetricKey,
    plaintext: &[u8],
    aad: &AssociatedData,
) -> Result<Vec<u8>, CryptoError> {
    let aad_bytes = aad.canonical()?;
    seal_xchacha_inner(key.expose_bytes(), plaintext, &aad_bytes, false)
}

// --- Low-level functions with raw associated data (used by keywrap) ---

/// Encrypts, taking raw associated data. Returns `header || nonce || ct||tag`.
/// The blob header is bound into the AAD (crypto-agility, see `bind_header`).
pub(crate) fn seal_xchacha(
    key: &[u8; SYMMETRIC_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    seal_xchacha_inner(key, plaintext, aad, true)
}

/// Decrypts a blob with raw associated data (with the header bound in the AAD).
pub(crate) fn open_xchacha(
    key: &[u8; SYMMETRIC_KEY_LEN],
    blob: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    open_xchacha_inner(key, blob, aad, true)
}

/// **FROZEN.** Pre-agility (round 1) seal with raw AAD: the header is NOT bound to the AAD.
/// For legacy `keywrap` (see `wrap_key_pre_agility`); not used by new code.
pub(crate) fn seal_xchacha_bare(
    key: &[u8; SYMMETRIC_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    seal_xchacha_inner(key, plaintext, aad, false)
}

/// **FROZEN.** Pre-agility (round 1) open with raw AAD: the header is NOT bound to the AAD.
/// For legacy `keywrap` (see `unwrap_key_pre_agility`); not used by new code.
pub(crate) fn open_xchacha_bare(
    key: &[u8; SYMMETRIC_KEY_LEN],
    blob: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    open_xchacha_inner(key, blob, aad, false)
}

/// The encryption core. `bind_header = true` (the current scheme) binds the 3-byte
/// header (`format_version || alg_id`) into the AEAD AAD — cryptographically pinning the blob to
/// its algorithm/version (crypto-agility protection against downgrade/header-confusion with a
/// second `AlgId`). `false` — the pre-agility (round 1) format: AAD without the header.
fn seal_xchacha_inner(
    key: &[u8; SYMMETRIC_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
    bind_header: bool,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let bound;
    let full_aad: &[u8] = if bind_header {
        bound = with_header(AlgId::XChaCha20Poly1305, aad);
        &bound
    } else {
        aad
    };
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: full_aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;

    let mut out = Vec::with_capacity(crate::version::HEADER_LEN + NONCE_LEN + ciphertext.len());
    write_header(&mut out, AlgId::XChaCha20Poly1305);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// The decryption core (see [`seal_xchacha_inner`] about `bind_header`).
fn open_xchacha_inner(
    key: &[u8; SYMMETRIC_KEY_LEN],
    blob: &[u8],
    aad: &[u8],
    bind_header: bool,
) -> Result<Vec<u8>, CryptoError> {
    let body = parse_expecting(blob, AlgId::XChaCha20Poly1305)?;
    if body.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Format);
    }
    let (nonce, ciphertext) = body.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let bound;
    let full_aad: &[u8] = if bind_header {
        bound = with_header(AlgId::XChaCha20Poly1305, aad);
        &bound
    } else {
        aad
    };
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: full_aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

/// `header(alg) || aad` — the blob header concatenated with the caller's associated data
/// (see `seal_xchacha`). The header has a fixed length (`HEADER_LEN`),
/// so the prefix is unambiguous without a separate length prefix.
fn with_header(alg: AlgId, aad: &[u8]) -> Vec<u8> {
    let header = header_bytes(alg);
    let mut out = Vec::with_capacity(header.len() + aad.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(aad);
    out
}
