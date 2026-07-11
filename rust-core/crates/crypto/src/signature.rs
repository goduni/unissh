//! Ed25519 signatures over versioned objects + version rollback detection.
//!
//! What is signed is not the "bare" content but a canonical structure binding
//! the object's identity, its monotonic version, and the content digest:
//! ```text
//! domain("unissh-sig-v1") || AssociatedData.canonical || content_digest(32, SHA-256)
//! ```
//! This way the signature simultaneously authorizes: who/what (vault_id+item_id), which version,
//! and which content. A forgery or a foreign key → `Signature`.
//!
//! Rollback detection is stateless: the signature by itself is also valid for an old version
//! (an attacker could have saved an old signed blob). So "freshness" is caught by
//! [`verify_no_rollback`], comparing against the last seen version. Storing the
//! "last seen version" is the caller's responsibility (the `storage` crate).
//!
//! Signature blob format (`alg_id = 0x0020`): `header(3) || signature(64)`.

use ed25519_dalek::{Signature, Signer};
use sha2::{Digest, Sha256};

use crate::aead::AssociatedData;
use crate::error::CryptoError;
use crate::keys::{Ed25519SigningKey, Ed25519VerifyingKey};
use crate::version::{parse_expecting, write_header, AlgId, HEADER_LEN};

/// Signature domain separator (binding to the scheme and version).
const SIG_DOMAIN: &[u8] = b"unissh-sig-v1";
/// Length of the Ed25519 signature.
const SIG_LEN: usize = 64;

/// The DEDICATED signature domain for per-account state (A3). Separate from `unissh-sig-v1`
/// (domain separation, sec-review A3 #5): an account-state signature MUST NOT be
/// reinterpreted as an Item-record signature. MUST match the server's
/// `verify_record_sig` tag7 byte-for-byte.
pub const ACCOUNT_STATE_SIG_DOMAIN: &[u8] = b"unissh-account-state-v1";

/// Canonical account-state signature message: `domain || version:u64be ||
/// sha256(payload)`.
fn account_state_message(version: u64, payload: &[u8]) -> Vec<u8> {
    let digest = VersionedObject::digest_content(payload);
    let mut out = Vec::with_capacity(ACCOUNT_STATE_SIG_DOMAIN.len() + 8 + 32);
    out.extend_from_slice(ACCOUNT_STATE_SIG_DOMAIN);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&digest);
    out
}

/// Signs per-account state (A3) with the dedicated domain. Returns a signature blob.
pub fn sign_account_state(
    signing_key: &Ed25519SigningKey,
    version: u64,
    payload: &[u8],
) -> Vec<u8> {
    let signature: Signature = signing_key.0.sign(&account_state_message(version, payload));
    let mut out = Vec::with_capacity(HEADER_LEN + SIG_LEN);
    write_header(&mut out, AlgId::Ed25519);
    out.extend_from_slice(&signature.to_bytes());
    out
}

/// Verifies the per-account state signature (A3).
pub fn verify_account_state(
    verifying_key: &Ed25519VerifyingKey,
    version: u64,
    payload: &[u8],
    sig_blob: &[u8],
) -> Result<(), CryptoError> {
    let body = parse_expecting(sig_blob, AlgId::Ed25519)?;
    let sig_bytes: [u8; SIG_LEN] = body.try_into().map_err(|_| CryptoError::Format)?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .0
        .verify_strict(&account_state_message(version, payload), &signature)
        .map_err(|_| CryptoError::Signature)
}

/// The versioned object — what gets signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedObject {
    /// Identity + monotonic version.
    pub aad: AssociatedData,
    /// Content digest (SHA-256). See [`VersionedObject::digest_content`].
    pub content_digest: [u8; 32],
}

impl VersionedObject {
    /// Constructs an object with a ready digest.
    pub fn new(aad: AssociatedData, content_digest: [u8; 32]) -> Self {
        Self {
            aad,
            content_digest,
        }
    }

    /// Constructs an object, computing the SHA-256 digest of the content.
    pub fn from_content(aad: AssociatedData, content: &[u8]) -> Self {
        Self {
            aad,
            content_digest: Self::digest_content(content),
        }
    }

    /// SHA-256 digest of arbitrary content.
    pub fn digest_content(content: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hasher.finalize().into()
    }

    /// The canonical message for signing.
    fn signing_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let aad = self.aad.canonical()?;
        let mut out = Vec::with_capacity(SIG_DOMAIN.len() + aad.len() + 32);
        out.extend_from_slice(SIG_DOMAIN);
        out.extend_from_slice(&aad);
        out.extend_from_slice(&self.content_digest);
        Ok(out)
    }
}

/// Signs a versioned object. Returns a signature blob.
pub fn sign_version(
    signing_key: &Ed25519SigningKey,
    obj: &VersionedObject,
) -> Result<Vec<u8>, CryptoError> {
    let message = obj.signing_bytes()?;
    let signature: Signature = signing_key.0.sign(&message);

    let mut out = Vec::with_capacity(HEADER_LEN + SIG_LEN);
    write_header(&mut out, AlgId::Ed25519);
    out.extend_from_slice(&signature.to_bytes());
    Ok(out)
}

/// Verifies the object's signature. Does not check rollback — only authenticity.
pub fn verify_version(
    verifying_key: &Ed25519VerifyingKey,
    obj: &VersionedObject,
    sig_blob: &[u8],
) -> Result<(), CryptoError> {
    let body = parse_expecting(sig_blob, AlgId::Ed25519)?;
    let sig_bytes: [u8; SIG_LEN] = body.try_into().map_err(|_| CryptoError::Format)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let message = obj.signing_bytes()?;
    verifying_key
        .0
        .verify_strict(&message, &signature)
        .map_err(|_| CryptoError::Signature)
}

/// Verifies the signature AND the version freshness: `obj.aad.version` must be strictly
/// greater than `last_seen`. Otherwise `Rollback`.
pub fn verify_no_rollback(
    verifying_key: &Ed25519VerifyingKey,
    obj: &VersionedObject,
    sig_blob: &[u8],
    last_seen: u64,
) -> Result<(), CryptoError> {
    verify_version(verifying_key, obj, sig_blob)?;
    if obj.aad.version <= last_seen {
        return Err(CryptoError::Rollback {
            attempted: obj.aad.version,
            last_seen,
        });
    }
    Ok(())
}
