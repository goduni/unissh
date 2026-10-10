//! Domain-separated Ed25519 signatures over an arbitrary canonical payload —
//! for contexts that do not fit into [`crate::signature::VersionedObject`]
//! (server-auth, audit).
//!
//! Message = `len(domain):u16 be || domain || payload`. The length-prefixed domain
//! guarantees that this message **cannot coincide** with a
//! `signature::sign_version` message (`SIG_DOMAIN` begins with ASCII 'u'=0x75, whereas here
//! the first byte is the high byte of the domain length, 0x00 for short domains) and that
//! two different domains do not overlap. The signature blob is the same as in
//! `signature` (`header || signature(64)`, `AlgId::Ed25519`).

use ed25519_dalek::{Signature, Signer};

use crate::error::CryptoError;
use crate::keys::{Ed25519SigningKey, Ed25519VerifyingKey};
use crate::version::{parse_expecting, write_header, AlgId, HEADER_LEN};

const SIG_LEN: usize = 64;

/// Signature domain of the server-auth challenge (see [`crate::server_auth`]).
pub const SERVER_AUTH_SIG_DOMAIN: &[u8] = b"unissh-server-auth-v1";
/// Signature domain of an audit record (the canonical payload is built by the audit module — P2).
pub const AUDIT_SIG_DOMAIN: &[u8] = b"unissh-audit-v1";
/// Signature domain of the self-attested registration binding (see [`crate::registration`]).
/// Binds `(account_id, x25519_pub, ed25519_pub)` under the keyset's Ed25519 key.
pub const REGISTRATION_SIG_DOMAIN: &[u8] = b"unissh-registration-v1";

/// Canonical message: length-prefixed domain + payload.
fn domain_signing_bytes(domain: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if domain.len() > u16::MAX as usize {
        return Err(CryptoError::InvalidLength);
    }
    let mut out = Vec::with_capacity(2 + domain.len() + payload.len());
    out.extend_from_slice(
        &u16::try_from(domain.len())
            .map_err(|_| CryptoError::InvalidLength)?
            .to_be_bytes(),
    );
    out.extend_from_slice(domain);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Signs `payload` in the context of `domain`. Blob = `header || sig(64)`.
///
/// **Crate-private (foot-gun removal, Milestone-2 review):** `domain` must be a
/// fixed protocol constant (one of `*_SIG_DOMAIN`), **not**
/// attacker-controlled. Non-collision with other domains/`signature` relies on
/// short, pre-known domains; an arbitrary long `domain` (with a length high
/// byte of 0x75) could in theory recreate the `unissh-sig-v1` prefix of
/// another protocol. That is why the function is **not** public: external callers
/// must go through the type-safe wrappers with a fixed domain
/// ([`crate::sign_server_auth`], [`crate::sign_registration`], the future
/// `sign_audit`), which cannot be called with an attacker-controlled domain.
pub(crate) fn domain_sign(
    signing_key: &Ed25519SigningKey,
    domain: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let message = domain_signing_bytes(domain, payload)?;
    let signature: Signature = signing_key.0.sign(&message);
    let mut out = Vec::with_capacity(HEADER_LEN + SIG_LEN);
    write_header(&mut out, AlgId::Ed25519);
    out.extend_from_slice(&signature.to_bytes());
    Ok(out)
}

/// Verifies a domain signature. A foreign key / corrupted payload / wrong domain →
/// `Signature`. Crate-private (see [`domain_sign`]): the external verifier goes
/// through [`crate::verify_server_auth`] / [`crate::verify_registration`].
pub(crate) fn domain_verify(
    verifying_key: &Ed25519VerifyingKey,
    domain: &[u8],
    payload: &[u8],
    sig_blob: &[u8],
) -> Result<(), CryptoError> {
    let body = parse_expecting(sig_blob, AlgId::Ed25519)?;
    let sig_bytes: [u8; SIG_LEN] = body.try_into().map_err(|_| CryptoError::Format)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let message = domain_signing_bytes(domain, payload)?;
    verifying_key
        .0
        .verify_strict(&message, &signature)
        .map_err(|_| CryptoError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Ed25519Keypair;

    fn kp() -> Ed25519Keypair {
        Ed25519Keypair::generate()
    }

    #[test]
    fn sign_verify_roundtrip() {
        let k = kp();
        let sig = domain_sign(&k.signing, SERVER_AUTH_SIG_DOMAIN, b"payload").unwrap();
        domain_verify(&k.verifying, SERVER_AUTH_SIG_DOMAIN, b"payload", &sig).unwrap();
    }

    #[test]
    fn rejects_wrong_key() {
        let a = kp();
        let b = kp();
        let sig = domain_sign(&a.signing, AUDIT_SIG_DOMAIN, b"x").unwrap();
        assert_eq!(
            domain_verify(&b.verifying, AUDIT_SIG_DOMAIN, b"x", &sig).unwrap_err(),
            CryptoError::Signature
        );
    }

    #[test]
    fn rejects_tampered_payload() {
        let k = kp();
        let sig = domain_sign(&k.signing, AUDIT_SIG_DOMAIN, b"x").unwrap();
        assert_eq!(
            domain_verify(&k.verifying, AUDIT_SIG_DOMAIN, b"y", &sig).unwrap_err(),
            CryptoError::Signature
        );
    }

    #[test]
    fn rejects_cross_domain() {
        // A signature under one domain is not valid under another (same payload).
        let k = kp();
        let sig = domain_sign(&k.signing, SERVER_AUTH_SIG_DOMAIN, b"x").unwrap();
        assert_eq!(
            domain_verify(&k.verifying, AUDIT_SIG_DOMAIN, b"x", &sig).unwrap_err(),
            CryptoError::Signature
        );
    }
}
