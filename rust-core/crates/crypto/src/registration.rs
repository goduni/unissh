//! Self-attested registration binding (server-spec §2.1): the device publishes
//! its keyset public keys and binds them to the account-id by signing with the keyset's
//! Ed25519 key. The domain `unissh-registration-v1` (see [`crate::domain_sig`]) is
//! non-colliding with server-auth / records / audit.
//!
//! The server side (assigning the account-id, verifying the signature on publish) is the
//! server repo; here only the blob construction and self-verify.

use crate::domain_sig::{domain_sign, domain_verify, REGISTRATION_SIG_DOMAIN};
use crate::error::CryptoError;
use crate::keys::{Ed25519SigningKey, Ed25519VerifyingKey};

/// The public registration payload: a bundle of identifiers and public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationPayload {
    /// account-id within the instance (a public identifier).
    pub account_id: Vec<u8>,
    /// Keyset X25519 public key.
    pub x25519_pub: [u8; 32],
    /// Keyset Ed25519 public key (also the canonical member-id, §2.1).
    pub ed25519_pub: [u8; 32],
}

impl RegistrationPayload {
    /// Canonical payload: length-prefixed account-id + two public keys.
    /// Public: reused when building the registration request to the server
    /// (`keychain::build_registration_request`) — these are the signed bytes, not a secret.
    pub fn canonical(&self) -> Result<Vec<u8>, CryptoError> {
        if self.account_id.len() > u16::MAX as usize {
            return Err(CryptoError::InvalidLength);
        }
        let mut out = Vec::with_capacity((2 + 64_usize).saturating_add(self.account_id.len()));
        out.extend_from_slice(
            &u16::try_from(self.account_id.len())
                .map_err(|_| CryptoError::InvalidLength)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.account_id);
        out.extend_from_slice(&self.x25519_pub);
        out.extend_from_slice(&self.ed25519_pub);
        Ok(out)
    }
}

/// Signs the registration payload with the keyset's Ed25519 key. Blob = `header || sig(64)`.
pub fn sign_registration(
    signing_key: &Ed25519SigningKey,
    payload: &RegistrationPayload,
) -> Result<Vec<u8>, CryptoError> {
    domain_sign(signing_key, REGISTRATION_SIG_DOMAIN, &payload.canonical()?)
}

/// Verifies the registration payload signature. A foreign key / corruption → `Signature`.
pub fn verify_registration(
    verifying_key: &Ed25519VerifyingKey,
    payload: &RegistrationPayload,
    sig_blob: &[u8],
) -> Result<(), CryptoError> {
    domain_verify(
        verifying_key,
        REGISTRATION_SIG_DOMAIN,
        &payload.canonical()?,
        sig_blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_sig::SERVER_AUTH_SIG_DOMAIN;
    use crate::keys::Ed25519Keypair;

    fn payload() -> RegistrationPayload {
        RegistrationPayload {
            account_id: b"acc-16-bytes----".to_vec(),
            x25519_pub: [1_u8; 32],
            ed25519_pub: [2_u8; 32],
        }
    }

    #[test]
    fn roundtrip() {
        let k = Ed25519Keypair::generate();
        let p = payload();
        let sig = sign_registration(&k.signing, &p).unwrap();
        verify_registration(&k.verifying, &p, &sig).unwrap();
    }

    #[test]
    fn rejects_tampered_account_id() {
        let k = Ed25519Keypair::generate();
        let p = payload();
        let sig = sign_registration(&k.signing, &p).unwrap();
        let mut t = p;
        t.account_id = b"acc-16-bytes-XXX".to_vec();
        assert_eq!(
            verify_registration(&k.verifying, &t, &sig).unwrap_err(),
            CryptoError::Signature
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let k = Ed25519Keypair::generate();
        let other = Ed25519Keypair::generate();
        let p = payload();
        let sig = sign_registration(&k.signing, &p).unwrap();
        assert_eq!(
            verify_registration(&other.verifying, &p, &sig).unwrap_err(),
            CryptoError::Signature
        );
    }

    #[test]
    fn cross_domain_blob_rejected() {
        // A server-auth-domain signature is not valid as registration over the same payload.
        let k = Ed25519Keypair::generate();
        let p = payload();
        let sig = domain_sign(&k.signing, SERVER_AUTH_SIG_DOMAIN, &p.canonical().unwrap()).unwrap();
        assert_eq!(
            verify_registration(&k.verifying, &p, &sig).unwrap_err(),
            CryptoError::Signature
        );
    }
}
