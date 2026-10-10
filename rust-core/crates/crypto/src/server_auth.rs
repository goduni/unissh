//! A signed server-auth challenge (spec §2.2): the client proves possession of
//! the keyset key by signing the server's nonce. The domain `unissh-server-auth-v1`
//! (see [`crate::domain_sig`]) is incompatible with the record signature, so that the server
//! challenge cannot be reused as a `VersionedObject` signature.

use crate::domain_sig::{domain_sign, domain_verify, SERVER_AUTH_SIG_DOMAIN};
use crate::error::CryptoError;
use crate::keys::{Ed25519SigningKey, Ed25519VerifyingKey};

/// The authentication challenge. All fields are public bytes; `expiry` is unix-seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAuthChallenge {
    /// The host/instance being authenticated to.
    pub host: Vec<u8>,
    /// account-id within the instance.
    pub account_id: Vec<u8>,
    /// device-id.
    pub device_id: Vec<u8>,
    /// key-id (which keyset key signs).
    pub key_id: Vec<u8>,
    /// The server's one-time nonce.
    pub nonce: Vec<u8>,
    /// Expiry (unix-seconds). The expiry check is done by the server; the crypto only binds it.
    pub expiry: u64,
}

impl ServerAuthChallenge {
    /// Canonical payload: length-prefixed fields + `expiry:u64 be`.
    fn canonical(&self) -> Result<Vec<u8>, CryptoError> {
        fn put(out: &mut Vec<u8>, f: &[u8]) -> Result<(), CryptoError> {
            if f.len() > u16::MAX as usize {
                return Err(CryptoError::InvalidLength);
            }
            out.extend_from_slice(
                &u16::try_from(f.len())
                    .map_err(|_| CryptoError::InvalidLength)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(f);
            Ok(())
        }
        let mut out = Vec::new();
        put(&mut out, &self.host)?;
        put(&mut out, &self.account_id)?;
        put(&mut out, &self.device_id)?;
        put(&mut out, &self.key_id)?;
        put(&mut out, &self.nonce)?;
        out.extend_from_slice(&self.expiry.to_be_bytes());
        Ok(out)
    }
}

/// Signs the challenge with the device's keyset key.
pub fn sign_server_auth(
    signing_key: &Ed25519SigningKey,
    challenge: &ServerAuthChallenge,
) -> Result<Vec<u8>, CryptoError> {
    domain_sign(signing_key, SERVER_AUTH_SIG_DOMAIN, &challenge.canonical()?)
}

/// Verifies the challenge signature. Does NOT check expiry/nonce-freshness — that is the server.
pub fn verify_server_auth(
    verifying_key: &Ed25519VerifyingKey,
    challenge: &ServerAuthChallenge,
    sig_blob: &[u8],
) -> Result<(), CryptoError> {
    domain_verify(
        verifying_key,
        SERVER_AUTH_SIG_DOMAIN,
        &challenge.canonical()?,
        sig_blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Ed25519Keypair;

    fn challenge() -> ServerAuthChallenge {
        ServerAuthChallenge {
            host: b"prod.example".to_vec(),
            account_id: b"acc-1".to_vec(),
            device_id: b"dev-1".to_vec(),
            key_id: b"key-1".to_vec(),
            nonce: b"nonce-abc".to_vec(),
            expiry: 1_900_000_000,
        }
    }

    #[test]
    fn roundtrip() {
        let k = Ed25519Keypair::generate();
        let c = challenge();
        let sig = sign_server_auth(&k.signing, &c).unwrap();
        verify_server_auth(&k.verifying, &c, &sig).unwrap();
    }

    #[test]
    fn rejects_modified_field() {
        let k = Ed25519Keypair::generate();
        let c = challenge();
        let sig = sign_server_auth(&k.signing, &c).unwrap();
        let mut tampered = c;
        tampered.nonce = b"nonce-xyz".to_vec();
        assert_eq!(
            verify_server_auth(&k.verifying, &tampered, &sig).unwrap_err(),
            CryptoError::Signature
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let k = Ed25519Keypair::generate();
        let other = Ed25519Keypair::generate();
        let c = challenge();
        let sig = sign_server_auth(&k.signing, &c).unwrap();
        assert_eq!(
            verify_server_auth(&other.verifying, &c, &sig).unwrap_err(),
            CryptoError::Signature
        );
    }
}
