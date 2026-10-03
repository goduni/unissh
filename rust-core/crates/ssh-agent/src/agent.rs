//! In-memory SSH agent: keeps keys only in-process, mlock/zeroize, signing.
//!
//! Supports all `ssh-key` key types: Ed25519, ECDSA (p256/p384/p521), RSA.
//! The private key is stored as an OpenSSH private key in an `mlock`-ed buffer and
//! is reconstructed only for the moment of signing (then zeroized). Signing goes
//! through `ssh-key` (a correct SSH format for each algorithm).

use std::collections::BTreeMap;

use rand_core::OsRng;
use rsa::pkcs1v15::SigningKey;
use sha2::{Sha256, Sha512};
use signature::{SignatureEncoding, Signer};
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::{Algorithm, Certificate, LineEnding, Mpint, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use unissh_vault::DecryptedItem;

use crate::error::AgentError;
use crate::locked::LockedBuffer;

/// A memory-locked key: the OpenSSH private key under `mlock`, a cached public
/// key and (optionally) an attached certificate. The signing key is reconstructed
/// from the buffer only for the moment of signing.
struct LockedKey {
    /// OpenSSH private key (decrypted) under `mlock`.
    pem: LockedBuffer,
    /// Public key (public, cached).
    public: PublicKey,
    /// Attached OpenSSH user certificate (for cert-based authentication).
    certificate: Option<Certificate>,
}

impl LockedKey {
    fn from_openssh(pem: &[u8]) -> Result<Self, AgentError> {
        let key = PrivateKey::from_openssh(pem).map_err(|_| AgentError::Parse)?;
        let public = key.public_key().clone();
        Ok(Self {
            pem: LockedBuffer::new(pem),
            public,
            certificate: None,
        })
        // `key` is zeroized on Drop.
    }

    fn sign(&self, data: &[u8], rsa_hash: RsaHash) -> Result<AgentSignature, AgentError> {
        let key = PrivateKey::from_openssh(self.pem.as_slice()).map_err(|_| AgentError::Parse)?;
        // We sign RSA ourselves (see `sign_rsa`): ssh-key 0.6.7 in its
        // `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey` takes `p` instead of `q`,
        // which makes its `try_sign` for RSA fail with "cryptographic error".
        if let KeypairData::Rsa(kp) = key.key_data() {
            return sign_rsa(kp, data, rsa_hash);
        }
        let sig = key
            .try_sign(data)
            .map_err(|e| AgentError::Ssh(e.to_string()))?;
        Ok(AgentSignature {
            algorithm: sig.algorithm().as_str().to_string(),
            signature: sig.as_bytes().to_vec(),
        })
        // `key` is zeroized on Drop.
    }
}

/// The hash an RSA signature is made with (RFC 8332): `rsa-sha2-256` or
/// `rsa-sha2-512`. Ignored for every other key type, whose algorithm fixes its
/// own hash.
///
/// There is deliberately no SHA-1 (`ssh-rsa`) member: this agent never makes a
/// SHA-1 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RsaHash {
    /// `rsa-sha2-256`.
    Sha256,
    /// `rsa-sha2-512` — the default, and what the transport uses for its own
    /// connections.
    #[default]
    Sha512,
}

/// Signing with an RSA key: `rsa-sha2-256` or `rsa-sha2-512` (RFC 8332) over
/// PKCS#1 v1.5.
///
/// We reconstruct `rsa::RsaPrivateKey` directly from the keypair components — this
/// works around the ssh-key 0.6.7 bug (its converter takes `p` twice instead of
/// `p,q`). We return the "raw" signature blob: the transport puts it into
/// `string(signature)`.
fn sign_rsa(kp: &RsaKeypair, data: &[u8], hash: RsaHash) -> Result<AgentSignature, AgentError> {
    let to_uint = |m: &Mpint| rsa::BigUint::try_from(m).map_err(|_| AgentError::Parse);
    let private = rsa::RsaPrivateKey::from_components(
        to_uint(&kp.public.n)?,
        to_uint(&kp.public.e)?,
        to_uint(&kp.private.d)?,
        vec![to_uint(&kp.private.p)?, to_uint(&kp.private.q)?],
    )
    .map_err(|e| AgentError::Ssh(e.to_string()))?;
    let (algorithm, sig) = match hash {
        RsaHash::Sha256 => (
            "rsa-sha2-256",
            SigningKey::<Sha256>::new(private).try_sign(data),
        ),
        RsaHash::Sha512 => (
            "rsa-sha2-512",
            SigningKey::<Sha512>::new(private).try_sign(data),
        ),
    };
    let sig = sig.map_err(|e| AgentError::Ssh(e.to_string()))?;
    Ok(AgentSignature {
        algorithm: algorithm.to_string(),
        signature: sig.to_bytes().to_vec(),
    })
}

/// An SSH signature produced by the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSignature {
    /// Signature algorithm name (`ssh-ed25519`, `rsa-sha2-512`, `ecdsa-sha2-nistp256`…).
    pub algorithm: String,
    /// SSH-encoded signature blob (what goes into `string(signature)`).
    pub signature: Vec<u8>,
}

/// Embedded in-memory SSH agent. **Not** the system ssh-agent.
#[derive(Default)]
pub struct InMemoryAgent {
    keys: BTreeMap<Vec<u8>, LockedKey>,
}

impl InMemoryAgent {
    /// Creates an empty agent.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key from an OpenSSH private key (any supported type).
    pub fn add_from_openssh(
        &mut self,
        key_id: impl Into<Vec<u8>>,
        openssh_pem: &[u8],
    ) -> Result<(), AgentError> {
        self.keys
            .insert(key_id.into(), LockedKey::from_openssh(openssh_pem)?);
        Ok(())
    }

    /// Adds a key from a decrypted vault item (content = OpenSSH private key).
    pub fn add_from_item(
        &mut self,
        key_id: impl Into<Vec<u8>>,
        item: &DecryptedItem,
    ) -> Result<(), AgentError> {
        self.add_from_openssh(key_id, item.content.as_slice())
    }

    /// Attaches an OpenSSH user certificate to an already-loaded key
    /// (for cert-based authentication). The certificate's key type must match.
    pub fn attach_certificate(
        &mut self,
        key_id: &[u8],
        cert_openssh: &str,
    ) -> Result<(), AgentError> {
        let cert = Certificate::from_openssh(cert_openssh).map_err(|_| AgentError::Parse)?;
        let key = self.keys.get_mut(key_id).ok_or(AgentError::NotFound)?;
        key.certificate = Some(cert);
        Ok(())
    }

    /// Signs arbitrary data (a challenge) with the key `key_id`. Returns the
    /// algorithm name and the SSH-encoded signature blob. An RSA key signs with
    /// `rsa-sha2-512`.
    pub fn sign(&self, key_id: &[u8], data: &[u8]) -> Result<AgentSignature, AgentError> {
        self.sign_with(key_id, data, RsaHash::default())
    }

    /// Like [`Self::sign`], with the hash an RSA key signs with chosen by the
    /// caller (an agent client's `SSH_AGENT_RSA_SHA2_256`/`_512` flag). Other key
    /// types ignore `rsa_hash`.
    pub fn sign_with(
        &self,
        key_id: &[u8],
        data: &[u8],
        rsa_hash: RsaHash,
    ) -> Result<AgentSignature, AgentError> {
        let key = self.keys.get(key_id).ok_or(AgentError::NotFound)?;
        key.sign(data, rsa_hash)
    }

    /// Public SSH key for `key_id`.
    pub fn public_key(&self, key_id: &[u8]) -> Option<PublicKey> {
        self.keys.get(key_id).map(|k| k.public.clone())
    }

    /// The attached certificate for `key_id`, if any.
    pub fn certificate(&self, key_id: &[u8]) -> Option<Certificate> {
        self.keys.get(key_id).and_then(|k| k.certificate.clone())
    }

    /// Removes a key from the agent (the secret is zeroized).
    pub fn remove(&mut self, key_id: &[u8]) -> bool {
        self.keys.remove(key_id).is_some()
    }

    /// Whether the key is loaded.
    pub fn contains(&self, key_id: &[u8]) -> bool {
        self.keys.contains_key(key_id)
    }

    /// List of the ids of the loaded keys.
    pub fn list(&self) -> Vec<Vec<u8>> {
        self.keys.keys().cloned().collect()
    }

    /// Number of loaded keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the agent is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Generates a new SSH key of the given algorithm. Returns `(OpenSSH private key,
/// OpenSSH public key)`. The private key is a `Zeroizing<String>` and is stored
/// encrypted in the vault (it is NOT written to disk in the clear).
pub fn generate_openssh(algorithm: Algorithm) -> Result<(Zeroizing<String>, String), AgentError> {
    let key = PrivateKey::random(&mut OsRng, algorithm)?;
    let pem = key.to_openssh(LineEnding::LF)?;
    let public = key.public_key().to_openssh()?;
    Ok((pem, public))
}

/// Convenience helper: generates an Ed25519 key (the default).
pub fn generate_ed25519_openssh() -> Result<(Zeroizing<String>, String), AgentError> {
    generate_openssh(Algorithm::Ed25519)
}
