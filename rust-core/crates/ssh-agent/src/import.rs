//! Import of private keys into the canonical OpenSSH format.
//!
//! `ssh-key` parses only the OpenSSH container (`-----BEGIN OPENSSH PRIVATE
//! KEY-----`). Real keys from `~/.ssh` are often stored in classic PEM:
//! PKCS#1 (`BEGIN RSA PRIVATE KEY`), SEC1 (`BEGIN EC PRIVATE KEY`) and PKCS#8
//! (`BEGIN PRIVATE KEY` / encrypted `BEGIN ENCRYPTED PRIVATE KEY`).
//! [`normalize_private_key_to_openssh`] recognizes the format and converts any
//! supported private key into an OpenSSH private key — from there it is stored
//! uniformly in the vault and used by the agent.
//!
//! Password-encrypted keys are decrypted with the supplied passphrase
//! ([`normalize_private_key_with_passphrase`]); without a passphrase
//! [`AgentError::Encrypted`] is returned (a signal for the UI to prompt for one).
//! Unsupported types (DSA) and legacy PEM encryption return dedicated errors.

use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
use ssh_key::{LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::error::AgentError;

/// Converts a private key in any supported PEM format into a canonical OpenSSH
/// private key. A passphrase is not needed only if the key is not encrypted;
/// otherwise see [`normalize_private_key_with_passphrase`].
pub fn normalize_private_key_to_openssh(input: &str) -> Result<Zeroizing<String>, AgentError> {
    normalize_private_key_with_passphrase(input, None)
}

/// Like [`normalize_private_key_to_openssh`], but with a passphrase for decrypting
/// protected keys.
///
/// Supported:
/// - OpenSSH (`BEGIN OPENSSH PRIVATE KEY`), including password-encrypted;
/// - PKCS#1 RSA (`BEGIN RSA PRIVATE KEY`);
/// - SEC1 EC (`BEGIN EC PRIVATE KEY`, nistp256/384/521);
/// - PKCS#8 (`BEGIN PRIVATE KEY`) and encrypted PKCS#8
///   (`BEGIN ENCRYPTED PRIVATE KEY`, PBES2): RSA / ECDSA / Ed25519.
///
/// Errors: [`AgentError::Encrypted`] — the key is encrypted and no passphrase was
/// provided; [`AgentError::WrongPassphrase`] — wrong passphrase;
/// [`AgentError::LegacyEncrypted`] — legacy OpenSSL PEM encryption;
/// [`AgentError::Unsupported`] — unsupported type (DSA); [`AgentError::Parse`] —
/// corrupt/unrecognized input.
pub fn normalize_private_key_with_passphrase(
    input: &str,
    passphrase: Option<&str>,
) -> Result<Zeroizing<String>, AgentError> {
    let pem = input.trim();
    let label = pem_label(pem).ok_or(AgentError::Parse)?;

    let key: PrivateKey = match label {
        "OPENSSH PRIVATE KEY" => {
            let k = PrivateKey::from_openssh(pem).map_err(|_| AgentError::Parse)?;
            if k.is_encrypted() {
                let pass = passphrase.ok_or(AgentError::Encrypted)?;
                k.decrypt(pass).map_err(|_| AgentError::WrongPassphrase)?
            } else {
                k
            }
        }
        "RSA PRIVATE KEY" => {
            if is_legacy_encrypted(pem) {
                return Err(AgentError::LegacyEncrypted);
            }
            let rsa = rsa::RsaPrivateKey::from_pkcs1_pem(pem).map_err(|_| AgentError::Parse)?;
            rsa_to_private_key(rsa)?
        }
        "EC PRIVATE KEY" => {
            if is_legacy_encrypted(pem) {
                return Err(AgentError::LegacyEncrypted);
            }
            ec_sec1_to_private_key(pem)?
        }
        "PRIVATE KEY" => pkcs8_to_private_key(pem)?,
        "ENCRYPTED PRIVATE KEY" => {
            let pass = passphrase.ok_or(AgentError::Encrypted)?;
            pkcs8_encrypted_to_private_key(pem, pass)?
        }
        "DSA PRIVATE KEY" => return Err(AgentError::Unsupported),
        _ => return Err(AgentError::Parse),
    };

    // Caught here, after parsing, because a security-key credential is
    // structurally valid: the file carries a key handle and an application id,
    // not a private scalar. Left alone it would import without complaint and
    // then fail at authentication with an opaque signing error — which reads as
    // a broken client rather than a key we cannot use yet.
    if matches!(
        key.key_data(),
        ssh_key::private::KeypairData::SkEd25519(_)
            | ssh_key::private::KeypairData::SkEcdsaSha2NistP256(_)
    ) {
        return Err(AgentError::SecurityKeyUnsupported);
    }

    key.to_openssh(LineEnding::LF).map_err(AgentError::from)
}

/// Extracts the label from the first line `-----BEGIN <label>-----`.
fn pem_label(pem: &str) -> Option<&str> {
    const BEGIN: &str = "-----BEGIN ";
    let start = pem.find(BEGIN)? + BEGIN.len();
    let rest = &pem[start..];
    let end = rest.find("-----")?;
    Some(rest[..end].trim())
}

/// Legacy OpenSSL encryption inside PKCS#1/SEC1: the `Proc-Type: 4,ENCRYPTED` /
/// `DEK-Info` headers. The label in that case is the ordinary one (`RSA PRIVATE KEY`).
fn is_legacy_encrypted(pem: &str) -> bool {
    pem.contains("ENCRYPTED")
}

fn rsa_to_private_key(rsa: rsa::RsaPrivateKey) -> Result<PrivateKey, AgentError> {
    let kp = RsaKeypair::try_from(rsa).map_err(|_| AgentError::Parse)?;
    PrivateKey::new(KeypairData::from(kp), "").map_err(AgentError::from)
}

/// SEC1 EC private key (`BEGIN EC PRIVATE KEY`): try the curves in order.
fn ec_sec1_to_private_key(pem: &str) -> Result<PrivateKey, AgentError> {
    if let Ok(sk) = p256::SecretKey::from_sec1_pem(pem) {
        return p256_to_private_key(sk);
    }
    if let Ok(sk) = p384::SecretKey::from_sec1_pem(pem) {
        return p384_to_private_key(sk);
    }
    if let Ok(sk) = p521::SecretKey::from_sec1_pem(pem) {
        return p521_to_private_key(sk);
    }
    Err(AgentError::Unsupported)
}

/// Unencrypted PKCS#8 (`BEGIN PRIVATE KEY`): try RSA / EC / Ed25519.
fn pkcs8_to_private_key(pem: &str) -> Result<PrivateKey, AgentError> {
    if let Ok(rsa) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
        return rsa_to_private_key(rsa);
    }
    if let Ok(sk) = p256::SecretKey::from_pkcs8_pem(pem) {
        return p256_to_private_key(sk);
    }
    if let Ok(sk) = p384::SecretKey::from_pkcs8_pem(pem) {
        return p384_to_private_key(sk);
    }
    if let Ok(sk) = p521::SecretKey::from_pkcs8_pem(pem) {
        return p521_to_private_key(sk);
    }
    if let Ok(sk) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
        return ed25519_to_private_key(&sk);
    }
    Err(AgentError::Unsupported)
}

/// Encrypted PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`, PBES2): decrypt with
/// `pass` and parse as an ordinary key. If no branch matched, the passphrase is
/// wrong (or the algorithm inside is not supported).
fn pkcs8_encrypted_to_private_key(pem: &str, pass: &str) -> Result<PrivateKey, AgentError> {
    if let Ok(rsa) = rsa::RsaPrivateKey::from_pkcs8_encrypted_pem(pem, pass) {
        return rsa_to_private_key(rsa);
    }
    if let Ok(sk) = p256::SecretKey::from_pkcs8_encrypted_pem(pem, pass) {
        return p256_to_private_key(sk);
    }
    if let Ok(sk) = p384::SecretKey::from_pkcs8_encrypted_pem(pem, pass) {
        return p384_to_private_key(sk);
    }
    if let Ok(sk) = p521::SecretKey::from_pkcs8_encrypted_pem(pem, pass) {
        return p521_to_private_key(sk);
    }
    if let Ok(sk) = ed25519_dalek::SigningKey::from_pkcs8_encrypted_pem(pem, pass) {
        return ed25519_to_private_key(&sk);
    }
    Err(AgentError::WrongPassphrase)
}

fn ed25519_to_private_key(sk: &ed25519_dalek::SigningKey) -> Result<PrivateKey, AgentError> {
    PrivateKey::new(KeypairData::from(Ed25519Keypair::from(sk)), "").map_err(AgentError::from)
}

fn p256_to_private_key(sk: p256::SecretKey) -> Result<PrivateKey, AgentError> {
    let public = sk.public_key();
    let kp = EcdsaKeypair::NistP256 {
        public: public.into(),
        private: sk.into(),
    };
    PrivateKey::new(KeypairData::from(kp), "").map_err(AgentError::from)
}

fn p384_to_private_key(sk: p384::SecretKey) -> Result<PrivateKey, AgentError> {
    let public = sk.public_key();
    let kp = EcdsaKeypair::NistP384 {
        public: public.into(),
        private: sk.into(),
    };
    PrivateKey::new(KeypairData::from(kp), "").map_err(AgentError::from)
}

fn p521_to_private_key(sk: p521::SecretKey) -> Result<PrivateKey, AgentError> {
    let public = sk.public_key();
    let kp = EcdsaKeypair::NistP521 {
        public: public.into(),
        private: sk.into(),
    };
    PrivateKey::new(KeypairData::from(kp), "").map_err(AgentError::from)
}
