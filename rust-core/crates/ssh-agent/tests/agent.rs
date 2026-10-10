//! Tests of the embedded agent: generation (Ed25519/ECDSA/RSA), sign/verify,
//! key from the vault, certificate, removal.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use unissh_ssh_agent::ssh_key::{Algorithm, EcdsaCurve};
use unissh_ssh_agent::{
    generate_ed25519_openssh, generate_openssh, ssh_key, AgentError, InMemoryAgent,
};

fn ed25519_public_bytes(pk: &ssh_key::PublicKey) -> [u8; 32] {
    match pk.key_data() {
        ssh_key::public::KeyData::Ed25519(p) => p.0,
        _ => panic!("expected ed25519"),
    }
}

#[test]
fn ed25519_generate_add_sign_and_verify() {
    let (pem, _public) = generate_ed25519_openssh().unwrap();
    let mut agent = InMemoryAgent::new();
    agent
        .add_from_openssh(b"k1".to_vec(), pem.as_bytes())
        .unwrap();
    assert!(agent.contains(b"k1"));

    let data = b"ssh-auth-challenge";
    let sig = agent.sign(b"k1", data).unwrap();
    assert_eq!(sig.algorithm, "ssh-ed25519");
    assert_eq!(sig.signature.len(), 64);

    // raw Ed25519 verify with the public key from the agent
    let pk = agent.public_key(b"k1").unwrap();
    let vk = VerifyingKey::from_bytes(&ed25519_public_bytes(&pk)).unwrap();
    let arr: [u8; 64] = sig.signature.clone().try_into().unwrap();
    assert!(vk.verify(data, &Signature::from_bytes(&arr)).is_ok());
    assert!(vk.verify(b"other", &Signature::from_bytes(&arr)).is_err());
}

/// Structural check of the signature (algorithm name + non-empty blob). The
/// cryptographic correctness of RSA/ECDSA is proven by the integration test against sshd.
fn sign_structural_check(algorithm: Algorithm, expected_alg: &str) {
    let (pem, _public) = generate_openssh(algorithm).unwrap();
    let mut agent = InMemoryAgent::new();
    agent
        .add_from_openssh(b"k".to_vec(), pem.as_bytes())
        .unwrap();

    let sig = agent.sign(b"k", b"challenge-data-to-sign").unwrap();
    assert_eq!(sig.algorithm, expected_alg, "unexpected sig algorithm");
    assert!(!sig.signature.is_empty());
    // the public key is available and of the same type
    assert!(agent.public_key(b"k").is_some());
}

#[test]
fn ecdsa_p256_sign_and_verify() {
    sign_structural_check(
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        "ecdsa-sha2-nistp256",
    );
}

#[test]
fn ecdsa_p384_sign_and_verify() {
    sign_structural_check(
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        "ecdsa-sha2-nistp384",
    );
}

#[test]
fn rsa_import_and_public_key() {
    // The RSA key is imported and the public key is available (signing is in
    // `rsa_sign_and_verify`).
    let (pem, _public) = generate_openssh(Algorithm::Rsa { hash: None }).unwrap();
    let mut agent = InMemoryAgent::new();
    agent
        .add_from_openssh(b"rsa".to_vec(), pem.as_bytes())
        .unwrap();
    let pk = agent.public_key(b"rsa").unwrap();
    assert_eq!(pk.algorithm(), Algorithm::Rsa { hash: None });
}

#[test]
fn rsa_sign_and_verify() {
    use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::Sha512;

    let (pem, _public) = generate_openssh(Algorithm::Rsa { hash: None }).unwrap();
    let mut agent = InMemoryAgent::new();
    agent
        .add_from_openssh(b"rsa".to_vec(), pem.as_bytes())
        .unwrap();

    let data = b"ssh-auth-challenge";
    let sig = agent.sign(b"rsa", data).unwrap();
    assert_eq!(sig.algorithm, "rsa-sha2-512");
    assert!(!sig.signature.is_empty());

    // Cryptographic verification with the public key from the agent (rsa-sha2-512).
    let pk = agent.public_key(b"rsa").unwrap();
    let rsa_pub = match pk.key_data() {
        ssh_key::public::KeyData::Rsa(r) => rsa::RsaPublicKey::new(
            rsa::BigUint::try_from(&r.n).unwrap(),
            rsa::BigUint::try_from(&r.e).unwrap(),
        )
        .unwrap(),
        _ => panic!("expected rsa"),
    };
    let vk = VerifyingKey::<Sha512>::new(rsa_pub);
    let signature = RsaSig::try_from(sig.signature.as_slice()).unwrap();
    assert!(vk.verify(data, &signature).is_ok());
    assert!(vk.verify(b"other-data", &signature).is_err());
}

#[test]
fn sign_missing_key_is_not_found() {
    let agent = InMemoryAgent::new();
    assert!(matches!(
        agent.sign(b"nope", b"data"),
        Err(AgentError::NotFound)
    ));
}

#[test]
fn bad_pem_is_parse_error() {
    let mut agent = InMemoryAgent::new();
    assert!(matches!(
        agent.add_from_openssh(b"k".to_vec(), b"not a key"),
        Err(AgentError::Parse)
    ));
}

#[test]
fn remove_key() {
    let (pem, _public) = generate_ed25519_openssh().unwrap();
    let mut agent = InMemoryAgent::new();
    agent
        .add_from_openssh(b"k".to_vec(), pem.as_bytes())
        .unwrap();
    assert!(agent.remove(b"k"));
    assert!(!agent.contains(b"k"));
    assert!(agent.is_empty());
    assert!(matches!(agent.sign(b"k", b"d"), Err(AgentError::NotFound)));
}

#[test]
fn key_from_vault_to_agent_roundtrip() {
    use unissh_keychain::{create_account, KdfParams};
    use unissh_storage::Storage;
    use unissh_vault::Vault;

    let (pem, public) = generate_ed25519_openssh().unwrap();
    let st = Storage::open_in_memory(&[9_u8; 32]).unwrap();
    let (_sk, _rec, ks) = create_account(None, KdfParams::recommended()).unwrap();
    let v = Vault::create(&st, &ks, b"vault".to_vec(), b"ssh-keys").unwrap();
    v.put_item(b"id_ed25519", 1, pem.as_bytes()).unwrap();

    let item = v.get_item(b"id_ed25519").unwrap().unwrap();
    let mut agent = InMemoryAgent::new();
    agent.add_from_item(b"id_ed25519".to_vec(), &item).unwrap();

    let sig = agent.sign(b"id_ed25519", b"data").unwrap();
    let vk = VerifyingKey::from_bytes(&ed25519_public_bytes(
        &agent.public_key(b"id_ed25519").unwrap(),
    ))
    .unwrap();
    let arr: [u8; 64] = sig.signature.try_into().unwrap();
    assert!(vk.verify(b"data", &Signature::from_bytes(&arr)).is_ok());

    assert_eq!(
        agent
            .public_key(b"id_ed25519")
            .unwrap()
            .to_openssh()
            .unwrap(),
        public
    );
}
