//! Byte-parity §15.2: the server's `verify_strict` (registration / server-auth) and
//! keyset-header parsing MUST accept exactly what the core signs/serializes.
//! Cross-domain reject (§5.3) is checked explicitly.

use unissh_crypto::{
    Ed25519Keypair, RegistrationPayload as CoreReg, ServerAuthChallenge as CoreChal, X25519Keypair,
    sign_registration, sign_server_auth,
};
use unissh_keychain::{KdfParams, create_account};
use unissh_server::crypto as sc;

#[test]
fn registration_verify_matches_core_and_rejects_tamper() {
    let k = Ed25519Keypair::generate();
    let xk = X25519Keypair::generate();
    let ed = k.verifying.to_bytes();
    let x = xk.public.to_bytes();
    let account_id = b"acct-16-bytes!!!".to_vec();

    let core_payload = CoreReg {
        account_id: account_id.clone(),
        x25519_pub: x,
        ed25519_pub: ed,
    };
    let sig = sign_registration(&k.signing, &core_payload).unwrap();

    let ours = sc::RegistrationPayload {
        account_id: account_id.clone(),
        x25519_pub: x,
        ed25519_pub: ed,
    };
    sc::verify_registration(&ours, &sig).expect("core-signed registration must verify");

    // Tamper account_id → reject.
    let mut bad = ours.clone();
    bad.account_id = b"acct-16-bytes-XX".to_vec();
    assert!(sc::verify_registration(&bad, &sig).is_err());

    // Wrong signing key (self-attested: a different ed in payload changes vk) → reject.
    let other = Ed25519Keypair::generate();
    let mut wrong = ours.clone();
    wrong.ed25519_pub = other.verifying.to_bytes();
    assert!(sc::verify_registration(&wrong, &sig).is_err());
}

#[test]
fn server_auth_verify_matches_core_and_rejects() {
    let k = Ed25519Keypair::generate();
    let chal = CoreChal {
        host: b"prod.example".to_vec(),
        account_id: b"acc-1".to_vec(),
        device_id: b"dev-1".to_vec(),
        key_id: b"key-1".to_vec(),
        nonce: b"nonce-abc".to_vec(),
        expiry: 1_900_000_000,
    };
    let sig = sign_server_auth(&k.signing, &chal).unwrap();

    let ours = sc::ServerAuthChallenge {
        host: b"prod.example".to_vec(),
        account_id: b"acc-1".to_vec(),
        device_id: b"dev-1".to_vec(),
        key_id: b"key-1".to_vec(),
        nonce: b"nonce-abc".to_vec(),
        expiry: 1_900_000_000,
    };
    sc::verify_server_auth(&k.verifying.to_bytes(), &ours, &sig)
        .expect("core-signed challenge must verify");

    // Wrong key.
    let other = Ed25519Keypair::generate();
    assert!(sc::verify_server_auth(&other.verifying.to_bytes(), &ours, &sig).is_err());

    // Tampered nonce.
    let mut t = ours.clone();
    t.nonce = b"nonce-xyz".to_vec();
    assert!(sc::verify_server_auth(&k.verifying.to_bytes(), &t, &sig).is_err());
}

#[test]
fn cross_domain_registration_sig_not_valid_as_server_auth() {
    // A registration-domain signature must NOT verify as server-auth
    // (the length-prefixed domain separates the contexts, §5.3 / domain_sig.rs).
    let k = Ed25519Keypair::generate();
    let core_payload = CoreReg {
        account_id: b"acct-16-bytes!!!".to_vec(),
        x25519_pub: [1_u8; 32],
        ed25519_pub: k.verifying.to_bytes(),
    };
    let reg_sig = sign_registration(&k.signing, &core_payload).unwrap();

    // Try feeding the registration signature into server-auth verify over
    // some challenge — it must be rejected.
    let chal = sc::ServerAuthChallenge {
        host: b"acct-16-bytes!!!".to_vec(),
        account_id: vec![],
        device_id: vec![],
        key_id: vec![],
        nonce: vec![],
        expiry: 0,
    };
    assert!(sc::verify_server_auth(&k.verifying.to_bytes(), &chal, &reg_sig).is_err());
}

#[test]
fn keyset_header_parse_matches_core() {
    // SecretKeyOnly: password None → Argon2id doesn't run (fast). params are ignored.
    let params = KdfParams::recommended();
    let (_secret, keyset, _unlocked) = create_account(None, params).unwrap();
    let blob = keyset.to_bytes().unwrap();

    let h = sc::parse_keyset_header(&blob).expect("valid keyset header");
    assert_eq!(h.mode, 2, "SecretKeyOnly mode");
    assert_eq!(h.generation, 1, "fresh keyset generation == 1");
    assert_eq!(h.x25519_pub, keyset.x25519_public);
    assert_eq!(h.ed25519_pub, keyset.ed25519_public);

    // Corrupt format version byte → reject.
    let mut bad = blob.clone();
    bad[0] = 0x09;
    assert!(sc::parse_keyset_header(&bad).is_err());

    // Truncated below pubkeys → reject.
    assert!(sc::parse_keyset_header(&blob[..8]).is_err());
}
