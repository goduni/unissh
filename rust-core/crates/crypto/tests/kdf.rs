//! Argon2id KDF: determinism, dependence on salt/password, parameter serialization.

use unissh_crypto::{derive_key, KdfParams};

/// Lightweight parameters for test speed (still Argon2id).
fn fast(salt: u8) -> KdfParams {
    KdfParams {
        mem_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
        salt: vec![salt; 16],
    }
}

#[test]
fn deterministic() {
    let p = fast(7);
    let k1 = derive_key(b"correct horse battery staple", &p).unwrap();
    let k2 = derive_key(b"correct horse battery staple", &p).unwrap();
    assert_eq!(k1.expose_bytes(), k2.expose_bytes());
}

#[test]
fn matches_argon2_0_5_3_keys() {
    // Frozen outputs from argon2 0.5.3, Argon2id v0x13, with a 32-byte key.
    // Existing encrypted keysets must unlock with the same password after a
    // dependency upgrade: a same-version round-trip cannot catch this regression.
    let cases = [
        (
            65536,
            3,
            1,
            "84724983f9d88b4e19321a45d33f5e65351160e6d5d989338d28f6e1536e2f26",
        ),
        (
            19456,
            2,
            1,
            "a74b109e02c0d61365d57ce4ef083d0b615e585c3f7ddeef10c21fd400a2b08f",
        ),
        (
            19456,
            2,
            2,
            "979e7455dca02c93d18612617d2cc23bd34c033791dfef6f7fdb2570830275f2",
        ),
    ];
    for (mem_kib, iterations, parallelism, expected) in cases {
        let params = KdfParams {
            mem_kib,
            iterations,
            parallelism,
            salt: vec![0x12; 16],
        };
        let restored = KdfParams::from_blob(&params.to_blob().unwrap()).unwrap();
        let key = derive_key(b"compatibility-test-password", &restored).unwrap();
        assert_eq!(hex::encode(key.expose_bytes()), expected);
    }
}

#[test]
fn different_salt_differs() {
    let k1 = derive_key(b"pw", &fast(1)).unwrap();
    let k2 = derive_key(b"pw", &fast(2)).unwrap();
    assert_ne!(k1.expose_bytes(), k2.expose_bytes());
}

#[test]
fn wrong_password_differs() {
    let p = fast(5);
    let k1 = derive_key(b"password", &p).unwrap();
    let k2 = derive_key(b"Password", &p).unwrap();
    assert_ne!(k1.expose_bytes(), k2.expose_bytes());
}

#[test]
fn params_blob_roundtrip() {
    let p = KdfParams::recommended();
    let blob = p.to_blob().unwrap();
    let p2 = KdfParams::from_blob(&blob).unwrap();
    assert_eq!(p, p2);
}

#[test]
fn params_blob_rejects_truncation() {
    let p = KdfParams::recommended();
    let blob = p.to_blob().unwrap();
    assert!(KdfParams::from_blob(&blob[..blob.len() - 3]).is_err());
}

#[test]
fn recommended_meets_memory_floor() {
    // spec 5.5: Argon2id memory ≥ 64 MiB.
    assert!(KdfParams::recommended().mem_kib >= 64 * 1024);
}

#[test]
fn from_blob_rejects_oversized_params() {
    // An untrusted blob with a huge mem_kib must not parse (DoS protection:
    // the Argon2 allocation happens before AEAD authentication on the import_vault path).
    let evil = KdfParams {
        mem_kib: u32::MAX,
        iterations: 3,
        parallelism: 1,
        salt: vec![0u8; 16],
    };
    let blob = evil.to_blob().unwrap();
    assert!(KdfParams::from_blob(&blob).is_err());

    // Out-of-bounds iterations/parallelism are rejected too.
    let evil_iter = KdfParams {
        mem_kib: 65536,
        iterations: 1_000_000,
        parallelism: 1,
        salt: vec![0u8; 16],
    };
    assert!(KdfParams::from_blob(&evil_iter.to_blob().unwrap()).is_err());

    // The recommended parameters are still valid.
    let ok = KdfParams::recommended();
    assert!(KdfParams::from_blob(&ok.to_blob().unwrap()).is_ok());
}
