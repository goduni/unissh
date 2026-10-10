//! An end-to-end mini-scenario of the envelope hierarchy on the `crypto` primitives (without
//! keychain/storage/ssh): password → unlock key (Argon2id) → wraps the vault's VK
//! → VK wraps the per-item key → encrypts an "SSH key" with a binding to
//! `vault_id+item_id+version`; the change is signed (Ed25519) with rollback detection;
//! the VK can be handed to another member under their X25519 key (HPKE).

use unissh_crypto::{
    aead_decrypt, aead_encrypt, derive_key, open_key_with_secret, seal_key_to_public, sign_version,
    unwrap_key, verify_no_rollback, AssociatedData, Ed25519Keypair, KdfParams, SymmetricKey,
    VersionedObject, X25519Keypair,
};

fn fast_params() -> KdfParams {
    KdfParams {
        mem_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
        salt: vec![9_u8; 16],
    }
}

#[test]
fn envelope_hierarchy_and_signed_version() {
    let params = fast_params();

    // 1. unlock key from the master password
    let unlock = derive_key(b"master-password", &params).unwrap();

    // 2. the vault's VK, wrapped by the unlock key
    let vk = SymmetricKey::generate();
    let wrapped_vk = wrap(&unlock, &vk, b"vault:demo");

    // 3. the per-item key, wrapped by the VK
    let item_key = SymmetricKey::generate();
    let wrapped_item_key = wrap(&vk, &item_key, b"item:ssh-key-1");

    // 4. the item content encrypted with the per-item key, bound to the context
    let aad = AssociatedData::new(b"vault:demo".to_vec(), b"item:ssh-key-1".to_vec(), 1);
    let ssh_private = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-bytes\n-----END-----";
    let ciphertext = aead_encrypt(&item_key, ssh_private, &aad).unwrap();

    // 5. signature of the change version
    let signer = Ed25519Keypair::generate();
    let versioned = VersionedObject::from_content(aad.clone(), &ciphertext);
    let signature = sign_version(&signer.signing, &versioned).unwrap();

    // --- the reverse path: unlocking with the same password ---
    let unlock2 = derive_key(b"master-password", &params).unwrap();
    let vk2 = unwrap_key(&unlock2, &wrapped_vk, b"vault:demo").unwrap();
    let item_key2 = unwrap_key(&vk2, &wrapped_item_key, b"item:ssh-key-1").unwrap();
    let recovered = aead_decrypt(&item_key2, &ciphertext, &aad).unwrap();
    assert_eq!(recovered, ssh_private);

    // the signature is valid; a rollback (last_seen >= version) is caught
    assert!(verify_no_rollback(&signer.verifying, &versioned, &signature, 0).is_ok());
    assert!(verify_no_rollback(&signer.verifying, &versioned, &signature, 1).is_err());

    // 6. hand the VK to another member under their X25519 (the sharing format via HPKE)
    let recipient = X25519Keypair::generate();
    let wrapped_for_recipient = seal_key_to_public(&recipient.public, &vk, b"vault:demo").unwrap();
    let vk_recipient =
        open_key_with_secret(&recipient.secret, &wrapped_for_recipient, b"vault:demo").unwrap();
    assert_eq!(vk_recipient.expose_bytes(), vk.expose_bytes());
}

#[test]
fn wrong_master_password_cannot_unlock_vault() {
    let params = fast_params();
    let unlock = derive_key(b"right-password", &params).unwrap();
    let vk = SymmetricKey::generate();
    let wrapped_vk = wrap(&unlock, &vk, b"vault:demo");

    let wrong_unlock = derive_key(b"wrong-password", &params).unwrap();
    assert!(unwrap_key(&wrong_unlock, &wrapped_vk, b"vault:demo").is_err());
}

fn wrap(kek: &SymmetricKey, key: &SymmetricKey, aad: &[u8]) -> Vec<u8> {
    unissh_crypto::wrap_key(kek, key, aad).unwrap()
}
