//! # unissh-crypto
//!
//! Cryptographic foundation of the UniSSH core. A standalone crate: without
//! storage, SSH, UI, or the network.
//!
//! ## What's inside
//! - **Primitives** (spec 5.5): Argon2id (KDF), XChaCha20-Poly1305 (the default
//!   symmetric cipher), HPKE RFC 9180 over X25519 (public-key encryption),
//!   Ed25519 (signatures).
//! - **Envelope wrappers**: wrapping of a symmetric key under a public key
//!   ([`hpke_seal`]) and symmetric wrapping of a key by another key ([`keywrap`]).
//! - **AEAD with associated data** ([`aead`]): binding to `vault_id+item_id+version`.
//! - **Signatures + monotonic versions** ([`signature`]): signature of an object with a version
//!   and detection of a backward rollback.
//! - **Domain-separated signatures** ([`domain_sig`]): Ed25519 signature over an
//!   arbitrary canonical payload in an explicit domain (`server-auth`, audit) —
//!   for contexts outside [`signature::VersionedObject`]. Built on them —
//!   the signed server-auth challenge ([`server_auth`]).
//! - **Epoch binding of the VK wrapper** ([`hpke_seal::vk_wrap_info`]): the canonical
//!   HPKE `info` binding the VK wrapper to `vault_id‖member_pubkey‖key_epoch`
//!   (anti-replay on VK rotation).
//! - **Per-blob versioning** ([`version`]): a format-version byte + the algorithm
//!   id (crypto agility — the crypto can be rotated later).
//!
//! ## Blob versioning
//! Each blob begins with the header `format_version(1) || alg_id(2 be)`.
//! The algorithm registry and the reserved extension points (AES-256-GCM,
//! the PQ hybrid X25519+ML-KEM) are in [`version::AlgId`].
//!
//! ## Secrets
//! Secret keys are zeroized on Drop. Access to a secret's raw bytes is only
//! through explicit `expose_*` methods. `mlock` of memory pages is the job of the
//! `ssh-agent` crate, not this one.
//!
//! ## What is not here
//! The key hierarchy (Secret Key, unlock, keyset → `keychain`), storage
//! (`storage`), SSH (`ssh-transport`/`ssh-agent`), sync/network. AES-256-GCM and
//! the PQ hybrid are only reserved in the registry, not implemented.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;

pub mod aead;
pub mod domain_sig;
pub mod hpke_seal;
pub mod kdf;
pub mod keys;
pub mod keywrap;
pub mod registration;
pub mod server_auth;
pub mod signature;
pub mod version;

pub use error::CryptoError;

// Flat, convenient re-export of the main API.
pub use aead::{
    aead_decrypt, aead_decrypt_pre_agility, aead_encrypt, aead_encrypt_pre_agility, AssociatedData,
};
// domain_sign/domain_verify are crate-private (foot-gun removal, Milestone-2 review):
// external callers go through the type-safe wrappers sign_server_auth/
// sign_registration. Only the domain constants (the domain registry) are public.
pub use domain_sig::{AUDIT_SIG_DOMAIN, REGISTRATION_SIG_DOMAIN, SERVER_AUTH_SIG_DOMAIN};
pub use hpke_seal::{open_key_with_secret, seal_key_to_public, vk_wrap_info};
pub use kdf::{derive_key, KdfParams};
pub use keys::{
    random_bytes, Ed25519Keypair, Ed25519SigningKey, Ed25519VerifyingKey, SymmetricKey,
    X25519Keypair, X25519PublicKey, X25519SecretKey,
};
pub use keywrap::{unwrap_key, unwrap_key_pre_agility, wrap_key, wrap_key_pre_agility};
pub use registration::{sign_registration, verify_registration, RegistrationPayload};
pub use server_auth::{sign_server_auth, verify_server_auth, ServerAuthChallenge};
pub use signature::{
    sign_account_state, sign_version, verify_account_state, verify_no_rollback, verify_version,
    VersionedObject, ACCOUNT_STATE_SIG_DOMAIN,
};
pub use version::{AlgId, FORMAT_VERSION};
