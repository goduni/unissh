//! # unissh-keychain
//!
//! The UniSSH key hierarchy (spec 5.1). Built on [`unissh_crypto`].
//!
//! Bottom-up:
//! 1. **Secret Key** ([`SecretKey`]) — ~128 bits, generated on the device, never
//!    leaves for the server.
//! 2. **Argon2id** over the master password (the primitive and parameters come from `crypto`).
//! 3. **Unlock Key** = `combine(Argon2id(password), Secret Key)` (HKDF-SHA256).
//! 4. **Personal keyset** — an X25519 + Ed25519 pair, encrypted under the Unlock Key
//!    ([`EncryptedKeyset`] / [`UnlockedKeyset`]).
//!
//! The passwordless mode (SSO + trusted devices) is provided as [`UnlockMode::SecretKeyOnly`]:
//! the root is the Secret Key (+ a device secret in the future). Biometrics are not
//! implemented here — that is the UI project's platform layer.
//!
//! ## What is not here
//! Storage (`storage`), vaults/VK (`vault`), SSH. Per-instance isolation is the
//! responsibility of `storage` (each instance stores its own keyset record separately).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod account;
mod error;
mod keyset;
mod onboarding_floor;
mod onboarding_pake;
mod secret_key;
mod server_auth;
mod unlock;

pub use account::{
    build_registration, build_registration_request, generate_account_id, load_account_id,
    store_account_id, verify_registration, ACCOUNT_ID_LEN,
};
pub use error::KeychainError;
pub use keyset::{
    change_password, create_account, unlock_account, unlock_account_migrating, EncryptedKeyset,
    UnlockMode, UnlockedKeyset,
};
pub use onboarding_floor::{
    keyset_gen_floor, raise_floor_after_change_password, raise_keyset_gen_floor,
    unlock_account_checked,
};
pub use onboarding_pake::{OnboardInitiator, OnboardResponder};
pub use secret_key::{SecretKey, SECRET_KEY_LEN};
pub use server_auth::sign_server_challenge;
pub use unlock::derive_escrow_auth_key;

// Re-export of the crypto types needed by keyset consumers.
pub use unissh_crypto::{Ed25519Keypair, KdfParams, ServerAuthChallenge, X25519Keypair};
