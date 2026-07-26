//! # unissh-ssh-agent
//!
//! Embedded **in-memory** SSH agent (spec 10.1). NOT the system ssh-agent: keys
//! live only inside the core process.
//!
//! ## Key flow
//! An SSH private key is an ordinary vault item (ciphertext). Before use it is
//! decrypted by the `vault` layer and handed to the agent
//! ([`InMemoryAgent::add_from_item`]). Inside the agent the OpenSSH private key
//! sits in **`mlock`-ed** memory and is **zeroized** on removal; the signing key
//! is reconstructed from it only for the moment of signing. Ed25519, ECDSA
//! (p256/p384/p521) and RSA are supported.
//!
//! A plaintext key is never written to disk. [`generate_openssh`] /
//! [`generate_ed25519_openssh`] return the private key as `Zeroizing<String>` —
//! it is stored encrypted in the vault.
//!
//! ## Transport integration
//! The private key **never leaves the agent**: [`InMemoryAgent::sign`] signs the
//! challenge and returns the SSH signature blob; [`InMemoryAgent::public_key`] and
//! [`InMemoryAgent::certificate`] return the public key/certificate. On top of
//! these, `ssh-transport` implements `russh::auth::Signer`.
//!
//! ## Limitations / out of scope
//! The SSH transport/connect itself is the `ssh-transport` crate. **Agent
//! forwarding** is not implemented (spec 10.2) — `ProxyJump` is used instead, so
//! the key is never handed to a bastion.
//!
//! This crate is not the system agent and does not wrap one; keys added here live
//! only in this process. Talking to the *operating system's* agent is a separate,
//! per-host opt-in that lives in `ssh-transport`
//! (`Auth::SystemAgent`) — that is the route to hardware tokens and smart cards,
//! whose keys by definition never enter this agent.
//!
//! FIDO/U2F credentials (`sk-*`) are rejected at import: they parse, because the
//! file holds a key handle rather than a private scalar, but signing needs the
//! token. Use them through the system agent.
//!
//! `mlock` is best-effort (see [`locked`]).

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod agent;
mod error;
mod import;
mod locked;

pub use agent::{generate_ed25519_openssh, generate_openssh, AgentSignature, InMemoryAgent};
pub use error::AgentError;
pub use import::{normalize_private_key_to_openssh, normalize_private_key_with_passphrase};

// Re-export ssh-key for consumers (ssh-transport, tests).
pub use ssh_key;
