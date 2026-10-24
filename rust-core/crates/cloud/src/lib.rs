//! Client for a self-hosted UniSSH server's `/v1` API.
//!
//! The core (`unissh_ffi`) is deliberately network-less: it supplies every crypto
//! primitive and the sync engine, and the caller supplies the wire. This crate is
//! that wire, shared by the desktop app and the headless CLI so the two cannot
//! drift apart on the protocol:
//!
//! - [`client`] — the blocking HTTP client, base64 helpers and the server's
//!   error-envelope mapping;
//! - [`identity`] — accounts, devices, sessions, spaces, escrow and the pairing relay;
//! - [`transport`] — the [`unissh_ffi::FfiSyncTransport`] the core's sync engine drives;
//! - [`onboard`] — device-to-device pairing (the PAKE over the relay);
//! - [`recovery`] — installing a recovered keyset.
//!
//! Server access is optional and additive: local mode works without any of it.
//! The server is untrusted for confidentiality — every blob it relays is built,
//! signed and verified by the core — and the bearer tokens this crate carries
//! are never logged. Where a credential has to be remembered (the Secret Key a
//! pairing delivers), the caller decides where: the app's OS keychain, the CLI's
//! own store.

pub mod client;
pub mod dto;
mod error;
pub mod identity;
pub mod onboard;
pub mod recovery;
pub mod transport;

#[cfg(test)]
mod test_server;

pub use error::{CloudError, CloudResult};
