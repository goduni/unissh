//! Cloud server integration.
//!
//! The core (`unissh_ffi`) is deliberately network-less: it supplies every crypto
//! primitive and the sync engine, but the HTTP/relay client must be provided by
//! the caller. This module is that client — the Tauri backend's bridge to a
//! self-hosted UniSSH server (`/v1`, JSON over TLS).
//!
//! Server access is **optional and additive**: local mode (offline Secret
//! Key unlock) works without it. All identifiers/blobs on the wire are base64
//! STANDARD, as on the server. The Bearer token is held in-process (access — in memory,
//! refresh — in the OS keychain); raw keyset/signature blobs are built exclusively by the core.

pub mod client;
pub mod commands;
pub mod config;
pub mod identity;
pub mod oidc;
pub mod onboard;
pub mod tokens;
pub mod transport;

#[cfg(test)]
mod tests;

pub use config::{CloudState, ServerList, ServerStatus};
