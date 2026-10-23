//! Cloud server integration.
//!
//! The wire — HTTP client, API calls, sync transport, pairing relay — is the
//! shared `unissh-cloud` crate, re-exported here under the module names the app
//! has always used. What stays in the app is what only the app has: the Tauri
//! commands, the multi-server link set with its refresh tokens in the OS
//! keychain, and the browser-based SSO flow.
//!
//! Server access is **optional and additive**: local mode (offline Secret
//! Key unlock) works without it. All identifiers/blobs on the wire are base64
//! STANDARD, as on the server. The Bearer token is held in-process (access — in memory,
//! refresh — in the OS keychain); raw keyset/signature blobs are built exclusively by the core.

pub use unissh_cloud::{client, identity, onboard, recovery, transport};

pub mod commands;
pub mod config;
pub mod oidc;
pub mod tokens;

pub use config::{CloudState, ServerList, ServerStatus};
