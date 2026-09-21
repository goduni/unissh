//! An embeddable MCP HTTP adapter, not a standalone server executable.
//!
//! No vault or SSH dependency is allowed here. The native app supplies authentication
//! and a broker implementing [`Backend`]; the broker owns grants, sessions and runs.
//! Binding is explicit and always loopback-only. Nothing starts on library load.

#![forbid(unsafe_code)]

pub mod contract;
pub mod credentials;
mod limited_listener;
mod server;

use std::{future::Future, pin::Pin};

pub use server::LocalServer;
pub use tokio_util::sync::CancellationToken;

/// Hard logging policy for every sink in the embedding application. SDK events
/// contain raw tool data at multiple levels; environment overrides cannot opt in.
pub fn diagnostics_allowed(target: &str) -> bool {
    target != "rmcp" && !target.starts_with("rmcp::")
}

/// Trusted caller identity supplied by native authentication, never tool arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrationId(pub String);

/// Verify a bearer credential against native integration records on EVERY request.
/// Implementations must not log or retain the plaintext credential.
pub trait Authenticator: Send + Sync + 'static {
    fn authenticate(&self, credential: &str) -> Option<IntegrationId>;
}

pub type BackendResult<'a> =
    Pin<Box<dyn Future<Output = Result<serde_json::Value, contract::ToolError>> + Send + 'a>>;

/// The broker must authorize all operations, including list/read/cancel.
/// HTTP request lifetime is not permission or SSH-session lifetime.
pub trait Backend: Send + Sync + 'static {
    fn call(&self, integration: IntegrationId, request: contract::ToolRequest)
        -> BackendResult<'_>;
}

/// Fail-closed backend for transport validation before native grants are wired up.
pub struct NoGrants;

impl Backend for NoGrants {
    fn call(&self, _: IntegrationId, _: contract::ToolRequest) -> BackendResult<'_> {
        Box::pin(async { Err(contract::ToolError::GrantRequired) })
    }
}
