//! HTTP modules (ARCH §14 / spec §2.2): identity, sync, vault_meta, policy, audit.
//! Each module exports `routes() -> Router<AppState>`.

pub mod admin;
pub mod audit;
pub mod escrow;
pub mod identity;
pub mod instance;
pub mod oidc;
pub mod ops;
pub mod pending;
pub mod policy;
pub mod spaces;
pub mod sync;
pub mod vault_meta;
