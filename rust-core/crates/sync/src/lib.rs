//! # unissh-sync
//!
//! UniSSH client-side sync engine (server-tz §3, §9, §1.1). Relies on
//! `crypto` (verify), `storage` (monotonic put/cursor/epoch floor), `vault`
//! (verify_record_authority / verify_chain_to_epoch / membership), `keychain`
//! (generation floor).
//!
//! ## Threat model: transport is UNTRUSTED
//! `SyncTransport` (and its in-memory mock) is a stand-in for an **untrusted** server
//! (ARCH §3.1, server-tz §1.1). The engine NEVER trusts `server_seq`, nor
//! ordering, nor object content. Every object from the delta goes through
//! **verify-before-apply**: signature (`crypto`/`vault`) → `key_epoch >= floor`
//! (`storage.get_vault_epoch_floor`) → author authority (the `vault` member model)
//! → keyset generation `>= floor` (`keychain`) — and only then the monotonic
//! `storage.put_*` (signed-version LWW).
//!
//! ## Guarantees (never panics — typed report/error)
//! - stale/version rollback (`StorageError::VersionRollback`) → SKIP;
//! - equal version with different content → surfaced as [`Conflict`] (local
//!   is not overwritten);
//! - equivocating manifest@epoch (a different member-set of the same epoch) → [`Conflict`],
//!   the trusted manifest is NOT overwritten (anti-equivocation);
//! - forged/non-member object → REJECTED, not applied;
//! - `key_epoch`/generation below the floor → REJECTED;
//! - keyset: the generation floor is NOT moved from the unauthenticated header of the blob
//!   (only credentials move it on the unlock path) — otherwise tampering with the
//!   `generation` header bytes would lock the legitimate keyset;
//! - audit: the author must be the trusted instance anchor (`genesis_owner`);
//! - a transport that hands off/reports a cursor `< last-seen` → REJECTED;
//! - the trusted cursor moves ONLY monotonically forward.
//!
//! ## What is not here
//! A real network/server (only the trait + mock), content/VK decryption
//! (no plaintext leaves), CRDT merge (LWW; CRDT — ⏳ LATER).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod engine;
mod error;
mod object;
mod transport;

pub use engine::{
    apply_pulled_objects, pull_cursor_key, push_cursor_key, reset_pull_cursor, sync_pull,
    sync_push, Conflict, PushReport, RejectReason, Rejected, SyncContext, SyncReport,
};
pub use error::SyncError;
pub use object::{AccountStateObject, AuditObject, ObjectTag, SyncObject};
pub use transport::{InMemoryTransport, SyncTransport};
