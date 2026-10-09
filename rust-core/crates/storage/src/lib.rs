//! # unissh-storage
//!
//! UniSSH local encrypted storage: SQLite + **SQLCipher**. Relies on the formats
//! defined by `crypto`/`keychain`/`vault` (stores already-encrypted blobs +
//! cleartext metadata).
//!
//! ## Instance isolation (spec 2A)
//! Each instance is a **separate encrypted DB file with its own key**. Data from
//! different instances is never physically mixed; compromising one instance's key
//! does not expose another. A local vault is an "instance without a server".
//!
//! ## Data model (designed for future sync, spec 9 / 5.4)
//! - [`VaultRecord`], [`ItemRecord`] with fields: **monotonic version**, **author
//!   signature** (Ed25519 blob) + its public key, **tombstone** (deletion is a
//!   first-class event), `server_seq` (sync cursor, not used yet).
//! - Binding of `vault_id+item_id+version` — via associated data at the `vault` layer.
//! - Storage **does not encrypt content** and **does not verify signatures** — that is the `vault` layer.
//!   Storage guarantees version monotonicity (anti-rollback at the DB level),
//!   instance isolation, and ciphertext storage.
//!
//! ## What is not here
//! Network sync (there is no server), VK/sharing/encryption (the `vault` layer).

#![forbid(unsafe_code)]

mod error;
mod records;
mod schema;
mod store;

pub use error::StorageError;
pub use records::{
    AccountStateRecord, AuditEntry, CachePolicy, ConsistencyIssue, ConsistencyKind,
    ConsistencyReport, ItemRecord, KnownHost, MemberRole, MembershipGrant, MembershipManifest,
    PinnedMemberKey, SyncTarget, VaultRecord, VaultTrustAnchor,
};
pub use store::{Storage, DB_KEY_LEN};
