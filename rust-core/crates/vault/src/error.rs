//! Errors of the vault crate.

use thiserror::Error;
use unissh_crypto::CryptoError;
use unissh_storage::StorageError;

/// Errors of vault operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultError {
    /// Vault or item not found.
    #[error("not found")]
    NotFound,

    /// Failed to unwrap the VK/key (wrong keyset) or to decrypt the content.
    #[error("decryption failed (wrong keyset or vault key)")]
    Decrypt,

    /// The vault/item record signature does not verify (metadata tampering).
    #[error("record signature verification failed")]
    SignatureInvalid,

    /// Structurally malformed record.
    #[error("malformed record")]
    Format,

    /// The target id is already taken by a live item (e.g. on rename).
    #[error("item already exists")]
    AlreadyExists,

    /// Manifest signed by a key that is not an admin in the previous epoch
    /// (or, for genesis, not the creator's key) — authority chain violation.
    #[error("membership authority invalid")]
    AuthorityInvalid,

    /// Epoch monotonicity violated (genesis != 1, or next != prev+1, or
    /// epoch below the trusted floor).
    #[error("key epoch invalid or rolled back")]
    EpochInvalid,

    /// The record's author is not in the vault's signed member-set at its epoch.
    #[error("author is not a member at record epoch")]
    NotAMember,

    /// The presented member-pubkey does not match the pinned one (pinning).
    #[error("member pubkey does not match pin")]
    PinMismatch,

    /// Grant expired (`not_after` in the past) — read access revoked by time.
    /// Enforced locally by the client, not relying on the untrusted server (F16).
    #[error("grant expired (not_after has passed)")]
    GrantExpired,

    /// This account may only view the vault (its role in the vault's verified
    /// member set is Viewer): an item write is refused before anything is stored.
    /// Every other member's verify-before-apply and the server would refuse the
    /// record anyway, so writing it locally would only leave this device's copy
    /// diverged, and the record unreadable here too.
    #[error("this account can only view this vault")]
    ReadOnly,

    /// Crypto-layer error.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// Storage error.
    #[error(transparent)]
    Storage(#[from] StorageError),
}
