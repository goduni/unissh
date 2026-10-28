//! Sync engine errors.

use thiserror::Error;
use unissh_crypto::CryptoError;
use unissh_keychain::KeychainError;
use unissh_storage::StorageError;
use unissh_vault::VaultError;

/// Fatal sync errors. Non-fatal ones (stale/conflict/reject of individual
/// objects) are NOT errors but entries in [`crate::SyncReport`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SyncError {
    /// The transport reported a version (`report_version`) BELOW the trusted cursor —
    /// a rollback of the server's maximum (snapshot-replay/server substitution). Fatal:
    /// sync aborts, the cursor does not move.
    #[error("transport reported version {reported} below trusted cursor {cursor}")]
    TransportRollback {
        /// What the transport reported.
        reported: u64,
        /// The trusted last-seen cursor.
        cursor: u64,
    },

    /// An attempt to lower the trusted cursor (internal invariant: `set_cursor`
    /// moves forward only). Should not happen with a correct engine;
    /// returned as a safeguard instead of a silent lowering.
    #[error("cursor rollback: attempted {attempted} < current {current}")]
    CursorRollback {
        /// The current cursor.
        current: u64,
        /// The attempted lowering.
        attempted: u64,
    },

    /// A structurally malformed object at a level that cannot be reduced to a reject of an
    /// individual record (e.g. its type cannot even be determined). Usually a broken object goes into
    /// the report's `rejected`; this variant is for codec errors outside the per-object loop.
    #[error("malformed sync object")]
    Format,

    /// The server refused a push request as too large (an object over its
    /// `max_object_bytes`, too many objects, or a request body over its limit).
    /// Returned by a transport; [`crate::sync_push`] answers it by halving the
    /// request, and surfaces it only for an object that cannot be left out.
    #[error("the server refused the push as too large")]
    PayloadTooLarge,

    /// The server refused a push request as not permitted (HTTP 403: its write
    /// policy refused an object in it — a Viewer's item, an author who is not
    /// a member at the object's epoch). The whole request is refused, so
    /// [`crate::sync_push`] answers it by halving the request until the
    /// refused object is alone, and surfaces it only for an object that
    /// cannot be left out.
    #[error("the server refused the push as not permitted")]
    Forbidden,

    /// A vault-layer error (verify/authority).
    #[error(transparent)]
    Vault(#[from] VaultError),

    /// A storage-layer error.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// A crypto-layer error.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// A keychain-layer error (keyset generation floor).
    #[error(transparent)]
    Keychain(#[from] KeychainError),
}
