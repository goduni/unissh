//! Trusted keyset generation floor (anti-rollback, server-tz §9 Path A / §13.13b).
//!
//! An `EncryptedKeyset` record carries a monotonic `generation` (increases on
//! password change). A malicious server cannot forge a keyset (AEAD does not
//! authenticate under a foreign key), but it can hand back a **stale**
//! generation — a rollback of an unlock/password change. The floor is stored in
//! storage-meta (`"keyset_gen_floor"`, u64 be) **outside** the replicated data
//! and refuses to accept a record older than the one already seen.
//!
//! ## Honest onboarding gap (TOFU-generation, §13.13c)
//! A fresh device WITHOUT a prior floor accepts the **first** generation it sees
//! as the floor. Confidentiality is preserved (the keyset cannot be decrypted
//! without credentials), but there is a freshness gap: on the very first unlock
//! the server could hand back a stale generation. Closing it (the Emergency Kit
//! commits the expected generation) is a seam onto the `recovery` crate
//! (Milestone 2); here we document it honestly and do NOT hide it behind an
//! invariant.

use unissh_storage::Storage;

use crate::error::KeychainError;
use crate::keyset::{unlock_account, EncryptedKeyset, UnlockedKeyset};
use crate::secret_key::SecretKey;

/// Storage-meta key for the trusted keyset generation floor.
const META_GEN_FLOOR: &str = "keyset_gen_floor";

/// Reads the trusted generation floor (if set).
pub fn keyset_gen_floor(storage: &Storage) -> Result<Option<u64>, KeychainError> {
    match storage.get_meta(META_GEN_FLOOR)? {
        Some(v) => {
            let arr: [u8; 8] = v.as_slice().try_into().map_err(|_| KeychainError::Format)?;
            Ok(Some(u64::from_be_bytes(arr)))
        }
        None => Ok(None),
    }
}

/// Raises the generation floor to `floor` (monotonic: it cannot be lowered).
pub fn raise_keyset_gen_floor(storage: &Storage, floor: u64) -> Result<(), KeychainError> {
    let current = keyset_gen_floor(storage)?.unwrap_or(0);
    if floor > current {
        storage.set_meta(META_GEN_FLOOR, &floor.to_be_bytes())?;
    }
    Ok(())
}

/// Unlocks a keyset with an anti-rollback floor check (server-tz §13.13).
///
/// 1. If `record.generation < floor` → [`KeychainError::GenerationRollback`]
///    (rejected BEFORE the expensive Argon2id, without leaking an oracle).
/// 2. Otherwise the usual [`unlock_account`] (AEAD authentication of the credentials).
/// 3. On success it raises the floor to `record.generation` (TOFU when no floor is set).
pub fn unlock_account_checked(
    record: &EncryptedKeyset,
    password: Option<&[u8]>,
    secret_key: &SecretKey,
    storage: &Storage,
) -> Result<UnlockedKeyset, KeychainError> {
    let floor = keyset_gen_floor(storage)?.unwrap_or(0);
    let attempted = u64::from(record.generation);
    if attempted < floor {
        return Err(KeychainError::GenerationRollback { attempted, floor });
    }
    let unlocked = unlock_account(record, password, secret_key)?;
    raise_keyset_gen_floor(storage, attempted)?;
    Ok(unlocked)
}

/// Raises the trusted floor after a successful password change (server-tz §13.13b).
/// Call it right after persisting the new `change_password` record: it guarantees
/// that the old blob (a password downgrade) will no longer pass
/// `unlock_account_checked` on this device.
pub fn raise_floor_after_change_password(
    storage: &Storage,
    new_record: &EncryptedKeyset,
) -> Result<(), KeychainError> {
    raise_keyset_gen_floor(storage, u64::from(new_record.generation))
}
