//! Sync engine: [`sync_pull`] / [`sync_push`] + report types.
//!
//! The transport is untrusted (see crate-doc). Delta processing order is
//! strict `server_seq` ASC; the cursor advances ONLY monotonically forward and ONLY
//! after the corresponding seq is processed. Every object goes through
//! verify-before-apply (Task 7); violations are report entries, not a panic.

use unissh_storage::{ItemRecord, Storage, VaultRecord};
use unissh_vault::{
    check_item_record, check_vault_record, verify_record_authority, IntegrityFailure,
};

use crate::error::SyncError;
use crate::object::SyncObject;
use crate::transport::SyncTransport;

/// Key prefix for the trusted pull cursor in `sync_state` (last-seen `server_seq`).
const PULL_CURSOR_PREFIX: &str = "sync:pull";
/// Key prefix for the push cursor (last-pushed `audit.seq`).
const PUSH_CURSOR_PREFIX: &str = "sync:push";

/// Pull-cursor key FOR A SPECIFIC tenant. Multiple linked servers do NOT
/// share one cursor: their `server_seq` are independent spaces, and a shared cursor
/// dropped the second server's pull into `TransportRollback` (or silently lost rows).
pub fn pull_cursor_key(tenant: &[u8]) -> String {
    format!("{PULL_CURSOR_PREFIX}:{}", hex_lower(tenant))
}

/// Resets a tenant's pull cursor to 0 → the next pull re-reads the ENTIRE history
/// (`seq > 0`), not just the delta. Needed when objects were already processed under
/// a DIFFERENT authority context and rejected: a reject also advances the cursor (see
/// [`sync_pull`]). The classic case: a device pulled someone else's single-owner vault
/// under a different keyset (author ≠ anchor → reject, cursor moved forward), and then the keyset
/// changed to the owner's (re-attach). Without a reset the owner would NEVER re-read
/// the vault it can NOW decrypt. Idempotent; re-pulling
/// already-applied objects is a no-op (LWW).
pub fn reset_pull_cursor(storage: &Storage, tenant: &[u8]) -> Result<(), SyncError> {
    storage.set_sync_cursor(&pull_cursor_key(tenant), 0)?;
    Ok(())
}

/// Push-cursor key for a specific tenant (likewise: audit must go to
/// each linked server independently).
pub fn push_cursor_key(tenant: &[u8]) -> String {
    format!("{PUSH_CURSOR_PREFIX}:{}", hex_lower(tenant))
}

/// Cursor prefix for the pushed account-state version FOR a tenant. account-state
/// is broadcast to EVERY server, so a single dirty flag (single-server) does not
/// cover it — we track it per-tenant by the last pushed `version`.
const ACCT_PUSH_CURSOR_PREFIX: &str = "sync:acctpush";
fn acct_push_cursor_key(tenant: &[u8]) -> String {
    format!("{ACCT_PUSH_CURSOR_PREFIX}:{}", hex_lower(tenant))
}

/// Lowercase hex of the opaque tenant bytes for the `sync_state` key (no external
/// dependencies; the input may be arbitrary bytes).
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Sync context: the trusted anchors the engine does NOT guess.
#[derive(Debug, Clone)]
pub struct SyncContext {
    /// Genesis owner of the instance's vaults = the keyset owner's Ed25519 pubkey.
    /// Provided by the caller (see `vault::verify_record_authority`).
    pub genesis_owner: Vec<u8>,
    /// Tenant of the server being synced (opaque `tenant_b64` bytes). Determines
    /// the per-tenant cursor key — isolation of multi-server sync.
    pub tenant: Vec<u8>,
}

/// Reason an object was rejected (REJECTED — the untrusted object was NOT applied).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    /// `server_seq <= the trusted cursor` (replayed/rolled-back feed).
    BelowCursor,
    /// The record's signature does not verify.
    SignatureFailed,
    /// The author is not authorized (not a member@epoch / broken D1 chain / not the owner).
    AuthorityFailed,
    /// `key_epoch` is below the trusted vault epoch floor.
    EpochBelowFloor,
    /// The keyset generation is below the trusted floor.
    GenerationBelowFloor,
    /// Structurally broken/unknown object.
    Malformed,
}

/// An object rejected during pull (with open metadata for diagnostics; no
/// plaintext/secrets).
#[derive(Debug, Clone)]
pub struct Rejected {
    /// The object's server_seq (as the transport reported it).
    pub server_seq: u64,
    /// vault_id (hex-independent — raw open bytes), if present.
    pub vault_id: Option<Vec<u8>>,
    /// Reason.
    pub reason: RejectReason,
}

/// Equal-version conflict (server-tz §3.4): incoming and local have the same
/// signed version but different content. The local copy is NOT overwritten.
#[derive(Debug, Clone)]
pub struct Conflict {
    /// The object's vault_id.
    pub vault_id: Vec<u8>,
    /// item_id (empty for a vault record).
    pub item_id: Vec<u8>,
    /// The disputed version.
    pub version: u64,
}

/// Pull report. No plaintext/secrets.
#[derive(Debug, Clone, Default)]
pub struct SyncReport {
    /// How many objects were applied (merged).
    pub applied: u64,
    /// How many were skipped as stale/version rollback (not an error).
    pub skipped_stale: u64,
    /// Equal-version conflicts (surfaced, local untouched).
    pub conflicts: Vec<Conflict>,
    /// Rejected untrusted objects (verify/floor/cursor fail).
    pub rejected: Vec<Rejected>,
}

/// Push report.
#[derive(Debug, Clone, Default)]
pub struct PushReport {
    /// How many objects were handed to the transport.
    pub pushed: u64,
}

/// Pulls the delta from the untrusted transport and applies verify-before-apply.
///
/// 1. `last = get_sync_cursor(PULL_CURSOR).unwrap_or(0)`.
/// 2. anti-rollback: `transport.report_version() < last` → [`SyncError::TransportRollback`].
/// 3. the delta is sorted by `server_seq` ASC (tie-break by the object's bytes).
/// 4. for each object in seq order: below-cursor → REJECTED; otherwise verify
///    (Task 7) → apply/skip/conflict/reject; the cursor is raised to seq
///    after processing (see D-SEQ-ORDER).
pub fn sync_pull(
    transport: &mut dyn SyncTransport,
    storage: &Storage,
    ctx: &SyncContext,
) -> Result<SyncReport, SyncError> {
    let cursor_key = pull_cursor_key(&ctx.tenant);
    let last = storage.get_sync_cursor(&cursor_key)?.unwrap_or(0);
    if transport.report_version() < last {
        return Err(SyncError::TransportRollback {
            reported: transport.report_version(),
            cursor: last,
        });
    }

    let mut delta = transport.delta_since(last);
    // We do not trust the transport's order: we sort it ourselves.
    // Key = (server_seq ASC, object bytes ASC as tie-break); `sort_by_cached_key`
    // serializes each object once instead of on every comparison. Total order is
    // identical to the previous `sort_by`, so the apply order is unchanged.
    delta.sort_by_cached_key(|(seq, obj)| (*seq, obj.to_bytes().unwrap_or_default()));

    let mut report = SyncReport::default();
    let mut cursor = last;
    for (seq, obj) in delta {
        if seq <= last {
            report.rejected.push(Rejected {
                server_seq: seq,
                vault_id: obj.vault_id().map(|v| v.to_vec()),
                reason: RejectReason::BelowCursor,
            });
            continue; // below-cursor does NOT move the cursor
        }
        process_object(storage, ctx, &obj, seq, &mut report)?;
        // the object at seq was processed (applied/skip/conflict/reject-verify) →
        // advance the cursor (monotonically forward).
        if seq > cursor {
            advance_cursor(storage, &cursor_key, &mut cursor, seq)?;
        }
    }
    // Counts only — never the objects' (encrypted) contents or keys.
    if report.conflicts.is_empty() && report.rejected.is_empty() {
        log::info!(
            "sync pull: applied={}, skipped_stale={}",
            report.applied,
            report.skipped_stale
        );
    } else {
        log::warn!(
            "sync pull: applied={}, skipped_stale={}, conflicts={}, rejected={}",
            report.applied,
            report.skipped_stale,
            report.conflicts.len(),
            report.rejected.len()
        );
    }
    Ok(report)
}

/// Apply an already-fetched, targeted set of pulled objects (e.g. ONE vault fetched
/// out-of-band via `?vault=<id>`) through the SAME verify-before-apply path as
/// [`sync_pull`], but WITHOUT touching the per-tenant pull cursor. Used by "Pull this
/// vault": the caller fetches just that vault's objects and applies them here, so the
/// global cursor does not advance and other vaults' not-yet-pulled objects are not
/// skipped. Vault records still materialize born-bound to `ctx.tenant`.
pub fn apply_pulled_objects(
    storage: &Storage,
    ctx: &SyncContext,
    mut objects: Vec<(u64, SyncObject)>,
) -> Result<SyncReport, SyncError> {
    // Same self-imposed total order as sync_pull (server_seq ASC, bytes tie-break) —
    // we do not trust the caller's order.
    objects.sort_by_cached_key(|(seq, obj)| (*seq, obj.to_bytes().unwrap_or_default()));
    let mut report = SyncReport::default();
    for (seq, obj) in objects {
        process_object(storage, ctx, &obj, seq, &mut report)?;
    }
    Ok(report)
}

/// Raises the cursor to `to` (forward only), persists it. A decrease → error.
fn advance_cursor(
    storage: &Storage,
    cursor_key: &str,
    cursor: &mut u64,
    to: u64,
) -> Result<(), SyncError> {
    if to < *cursor {
        return Err(SyncError::CursorRollback {
            current: *cursor,
            attempted: to,
        });
    }
    storage.set_sync_cursor(cursor_key, to)?;
    *cursor = to;
    Ok(())
}

/// Verify-before-apply of a single object. Order (D-VERIFY-FIRST): signature →
/// epoch-floor → authority → (conflict-check) → monotonic `put` (LWW). Any
/// violation becomes a typed report entry, NOT a panic. An object that fails
/// verify/floor/authority does NOT reach `put`.
fn process_object(
    storage: &Storage,
    ctx: &SyncContext,
    obj: &SyncObject,
    seq: u64,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    match obj {
        SyncObject::Vault(v) => process_vault(storage, ctx, v, seq, report),
        SyncObject::Item(i) => process_item(storage, ctx, i, seq, report),
        SyncObject::MembershipManifest(m) => process_manifest(storage, ctx, m, seq, report),
        SyncObject::MembershipGrant(g) => process_grant(storage, ctx, g, seq, report),
        SyncObject::Audit(a) => process_audit(storage, ctx, a, seq, report),
        SyncObject::Keyset(b) => process_keyset(storage, b, seq, report),
        SyncObject::AccountState(a) => process_account_state(storage, ctx, a, seq, report),
    }
}

/// Helper: add a reject entry.
fn reject(report: &mut SyncReport, seq: u64, vault_id: Option<&[u8]>, reason: RejectReason) {
    report.rejected.push(Rejected {
        server_seq: seq,
        vault_id: vault_id.map(|v| v.to_vec()),
        reason,
    });
}

/// LWW result of a monotonic put: Ok(true)=applied, Ok(false)=skip-stale.
fn put_lww<F>(put: F) -> Result<bool, SyncError>
where
    F: FnOnce() -> Result<(), unissh_storage::StorageError>,
{
    match put() {
        Ok(()) => Ok(true),
        Err(unissh_storage::StorageError::VersionRollback { .. }) => Ok(false),
        Err(e) => Err(SyncError::from(e)),
    }
}

/// Trusted authority anchor for a specific vault (A0): the pinned per-vault
/// genesis owner (TOFU at share-accept — a vault created by a teammate) OR the local
/// keyset (`ctx.genesis_owner`) for own vaults, where no anchor row exists.
/// The pinned anchor is read from storage, NOT from the untrusted object.
fn vault_anchor(
    storage: &Storage,
    vault_id: &[u8],
    ctx: &SyncContext,
) -> Result<Vec<u8>, SyncError> {
    match storage.get_vault_trust_anchor(vault_id)? {
        Some(a) => Ok(a.genesis_owner_pubkey),
        None => Ok(ctx.genesis_owner.clone()),
    }
}

fn process_vault(
    storage: &Storage,
    ctx: &SyncContext,
    v: &VaultRecord,
    seq: u64,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    // The trusted anchor of this vault (per-vault pin, otherwise the local keyset).
    let anchor = vault_anchor(storage, &v.vault_id, ctx)?;
    // (1) signature + author structure. Malformed/SignatureInvalid → reject immediately;
    // AuthorMismatch/NotAuthorized is decided by authority below (a member may ≠ owner).
    if let Some(f) = check_vault_record(v, &anchor) {
        match f {
            IntegrityFailure::Malformed => {
                reject(report, seq, Some(&v.vault_id), RejectReason::Malformed);
                return Ok(());
            }
            IntegrityFailure::SignatureInvalid => {
                reject(
                    report,
                    seq,
                    Some(&v.vault_id),
                    RejectReason::SignatureFailed,
                );
                return Ok(());
            }
            _ => {}
        }
    }
    // (2) epoch-floor.
    let floor = storage.get_vault_epoch_floor(&v.vault_id)?.unwrap_or(0);
    if v.key_epoch < floor {
        reject(
            report,
            seq,
            Some(&v.vault_id),
            RejectReason::EpochBelowFloor,
        );
        return Ok(());
    }
    // (3) authority (membership vs single-owner — vault decides itself).
    if verify_record_authority(storage, &v.vault_id, &v.author_pubkey, v.key_epoch, &anchor)
        .is_err()
    {
        reject(
            report,
            seq,
            Some(&v.vault_id),
            RejectReason::AuthorityFailed,
        );
        return Ok(());
    }
    // (4) equal-version conflict-check, then LWW merge.
    if let Some(local) = storage.get_vault(&v.vault_id)? {
        if local.version == v.version {
            if vault_content_eq(&local, v) {
                return Ok(()); // idempotent re-pull
            }
            report.conflicts.push(Conflict {
                vault_id: v.vault_id.clone(),
                item_id: Vec::new(),
                version: v.version,
            });
            return Ok(()); // do NOT overwrite
        }
    }
    // A vault pulled from `ctx.tenant`'s space is, by construction, bound to that
    // tenant. Stamp the local routing label so it materializes born-bound —
    // otherwise it lands unbound (the wire format omits sync_tenant, object.rs),
    // the legacy auto-bind rebinds + re-dirties it, and it re-pushes as a
    // server-side duplicate (mass-duplication incident). `sync_tenant` is not part
    // of `vault_content_eq`, so this does not disturb the equal-version idempotent
    // re-pull check above.
    let bound = VaultRecord {
        sync_tenant: ctx.tenant.clone(),
        ..v.clone()
    };
    if put_lww(|| storage.put_vault(&bound))? {
        report.applied += 1;
    } else {
        report.skipped_stale += 1;
    }
    Ok(())
}

fn process_item(
    storage: &Storage,
    ctx: &SyncContext,
    i: &ItemRecord,
    seq: u64,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    let anchor = vault_anchor(storage, &i.vault_id, ctx)?;
    match check_item_record(i, &anchor) {
        Some(IntegrityFailure::Malformed) => {
            reject(report, seq, Some(&i.vault_id), RejectReason::Malformed);
            return Ok(());
        }
        Some(IntegrityFailure::SignatureInvalid) => {
            reject(
                report,
                seq,
                Some(&i.vault_id),
                RejectReason::SignatureFailed,
            );
            return Ok(());
        }
        _ => {}
    }
    let floor = storage.get_vault_epoch_floor(&i.vault_id)?.unwrap_or(0);
    if i.key_epoch < floor {
        reject(
            report,
            seq,
            Some(&i.vault_id),
            RejectReason::EpochBelowFloor,
        );
        return Ok(());
    }
    if verify_record_authority(storage, &i.vault_id, &i.author_pubkey, i.key_epoch, &anchor)
        .is_err()
    {
        reject(
            report,
            seq,
            Some(&i.vault_id),
            RejectReason::AuthorityFailed,
        );
        return Ok(());
    }
    if let Some(local) = storage.get_item(&i.vault_id, &i.item_id)? {
        if local.version == i.version {
            if item_content_eq(&local, i) {
                return Ok(());
            }
            report.conflicts.push(Conflict {
                vault_id: i.vault_id.clone(),
                item_id: i.item_id.clone(),
                version: i.version,
            });
            return Ok(());
        }
    }
    if put_lww(|| storage.put_item(i))? {
        report.applied += 1;
    } else {
        report.skipped_stale += 1;
    }
    Ok(())
}

fn process_manifest(
    storage: &Storage,
    ctx: &SyncContext,
    m: &unissh_storage::MembershipManifest,
    seq: u64,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    // (0) epoch-floor reject — symmetric with process_vault/item/grant/keyset
    // (defense-in-depth, anti-rollback §1.1). A manifest below the trusted vault epoch
    // floor is an attempt to roll membership back to a stale epoch; we reject BEFORE
    // anti-equivocation/verify. verify_chain_to_epoch below also does not anchor on
    // a sub-floor epoch, but an explicit reject is shorter and consistent with the other branches.
    let floor = storage.get_vault_epoch_floor(&m.vault_id)?.unwrap_or(0);
    if m.key_epoch < floor {
        reject(
            report,
            seq,
            Some(&m.vault_id),
            RejectReason::EpochBelowFloor,
        );
        return Ok(());
    }
    // Anti-equivocation (P6 fix, merge/overwrite of trusted state):
    // a manifest carries NO version/monotonicity, and put_membership_manifest is
    // ON CONFLICT DO UPDATE. Without this check an equivocating manifest@epoch
    // (validly signed by the genesis owner / a former admin, but with a DIFFERENT member-set)
    // would silently overwrite the already-trusted manifest of the same epoch, mutating
    // past membership. Therefore: if a manifest@epoch already exists locally and
    // DIFFERS from the incoming one — that is equivocation; surface as a Conflict (as for
    // equal-version records), do NOT overwrite. An identical re-pull is idempotent.
    if let Some(local) = storage.get_membership_manifest(&m.vault_id, m.key_epoch)? {
        if manifest_content_eq(&local, m) {
            return Ok(()); // idempotent re-pull of the already-trusted manifest
        }
        report.conflicts.push(Conflict {
            vault_id: m.vault_id.clone(),
            item_id: b"__manifest__".to_vec(),
            version: m.key_epoch,
        });
        return Ok(()); // do NOT overwrite the trusted manifest@epoch
    }

    // No manifest@epoch yet: verify-before-apply. verify_chain_to_epoch
    // reads from storage, so we put it inside a check-transaction and on an authority
    // failure we roll back (a broken/forged manifest does not remain in storage).
    use unissh_vault::verify_chain_to_epoch;
    let epoch = m.key_epoch;
    let anchor = vault_anchor(storage, &m.vault_id, ctx)?;
    let res: Result<bool, SyncError> = storage.transaction(|| {
        storage.put_membership_manifest(m)?;
        match verify_chain_to_epoch(storage, &m.vault_id, epoch, &anchor) {
            Ok(_) => Ok(true),
            // intentional rollback: we return Err so the transaction rolls back,
            // but this is NOT a fatal sync error — we turn it into a reject outside.
            Err(_) => Err(SyncError::Vault(unissh_vault::VaultError::AuthorityInvalid)),
        }
    });
    match res {
        Ok(true) => {
            report.applied += 1;
            // Anti-rollback (A0): raise the vault epoch floor to the applied
            // manifest's epoch (as rotate_vk does locally). A member's device does not
            // rotate itself, so without this its floor stays 0 and an untrusted
            // server could replay below-epoch records from a revoked write-member.
            // Monotonically forward (raise only). We raise only after a successful
            // verify-chain, so a reordered manifest@N will not lock @1..N-1.
            if m.key_epoch > floor {
                storage.set_vault_epoch_floor(&m.vault_id, m.key_epoch)?;
            }
            Ok(())
        }
        Err(SyncError::Vault(unissh_vault::VaultError::AuthorityInvalid)) => {
            reject(
                report,
                seq,
                Some(&m.vault_id),
                RejectReason::AuthorityFailed,
            );
            Ok(())
        }
        Err(e) => Err(e),
        Ok(false) => Ok(()),
    }
}

/// Comparison of the signed content of manifest records (anti-equivocation):
/// two manifest@epoch are equal only if the member-payload, signature and
/// author match. A different payload at the same epoch = equivocation.
fn manifest_content_eq(
    a: &unissh_storage::MembershipManifest,
    b: &unissh_storage::MembershipManifest,
) -> bool {
    a.manifest_blob == b.manifest_blob
        && a.signature == b.signature
        && a.author_pubkey == b.author_pubkey
}

fn process_grant(
    storage: &Storage,
    ctx: &SyncContext,
    g: &unissh_storage::MembershipGrant,
    seq: u64,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    use unissh_vault::{verify_chain_to_epoch, verify_grant};
    let floor = storage.get_vault_epoch_floor(&g.vault_id)?.unwrap_or(0);
    if g.key_epoch < floor {
        reject(
            report,
            seq,
            Some(&g.vault_id),
            RejectReason::EpochBelowFloor,
        );
        return Ok(());
    }
    // The verified member-set of the grant's epoch (requires an already-applied manifest@epoch).
    let anchor = vault_anchor(storage, &g.vault_id, ctx)?;
    let members = match verify_chain_to_epoch(storage, &g.vault_id, g.key_epoch, &anchor) {
        Ok(v) => v,
        Err(_) => {
            reject(
                report,
                seq,
                Some(&g.vault_id),
                RejectReason::AuthorityFailed,
            );
            return Ok(());
        }
    };
    if verify_grant(g, &g.vault_id, &members).is_err() {
        reject(
            report,
            seq,
            Some(&g.vault_id),
            RejectReason::AuthorityFailed,
        );
        return Ok(());
    }
    storage.put_membership_grant(g)?;
    report.applied += 1;
    Ok(())
}

fn process_audit(
    storage: &Storage,
    ctx: &SyncContext,
    a: &crate::object::AuditObject,
    seq: u64,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    // Audit is append-only, instance-level (no vault-scoping in v1).
    //
    // P6 fix (audit authority gap): the engine previously checked ONLY
    // the self-signature over entry_blob, while `author_pubkey` is chosen by the sender —
    // i.e. any keypair could, from the untrusted transport, append a validly-
    // self-signed audit entry (instance-level audit poisoning). We close this
    // by requiring that the author of an audit entry MUST be the trusted instance anchor
    // (`ctx.genesis_owner` = the keyset owner's Ed25519 pubkey). A foreign author →
    // AuthorityFailed, not applied.
    //
    // SEAM (Milestone 2, crate `audit`): when audit gains vault-scoped semantics,
    // the author must authorize through the vault's membership@epoch (admin view), not
    // only through the instance owner; the exact signature domain/AAD is also defined by `audit`.
    use unissh_crypto::{verify_version, AssociatedData, Ed25519VerifyingKey, VersionedObject};
    let author = match Ed25519VerifyingKey::from_bytes(&a.author_pubkey) {
        Ok(k) => k,
        Err(_) => {
            reject(report, seq, Some(&a.vault_id), RejectReason::Malformed);
            return Ok(());
        }
    };
    // Author authority: only the trusted instance owner may write audit in v1.
    if a.author_pubkey != ctx.genesis_owner {
        reject(
            report,
            seq,
            Some(&a.vault_id),
            RejectReason::AuthorityFailed,
        );
        return Ok(());
    }
    // Audit AAD: vault_id + b"__audit__" + version(0). The exact signature domain
    // of an audit entry is defined by the `audit` crate (Milestone 2) — this is a seam; if the format differs,
    // verify fails → reject, not a crash.
    let aad = AssociatedData::new(a.vault_id.clone(), b"__audit__".to_vec(), 0);
    let vo = VersionedObject::from_content(aad, &a.entry_blob);
    if verify_version(&author, &vo, &a.signature).is_err() {
        reject(
            report,
            seq,
            Some(&a.vault_id),
            RejectReason::SignatureFailed,
        );
        return Ok(());
    }
    storage.append_audit(&a.entry_blob, &a.signature, &a.author_pubkey)?;
    report.applied += 1;
    Ok(())
}

fn process_keyset(
    storage: &Storage,
    blob: &[u8],
    seq: u64,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    use unissh_keychain::{keyset_gen_floor, EncryptedKeyset};
    // IMPORTANT (P6 fix, apply-before-verify): `record.generation` is the bytes of the
    // keyset blob's header [2..6], which are NOT authenticated without unlocking
    // (generation is part of the wrapped_keyset associated data and is verified only
    // at `unlock_account`). The untrusted transport can take a genuine blob and
    // swap these bytes to u32::MAX. If we moved the floor from here, an attacker
    // poisons `keyset_gen_floor` and permanently locks the legitimate keyset via
    // `unlock_account_checked` (GenerationRollback) — DoS/account-lockout.
    //
    // Therefore the engine does NOT raise the floor here. The floor is raised ONLY after real
    // keyset authentication with credentials (`unlock_account_checked` / password change) —
    // outside the sync engine, on the trusted unlock path.
    let record = match EncryptedKeyset::from_bytes(blob) {
        Ok(r) => r,
        Err(_) => {
            reject(report, seq, None, RejectReason::Malformed);
            return Ok(());
        }
    };
    // Anti-rollback gate (safe, monotonically-down): a keyset feed with a generation
    // BELOW the trusted floor is discarded as a rollback. Only credentials move the floor.
    let floor = keyset_gen_floor(storage)?.unwrap_or(0);
    if (record.generation as u64) < floor {
        reject(report, seq, None, RejectReason::GenerationBelowFloor);
        return Ok(());
    }
    // The blob is confidential (AEAD) and carried as-is, but the engine does not
    // trustedly "apply" anything from an unauthenticated header — applied does NOT grow.
    Ok(())
}

/// Applies per-account state (A3): verify-before-apply + LWW by `version`.
/// The author MUST == the local account keyset (`ctx.genesis_owner`) — the state is
/// self-signed by the account, and the account's devices share the keyset; a foreign one → AuthorityFailed.
/// The signature is verified (`verify_account_state`), then LWW: a `version` strictly higher
/// than the stored one → apply. `payload` stays opaque (HPKE-self-sealed) —
/// the ffi decrypts it on read, not the engine.
fn process_account_state(
    storage: &Storage,
    ctx: &SyncContext,
    a: &crate::object::AccountStateObject,
    seq: u64,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    // The author must be the local account (a keyset shared between devices).
    if a.author_pubkey != ctx.genesis_owner {
        reject(report, seq, None, RejectReason::AuthorityFailed);
        return Ok(());
    }
    if unissh_vault::verify_account_state(&a.author_pubkey, a.version, &a.payload, &a.signature)
        .is_err()
    {
        reject(report, seq, None, RejectReason::SignatureFailed);
        return Ok(());
    }
    // DoS protection (sec-review A3 #8): storage.checked_version rejects version >
    // i64::MAX. We catch it here as a per-object reject so an untrusted server cannot, with a single
    // object carrying an inflated version, drop the ENTIRE pull (a `?` error would otherwise abort it).
    if a.version > i64::MAX as u64 {
        reject(report, seq, None, RejectReason::Malformed);
        return Ok(());
    }
    // LWW by the signed version (monotonically forward). S2: the version is monotonic
    // (update_account_state = cur+1, not wall-clock — an "eternal ceiling" from a
    // future-dated version is impossible), but TWO of the account's devices could
    // concurrently take the same cur+1 → equal version with different content. On an
    // equal version — a deterministic tiebreak by signature (max wins):
    // all devices CONVERGE to one state instead of diverging by
    // arrival-order (documented LWW limit #2).
    let existing = storage.get_account_state(&a.author_pubkey)?;
    let cur = existing.as_ref().map(|r| r.version).unwrap_or(0);
    if a.version < cur {
        report.skipped_stale += 1;
        return Ok(());
    }
    if a.version == cur {
        if let Some(r) = existing.as_ref() {
            // Equal version: apply ONLY if the incoming signature is strictly
            // greater than the stored one; otherwise keep the current one (convergence).
            if a.signature.as_slice() <= r.signature.as_slice() {
                report.skipped_stale += 1;
                return Ok(());
            }
        }
    }
    storage.set_account_state(&a.author_pubkey, a.version, &a.payload, &a.signature)?;
    report.applied += 1;
    Ok(())
}

/// Comparison of the signed content of vault records (for conflict detection).
fn vault_content_eq(a: &VaultRecord, b: &VaultRecord) -> bool {
    a.wrapped_vk == b.wrapped_vk
        && a.name_blob == b.name_blob
        && a.signature == b.signature
        && a.author_pubkey == b.author_pubkey
        && a.tombstone == b.tombstone
}

/// Comparison of the signed content of item records.
fn item_content_eq(a: &ItemRecord, b: &ItemRecord) -> bool {
    a.content_blob == b.content_blob
        && a.wrapped_item_key == b.wrapped_item_key
        && a.signature == b.signature
        && a.author_pubkey == b.author_pubkey
        && a.tombstone == b.tombstone
}

/// Collects the local syncable objects and pushes them to the transport (server-tz §3.3).
///
/// **1:1 binding of a cloud vault to a server:** only vaults whose `sync_tenant`
/// matches `target_tenant` (the synced server's tenant_id) are pushed. This excludes (a)
/// local vaults (their `sync_tenant` is empty → will not match any non-empty
/// tenant), and (b) cloud vaults bound to a DIFFERENT server — otherwise, with
/// several linked servers, switching the active one and syncing would send the
/// vault's ciphertext to the wrong server. `target_tenant` must be non-empty (the
/// ffi passes it from the transport's tenant); an empty one → nothing is pushed (safeguard).
///
/// **v1 model (D-PUSH, honestly):** for the selected vaults it collects the vault record,
/// items with tombstones (`list_items_including_tombstones`), membership manifests
/// and grants by epoch, and audit newer than `PUSH_CURSOR` (`list_audit`). The transport
/// assigns them server_seq (the server dedups by version-LWW). `PUSH_CURSOR`
/// advances to the last handed-off `audit.seq` (the only one with a stable
/// local monotonic seq). Per-object dirty-tracking is ⏳ LATER.
pub fn sync_push(
    transport: &mut dyn SyncTransport,
    storage: &Storage,
    target_tenant: &[u8],
) -> Result<PushReport, SyncError> {
    let mut objects: Vec<SyncObject> = Vec::new();

    // Only DIRTY objects of vaults bound to target_tenant (the 1:1 binding is already in
    // the query: `sync_tenant = target_tenant`). Local/foreign vaults do not get in.
    // An empty target_tenant will not match anything → no-op (safeguard).
    //
    // DEPENDENCY ORDER (critical): the receiver verifies each object's authority against
    // the membership manifest chain, and a rejected object ADVANCES THE CURSOR (a
    // dependency arriving later is never retried). So a dependency MUST be pushed before
    // its dependents, in the same batch — the server assigns server_seq in push order and
    // the pull processes in that order. Manifests first (an item/record authored at epoch
    // N needs the epoch-N manifest to verify), then the vault record, then grants (each
    // references its epoch's manifest), then items. Previously items preceded manifests, so
    // a cross-account member's items were rejected on first pull and silently dropped.
    for m in storage.list_dirty_bound_manifests(target_tenant)? {
        objects.push(SyncObject::MembershipManifest(m));
    }
    for v in storage.list_dirty_bound_vaults(target_tenant)? {
        objects.push(SyncObject::Vault(v));
    }
    for g in storage.list_dirty_bound_grants(target_tenant)? {
        objects.push(SyncObject::MembershipGrant(g));
    }
    for it in storage.list_dirty_bound_items(target_tenant)? {
        objects.push(SyncObject::Item(it));
    }

    // A3: account-state is broadcast to EVERY server, so it is not covered by
    // the dirty flag (which is single-server-bound) — we track it per-tenant by the version cursor.
    let acct_key = acct_push_cursor_key(target_tenant);
    let last_acct = storage.get_sync_cursor(&acct_key)?.unwrap_or(0);
    let mut max_acct = last_acct;
    for st in storage.list_account_states()? {
        if st.version > last_acct {
            objects.push(SyncObject::AccountState(
                crate::object::AccountStateObject {
                    author_pubkey: st.author_pubkey,
                    version: st.version,
                    payload: st.payload,
                    signature: st.signature,
                },
            ));
            if st.version > max_acct {
                max_acct = st.version;
            }
        }
    }

    // Audit newer than the push cursor (per-tenant: audit goes to each server independently).
    let push_key = push_cursor_key(target_tenant);
    let push_cursor = storage.get_sync_cursor(&push_key)?.unwrap_or(0);
    let audit = storage.list_audit(push_cursor)?;
    let mut max_audit_seq = push_cursor;
    for entry in &audit {
        // The audit's vault_id is open metadata; the storage AuditEntry carries no
        // vault_id field → in v1 we send an empty vault_id (audit is instance-level).
        // When the audit crate adds vault-scoping, extend this.
        objects.push(SyncObject::Audit(crate::object::AuditObject {
            vault_id: Vec::new(),
            entry_blob: entry.entry_blob.clone(),
            signature: entry.signature.clone(),
            author_pubkey: entry.author_pubkey.clone(),
        }));
        if entry.seq > max_audit_seq {
            max_audit_seq = entry.seq;
        }
    }

    let pushed = objects.len() as u64;
    // Nothing changed → no round-trip (this is exactly the point of dirty-tracking: a run
    // with no edits no longer re-uploads the whole vault).
    if pushed == 0 {
        return Ok(PushReport { pushed: 0 });
    }
    transport.push_objects(&objects)?;

    // Success → clear dirty on the pushed items and advance the cursors (account/audit) forward.
    storage.clear_dirty_for_tenant(target_tenant)?;
    if max_acct > last_acct {
        storage.set_sync_cursor(&acct_key, max_acct)?;
    }
    if max_audit_seq > push_cursor {
        storage.set_sync_cursor(&push_key, max_audit_seq)?;
    }

    // Count only — the pushed objects are encrypted blobs; never log their content.
    log::info!("sync push: pushed {pushed} object(s)");
    Ok(PushReport { pushed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{AuditObject, SyncObject};
    use crate::transport::{InMemoryTransport, SyncTransport};
    use unissh_storage::Storage;

    fn st() -> Storage {
        Storage::open_in_memory(&[7u8; 32]).unwrap()
    }
    fn audit(n: u8) -> SyncObject {
        SyncObject::Audit(AuditObject {
            vault_id: vec![n],
            entry_blob: vec![n],
            signature: vec![1u8; 67],
            author_pubkey: vec![2u8; 32],
        })
    }
    fn ctx() -> SyncContext {
        SyncContext {
            genesis_owner: vec![2u8; 32],
            tenant: b"test-tenant".to_vec(),
        }
    }

    #[test]
    fn transport_below_cursor_is_rejected() {
        let s = st();
        let mut t = InMemoryTransport::new();
        t.push_objects(&[audit(1), audit(2)]).unwrap();
        // the first pull advances the cursor to 2
        let r = sync_pull(&mut t, &s, &ctx()).unwrap();
        assert_eq!(
            s.get_sync_cursor(&pull_cursor_key(b"test-tenant")).unwrap(),
            Some(2)
        );
        let _ = r;
        // the server lies: it lowers report_version below the cursor → TransportRollback
        t.force_report_version(0);
        let err = sync_pull(&mut t, &s, &ctx()).unwrap_err();
        assert!(matches!(err, SyncError::TransportRollback { .. }));
        // the cursor is NOT lowered
        assert_eq!(
            s.get_sync_cursor(&pull_cursor_key(b"test-tenant")).unwrap(),
            Some(2)
        );
    }

    #[test]
    fn two_tenants_have_independent_pull_cursors() {
        let s = st();
        // tenant A: pull of two objects → cursor A = 2.
        let mut ta = InMemoryTransport::new();
        ta.push_objects(&[audit(1), audit(2)]).unwrap();
        let ctx_a = SyncContext {
            genesis_owner: vec![2u8; 32],
            tenant: b"tenant-A".to_vec(),
        };
        sync_pull(&mut ta, &s, &ctx_a).unwrap();
        assert_eq!(
            s.get_sync_cursor(&pull_cursor_key(b"tenant-A")).unwrap(),
            Some(2)
        );

        // tenant B on a FRESH server (independent seq space, report_version=1):
        // it must NOT fall into TransportRollback against cursor A and pulls up to its own.
        let mut tb = InMemoryTransport::new();
        tb.push_objects(&[audit(1)]).unwrap();
        let ctx_b = SyncContext {
            genesis_owner: vec![2u8; 32],
            tenant: b"tenant-B".to_vec(),
        };
        sync_pull(&mut tb, &s, &ctx_b).expect("tenant B must not see tenant A's cursor");
        assert_eq!(
            s.get_sync_cursor(&pull_cursor_key(b"tenant-B")).unwrap(),
            Some(1)
        );
        // cursor A is untouched by B's pull.
        assert_eq!(
            s.get_sync_cursor(&pull_cursor_key(b"tenant-A")).unwrap(),
            Some(2)
        );
    }

    #[test]
    fn push_cursor_is_per_tenant() {
        // One audit entry (seq 1). A push to tenant A moves cursor A; cursor B
        // stays empty → B will still hand off the same audit entry.
        let s = st();
        s.append_audit(&[9u8; 1], &[1u8; 67], &[2u8; 32]).unwrap();

        let mut ta = InMemoryTransport::new();
        sync_push(&mut ta, &s, b"tenant-A").unwrap();
        assert_eq!(
            s.get_sync_cursor(&push_cursor_key(b"tenant-A")).unwrap(),
            Some(1)
        );
        // the push cursor for tenant B is untouched.
        assert_eq!(
            s.get_sync_cursor(&push_cursor_key(b"tenant-B")).unwrap(),
            None
        );
    }

    #[test]
    fn objects_at_or_below_cursor_are_rejected_not_applied() {
        let s = st();
        let mut t = InMemoryTransport::new();
        t.push_objects(&[audit(1)]).unwrap();
        sync_pull(&mut t, &s, &ctx()).unwrap(); // cursor=1
                                                // the mock hands off everything with seq=1 (== cursor) even at report_version=1
        t.force_seq_floor(1);
        let r = sync_pull(&mut t, &s, &ctx()).unwrap();
        assert!(r
            .rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::BelowCursor)));
    }
}
