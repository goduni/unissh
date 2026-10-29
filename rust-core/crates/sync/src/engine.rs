//! Sync engine: [`sync_pull`] / [`sync_push`] + report types.
//!
//! The transport is untrusted (see crate-doc). Delta processing order is
//! strict `server_seq` ASC; the cursor advances ONLY monotonically forward and ONLY
//! after the corresponding seq is processed. Every object goes through
//! verify-before-apply (Task 7); violations are report entries, not a panic.

use std::collections::{HashMap, VecDeque};

use unissh_storage::{ItemRecord, ItemVersion, Storage, VaultRecord};
use unissh_vault::{
    check_item_record, check_vault_record, verify_record_authority, IntegrityFailure, VaultError,
};

use crate::error::SyncError;
use crate::object::{put_bytes, Reader, SyncObject};
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

/// Meta-key prefix for the items a tenant's server refused as too large (see
/// [`sync_push`]). `.v1` is the version of the value's layout ([`save_refused`]):
/// a different layout takes a new suffix, and the old slot is then just ignored
/// (the items are offered to the server once more).
const PUSH_REFUSED_PREFIX: &str = "sync:pushrefused.v1";
fn push_refused_key(tenant: &[u8]) -> String {
    format!("{PUSH_REFUSED_PREFIX}:{}", hex_lower(tenant))
}

/// Meta-key prefix for the items a tenant's server refused as not permitted
/// (see [`sync_push_as`]). Versioned like [`PUSH_REFUSED_PREFIX`].
const PUSH_FORBIDDEN_PREFIX: &str = "sync:pushforbidden.v1";
fn push_forbidden_key(tenant: &[u8]) -> String {
    format!("{PUSH_FORBIDDEN_PREFIX}:{}", hex_lower(tenant))
}

/// How many objects one push request carries at most. The server default
/// (`limits.max_objects_per_push`) is 1000; half of it leaves room for an
/// operator who lowered it, and a request the server still refuses is halved.
const PUSH_BATCH_MAX_OBJECTS: usize = 500;

/// How many encoded object bytes one push request carries at most. Objects are
/// sent base64-encoded in JSON (4/3 the size), so 1 MiB of objects is a request
/// of about 1.4 MiB. That is under the 2 MiB a server up to 0.5 really accepts:
/// its configured 16 MiB `limits.max_body_bytes` was never reached, because the
/// HTTP framework's own 2 MiB default applied first. An object that is larger on
/// its own travels alone.
const PUSH_BATCH_MAX_BYTES: usize = 1024 * 1024;

/// The size of the largest object a client legitimately pushes — the bound a
/// server's default `limits.max_object_bytes` is set to, so that every client
/// object is accepted.
///
/// That object is a session recording: its asciicast body is capped at 8 MiB by
/// the client (`RECORDING_MAX_BYTES` in `unissh-ffi`) and is stored inside the
/// item as a JSON string, where escaping at most doubles it (a body of nothing
/// but `"` and `\`). The remaining 1 MiB is headroom for the recording's
/// metadata and for what the vault and the sync framing add (AEAD tag and
/// nonce, the wrapped item key, the signature, the ids) — a few hundred bytes.
///
/// Two crates, one number each: `unissh-ffi` owns the recording cap, and this
/// crate owns the bound derived from it — the server reads it from here, and
/// does not depend on the FFI facade. The `8 MiB` below therefore restates the
/// cap; a compile-time assertion next to `RECORDING_MAX_BYTES` fails the build
/// if the cap outgrows this bound.
pub const LARGEST_CLIENT_OBJECT_BYTES: usize = 2 * 8 * 1024 * 1024 + 1024 * 1024;

/// Increments a report counter. Saturating: a count of objects can only reach
/// `u64::MAX` in theory, and clamping is the right answer for a metric.
const fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// Lowercase hex of the opaque tenant bytes for the `sync_state` key (no external
/// dependencies; the input may be arbitrary bytes).
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
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

/// An item the server refuses as too large, so it stays on this device only.
/// Open metadata, no content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooLarge {
    /// The item's vault_id.
    pub vault_id: Vec<u8>,
    /// The item's id.
    pub item_id: Vec<u8>,
    /// The item's type (open metadata), so it can be named by kind.
    pub item_type: u32,
    /// The refused version of the item.
    pub version: u64,
    /// Size of the encoded sync object, in bytes.
    pub bytes: u64,
}

/// Why a push leaves a dirty item out (see [`Unpushable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpushableReason {
    /// The item's author may not write it: by the vault's verified membership
    /// as this device holds it, the author has no write role at the item's
    /// epoch (a Viewer's edit, or one by a member since removed). Every other
    /// member's verify-before-apply would reject it, and so would this
    /// device's own read path.
    NotAuthorized,
    /// The server refused it as not permitted, on its own (HTTP 403).
    ServerRefused,
}

/// A dirty item no push can deliver, so it stays on this device only, left
/// out of every push until it changes (see [`sync_push_as`]). Open metadata,
/// no content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpushable {
    /// The item's vault_id.
    pub vault_id: Vec<u8>,
    /// The item's id.
    pub item_id: Vec<u8>,
    /// The item's type (open metadata), so it can be named by kind.
    pub item_type: u32,
    /// The left-out version of the item.
    pub version: u64,
    /// The author of that version.
    pub author_pubkey: Vec<u8>,
    /// Why it is left out.
    pub reason: UnpushableReason,
}

impl Unpushable {
    fn new(head: &ItemVersion, reason: UnpushableReason) -> Self {
        Self {
            vault_id: head.vault_id.clone(),
            item_id: head.item_id.clone(),
            item_type: head.item_type,
            version: head.version,
            author_pubkey: head.author_pubkey.clone(),
            reason,
        }
    }

    /// Whether this names `head`'s current version.
    fn is(&self, head: &ItemVersion) -> bool {
        self.vault_id == head.vault_id
            && self.item_id == head.item_id
            && self.version == head.version
    }
}

/// Push report.
#[derive(Debug, Clone, Default)]
pub struct PushReport {
    /// How many objects the transport accepted.
    pub pushed: u64,
    /// Items the server refused as too large — in this push, or in an earlier
    /// one and unchanged since (those are not sent again, see [`sync_push`]).
    /// They are NOT on the server; everything else was pushed.
    pub too_large: Vec<TooLarge>,
    /// Items no push can deliver (see [`Unpushable`]): their author may not
    /// write them, or the server refused them as not permitted. They are NOT
    /// on the server; everything else was pushed.
    pub unpushable: Vec<Unpushable>,
}

/// Pulls the delta from the untrusted transport and applies verify-before-apply.
///
/// 1. `last = get_sync_cursor(PULL_CURSOR).unwrap_or(0)`.
/// 2. anti-rollback: `transport.report_version() < last` → [`SyncError::TransportRollback`].
/// 3. the delta is taken page by page ([`SyncTransport::delta_since`] from the
///    cursor, until a page is empty or moves nothing); each page is sorted by
///    `server_seq` ASC (tie-break by the object's bytes).
/// 4. for each object in seq order: at or below the cursor the page was asked
///    from → REJECTED; otherwise verify (Task 7) → apply/skip/conflict/reject;
///    the cursor is raised to seq after processing (see D-SEQ-ORDER).
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

    let mut report = SyncReport::default();
    let mut cursor = last;
    // A transport may hand the delta over in pages (the server cuts them by
    // count and by bytes), so it is asked again from wherever the cursor got to,
    // and each page is verified, applied and dropped before the next one is
    // fetched — a first sync of a large vault is never held in memory whole.
    // The loop ends on an empty page, and on one that moved nothing: asking
    // again from the same cursor could only return the same objects.
    loop {
        let floor = cursor;
        let mut delta = transport.delta_since(floor);
        if delta.is_empty() {
            break;
        }
        // We do not trust the transport's order: we sort it ourselves.
        // Key = (server_seq ASC, object bytes ASC as tie-break); `sort_by_cached_key`
        // serializes each object once instead of on every comparison. Total order is
        // identical to the previous `sort_by`, so the apply order is unchanged.
        delta.sort_by_cached_key(|(seq, obj)| (*seq, obj.to_bytes().unwrap_or_default()));

        for (seq, obj) in delta {
            if seq <= floor {
                report.rejected.push(Rejected {
                    server_seq: seq,
                    vault_id: obj.vault_id().map(<[u8]>::to_vec),
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
        if cursor == floor {
            break;
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
        vault_id: vault_id.map(<[u8]>::to_vec),
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
    anchor_of(storage, vault_id, &ctx.genesis_owner)
}

/// [`vault_anchor`] with the local keyset's pubkey `own` in place of the
/// context.
fn anchor_of(storage: &Storage, vault_id: &[u8], own: &[u8]) -> Result<Vec<u8>, SyncError> {
    match storage.get_vault_trust_anchor(vault_id)? {
        Some(a) => Ok(a.genesis_owner_pubkey),
        None => Ok(own.to_vec()),
    }
}

/// Whether a dirty item's author may write it, by the same check the receiving
/// side's verify-before-apply makes ([`process_item`]): the push leaves out
/// what every other member would reject. Answers are kept per (vault, author,
/// epoch) — one membership-chain verification each, however many items share
/// them. Without the account's own pubkey (no anchor known) every item passes.
struct Authority<'a> {
    storage: &'a Storage,
    own: Option<&'a [u8]>,
    seen: HashMap<(Vec<u8>, Vec<u8>, u64), bool>,
}

impl<'a> Authority<'a> {
    fn new(storage: &'a Storage, own: Option<&'a [u8]>) -> Self {
        Self {
            storage,
            own,
            seen: HashMap::new(),
        }
    }

    fn may_write(&mut self, head: &ItemVersion) -> Result<bool, SyncError> {
        let Some(own) = self.own else {
            return Ok(true);
        };
        let key = (
            head.vault_id.clone(),
            head.author_pubkey.clone(),
            head.key_epoch,
        );
        if let Some(known) = self.seen.get(&key) {
            return Ok(*known);
        }
        let anchor = anchor_of(self.storage, &head.vault_id, own)?;
        let outcome = verify_record_authority(
            self.storage,
            &head.vault_id,
            &head.author_pubkey,
            head.key_epoch,
            &anchor,
        );
        // Not being able to read the database says nothing about the item.
        if let Err(e @ VaultError::Storage(_)) = outcome {
            return Err(e.into());
        }
        let allowed = outcome.is_ok();
        self.seen.insert(key, allowed);
        Ok(allowed)
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
            IntegrityFailure::AuthorMismatch | IntegrityFailure::NotAuthorized => {}
            // `IntegrityFailure` is `#[non_exhaustive]` in another crate: a future variant
            // falls through to the authority check below, as before.
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
        // Heal the routing label BEFORE any of the version arms below, because every
        // one of them can return without writing — and the label is not content, so
        // none of them would ever carry it.
        //
        // A vault that arrived in THIS tenant's delta and passed authority (3) is,
        // by construction, bound to this tenant; if the local copy has no label, it
        // predates born-bound (or a server was removed and cleared it). Such a vault
        // is *content-equal* to the server's — `sync_tenant` is deliberately outside
        // `vault_content_eq` to keep re-pull idempotent — so the equal-version arm
        // returns early and the stamp below is unreachable for exactly the vaults
        // that need it. The vault then reads "no server" forever and the one lever
        // the user has, "Pull from server", is the one that cannot work.
        if local.sync_tenant.is_empty() && !ctx.tenant.is_empty() {
            storage.adopt_pulled_binding(&v.vault_id, &ctx.tenant)?;
        }
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
        bump(&mut report.applied);
    } else {
        bump(&mut report.skipped_stale);
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
        bump(&mut report.applied);
    } else {
        bump(&mut report.skipped_stale);
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
    use unissh_vault::verify_chain_to_epoch;
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
    let epoch = m.key_epoch;
    let anchor = vault_anchor(storage, &m.vault_id, ctx)?;
    let res: Result<bool, SyncError> = storage.transaction(|| {
        storage.put_membership_manifest(m)?;
        match verify_chain_to_epoch(storage, &m.vault_id, epoch, &anchor) {
            Ok(_) => Ok(true),
            // intentional rollback: we return Err so the transaction rolls back,
            // but this is NOT a fatal sync error — we turn it into a reject outside.
            Err(_) => Err(SyncError::Vault(VaultError::AuthorityInvalid)),
        }
    });
    match res {
        Ok(true) => {
            bump(&mut report.applied);
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
        Err(SyncError::Vault(VaultError::AuthorityInvalid)) => {
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
    let Ok(members) = verify_chain_to_epoch(storage, &g.vault_id, g.key_epoch, &anchor) else {
        reject(
            report,
            seq,
            Some(&g.vault_id),
            RejectReason::AuthorityFailed,
        );
        return Ok(());
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
    bump(&mut report.applied);
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
    let Ok(author) = Ed25519VerifyingKey::from_bytes(&a.author_pubkey) else {
        reject(report, seq, Some(&a.vault_id), RejectReason::Malformed);
        return Ok(());
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
    bump(&mut report.applied);
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
    let Ok(record) = EncryptedKeyset::from_bytes(blob) else {
        reject(report, seq, None, RejectReason::Malformed);
        return Ok(());
    };
    // Anti-rollback gate (safe, monotonically-down): a keyset feed with a generation
    // BELOW the trusted floor is discarded as a rollback. Only credentials move the floor.
    let floor = keyset_gen_floor(storage)?.unwrap_or(0);
    if u64::from(record.generation) < floor {
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
        bump(&mut report.skipped_stale);
        return Ok(());
    }
    if a.version == cur {
        if let Some(r) = existing.as_ref() {
            // Equal version: apply ONLY if the incoming signature is strictly
            // greater than the stored one; otherwise keep the current one (convergence).
            if a.signature.as_slice() <= r.signature.as_slice() {
                bump(&mut report.skipped_stale);
                return Ok(());
            }
        }
    }
    storage.set_account_state(&a.author_pubkey, a.version, &a.payload, &a.signature)?;
    bump(&mut report.applied);
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
/// **v1 model (D-PUSH, honestly):** for the selected vaults it collects the dirty
/// vault records, items (tombstones included), membership manifests and grants,
/// the account states and the audit entries newer than their per-tenant cursors.
/// The transport assigns them server_seq (the server dedups by version-LWW).
///
/// **Requests:** the objects go out in dependency order, cut into requests of at
/// most `PUSH_BATCH_MAX_OBJECTS` objects and `PUSH_BATCH_MAX_BYTES` bytes —
/// a whole vault is dirty at once after a bind or a local-to-cloud move, and one
/// request for all of it would exceed the server's limits. Each accepted request
/// is settled at once (dirty flags cleared, cursors advanced), so a failure
/// later in the push returns the error without re-sending what was delivered.
/// Items — the only objects that can be large — are listed by id and loaded
/// request by request, so a vault full of recordings is never held in memory
/// whole.
///
/// **Too large for the server** ([`SyncError::PayloadTooLarge`] from the
/// transport): the request is halved until the object that does not fit is
/// alone. If that is an item, it is left out, the rest of the push continues and
/// the item is returned in [`PushReport::too_large`] — by this push and by every
/// later one, without being sent again, until the item changes or
/// [`forget_push_refusals`] is called. Any other object too large for the server
/// fails the push.
///
/// **Not permitted by the server** ([`SyncError::Forbidden`] from the
/// transport): the server refuses a whole request for one object its write
/// policy refuses, and does not say which. The request is halved the same way
/// until the refused object is alone; an item is then left out, reported in
/// [`PushReport::unpushable`] and remembered like a too-large one. Any other
/// object the server refuses fails the push. Without this, one Viewer's edit
/// made before the core refused them failed every push of the device (#166).
///
/// This push does not check authorship locally: [`sync_push_as`] does, and
/// is what a device that knows its account's key uses.
pub fn sync_push(
    transport: &mut dyn SyncTransport,
    storage: &Storage,
    target_tenant: &[u8],
) -> Result<PushReport, SyncError> {
    run_push(transport, storage, target_tenant, None, true)
}

/// [`sync_push`] to `ctx.tenant` that first leaves out the dirty items whose
/// author may not write them ([`UnpushableReason::NotAuthorized`]), by the
/// check the receiving side makes: the vault's pinned anchor, or
/// `ctx.genesis_owner` for a vault without one, as in [`sync_pull`]. They are
/// reported in [`PushReport::unpushable`] on every push until they change or
/// are discarded ([`discard_unpushable`]); nothing is sent for them, so the
/// server never sees a request it must refuse for them.
pub fn sync_push_as(
    transport: &mut dyn SyncTransport,
    storage: &Storage,
    ctx: &SyncContext,
) -> Result<PushReport, SyncError> {
    run_push(
        transport,
        storage,
        &ctx.tenant,
        Some(&ctx.genesis_owner),
        true,
    )
}

/// [`sync_push_vault_data`] with the authorship check of [`sync_push_as`].
pub fn sync_push_vault_data_as(
    transport: &mut dyn SyncTransport,
    storage: &Storage,
    ctx: &SyncContext,
) -> Result<PushReport, SyncError> {
    run_push(
        transport,
        storage,
        &ctx.tenant,
        Some(&ctx.genesis_owner),
        false,
    )
}

/// The dirty items of every vault bound to a server that no push delivers
/// ([`Unpushable`]): those whose author may not write them, checked as
/// [`sync_push_as`] checks them (`own` is the account's pubkey, the anchor of
/// a vault without a pinned one), and those the vault's server refused and
/// that are unchanged since. Reads only, and makes no request: what a caller
/// compares a later push's [`PushReport::unpushable`] against, to tell an edit
/// it is about to make from the ones already left out.
pub fn unpushable_items(storage: &Storage, own: &[u8]) -> Result<Vec<Unpushable>, SyncError> {
    let mut tenants: Vec<Vec<u8>> = Vec::new();
    for vault in storage.list_vaults()? {
        if !vault.sync_tenant.is_empty() && !tenants.contains(&vault.sync_tenant) {
            tenants.push(vault.sync_tenant);
        }
    }
    let mut authority = Authority::new(storage, Some(own));
    let mut out = Vec::new();
    for tenant in tenants {
        let refused = load_forbidden(storage, &push_forbidden_key(&tenant))?;
        for head in storage.list_dirty_bound_item_versions(&tenant)? {
            if let Some(r) = refused.iter().find(|r| r.is(&head)) {
                out.push(r.clone());
            } else if !authority.may_write(&head)? {
                out.push(Unpushable::new(&head, UnpushableReason::NotAuthorized));
            }
        }
    }
    Ok(out)
}

/// What [`discard_unpushable`] did.
#[derive(Debug, Clone, Default)]
pub struct Discarded {
    /// The account's own edits that were dropped: the server's copy of each
    /// took its place, or, for one the server holds nothing of, the item is
    /// gone (also in [`Self::removed`]).
    pub dropped: Vec<Unpushable>,
    /// The dropped edits whose item the server holds nothing of: removed.
    pub removed: Vec<Unpushable>,
    /// Other members' items no longer sent (their dirty flag cleared; the row
    /// is kept as it is).
    pub released: Vec<Unpushable>,
    /// What applying the server's copy of the vault did.
    pub pulled: SyncReport,
}

/// **Replaces the account's (`ctx.genesis_owner`) edits in `vault_id` that no
/// push delivers with the server's copy** (`server_copy`: the vault's objects
/// as the server has them, raw, every page, fetched by the caller before this
/// is called — `GET /v1/sync/delta?vault=<id>`).
///
/// A user-confirmed exception to rollback protection, for exactly the edits it
/// drops: it deletes a row past the version monotonicity that would otherwise
/// keep the local edit above the server's copy forever
/// ([`Storage::discard_unpushed_item`]), so that the server's (lower) version
/// can be stored again. Nothing else of the vault moves back.
///
/// - `server_copy` is read strictly: an object that does not parse fails this
///   ([`SyncError::ServerCopyUnreadable`]) before anything changes.
/// - Nothing is dropped on an old word: the server's remembered refusals for
///   this vault are forgotten and the vault data is pushed again first (as
///   [`sync_push_vault_data_as`]), so an edit is dropped only when this push
///   confirms it cannot be delivered — by the local authorship check, or a
///   fresh 403 for that item. An edit that goes through now is kept. A push
///   that fails fails this, and nothing is dropped.
/// - Then, in one transaction: the account's confirmed edits are deleted,
///   other members' unsendable items in the vault stop being sent (dirty flag
///   cleared, row kept), and `server_copy` is applied with verify-before-apply
///   as [`apply_pulled_objects`] applies it, without moving the pull cursor.
///   Every dropped item the server's copy holds must come back from it: one
///   that does not (verification rejected it) rolls the whole transaction back
///   with [`SyncError::NotRestored`]. A dropped item the server holds nothing
///   of is removed (its archived versions too, as on any delete) and named in
///   [`Discarded::removed`].
/// - The archived versions of a restored item are kept as they are (the
///   versions only this device had included): the dropped edit's history stays
///   readable.
pub fn discard_unpushable(
    transport: &mut dyn SyncTransport,
    storage: &Storage,
    ctx: &SyncContext,
    vault_id: &[u8],
    server_copy: &[Vec<u8>],
) -> Result<Discarded, SyncError> {
    let mut pulled: Vec<(u64, SyncObject)> = Vec::with_capacity(server_copy.len());
    let mut seq = 0_u64;
    for blob in server_copy {
        seq = seq.saturating_add(1);
        let Ok(object) = SyncObject::from_bytes(blob) else {
            return Err(SyncError::ServerCopyUnreadable);
        };
        pulled.push((seq, object));
    }
    // The items of the vault the server's copy holds.
    let mut held: Vec<Vec<u8>> = Vec::new();
    for (_, object) in &pulled {
        if let SyncObject::Item(it) = object {
            if it.vault_id == vault_id {
                held.push(it.item_id.clone());
            }
        }
    }

    let key = push_forbidden_key(&ctx.tenant);
    let others: Vec<Unpushable> = load_forbidden(storage, &key)?
        .into_iter()
        .filter(|u| u.vault_id != vault_id)
        .collect();
    save_forbidden(storage, &key, &others)?;
    let report = sync_push_vault_data_as(transport, storage, ctx)?;
    let (mine, theirs): (Vec<Unpushable>, Vec<Unpushable>) = report
        .unpushable
        .into_iter()
        .filter(|u| u.vault_id == vault_id)
        .partition(|u| u.author_pubkey == ctx.genesis_owner);

    storage.transaction(|| -> Result<Discarded, SyncError> {
        let mut out = Discarded::default();
        for u in mine {
            if storage.discard_unpushed_item(
                &u.vault_id,
                &u.item_id,
                u.version,
                &u.author_pubkey,
            )? {
                out.dropped.push(u);
            }
        }
        for u in theirs {
            let unchanged = storage
                .get_item(&u.vault_id, &u.item_id)?
                .is_some_and(|it| it.version == u.version && it.author_pubkey == u.author_pubkey);
            if unchanged {
                storage.clear_item_dirty(&u.vault_id, &u.item_id)?;
                out.released.push(u);
            }
        }
        out.pulled = apply_pulled_objects(storage, ctx, pulled)?;
        for u in &out.dropped {
            if held.contains(&u.item_id) {
                if storage.get_item(&u.vault_id, &u.item_id)?.is_none() {
                    return Err(SyncError::NotRestored);
                }
            } else {
                storage.clear_item_history(&u.vault_id, &u.item_id)?;
                out.removed.push(u.clone());
            }
        }
        Ok(out)
    })
}

/// [`sync_push`] of the vault data alone: the dirty vault records, items,
/// membership manifests and grants of the vaults bound to `target_tenant`. The
/// account states and the audit entries are not sent, and their cursors for
/// this tenant do not move.
///
/// For the first upload of a vault under a space label the device does not
/// otherwise sync. Those two kinds are tracked per label, not per server: a
/// push under a second label of the same server would hand it every account
/// state and the whole audit log once more. They reach the server with the
/// ordinary sync of the label the device does sync.
pub fn sync_push_vault_data(
    transport: &mut dyn SyncTransport,
    storage: &Storage,
    target_tenant: &[u8],
) -> Result<PushReport, SyncError> {
    run_push(transport, storage, target_tenant, None, false)
}

/// The push behind [`sync_push`] (`account_wide`) and [`sync_push_vault_data`];
/// with `own` (the account's pubkey), behind their `_as` forms.
fn run_push(
    transport: &mut dyn SyncTransport,
    storage: &Storage,
    target_tenant: &[u8],
    own: Option<&[u8]>,
    account_wide: bool,
) -> Result<PushReport, SyncError> {
    let mut push = Push {
        storage,
        authority: Authority::new(storage, own),
        refused_key: push_refused_key(target_tenant),
        forbidden_key: push_forbidden_key(target_tenant),
        acct_key: acct_push_cursor_key(target_tenant),
        audit_key: push_cursor_key(target_tenant),
        before_items: VecDeque::new(),
        items: VecDeque::new(),
        after_items: VecDeque::new(),
        too_large: Vec::new(),
        unpushable: Vec::new(),
        acct_left: 0,
        acct_version: None,
    };
    push.queue(target_tenant)?;
    if account_wide {
        push.queue_account_wide()?;
    }
    let pushed = push.send(transport)?;

    // Counts only — the pushed objects are encrypted blobs; never log their content.
    let too_large = push.too_large;
    let unpushable = push.unpushable;
    if !too_large.is_empty() || !unpushable.is_empty() {
        log::warn!(
            "sync push: pushed {pushed} object(s); {} item(s) are too large for the server, \
             {} item(s) cannot be sent as not permitted",
            too_large.len(),
            unpushable.len()
        );
    } else if pushed > 0 {
        log::info!("sync push: pushed {pushed} object(s)");
    }
    Ok(PushReport {
        pushed,
        too_large,
        unpushable,
    })
}

/// One [`sync_push`] in progress.
///
/// What is still to send is three queues, sent in this order: the objects the
/// items depend on, the items, and the account-wide objects. Only the items
/// are queued by id — see [`Self::take_next`].
struct Push<'a> {
    storage: &'a Storage,
    /// Which dirty items' authors may write them.
    authority: Authority<'a>,
    /// Meta key of the tenant's remembered refusals.
    refused_key: String,
    /// Meta key of the tenant's remembered not-permitted refusals.
    forbidden_key: String,
    /// Cursor key of the tenant's pushed account-state version.
    acct_key: String,
    /// Cursor key of the tenant's pushed audit seq.
    audit_key: String,
    /// Membership manifests, vault records and grants, loaded: they are small.
    before_items: VecDeque<(SyncObject, Sent)>,
    /// The `(vault_id, item_id)` of the dirty items to send, not loaded yet.
    items: VecDeque<(Vec<u8>, Vec<u8>)>,
    /// Account states and audit entries, loaded: they are small.
    after_items: VecDeque<(SyncObject, Sent)>,
    /// Refused items: remembered ones first, then this push's.
    too_large: Vec<TooLarge>,
    /// Items left out as not permitted: remembered and locally found ones
    /// first, then the ones the server refuses in this push.
    unpushable: Vec<Unpushable>,
    /// Queued account states the server has not accepted yet.
    acct_left: usize,
    /// The highest queued account-state version, until the cursor moved to it.
    acct_version: Option<u64>,
}

impl Push<'_> {
    /// Collects the vault data the tenant's server is missing, in the order it
    /// must receive it.
    fn queue(&mut self, target_tenant: &[u8]) -> Result<(), SyncError> {
        let storage = self.storage;
        // Only DIRTY objects of vaults bound to target_tenant (the 1:1 binding is already in
        // the query: `sync_tenant = target_tenant`). Local/foreign vaults do not get in.
        // An empty target_tenant will not match anything → no-op (safeguard).
        //
        // DEPENDENCY ORDER (critical): the receiver verifies each object's authority against
        // the membership manifest chain, and a rejected object ADVANCES THE CURSOR (a
        // dependency arriving later is never retried). So a dependency MUST reach the server
        // before its dependents — the server assigns server_seq in push order and the pull
        // processes in that order. Manifests first (an item/record authored at epoch
        // N needs the epoch-N manifest to verify), then the vault record, then grants (each
        // references its epoch's manifest), then items. Previously items preceded manifests, so
        // a cross-account member's items were rejected on first pull and silently dropped.
        // The queue is cut into requests in this order and they are sent one after
        // another, so the order holds across requests too.
        for m in storage.list_dirty_bound_manifests(target_tenant)? {
            self.before_items
                .push_back((SyncObject::MembershipManifest(m), Sent::Dirty));
        }
        for v in storage.list_dirty_bound_vaults(target_tenant)? {
            self.before_items
                .push_back((SyncObject::Vault(v), Sent::Dirty));
        }
        for g in storage.list_dirty_bound_grants(target_tenant)? {
            self.before_items
                .push_back((SyncObject::MembershipGrant(g), Sent::Dirty));
        }
        // An item the server already refused as too large is not sent again while
        // it is unchanged: it would be refused again, at the cost of uploading it
        // on every sync. It stays dirty and is reported every time instead.
        // The dirty items are listed by id and version only: a refused item is
        // as large as items get, and this runs on every background sync. The
        // ones to send are loaded when their request is built.
        // The same goes for an item the server refused as not permitted, and
        // one whose author may not write it is not sent at all (see
        // `sync_push_as`): every member would reject it.
        let remembered = load_refused(storage, &self.refused_key)?;
        let forbidden = load_forbidden(storage, &self.forbidden_key)?;
        for head in storage.list_dirty_bound_item_versions(target_tenant)? {
            let known = remembered.iter().find(|r| {
                r.vault_id == head.vault_id
                    && r.item_id == head.item_id
                    && r.version == head.version
            });
            if let Some(r) = known {
                self.too_large.push(r.clone());
            } else if let Some(f) = forbidden.iter().find(|f| f.is(&head)) {
                self.unpushable.push(f.clone());
            } else if !self.authority.may_write(&head)? {
                self.unpushable
                    .push(Unpushable::new(&head, UnpushableReason::NotAuthorized));
            } else {
                self.items.push_back((head.vault_id, head.item_id));
            }
        }
        // Entries whose item was edited, deleted or pushed since are dropped.
        if self.too_large != remembered {
            save_refused(storage, &self.refused_key, &self.too_large)?;
        }
        if self.server_refused().ne(forbidden.iter()) {
            self.save_forbidden()?;
        }
        Ok(())
    }

    /// This push's items the server refused as not permitted: remembered ones
    /// first, then the ones refused now.
    fn server_refused(&self) -> impl Iterator<Item = &Unpushable> {
        self.unpushable
            .iter()
            .filter(|u| u.reason == UnpushableReason::ServerRefused)
    }

    fn save_forbidden(&self) -> Result<(), SyncError> {
        let refused: Vec<Unpushable> = self.server_refused().cloned().collect();
        save_forbidden(self.storage, &self.forbidden_key, &refused)
    }

    /// Collects what the tenant's server is missing of the objects that belong
    /// to the account, not to a vault: the account states and the audit log.
    /// Nothing depends on them, so they follow the items.
    fn queue_account_wide(&mut self) -> Result<(), SyncError> {
        let storage = self.storage;
        // A3: account-state is broadcast to EVERY server, so it is not covered by
        // the dirty flag (which is single-server-bound) — we track it per-tenant by the version cursor.
        let last_acct = storage.get_sync_cursor(&self.acct_key)?.unwrap_or(0);
        for st in storage.list_account_states()? {
            if st.version > last_acct {
                self.acct_version = self.acct_version.max(Some(st.version));
                self.acct_left = self.acct_left.saturating_add(1);
                self.after_items.push_back((
                    SyncObject::AccountState(crate::object::AccountStateObject {
                        author_pubkey: st.author_pubkey,
                        version: st.version,
                        payload: st.payload,
                        signature: st.signature,
                    }),
                    Sent::Account,
                ));
            }
        }

        // Audit newer than the push cursor (per-tenant: audit goes to each server independently).
        let push_cursor = storage.get_sync_cursor(&self.audit_key)?.unwrap_or(0);
        for entry in storage.list_audit(push_cursor)? {
            // The audit's vault_id is open metadata; the storage AuditEntry carries no
            // vault_id field → in v1 we send an empty vault_id (audit is instance-level).
            // When the audit crate adds vault-scoping, extend this.
            self.after_items.push_back((
                SyncObject::Audit(crate::object::AuditObject {
                    vault_id: Vec::new(),
                    entry_blob: entry.entry_blob,
                    signature: entry.signature,
                    author_pubkey: entry.author_pubkey,
                }),
                Sent::Audit(entry.seq),
            ));
        }
        Ok(())
    }

    /// Takes the next object to send off the queues, in dependency order. An
    /// item is read from storage here and not before, so that only the items
    /// of the request being built are in memory. (A queued item that is no
    /// longer in storage has nothing to send and is passed over.)
    fn take_next(&mut self) -> Result<Option<(SyncObject, Sent)>, SyncError> {
        if let Some(queued) = self.before_items.pop_front() {
            return Ok(Some(queued));
        }
        while let Some((vault_id, item_id)) = self.items.pop_front() {
            if let Some(item) = self.storage.get_item(&vault_id, &item_id)? {
                return Ok(Some((SyncObject::Item(item), Sent::Dirty)));
            }
        }
        Ok(self.after_items.pop_front())
    }

    /// Sends the queues, request by request; returns how many objects the
    /// transport accepted. Nothing queued → no request (the point of
    /// dirty-tracking: a run with no edits makes no round-trip).
    ///
    /// A request is a run of at most [`PUSH_BATCH_MAX_OBJECTS`] objects and
    /// [`PUSH_BATCH_MAX_BYTES`] encoded bytes; an object over the byte budget is
    /// a request of its own. It is built, sent, settled and dropped before the
    /// next one is read from storage.
    fn send(&mut self, transport: &mut dyn SyncTransport) -> Result<u64, SyncError> {
        let mut pushed = 0_u64;
        // The object that did not fit the request before: it opens the next one.
        let mut carried: Option<(SyncObject, Sent)> = None;
        loop {
            let mut request = Outgoing::default();
            loop {
                if carried.is_none() {
                    carried = self.take_next()?;
                }
                let Some((object, sent)) = carried.take() else {
                    break;
                };
                let size = object.encoded_len();
                let full = request.objects.len() >= PUSH_BATCH_MAX_OBJECTS
                    || request.bytes.saturating_add(size) > PUSH_BATCH_MAX_BYTES;
                if full && !request.objects.is_empty() {
                    carried = Some((object, sent));
                    break;
                }
                request.add(object, sent, size);
            }
            if request.objects.is_empty() {
                return Ok(pushed);
            }
            pushed = pushed.saturating_add(self.send_request(transport, &request)?);
        }
    }

    /// Sends one request; returns how many of its objects the transport
    /// accepted. A request the server refuses as too large is sent again in
    /// halves, in order.
    fn send_request(
        &mut self,
        transport: &mut dyn SyncTransport,
        request: &Outgoing,
    ) -> Result<u64, SyncError> {
        let mut pushed = 0_u64;
        // Parts still to send, last first (popped from the end): the whole
        // request, then the halves of a part the server refused.
        let whole = 0..request.objects.len();
        let mut pending = vec![whole];
        while let Some(part) = pending.pop() {
            let Some(objects) = request.objects.get(part.clone()) else {
                continue;
            };
            match transport.push_objects(objects) {
                Ok(_) => {
                    self.settle(request, &part)?;
                    pushed = pushed.saturating_add(part.len() as u64);
                }
                // The server's limits are its own (and an older server's are
                // lower than these requests assume): a refused part is halved
                // until the object that does not fit is alone. A request
                // refused as not permitted is refused for one of its objects
                // the server does not name: it is singled out the same way.
                Err(SyncError::PayloadTooLarge | SyncError::Forbidden) if part.len() > 1 => {
                    let mid = part.start.saturating_add(part.len() / 2);
                    pending.push(mid..part.end);
                    pending.push(part.start..mid);
                }
                Err(SyncError::PayloadTooLarge) => self.refuse(request, part.start)?,
                Err(SyncError::Forbidden) => self.forbid(request, part.start)?,
                Err(e) => return Err(e),
            }
        }
        Ok(pushed)
    }

    /// The server will not take the object at `index` of `request` even alone.
    /// An item depends on nothing that follows it, so the push goes on without
    /// it; it is remembered (see [`Self::queue`]) and reported, never dropped
    /// quietly. Any other object is a dependency of later ones: the push stops.
    fn refuse(&mut self, request: &Outgoing, index: usize) -> Result<(), SyncError> {
        let (Some(SyncObject::Item(it)), Some(bytes)) =
            (request.objects.get(index), request.sizes.get(index))
        else {
            return Err(SyncError::PayloadTooLarge);
        };
        self.too_large.push(TooLarge {
            vault_id: it.vault_id.clone(),
            item_id: it.item_id.clone(),
            item_type: it.item_type,
            version: it.version,
            bytes: *bytes as u64,
        });
        save_refused(self.storage, &self.refused_key, &self.too_large)
    }

    /// The server does not permit the object at `index` of `request`, even
    /// alone. As in [`Self::refuse`]: an item is left out, remembered and
    /// reported; any other object stops the push. (Only the server's own
    /// `forbidden` refusal reaches here as [`SyncError::Forbidden`]; the server
    /// refuses a push as a whole for a reason of its own with another status.)
    fn forbid(&mut self, request: &Outgoing, index: usize) -> Result<(), SyncError> {
        let Some(SyncObject::Item(it)) = request.objects.get(index) else {
            return Err(SyncError::Forbidden);
        };
        self.unpushable.push(Unpushable {
            vault_id: it.vault_id.clone(),
            item_id: it.item_id.clone(),
            item_type: it.item_type,
            version: it.version,
            author_pubkey: it.author_pubkey.clone(),
            reason: UnpushableReason::ServerRefused,
        });
        self.save_forbidden()
    }

    /// The transport accepted `part` of `request`: clears its dirty flags and
    /// advances the cursors now, so a failure later in the push does not send
    /// it again.
    fn settle(
        &mut self,
        request: &Outgoing,
        part: &std::ops::Range<usize>,
    ) -> Result<(), SyncError> {
        let storage = self.storage;
        let (Some(objects), Some(sent)) = (
            request.objects.get(part.clone()),
            request.sent.get(part.clone()),
        ) else {
            return Ok(());
        };
        let mut accounts = 0_usize;
        let mut audit_seq = None;
        storage.transaction(|| -> Result<(), SyncError> {
            for (obj, sent) in objects.iter().zip(sent) {
                match sent {
                    Sent::Dirty => clear_dirty(storage, obj)?,
                    Sent::Account => accounts = accounts.saturating_add(1),
                    // Audit entries are queued in seq order, so the last one
                    // of a part is its highest.
                    Sent::Audit(seq) => audit_seq = Some(*seq),
                }
            }
            Ok(())
        })?;
        if let Some(seq) = audit_seq {
            storage.set_sync_cursor(&self.audit_key, seq)?;
        }
        // One version cursor covers every account state, so it moves only once
        // all of them are on the server.
        self.acct_left = self.acct_left.saturating_sub(accounts);
        if self.acct_left == 0 {
            if let Some(version) = self.acct_version.take() {
                storage.set_sync_cursor(&self.acct_key, version)?;
            }
        }
        Ok(())
    }
}

/// Makes the next [`sync_push`] to `tenant` send again the items its server
/// refused — as too large, for when the server's limit was raised, or as not
/// permitted, for a refusal that was not about the item after all (a
/// server-side state since cleared). Raising the account's role does not get
/// an edit through: the server checks the author's role at the epoch the edit
/// was written at, so a Viewer's edit is refused again however often it is
/// sent; it is edited again (at the new role) or discarded
/// ([`discard_unpushable`]). Items whose author may not write them by this
/// device's own check are not sent either way.
pub fn forget_push_refusals(storage: &Storage, tenant: &[u8]) -> Result<(), SyncError> {
    save_refused(storage, &push_refused_key(tenant), &[])?;
    save_forbidden(storage, &push_forbidden_key(tenant), &[])
}

/// What settles an object once the transport accepted it.
enum Sent {
    /// A dirty-flagged row: the flag is cleared.
    Dirty,
    /// An account state: the per-tenant version cursor moves once all are sent.
    Account,
    /// An audit entry with this local seq: the per-tenant push cursor moves to it.
    Audit(u64),
}

/// The objects of one request, in dependency order, with their encoded sizes.
#[derive(Default)]
struct Outgoing {
    objects: Vec<SyncObject>,
    sent: Vec<Sent>,
    sizes: Vec<usize>,
    /// The sum of `sizes`.
    bytes: usize,
}

impl Outgoing {
    /// Appends `object`, whose encoded size is `size`. The size is known from
    /// the field lengths ([`SyncObject::encoded_len`]): serializing only to
    /// measure would copy every object once more than the request does.
    fn add(&mut self, object: SyncObject, sent: Sent, size: usize) {
        self.bytes = self.bytes.saturating_add(size);
        self.sizes.push(size);
        self.objects.push(object);
        self.sent.push(sent);
    }
}

/// Clears the dirty flag of one pushed object.
fn clear_dirty(storage: &Storage, obj: &SyncObject) -> Result<(), SyncError> {
    match obj {
        SyncObject::Vault(v) => storage.clear_vault_dirty(&v.vault_id)?,
        SyncObject::Item(i) => storage.clear_item_dirty(&i.vault_id, &i.item_id)?,
        SyncObject::MembershipManifest(m) => {
            storage.clear_manifest_dirty(&m.vault_id, m.key_epoch)?;
        }
        SyncObject::MembershipGrant(g) => {
            storage.clear_grant_dirty(&g.vault_id, &g.member_pubkey, g.key_epoch)?;
        }
        // Tracked by cursors, not by a dirty flag.
        SyncObject::Audit(_) | SyncObject::Keyset(_) | SyncObject::AccountState(_) => {}
    }
    Ok(())
}

/// The items remembered as refused for a tenant. Device-local bookkeeping in
/// the `meta` table; a value that does not parse counts as empty (the items are
/// then simply offered to the server again).
fn load_refused(storage: &Storage, key: &str) -> Result<Vec<TooLarge>, SyncError> {
    let Some(bytes) = storage.get_meta(key)? else {
        return Ok(Vec::new());
    };
    let mut r = Reader::new(&bytes);
    let mut out = Vec::new();
    while !r.is_empty() {
        match read_refused(&mut r) {
            Ok(e) => out.push(e),
            Err(_) => return Ok(Vec::new()),
        }
    }
    Ok(out)
}

fn read_refused(r: &mut Reader<'_>) -> Result<TooLarge, SyncError> {
    Ok(TooLarge {
        vault_id: r.bytes()?,
        item_id: r.bytes()?,
        item_type: r.u32()?,
        version: r.u64()?,
        bytes: r.u64()?,
    })
}

fn save_refused(storage: &Storage, key: &str, refused: &[TooLarge]) -> Result<(), SyncError> {
    let mut out = Vec::new();
    for r in refused {
        put_bytes(&mut out, &r.vault_id)?;
        put_bytes(&mut out, &r.item_id)?;
        out.extend_from_slice(&r.item_type.to_be_bytes());
        out.extend_from_slice(&r.version.to_be_bytes());
        out.extend_from_slice(&r.bytes.to_be_bytes());
    }
    storage.set_meta(key, &out)?;
    Ok(())
}

/// The items remembered as not permitted by a tenant's server; like
/// [`load_refused`], a value that does not parse counts as empty.
fn load_forbidden(storage: &Storage, key: &str) -> Result<Vec<Unpushable>, SyncError> {
    let Some(bytes) = storage.get_meta(key)? else {
        return Ok(Vec::new());
    };
    let mut r = Reader::new(&bytes);
    let mut out = Vec::new();
    while !r.is_empty() {
        match read_forbidden(&mut r) {
            Ok(e) => out.push(e),
            Err(_) => return Ok(Vec::new()),
        }
    }
    Ok(out)
}

fn read_forbidden(r: &mut Reader<'_>) -> Result<Unpushable, SyncError> {
    Ok(Unpushable {
        vault_id: r.bytes()?,
        item_id: r.bytes()?,
        item_type: r.u32()?,
        version: r.u64()?,
        author_pubkey: r.bytes()?,
        reason: UnpushableReason::ServerRefused,
    })
}

fn save_forbidden(storage: &Storage, key: &str, refused: &[Unpushable]) -> Result<(), SyncError> {
    let mut out = Vec::new();
    for r in refused {
        put_bytes(&mut out, &r.vault_id)?;
        put_bytes(&mut out, &r.item_id)?;
        out.extend_from_slice(&r.item_type.to_be_bytes());
        out.extend_from_slice(&r.version.to_be_bytes());
        put_bytes(&mut out, &r.author_pubkey)?;
    }
    storage.set_meta(key, &out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::AuditObject;
    use crate::transport::InMemoryTransport;

    fn st() -> Storage {
        Storage::open_in_memory(&[7_u8; 32]).unwrap()
    }
    fn audit(n: u8) -> SyncObject {
        SyncObject::Audit(AuditObject {
            vault_id: vec![n],
            entry_blob: vec![n],
            signature: vec![1_u8; 67],
            author_pubkey: vec![2_u8; 32],
        })
    }
    fn ctx() -> SyncContext {
        SyncContext {
            genesis_owner: vec![2_u8; 32],
            tenant: b"test-tenant".to_vec(),
        }
    }

    #[test]
    fn transport_below_cursor_is_rejected() {
        let s = st();
        let mut t = InMemoryTransport::new();
        t.push_objects(&[audit(1), audit(2)]).unwrap();
        // the first pull advances the cursor to 2
        sync_pull(&mut t, &s, &ctx()).unwrap();
        assert_eq!(
            s.get_sync_cursor(&pull_cursor_key(b"test-tenant")).unwrap(),
            Some(2)
        );
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
            genesis_owner: vec![2_u8; 32],
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
            genesis_owner: vec![2_u8; 32],
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
        s.append_audit(&[9_u8; 1], &[1_u8; 67], &[2_u8; 32])
            .unwrap();

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
