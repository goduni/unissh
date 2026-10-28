//! Trusting a vault a teammate shared with this account (A0, share-accept).
//!
//! Sync verifies a vault against its pinned genesis owner (the author of the
//! epoch-1 membership manifest) and, for a vault with no pin, against this
//! account's own keyset. So a vault a teammate created is rejected until its
//! owner is pinned, and the pin must come from the user, who confirms the
//! owner's fingerprint out of band: the server is never trusted to say who
//! owns a vault.
//!
//! [`Core::inspect_shared_vault_paged`] reads the vault's membership objects
//! as the server serves them, verifies the whole manifest chain in memory
//! against its genesis author as the candidate owner (`unissh_vault::verify_chain`,
//! the walk sync uses), and checks that the latest epoch holds a grant this
//! account opens (`unissh_vault::open_own_grant`, as `Vault::open` does). It
//! writes nothing. [`Core::trust_shared_vault_paged`] inspects again, compares
//! the fingerprint the user got from the owner, and pins in the same step.
//! What this module adds over the vault crate is only the share-accept policy:
//! one creator, no gap, a grant to this account, and the user's confirmation.
//!
//! [`Core::pull_vault_paged`] is the targeted single-vault pull that brings
//! the vault in after the pin. It does not move the pull cursor — the objects
//! an earlier sync rejected advanced it, so an ordinary sync never sees them
//! again.

use std::collections::{BTreeMap, BTreeSet};

use unissh_storage::{MembershipGrant, MembershipManifest};
use unissh_sync::SyncObject;
use unissh_vault::{
    member_fingerprint, open_own_grant, pin_and_verify_vault_anchor, verify_chain, verify_manifest,
    VaultError,
};

use super::{decode_vid, map_vault_err, Core, CoreState, FfiError, FfiMemberRole, FfiSyncReport};

/// At most this many distinct manifests are kept for one epoch. A real vault
/// has one; a server that serves more is refused rather than walked.
const MAX_MANIFESTS_PER_EPOCH: usize = 8;

/// At most this many distinct grants to this account are kept for one epoch.
const MAX_OWN_GRANTS_PER_EPOCH: usize = 8;

/// What a pin of the vault's genesis owner on this device says about the
/// owner the server's objects name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiVaultTrust {
    /// No owner is pinned for this vault here yet: the user has to confirm one.
    NotPinned,
    /// This owner is pinned here already (the vault may still need a pull).
    Pinned,
    /// ANOTHER owner is pinned for this vault here. The server now presents a
    /// different creator — a pin is refused, and the user should be told.
    PinnedToAnotherOwner,
}

/// What [`Core::trust_shared_vault_paged`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiTrustOutcome {
    /// The owner is pinned now: pull the vault next.
    Trusted,
    /// This owner was pinned already: pull the vault next.
    AlreadyTrusted,
    /// The fingerprint given is not the owner's. Nothing was pinned.
    FingerprintMismatch,
    /// Another owner is pinned for this vault here, and the server now names
    /// a different one. Nothing was changed; the user must be told loudly.
    PinnedToAnotherOwner,
}

/// A vault shared with this account, as its verified membership chain shows
/// it. Public keys and a fingerprint only; nothing secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SharedVaultInfo {
    /// The vault id (hex).
    pub vault_id: String,
    /// The candidate owner: the author of the vault's genesis manifest
    /// (Ed25519, hex). It is NOT trusted until the user confirmed
    /// [`Self::fingerprint`] with the owner and pinned it.
    pub owner_ed25519_hex: String,
    /// The fingerprint of the key that created this vault, in the
    /// `member_fingerprint` format (hex(SHA-256(ed25519_pub)), 64
    /// characters). Whether it is the teammate's is what the user checks,
    /// against the fingerprint the owner reads out from their own device.
    pub fingerprint: String,
    /// This account's role at the latest epoch of the chain.
    pub my_role: FfiMemberRole,
    /// The latest membership epoch the chain verified up to.
    pub epoch: u64,
    /// What this device has pinned for the vault.
    pub trust: FfiVaultTrust,
}

/// A vault the server lists that has no record on this device (live or
/// deleted), as [`Core::vaults_not_here`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotHere {
    /// The vault id (hex, lowercase).
    pub vault_id: String,
    /// An owner is pinned for it here: it was trusted but is not fetched yet,
    /// or the server now names a different owner (an inspection tells which).
    pub pinned: bool,
}

/// One page of a single vault's objects: `next_page(cursor)` returns the raw
/// object blobs that follow `cursor` (0 for the first page) and the cursor of
/// the next page, `None` after the last one. A page that could not be read is
/// an error, never an empty last page: a cut-short set must not pass for the
/// whole of it.
pub type VaultPage = (Vec<Vec<u8>>, Option<u64>);

/// A fingerprint as the user typed or pasted it, in the `member_fingerprint`
/// form (64 lowercase hex digits): spaces, `:` and `-` are dropped and case is
/// ignored. `None` when what is left is not exactly 64 hex digits — a prefix
/// is not a fingerprint.
pub fn normalize_fingerprint(typed: &str) -> Option<String> {
    let digits: String = typed
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(*c, ':' | '-'))
        .collect();
    (digits.len() == 64 && digits.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| digits.to_ascii_lowercase())
}

/// A fingerprint in groups of four, the way the app and the CLI show it, so
/// that it is easy to read out and compare.
#[uniffi::export]
pub fn grouped_fingerprint(fingerprint: String) -> String {
    let chars: Vec<char> = fingerprint.chars().collect();
    chars
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The vault's membership objects, kept from the pages as they come.
#[derive(Default)]
struct Membership {
    /// Distinct manifests by epoch, at most [`MAX_MANIFESTS_PER_EPOCH`] each.
    manifests: BTreeMap<u64, Vec<MembershipManifest>>,
    /// Distinct grants to THIS account by epoch, at most
    /// [`MAX_OWN_GRANTS_PER_EPOCH`] each; grants to others are not kept.
    grants: BTreeMap<u64, Vec<MembershipGrant>>,
    /// An epoch the server served too many manifests for. Every manifest
    /// epoch is on the chain (1 up to the highest served), so any of them
    /// refuses the vault.
    crowded_manifests: Option<u64>,
    /// The epochs the server served too many grants to this account for.
    /// Only the latest epoch's grants are read, so only a crowded latest
    /// epoch refuses the vault: re-grants at an older epoch do not.
    crowded_grants: BTreeSet<u64>,
}

impl Membership {
    /// Keeps the manifests of `vault_id`, and its grants to `own_ed`, among
    /// `objects` (raw delta blobs); everything else, and a blob that does not
    /// parse, is dropped, as the untrusted pull path drops it.
    fn take(&mut self, vault_id: &[u8], own_ed: &[u8], objects: &[Vec<u8>]) {
        for blob in objects {
            let Ok(object) = SyncObject::from_bytes(blob) else {
                continue;
            };
            if let SyncObject::MembershipManifest(m) = object {
                if m.vault_id == vault_id {
                    let epoch = m.key_epoch;
                    let at = self.manifests.entry(epoch).or_default();
                    if !keep(at, m, MAX_MANIFESTS_PER_EPOCH) {
                        self.crowded_manifests.get_or_insert(epoch);
                    }
                }
            } else if let SyncObject::MembershipGrant(g) = object {
                if g.vault_id == vault_id && g.member_pubkey == own_ed {
                    let epoch = g.key_epoch;
                    let at = self.grants.entry(epoch).or_default();
                    if !keep(at, g, MAX_OWN_GRANTS_PER_EPOCH) {
                        self.crowded_grants.insert(epoch);
                    }
                }
            }
        }
    }
}

/// Adds `item` to `at` unless it is there already; `false` when `at` is full
/// and `item` is new. `at` holds at most `cap` items, so the check is cheap.
fn keep<T: PartialEq>(at: &mut Vec<T>, item: T, cap: usize) -> bool {
    if at.contains(&item) {
        return true;
    }
    if at.len() >= cap {
        return false;
    }
    at.push(item);
    true
}

/// What an inspection found.
enum Inspected {
    /// This account created the vault: it is verified against the own keyset
    /// and needs no pin.
    Own,
    /// A vault someone else created, shared with this account.
    Shared(SharedVaultInfo),
}

/// Why a vault cannot be offered for trust, in words for the user.
fn refused(why: &str) -> FfiError {
    FfiError::Other {
        msg: format!("this vault cannot be trusted: {why}"),
    }
}

/// The candidate owner of `vault_id`: the one author of its epoch-1
/// manifests that verify as a genesis (signed by their own author). A
/// manifest whose signature does not verify is ignored here — it cannot
/// stand for a creator — and two VALID genesis manifests by different
/// authors are refused: the server is offering a second owner, and no choice
/// between them is safe to make.
fn genesis_author(vault_id: &[u8], membership: &Membership) -> Result<Vec<u8>, FfiError> {
    let mut owner: Option<&[u8]> = None;
    for m in membership.manifests.get(&1).into_iter().flatten() {
        if verify_manifest(m, vault_id, None, &m.author_pubkey).is_err() {
            continue;
        }
        match owner {
            None => owner = Some(m.author_pubkey.as_slice()),
            Some(first) if first == m.author_pubkey.as_slice() => {}
            Some(_) => return Err(refused("the server presents two different creators for it")),
        }
    }
    owner
        .map(<[u8]>::to_vec)
        .ok_or_else(|| refused("the server holds no valid genesis manifest for it"))
}

/// Verifies `membership` of `vault_id` for the account `state` holds.
///
/// 1. The genesis author names the candidate owner ([`genesis_author`]); if
///    it is this account, the vault is its own.
/// 2. Every epoch from 1 to the highest the server serves must verify against
///    the one before it (D1, `verify_chain`), with no gap. A manifest that
///    does not chain is refused rather than skipped: the chain is what the
///    sync will hold the vault to after the pin.
/// 3. The latest epoch must hold a grant to this account that verifies
///    against that epoch's member set and opens with this account's key
///    (`open_own_grant`) — proof the owner shared the vault with exactly this
///    keyset.
fn inspect(
    state: &CoreState,
    vault_id: &[u8],
    membership: &Membership,
) -> Result<Inspected, FfiError> {
    if let Some(epoch) = membership.crowded_manifests {
        return Err(refused(&format!(
            "the server serves too many manifests for it at epoch {epoch}"
        )));
    }
    let owner = genesis_author(vault_id, membership)?;
    if owner == state.keyset.signing.verifying.to_bytes() {
        return Ok(Inspected::Own);
    }

    let latest = membership
        .manifests
        .keys()
        .next_back()
        .copied()
        .unwrap_or(1);
    if (1..=latest).any(|epoch| !membership.manifests.contains_key(&epoch)) {
        return Err(refused("its membership chain has a gap"));
    }
    let members = verify_chain(
        vault_id,
        &owner,
        (1..=latest).map(|epoch| {
            Ok::<_, VaultError>(
                membership
                    .manifests
                    .get(&epoch)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            )
        }),
    )
    .map_err(|e| refused(&format!("its membership chain does not verify ({e})")))?;

    if membership.crowded_grants.contains(&members.epoch()) {
        return Err(refused(&format!(
            "the server serves too many grants to this account for it at epoch {}",
            members.epoch()
        )));
    }
    let grants = membership
        .grants
        .get(&members.epoch())
        .map(Vec::as_slice)
        .unwrap_or_default();
    // The vault key is dropped (and zeroized) right away: opening it is the
    // proof, nothing reads the vault here.
    let (_, role) = open_own_grant(grants, vault_id, &members, &state.keyset).map_err(|e| {
        refused(&format!(
            "it grants this account nothing at its latest epoch ({e})"
        ))
    })?;

    let trust = match state
        .storage
        .get_vault_trust_anchor(vault_id)
        .map_err(FfiError::other)?
    {
        None => FfiVaultTrust::NotPinned,
        Some(a) if a.genesis_owner_pubkey == owner => FfiVaultTrust::Pinned,
        Some(_) => FfiVaultTrust::PinnedToAnotherOwner,
    };
    Ok(Inspected::Shared(SharedVaultInfo {
        vault_id: hex::encode(vault_id),
        owner_ed25519_hex: hex::encode(&owner),
        fingerprint: member_fingerprint(&owner),
        my_role: FfiMemberRole::from_core(role),
        epoch: members.epoch(),
        trust,
    }))
}

/// Adds the pull-side counts of `page` to `total`.
const fn add_pulled(total: &mut FfiSyncReport, page: &FfiSyncReport) {
    total.applied = total.applied.saturating_add(page.applied);
    total.skipped_stale = total.skipped_stale.saturating_add(page.skipped_stale);
    total.conflicts = total.conflicts.saturating_add(page.conflicts);
    total.rejected = total.rejected.saturating_add(page.rejected);
}

impl Core {
    /// Reads every page of `vault_id`'s objects and keeps its membership.
    fn membership_of(
        &self,
        vid: &[u8],
        mut next_page: impl FnMut(u64) -> Result<VaultPage, FfiError>,
    ) -> Result<Membership, FfiError> {
        let own_ed = self.with_state(|state| Ok(state.keyset.signing.verifying.to_bytes()))?;
        let mut membership = Membership::default();
        let mut cursor = 0_u64;
        loop {
            let (objects, next) = next_page(cursor)
                .map_err(|e| refused(&format!("its objects could not be read in full ({e})")))?;
            membership.take(vid, &own_ed, &objects);
            match next {
                Some(next) => cursor = next,
                None => return Ok(membership),
            }
        }
    }

    /// **Inspects a vault shared with this account** before its owner is
    /// trusted, over objects fetched page by page (see [`VaultPage`]): only
    /// the vault's manifests and the grants to this account are kept, so the
    /// vault's items are never held in memory. A page that cannot be read
    /// fails the inspection.
    ///
    /// `Ok(None)`: this account created the vault itself — it needs no trust.
    /// Requires unlock. Writes nothing.
    pub fn inspect_shared_vault_paged(
        &self,
        vault_id: &str,
        next_page: impl FnMut(u64) -> Result<VaultPage, FfiError>,
    ) -> Result<Option<SharedVaultInfo>, FfiError> {
        let vid = decode_vid(vault_id)?;
        let membership = self.membership_of(&vid, next_page)?;
        self.with_state(|state| match inspect(state, &vid, &membership)? {
            Inspected::Own => Ok(None),
            Inspected::Shared(info) => Ok(Some(info)),
        })
    }

    /// **Trusts the owner of a vault shared with this account**: inspects it
    /// again (as [`Self::inspect_shared_vault_paged`]), compares and pins its
    /// genesis owner in one step under the core's state lock, so what is
    /// pinned is exactly what was compared.
    ///
    /// `expected_fingerprint` is always required: the owner's fingerprint as
    /// the user got it from them, or the one the caller DISPLAYED and the user
    /// confirmed (spaces, `:`, `-` and case ignored). The owner is pinned only
    /// if it is the vault creator's, so a server that changes its answer
    /// between the display and the pin is caught; nothing pins "whatever the
    /// inspection finds".
    ///
    /// Refused (an error) for a vault this account created, a broken chain,
    /// no grant, or a value that is not a fingerprint. Requires unlock.
    pub fn trust_shared_vault_paged(
        &self,
        vault_id: &str,
        expected_fingerprint: &str,
        next_page: impl FnMut(u64) -> Result<VaultPage, FfiError>,
    ) -> Result<FfiTrustOutcome, FfiError> {
        let vid = decode_vid(vault_id)?;
        let expected = normalize_fingerprint(expected_fingerprint).ok_or_else(|| {
            FfiError::other("that is not a fingerprint: a fingerprint is 64 hex digits")
        })?;
        let membership = self.membership_of(&vid, next_page)?;
        self.with_state(|state| {
            let info = match inspect(state, &vid, &membership)? {
                Inspected::Own => {
                    return Err(FfiError::other(
                        "this vault was created by this account: it needs no trust",
                    ))
                }
                Inspected::Shared(info) => info,
            };
            match info.trust {
                FfiVaultTrust::PinnedToAnotherOwner => {
                    return Ok(FfiTrustOutcome::PinnedToAnotherOwner)
                }
                FfiVaultTrust::Pinned => return Ok(FfiTrustOutcome::AlreadyTrusted),
                FfiVaultTrust::NotPinned => {}
            }
            if expected != info.fingerprint {
                return Ok(FfiTrustOutcome::FingerprintMismatch);
            }
            let owner = hex::decode(&info.owner_ed25519_hex).map_err(FfiError::other)?;
            pin_and_verify_vault_anchor(&state.storage, &vid, &owner).map_err(map_vault_err)?;
            Ok(FfiTrustOutcome::Trusted)
        })
    }

    /// Which of `vault_ids` (hex, from the server's catalog) have no record on
    /// this device at all, and whether an owner is pinned for each. A cheap,
    /// local check: nothing is fetched or verified. An id that is not hex is
    /// left out. Requires unlock.
    pub fn vaults_not_here(&self, vault_ids: &[String]) -> Result<Vec<NotHere>, FfiError> {
        self.with_state(|state| {
            let mut out = Vec::new();
            for id in vault_ids {
                let Ok(vid) = decode_vid(id) else {
                    continue;
                };
                if state
                    .storage
                    .get_vault(&vid)
                    .map_err(FfiError::other)?
                    .is_some()
                {
                    continue;
                }
                let pinned = state
                    .storage
                    .get_vault_trust_anchor(&vid)
                    .map_err(FfiError::other)?
                    .is_some();
                out.push(NotHere {
                    vault_id: hex::encode(&vid),
                    pinned,
                });
            }
            Ok(out)
        })
    }

    /// **Pull ONE vault** page by page (see [`VaultPage`]): each page goes
    /// through [`Core::apply_pulled_vault`] — verify-before-apply, born-bound
    /// to `tenant_b64` — before the next is asked for, so the vault is never
    /// held in memory whole; a later page verifies against what the earlier
    /// ones applied. The per-tenant pull cursor does not move, which makes this
    /// the way to bring in a vault an earlier sync rejected (a teammate's
    /// vault before its owner was pinned). The report is the sum over the
    /// pages.
    ///
    /// A page that cannot be read ends the pull with an error saying it was
    /// cut short (what the earlier pages applied stays applied): a partial
    /// vault never reports as a complete pull. Requires unlock.
    pub fn pull_vault_paged(
        &self,
        tenant_b64: &str,
        mut next_page: impl FnMut(u64) -> Result<VaultPage, FfiError>,
    ) -> Result<FfiSyncReport, FfiError> {
        // The zero report of an empty apply: the shape stays the core's.
        let mut total = self.apply_pulled_vault(tenant_b64.to_owned(), Vec::new())?;
        let mut cursor = 0_u64;
        loop {
            let (objects, next) = next_page(cursor).map_err(|e| FfiError::Other {
                msg: format!(
                    "the pull of this vault was cut short after {} object(s) were applied: {e}",
                    total.applied
                ),
            })?;
            if !objects.is_empty() {
                let page = self.apply_pulled_vault(tenant_b64.to_owned(), objects)?;
                add_pulled(&mut total, &page);
            }
            match next {
                Some(next) => cursor = next,
                None => return Ok(total),
            }
        }
    }
}

/// One page holding all of `objects`, for the uniffi entry points that take
/// the vault's blobs in one piece.
fn one_page(objects: Vec<Vec<u8>>) -> impl FnMut(u64) -> Result<VaultPage, FfiError> {
    let mut pages = Some(objects);
    move |_| Ok((pages.take().unwrap_or_default(), None))
}

/// [`Core::inspect_shared_vault`]'s body: `objects` are the vault's raw delta
/// blobs in one piece.
pub(crate) fn inspect_objects(
    core: &Core,
    vault_id: &str,
    objects: Vec<Vec<u8>>,
) -> Result<Option<SharedVaultInfo>, FfiError> {
    core.inspect_shared_vault_paged(vault_id, one_page(objects))
}

/// [`Core::trust_shared_vault`]'s body: `objects` are the vault's raw delta
/// blobs in one piece.
pub(crate) fn trust_objects(
    core: &Core,
    vault_id: &str,
    objects: Vec<Vec<u8>>,
    expected_fingerprint: &str,
) -> Result<FfiTrustOutcome, FfiError> {
    core.trust_shared_vault_paged(vault_id, expected_fingerprint, one_page(objects))
}
