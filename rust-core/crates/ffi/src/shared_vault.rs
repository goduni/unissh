//! Trusting a vault a teammate shared with this account (A0, share-accept).
//!
//! Sync verifies a vault against its pinned genesis owner (the author of the
//! epoch-1 membership manifest) and, for a vault with no pin, against this
//! account's own keyset. So a vault a teammate created is rejected until its
//! owner is pinned, and the pin must come from the user, who confirms the
//! owner's fingerprint out of band: the server is never trusted to say who
//! owns a vault.
//!
//! This module gives the user what to confirm. [`Core::inspect_shared_vault`]
//! reads the vault's membership objects as the server serves them, verifies
//! the whole manifest chain in memory against its genesis author as the
//! candidate owner, and checks that the latest epoch holds a grant this
//! account can open. It writes nothing: the pin is
//! [`Core::pin_vault_genesis_owner`], after the user compared fingerprints.
//!
//! [`Core::pull_vault_paged`] is the targeted single-vault pull that brings
//! the vault in after the pin. It does not move the pull cursor — the objects
//! an earlier sync rejected advanced it, so an ordinary sync never sees them
//! again.

use std::collections::BTreeMap;

use unissh_storage::{MembershipGrant, MembershipManifest};
use unissh_sync::SyncObject;
use unissh_vault::{
    member_fingerprint, open_grant, verify_grant, verify_manifest, VerifiedMembers,
};

use super::{decode_vid, Core, CoreState, FfiError, FfiMemberRole, FfiSyncReport};

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
    /// The owner's fingerprint in the `member_fingerprint` format
    /// (hex(SHA-256(ed25519_pub)), 64 characters): what the user compares with
    /// the fingerprint the owner reads out from their own device.
    pub fingerprint: String,
    /// This account's role at the latest epoch of the chain.
    pub my_role: FfiMemberRole,
    /// The latest membership epoch the chain verified up to.
    pub epoch: u64,
    /// What this device has pinned for the vault.
    pub trust: FfiVaultTrust,
}

/// The vault's membership objects, kept from the pages as they come.
#[derive(Default)]
struct Membership {
    /// Manifests by epoch; an epoch the server serves twice keeps both.
    manifests: BTreeMap<u64, Vec<MembershipManifest>>,
    grants: Vec<MembershipGrant>,
}

impl Membership {
    /// Keeps the manifests and grants of `vault_id` among `objects` (raw
    /// delta blobs); everything else, and a blob that does not parse, is
    /// dropped, as the untrusted pull path drops it.
    fn take(&mut self, vault_id: &[u8], objects: &[Vec<u8>]) {
        for blob in objects {
            let Ok(object) = SyncObject::from_bytes(blob) else {
                continue;
            };
            if let SyncObject::MembershipManifest(m) = &object {
                if m.vault_id == vault_id {
                    let at = self.manifests.entry(m.key_epoch).or_default();
                    if !at.contains(m) {
                        at.push(m.clone());
                    }
                }
            } else if let SyncObject::MembershipGrant(g) = &object {
                if g.vault_id == vault_id {
                    self.grants.push(g.clone());
                }
            }
        }
    }
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

/// Verifies `membership` of `vault_id` for the account `state` holds.
///
/// 1. The genesis manifest (epoch 1) names the candidate owner, its author.
///    Two epoch-1 manifests by different authors are refused: the server is
///    offering a second owner, and no choice between them is safe to make.
/// 2. Every epoch from 1 to the highest the server serves must verify against
///    the one before it (D1, `verify_manifest`), with no gap. A manifest that
///    does not chain is refused rather than skipped: the chain is what the
///    sync will hold the vault to after the pin.
/// 3. The latest epoch must hold a grant to this account that verifies
///    against that epoch's member set and opens with this account's key —
///    proof the owner shared the vault with exactly this keyset.
fn inspect(
    state: &CoreState,
    vault_id: &[u8],
    membership: &Membership,
) -> Result<Inspected, FfiError> {
    let own_ed = state.keyset.signing.verifying.to_bytes();
    let genesis = membership.manifests.get(&1);
    let owner = genesis
        .and_then(|at| at.first())
        .ok_or_else(|| refused("the server holds no genesis manifest for it"))?
        .author_pubkey
        .clone();
    if genesis
        .into_iter()
        .flatten()
        .any(|m| m.author_pubkey != owner)
    {
        return Err(refused("the server presents two different creators for it"));
    }
    if owner == own_ed {
        return Ok(Inspected::Own);
    }

    let latest = membership
        .manifests
        .keys()
        .next_back()
        .copied()
        .unwrap_or(1);
    let mut verified: Option<VerifiedMembers> = None;
    for epoch in 1..=latest {
        let candidates = membership
            .manifests
            .get(&epoch)
            .ok_or_else(|| refused("its membership chain has a gap"))?;
        let mut last_err = None;
        let mut next = None;
        for m in candidates {
            match verify_manifest(m, vault_id, verified.as_ref(), &owner) {
                Ok(members) => {
                    next = Some(members);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        match (next, last_err) {
            (Some(members), _) => verified = Some(members),
            (None, Some(e)) => {
                return Err(refused(&format!(
                    "its membership at epoch {epoch} does not verify ({e})"
                )))
            }
            (None, None) => return Err(refused("its membership chain has a gap")),
        }
    }
    let members = verified.ok_or_else(|| refused("its membership chain has a gap"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        // Fail closed, as `Vault::open` does: an unreadable clock expires
        // every grant that carries an expiry.
        .unwrap_or(i64::MAX);
    let grant = membership
        .grants
        .iter()
        .filter(|g| g.member_pubkey == own_ed && g.key_epoch == members.epoch())
        .find(|g| {
            verify_grant(g, vault_id, &members).is_ok()
                && open_grant(
                    g,
                    vault_id,
                    &state.keyset.encryption.secret,
                    &own_ed,
                    members.epoch(),
                    now,
                )
                .is_ok()
        })
        .ok_or_else(|| refused("it grants this account nothing at its latest epoch"))?;

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
        my_role: FfiMemberRole::from_core(grant.role),
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

/// One page of a single vault's objects: `next_page(cursor)` returns the raw
/// object blobs that follow `cursor` (0 for the first page) and the cursor of
/// the next page, `None` after the last one.
pub type VaultPage = (Vec<Vec<u8>>, Option<u64>);

impl Core {
    /// [`Core::inspect_shared_vault`] over objects fetched page by page (see
    /// [`VaultPage`]): only the vault's manifests and grants are kept from the
    /// pages, so the vault's items are never held in memory.
    ///
    /// `Ok(None)` — this account created the vault itself: it needs no trust.
    /// Requires unlock. Writes nothing.
    pub fn inspect_shared_vault_paged(
        &self,
        vault_id: &str,
        mut next_page: impl FnMut(u64) -> VaultPage,
    ) -> Result<Option<SharedVaultInfo>, FfiError> {
        let vid = decode_vid(vault_id)?;
        let mut membership = Membership::default();
        let mut cursor = 0_u64;
        loop {
            let (objects, next) = next_page(cursor);
            membership.take(&vid, &objects);
            match next {
                Some(next) => cursor = next,
                None => break,
            }
        }
        self.with_state(|state| match inspect(state, &vid, &membership)? {
            Inspected::Own => Ok(None),
            Inspected::Shared(info) => Ok(Some(info)),
        })
    }

    /// **Pull ONE vault** page by page (see [`VaultPage`]): each page goes
    /// through [`Core::apply_pulled_vault`] — verify-before-apply, born-bound
    /// to `tenant_b64` — before the next is asked for, so the vault is never
    /// held in memory whole; a later page verifies against what the earlier
    /// ones applied. The per-tenant pull cursor does not move, which makes this
    /// the way to bring in a vault an earlier sync rejected (a teammate's
    /// vault before its owner was pinned). The report is the sum over the
    /// pages. Requires unlock.
    pub fn pull_vault_paged(
        &self,
        tenant_b64: &str,
        mut next_page: impl FnMut(u64) -> VaultPage,
    ) -> Result<FfiSyncReport, FfiError> {
        let mut total: Option<FfiSyncReport> = None;
        let mut cursor = 0_u64;
        loop {
            let (objects, next) = next_page(cursor);
            if !objects.is_empty() {
                let page = self.apply_pulled_vault(tenant_b64.to_owned(), objects)?;
                if let Some(sum) = total.as_mut() {
                    add_pulled(sum, &page);
                } else {
                    total = Some(page);
                }
            }
            match next {
                Some(next) => cursor = next,
                None => break,
            }
        }
        match total {
            Some(total) => Ok(total),
            // Nothing came: the zero report of an empty apply.
            None => self.apply_pulled_vault(tenant_b64.to_owned(), Vec::new()),
        }
    }
}

/// [`Core::inspect_shared_vault`]'s body: `objects` are the vault's raw delta
/// blobs in one piece.
pub(crate) fn inspect_objects(
    core: &Core,
    vault_id: &str,
    objects: Vec<Vec<u8>>,
) -> Result<SharedVaultInfo, FfiError> {
    let mut pages = Some(objects);
    core.inspect_shared_vault_paged(vault_id, |_| (pages.take().unwrap_or_default(), None))?
        .ok_or_else(|| FfiError::Other {
            msg: "this vault was created by this account: it needs no trust".into(),
        })
}
