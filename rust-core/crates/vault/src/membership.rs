//! Membership, grants, and authority verification (spec §13 items 6–8, server-tz §5/§1.1).
//!
//! ## Model
//! A vault's membership = an **admin-signed manifest** for each `key_epoch`,
//! listing the entire member set (`ed25519_pub` + role). This is the authority:
//! the individual `Enc(VK, member_pub)` grants are bound to it. The client
//! **verifies the authority chain** (D1, Keybase-sigchain style): the manifest of
//! epoch N must be signed by an admin from the manifest of epoch N-1; genesis
//! (epoch 1) is anchored on the vault creator's pubkey (pinned at onboarding).
//!
//! ## Coexistence with local vaults (D2)
//! The predicate `author ∈ members@epoch` is applied **only** when a manifest
//! exists for the vault. Single-owner local vaults are unchanged — see `vault.rs`.
//!
//! ## Binding (D3)
//! ALL VK wrappings (per-member grants, the owner wrapping of the record, and
//! `vault.rs::seal_vk_to_recipient`) use a single domain-separated
//! `crypto::vk_wrap_info(vault_id, recipient_ed25519, key_epoch)` as the HPKE-info —
//! the envelope is opened exactly through [`open_grant`] (F17). VK rotation and epoch
//! transitions are IMPLEMENTED (`build_manifest`/`verify_manifest`/`verify_chain_to_epoch` +
//! `vault.rs::rotate_vk`): manifest@N+1 is signed by an admin from set@N, grants
//! are re-issued under VK'. Per-grant `not_after` is enforced on read by BOTH the
//! server AND the client ([`open_grant`], F16) — we do not trust the untrusted server to filter.

use sha2::{Digest, Sha256};
use unissh_crypto::{
    aead_decrypt, aead_encrypt, open_key_with_secret, seal_key_to_public,
    sign_account_state as crypto_sign_account_state, sign_version,
    verify_account_state as crypto_verify_account_state, verify_version, vk_wrap_info,
    AssociatedData, Ed25519VerifyingKey, SymmetricKey, VersionedObject, X25519PublicKey,
    X25519SecretKey,
};
use unissh_keychain::UnlockedKeyset;
use unissh_storage::{MemberRole, MembershipGrant, MembershipManifest, Storage};

use crate::error::VaultError;

/// Domain separator for the manifest payload (binding to schema/version).
const MANIFEST_DOMAIN: &[u8] = b"unissh-manifest-v1";
/// AAD marker of a manifest record (acting as `item_id`).
const MANIFEST_AAD_MARKER: &[u8] = b"__manifest__";
/// Domain separator for the grant payload.
const GRANT_DOMAIN: &[u8] = b"unissh-grant-v1";

/// One-byte role codec (storage keeps the role as `i64`, but the canonical
/// manifest payload needs a compact deterministic byte). `MemberRole` is
/// `#[non_exhaustive]` → wildcard branches for forward compatibility.
trait RoleByte {
    fn to_u8(self) -> u8;
    fn from_u8(v: u8) -> Option<MemberRole>;
}
impl RoleByte for MemberRole {
    fn to_u8(self) -> u8 {
        match self {
            MemberRole::Viewer => 0,
            MemberRole::Editor => 1,
            MemberRole::Admin => 2,
            _ => 0,
        }
    }
    fn from_u8(v: u8) -> Option<MemberRole> {
        match v {
            0 => Some(MemberRole::Viewer),
            1 => Some(MemberRole::Editor),
            2 => Some(MemberRole::Admin),
            _ => None,
        }
    }
}

/// One vault member in a manifest set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Canonical member-id = the keyset's Ed25519 pubkey (32 bytes).
    pub ed25519_pub: Vec<u8>,
    /// The member's role.
    pub role: MemberRole,
}

/// A verified member set for a specific epoch (the result of [`verify_manifest`]).
/// The authority is already confirmed — it can be relied on when checking records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMembers {
    #[allow(dead_code)]
    vault_id: Vec<u8>,
    key_epoch: u64,
    members: Vec<Member>,
}

impl VerifiedMembers {
    /// The epoch of this set.
    pub fn epoch(&self) -> u64 {
        self.key_epoch
    }
    /// Whether the set contains a member with the given Ed25519 pubkey.
    pub fn contains(&self, ed25519_pub: &[u8]) -> bool {
        self.members.iter().any(|m| m.ed25519_pub == ed25519_pub)
    }
    /// Whether the given key is an admin in this set.
    pub fn is_admin(&self, ed25519_pub: &[u8]) -> bool {
        self.members
            .iter()
            .any(|m| m.ed25519_pub == ed25519_pub && m.role == MemberRole::Admin)
    }
    /// Whether the member has the right to **author content** (item/vault records):
    /// Editor or Admin. A Viewer (read-only) does not. A non-member does not either.
    pub fn can_write(&self, ed25519_pub: &[u8]) -> bool {
        matches!(
            self.role_of(ed25519_pub),
            Some(MemberRole::Editor) | Some(MemberRole::Admin)
        )
    }
    /// The role of the member with the given Ed25519 pubkey (`None` if not a member).
    pub fn role_of(&self, ed25519_pub: &[u8]) -> Option<MemberRole> {
        self.members
            .iter()
            .find(|m| m.ed25519_pub == ed25519_pub)
            .map(|m| m.role)
    }
    /// A slice of the members (read-only).
    pub fn members(&self) -> &[Member] {
        &self.members
    }
}

/// AAD of a manifest record: `vault_id + "__manifest__" + key_epoch`.
fn manifest_aad(vault_id: &[u8], key_epoch: u64) -> AssociatedData {
    AssociatedData::new(vault_id.to_vec(), MANIFEST_AAD_MARKER.to_vec(), key_epoch)
}

/// Canonical (deterministic) serialization of the member set.
/// Members are sorted by `ed25519_pub` ASC — anti-equivocation: the same set
/// yields the same payload regardless of the input order.
fn canonical_member_payload(key_epoch: u64, members: &[Member]) -> Result<Vec<u8>, VaultError> {
    let mut sorted = members.to_vec();
    sorted.sort_by(|a, b| a.ed25519_pub.cmp(&b.ed25519_pub));
    // forbid duplicate member-ids (otherwise the role is ambiguous)
    for w in sorted.windows(2) {
        if w[0].ed25519_pub == w[1].ed25519_pub {
            return Err(VaultError::Format);
        }
    }
    if sorted.len() > u32::MAX as usize {
        return Err(VaultError::Format);
    }
    let mut out = Vec::new();
    out.extend_from_slice(MANIFEST_DOMAIN);
    out.extend_from_slice(&key_epoch.to_be_bytes());
    out.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for m in &sorted {
        if m.ed25519_pub.len() > u16::MAX as usize {
            return Err(VaultError::Format);
        }
        out.push(m.role.to_u8());
        out.extend_from_slice(&(m.ed25519_pub.len() as u16).to_be_bytes());
        out.extend_from_slice(&m.ed25519_pub);
    }
    Ok(out)
}

/// Parses the canonical payload back into a member set (for verification).
fn parse_member_payload(key_epoch: u64, payload: &[u8]) -> Result<Vec<Member>, VaultError> {
    let mut p = payload;
    let dom_len = MANIFEST_DOMAIN.len();
    if p.len() < dom_len + 8 + 4 || &p[..dom_len] != MANIFEST_DOMAIN {
        return Err(VaultError::Format);
    }
    p = &p[dom_len..];
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&p[..8]);
    if u64::from_be_bytes(epoch_bytes) != key_epoch {
        return Err(VaultError::Format);
    }
    p = &p[8..];
    let mut cnt_bytes = [0u8; 4];
    cnt_bytes.copy_from_slice(&p[..4]);
    let count = u32::from_be_bytes(cnt_bytes) as usize;
    p = &p[4..];
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        if p.is_empty() {
            return Err(VaultError::Format);
        }
        let role = MemberRole::from_u8(p[0]).ok_or(VaultError::Format)?;
        p = &p[1..];
        if p.len() < 2 {
            return Err(VaultError::Format);
        }
        let mut len_bytes = [0u8; 2];
        len_bytes.copy_from_slice(&p[..2]);
        let len = u16::from_be_bytes(len_bytes) as usize;
        p = &p[2..];
        if p.len() < len {
            return Err(VaultError::Format);
        }
        members.push(Member {
            ed25519_pub: p[..len].to_vec(),
            role,
        });
        p = &p[len..];
    }
    if !p.is_empty() {
        return Err(VaultError::Format);
    }
    Ok(members)
}

/// Builds a signed membership manifest for epoch `key_epoch`.
///
/// The signature is `sign_version(admin.signing, VersionedObject(AAD(vault_id,
/// "__manifest__", key_epoch), canonical_member_payload))` — it reuses the
/// existing record-signing idiom (no new crypto).
pub fn build_manifest(
    admin_keyset: &UnlockedKeyset,
    vault_id: &[u8],
    key_epoch: u64,
    members: &[Member],
) -> Result<MembershipManifest, VaultError> {
    let payload = canonical_member_payload(key_epoch, members)?;
    let vo = VersionedObject::from_content(manifest_aad(vault_id, key_epoch), &payload);
    let signature = sign_version(&admin_keyset.signing.signing, &vo)?;
    Ok(MembershipManifest {
        vault_id: vault_id.to_vec(),
        key_epoch,
        manifest_blob: payload,
        signature,
        author_pubkey: admin_keyset.signing.verifying.to_bytes().to_vec(),
    })
}

/// Verifies a manifest: (1) the signature is valid under `author_pubkey`;
/// (2) **authority** (D1) — `author_pubkey` is an admin in `prev` (or, for genesis,
/// == `genesis_owner`); (3) epoch monotonicity. Returns the verified set.
///
/// `prev` = `None` ⇒ this is genesis (expects `key_epoch == 1`, signer ==
/// `genesis_owner`). `prev = Some(v)` ⇒ expects `key_epoch == v.epoch()+1`
/// and the signer is an admin in `v`.
pub fn verify_manifest(
    manifest: &MembershipManifest,
    vault_id: &[u8],
    prev: Option<&VerifiedMembers>,
    genesis_owner: &[u8],
) -> Result<VerifiedMembers, VaultError> {
    if manifest.vault_id != vault_id {
        return Err(VaultError::Format);
    }
    // 1) signature under the claimed author
    let author =
        Ed25519VerifyingKey::from_bytes(&manifest.author_pubkey).map_err(|_| VaultError::Format)?;
    let vo = VersionedObject::from_content(
        manifest_aad(vault_id, manifest.key_epoch),
        &manifest.manifest_blob,
    );
    verify_version(&author, &vo, &manifest.signature).map_err(|_| VaultError::SignatureInvalid)?;

    // 2) epoch monotonicity + 3) authority
    match prev {
        None => {
            if manifest.key_epoch != 1 {
                return Err(VaultError::EpochInvalid);
            }
            if manifest.author_pubkey != genesis_owner {
                return Err(VaultError::AuthorityInvalid);
            }
        }
        Some(prev) => {
            if manifest.key_epoch != prev.epoch().saturating_add(1) {
                return Err(VaultError::EpochInvalid);
            }
            if !prev.is_admin(&manifest.author_pubkey) {
                return Err(VaultError::AuthorityInvalid);
            }
        }
    }

    let members = parse_member_payload(manifest.key_epoch, &manifest.manifest_blob)?;
    Ok(VerifiedMembers {
        vault_id: vault_id.to_vec(),
        key_epoch: manifest.key_epoch,
        members,
    })
}

// --- per-member grants (D3) ---

/// Grant AAD: `vault_id + member_ed25519_pub + key_epoch`.
fn grant_aad(vault_id: &[u8], member_ed25519_pub: &[u8], key_epoch: u64) -> AssociatedData {
    AssociatedData::new(vault_id.to_vec(), member_ed25519_pub.to_vec(), key_epoch)
}

/// The signed grant content:
/// `GRANT_DOMAIN || role:u8 || not_after:i64be(8) || wrapped_vk`.
/// `not_after` (fixed 8 bytes BE; sentinel `<=0` = no expiry) is INSIDE the
/// signature → the validity period is authenticated, the server cannot forge it.
/// The width is fixed because `wrapped_vk` has no length prefix.
fn grant_signed_content(role: MemberRole, not_after: i64, wrapped_vk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(GRANT_DOMAIN.len() + 1 + 8 + wrapped_vk.len());
    out.extend_from_slice(GRANT_DOMAIN);
    out.push(role.to_u8());
    out.extend_from_slice(&not_after.to_be_bytes());
    out.extend_from_slice(wrapped_vk);
    out
}

/// Builds a signed per-member grant: wraps `vk` under the recipient's X25519
/// pubkey with the binding `vk_wrap_info(vault_id, member_ed25519_pub, key_epoch)`
/// (D3), then signs `(role || wrapped_vk)` under the grant AAD.
#[allow(clippy::too_many_arguments)]
pub fn build_grant(
    admin_keyset: &UnlockedKeyset,
    vault_id: &[u8],
    recipient_x25519_pub: &[u8],
    member_ed25519_pub: &[u8],
    role: MemberRole,
    key_epoch: u64,
    vk: &SymmetricKey,
) -> Result<MembershipGrant, VaultError> {
    let recipient =
        X25519PublicKey::from_bytes(recipient_x25519_pub).map_err(|_| VaultError::Format)?;
    let info = vk_wrap_info(vault_id, member_ed25519_pub, key_epoch)?;
    let wrapped_vk = seal_key_to_public(&recipient, vk, &info)?;

    // build_grant issues a grant WITHOUT expiry (not_after=0). Per-grant expiry
    // is set by a separate path (e.g. the admin panel via wasm) by constructing
    // a grant with not_after != 0; the format and the server-side read-enforce support it.
    let not_after = 0i64;
    let content = grant_signed_content(role, not_after, &wrapped_vk);
    let vo =
        VersionedObject::from_content(grant_aad(vault_id, member_ed25519_pub, key_epoch), &content);
    let signature = sign_version(&admin_keyset.signing.signing, &vo)?;
    Ok(MembershipGrant {
        vault_id: vault_id.to_vec(),
        member_pubkey: member_ed25519_pub.to_vec(),
        key_epoch,
        role,
        not_after,
        wrapped_vk,
        signature,
        author_pubkey: admin_keyset.signing.verifying.to_bytes().to_vec(),
    })
}

/// Verifies a grant: (1) the signature is valid under `author_pubkey`; (2) the
/// author is an admin in the verified set `members` (whose epoch matches the
/// grant's epoch); (3) **defense-in-depth consistency** — the grant's recipient
/// (`member_pubkey`) is a member of the set AND its role in the manifest matches
/// `grant.role`.
///
/// (3) does not elevate authority (the read right comes from the manifest, not from
/// the grant), but it prevents an authorized admin from issuing a VK envelope to a
/// non-member or assigning the recipient a role that diverges from the manifest —
/// removing a source of ambiguity before member-via-grant VK acquisition (P4) starts
/// relying on grants.
pub fn verify_grant(
    grant: &MembershipGrant,
    vault_id: &[u8],
    members: &VerifiedMembers,
) -> Result<(), VaultError> {
    if grant.vault_id != vault_id {
        return Err(VaultError::Format);
    }
    if grant.key_epoch != members.epoch() {
        return Err(VaultError::EpochInvalid);
    }
    let author =
        Ed25519VerifyingKey::from_bytes(&grant.author_pubkey).map_err(|_| VaultError::Format)?;
    let content = grant_signed_content(grant.role, grant.not_after, &grant.wrapped_vk);
    let vo = VersionedObject::from_content(
        grant_aad(vault_id, &grant.member_pubkey, grant.key_epoch),
        &content,
    );
    verify_version(&author, &vo, &grant.signature).map_err(|_| VaultError::SignatureInvalid)?;
    if !members.is_admin(&grant.author_pubkey) {
        return Err(VaultError::AuthorityInvalid);
    }
    // (3) the recipient must be a member of the set...
    let recipient_role = members
        .role_of(&grant.member_pubkey)
        .ok_or(VaultError::NotAMember)?;
    // ...and the grant's role must match its role in the manifest.
    if recipient_role != grant.role {
        return Err(VaultError::AuthorityInvalid);
    }
    Ok(())
}

/// Opens a grant — the recipient unwraps the VK with their X25519 secret.
/// `member_ed25519_pub`/`key_epoch` must match the grant's binding
/// (`vk_wrap_info`); otherwise — `Decrypt`.
///
/// `now` (unix seconds) enforces the per-grant `not_after` LOCALLY (F16): an
/// expired grant is not opened, even if the untrusted server did hand it over. Sentinel
/// `not_after <= 0` = no expiry.
pub fn open_grant(
    grant: &MembershipGrant,
    vault_id: &[u8],
    recipient_secret: &X25519SecretKey,
    member_ed25519_pub: &[u8],
    key_epoch: u64,
    now: i64,
) -> Result<SymmetricKey, VaultError> {
    if grant.not_after > 0 && now >= grant.not_after {
        return Err(VaultError::GrantExpired);
    }
    let info = vk_wrap_info(vault_id, member_ed25519_pub, key_epoch)?;
    open_key_with_secret(recipient_secret, &grant.wrapped_vk, &info)
        .map_err(|_| VaultError::Decrypt)
}

// `parse_verified` (only a self-signature check, without the D1 chain) was removed
// in the P3 review: the read path no longer trusts the mere presence of a manifest
// in storage — see `verify_chain_to_epoch`.

/// Public re-export for the sync engine (P6): re-verifies the **full D1 chain**
/// of membership from genesis (epoch 1) up to `target_epoch` inclusive, re-reading
/// each manifest from storage and checking it via [`verify_manifest`] against the
/// previous verified set (genesis is anchored on `genesis_owner`). Returns the
/// verified set of `target_epoch`.
///
/// This is a **self-contained** read path under the untrusted-DB / sync-ready threat
/// model (ARCH.md): it does NOT trust the fact that a manifest sits in storage — it
/// proves the authority of each epoch from the pinned anchor. Thus an injected
/// self-consistent manifest (author=attacker, members=[attacker]) at any epoch is
/// rejected, because the chain from genesis to attacker does not lead there.
///
/// Any gap in the chain (a missing intermediate manifest), a tampered genesis
/// (signer ≠ `genesis_owner`), or a break in the sigchain → an error
/// (`AuthorityInvalid`/`EpochInvalid`/…), not silent trust in storage.
///
/// `target_epoch == 0` (the single-owner fallback, no manifest present) does not
/// reach here — the caller decides that (`verify_record_authority`).
pub fn verify_chain_to_epoch(
    storage: &Storage,
    vault_id: &[u8],
    target_epoch: u64,
    genesis_owner: &[u8],
) -> Result<VerifiedMembers, VaultError> {
    if target_epoch == 0 {
        return Err(VaultError::EpochInvalid);
    }
    let mut prev: Option<VerifiedMembers> = None;
    for epoch in 1..=target_epoch {
        let manifest = storage
            .get_membership_manifest(vault_id, epoch)?
            // A gap in the chain — authority is unprovable (storage cannot be trusted).
            .ok_or(VaultError::AuthorityInvalid)?;
        let verified = verify_manifest(&manifest, vault_id, prev.as_ref(), genesis_owner)?;
        prev = Some(verified);
    }
    // target_epoch >= 1 ⇒ the loop ran at least once ⇒ prev is Some.
    prev.ok_or(VaultError::EpochInvalid)
}

// --- member-pubkey pinning (TOFU) + OOB fingerprint (spec §13 item 7) ---

/// A member's Ed25519 pubkey fingerprint for OOB confirmation (like Bitwarden Confirm /
/// 1Password fingerprint): hex(SHA-256(ed25519_pub)). 64 hex characters.
pub fn member_fingerprint(ed25519_pub: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ed25519_pub);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Pins a member pubkey (TOFU modeled on `known_hosts`) and verifies the match
/// on re-presentation (spec §13 item 7). The first presentation under `account_id`
/// is pinned; subsequent ones must match **exactly**, otherwise `PinMismatch`
/// (protection against pubkey substitution by a malicious server before key-transparency).
///
/// `account_id` is open metadata (the member's id within the instance). Returns `Ok`
/// both on the first pin and on a match. A mismatch does **not** overwrite the trusted
/// key — `pin_member_key` (UPSERT) is called only on the first pin.
pub fn pin_and_verify_member(
    storage: &Storage,
    account_id: &[u8],
    presented_ed25519_pub: &[u8],
) -> Result<(), VaultError> {
    match storage.get_pinned_member_key(account_id)? {
        Some(pinned) => {
            if pinned.member_pubkey == presented_ed25519_pub {
                Ok(())
            } else {
                Err(VaultError::PinMismatch)
            }
        }
        None => {
            let fp = member_fingerprint(presented_ed25519_pub);
            storage.pin_member_key(account_id, presented_ed25519_pub, &fp)?;
            Ok(())
        }
    }
}

/// HPKE info string for self-sealing the per-account state payload (domain binding).
const ACCOUNT_SEAL_INFO: &[u8] = b"unissh-account-state-seal-v1";

/// Signs the per-account state (A3) with a dedicated domain (crypto). `payload` is
/// an already self-sealed blob (encryption is [`seal_account_payload`]). Returns the signature blob.
pub fn sign_account_state(
    keyset: &UnlockedKeyset,
    version: u64,
    payload: &[u8],
) -> Result<Vec<u8>, VaultError> {
    Ok(crypto_sign_account_state(
        &keyset.signing.signing,
        version,
        payload,
    ))
}

/// Verifies the per-account state signature (A3) against `author_pubkey`.
pub fn verify_account_state(
    author_pubkey: &[u8],
    version: u64,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), VaultError> {
    let author = Ed25519VerifyingKey::from_bytes(author_pubkey).map_err(|_| VaultError::Format)?;
    crypto_verify_account_state(&author, version, payload, signature)
        .map_err(|_| VaultError::SignatureInvalid)
}

/// Self-seals the per-account state payload under the ACCOUNT's X25519 key (A3.2, hybrid:
/// HPKE wrapping of a random symkey to one's own pub + AEAD payload under it). Only
/// one's own keyset can open it; the server does not read the payload. Format: `put(wrapped) || put(ct)`.
pub fn seal_account_payload(
    keyset: &UnlockedKeyset,
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let symkey = SymmetricKey::generate();
    let wrapped = seal_key_to_public(&keyset.encryption.public, &symkey, ACCOUNT_SEAL_INFO)
        .map_err(|_| VaultError::Format)?;
    let aad = AssociatedData::new(Vec::new(), ACCOUNT_SEAL_INFO.to_vec(), 0);
    let ct = aead_encrypt(&symkey, plaintext, &aad).map_err(|_| VaultError::Format)?;
    let mut out = Vec::with_capacity(8 + wrapped.len() + ct.len());
    put_len_prefixed(&mut out, &wrapped)?;
    put_len_prefixed(&mut out, &ct)?;
    Ok(out)
}

/// Opens a self-sealed payload with one's own keyset (the inverse of [`seal_account_payload`]).
pub fn open_account_payload(keyset: &UnlockedKeyset, sealed: &[u8]) -> Result<Vec<u8>, VaultError> {
    let (wrapped, rest) = take_len_prefixed(sealed)?;
    let (ct, rest2) = take_len_prefixed(rest)?;
    if !rest2.is_empty() {
        return Err(VaultError::Format);
    }
    let symkey = open_key_with_secret(&keyset.encryption.secret, wrapped, ACCOUNT_SEAL_INFO)
        .map_err(|_| VaultError::Format)?;
    let aad = AssociatedData::new(Vec::new(), ACCOUNT_SEAL_INFO.to_vec(), 0);
    aead_decrypt(&symkey, ct, &aad).map_err(|_| VaultError::Format)
}

fn put_len_prefixed(out: &mut Vec<u8>, b: &[u8]) -> Result<(), VaultError> {
    let len = u32::try_from(b.len()).map_err(|_| VaultError::Format)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn take_len_prefixed(b: &[u8]) -> Result<(&[u8], &[u8]), VaultError> {
    if b.len() < 4 {
        return Err(VaultError::Format);
    }
    let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let rest = &b[4..];
    if rest.len() < len {
        return Err(VaultError::Format);
    }
    Ok((&rest[..len], &rest[len..]))
}

/// Pins a per-vault trust anchor (the genesis-owner of a vault created by a teammate),
/// modeled on [`pin_and_verify_member`]: the first presentation under `vault_id` is pinned
/// (TOFU via an OOB fingerprint), subsequent ones must match **exactly**, otherwise
/// `PinMismatch` (protection against a silent vault→owner rebinding by a malicious server).
/// A mismatch does **not** overwrite the trusted anchor.
///
/// `presented_genesis_owner` — the vault's Ed25519 creator-pubkey (the author of the genesis
/// manifest at epoch 1), obtained OOB, NOT from the untrusted transport.
pub fn pin_and_verify_vault_anchor(
    storage: &Storage,
    vault_id: &[u8],
    presented_genesis_owner: &[u8],
) -> Result<(), VaultError> {
    match storage.get_vault_trust_anchor(vault_id)? {
        Some(anchor) => {
            if anchor.genesis_owner_pubkey == presented_genesis_owner {
                Ok(())
            } else {
                Err(VaultError::PinMismatch)
            }
        }
        None => {
            storage.set_vault_trust_anchor(vault_id, presented_genesis_owner)?;
            Ok(())
        }
    }
}

// --- add_member flow (6a): build+verify, then persist atomically ---

/// Adds/updates the vault's membership at epoch `key_epoch`: builds the manifest and
/// per-member grants, **verifies** them (the manifest against the D1 chain over
/// `prev`/`genesis_owner`; each grant against the verified set), and only then
/// persists via storage. Atomic (one transaction): the manifest + all grants are
/// written together.
///
/// `prev` = the verified set of the previous epoch (`None` for genesis). `grants` —
/// `(recipient_x25519_pub, member_ed25519_pub, role)` per recipient of a VK
/// wrapping. `vk` — the current Vault Key (wrapped under each recipient).
///
/// This is the write path for a manifest into storage with verification on receipt
/// (build+verify before persist). **The read path does NOT rely on it** as the
/// source of truth: under the untrusted-DB threat model it self-sufficiently
/// re-verifies the D1 chain from genesis (`verify_record_authority` →
/// `verify_chain_to_epoch`). The check here is defense-in-depth and consistency
/// (we don't write a knowingly broken manifest).
///
/// VK rotation / epoch transition (generating a new VK, re-wrapping item keys,
/// raising the epoch floor) is **P4**, not done here.
#[allow(clippy::too_many_arguments)]
pub fn add_member(
    storage: &Storage,
    admin_keyset: &UnlockedKeyset,
    vault_id: &[u8],
    key_epoch: u64,
    prev: Option<&VerifiedMembers>,
    genesis_owner: &[u8],
    members: &[Member],
    grants: &[(Vec<u8>, Vec<u8>, MemberRole)],
    vk: &SymmetricKey,
) -> Result<VerifiedMembers, VaultError> {
    // 1) build + verify the manifest (D1 authority/epoch)
    let manifest = build_manifest(admin_keyset, vault_id, key_epoch, members)?;
    let verified = verify_manifest(&manifest, vault_id, prev, genesis_owner)?;

    // 2) build + verify the grants against the verified set
    let mut built = Vec::with_capacity(grants.len());
    for (recip_x, member_ed, role) in grants {
        let g = build_grant(
            admin_keyset,
            vault_id,
            recip_x,
            member_ed,
            *role,
            key_epoch,
            vk,
        )?;
        verify_grant(&g, vault_id, &verified)?;
        built.push(g);
    }

    // 3) persist atomically (defense-in-depth: on receipt we write only
    //    verified manifests; the read path re-verifies the chain anyway)
    storage.transaction(|| {
        storage.put_membership_manifest(&manifest)?;
        for g in &built {
            storage.put_membership_grant(g)?;
        }
        // Local admin write → must push. (The sync-receive path applies membership
        // via storage.put_membership_* directly, so it never marks dirty here.)
        storage.mark_membership_dirty(vault_id, key_epoch)?;
        Ok::<(), VaultError>(())
    })?;

    Ok(verified)
}
