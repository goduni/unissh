//! Regression negatives from the P6 adversarial review (Milestone 2).
//!
//! Each test reproduces a specific proven defect and locks in the fix:
//! 1. keyset: a tampered header `generation` does NOT poison `keyset_gen_floor`;
//! 2. membership-manifest: an equivocating manifest@epoch does NOT overwrite
//!    the already-trusted one (anti-equivocation → Conflict, not a silent UPSERT);
//! 3. manifest happy-path + forged/broken-chain (previously uncovered);
//! 4. grant happy-path + author-not-admin / recipient-not-member.

use unissh_crypto::{KdfParams, SymmetricKey};
use unissh_keychain::{create_account, keyset_gen_floor, UnlockedKeyset};
use unissh_storage::{MemberRole, Storage};
use unissh_sync::{
    sync_pull, AccountStateObject, AuditObject, InMemoryTransport, RejectReason, SyncContext,
    SyncObject, SyncTransport,
};
use unissh_vault::{
    build_grant, build_manifest, sign_account_state, verify_manifest, Member, Vault,
};

fn test_params() -> KdfParams {
    // ≥ the OWASP minimum (19 MiB / t=2): the sync keyset object is parsed via from_blob.
    KdfParams {
        mem_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
        salt: vec![1u8; 16],
    }
}

fn account(db_key: &[u8; 32]) -> (Storage, UnlockedKeyset) {
    let s = Storage::open_in_memory(db_key).unwrap();
    let (_sk, _enc, unlocked) = create_account(Some(b"pw"), test_params()).unwrap();
    (s, unlocked)
}

fn genesis(unlocked: &UnlockedKeyset) -> Vec<u8> {
    unlocked.signing.verifying.to_bytes().to_vec()
}

fn ctx(unlocked: &UnlockedKeyset) -> SyncContext {
    SyncContext {
        genesis_owner: genesis(unlocked),
        tenant: b"oracle-tenant".to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Defect 1 (MAJOR): apply-before-verify in process_keyset.
// The attacker takes a genuine keyset blob and corrupts the header bytes [2..6]
// (the unauthenticated `generation`) to u32::MAX. The engine previously raised
// keyset_gen_floor from this un-numbered field → permanent lockout
// of the legitimate keyset via unlock_account_checked GenerationRollback.
// Fix: the floor is NOT moved from an unauthenticated header.
// ---------------------------------------------------------------------------
#[test]
fn tampered_keyset_generation_does_not_poison_gen_floor() {
    let (sb, _kb) = account(&[20u8; 32]);
    // A fresh victim account + its genuine keyset blob (generation == 1).
    let (_sk, enc, victim) = create_account(Some(b"pw"), test_params()).unwrap();
    let mut blob = enc.to_bytes().unwrap();
    // Corrupt the header bytes [2..6] → u32::MAX (generation). AEAD/wrapped_keyset
    // are left untouched: the blob stays "genuine", but the header lies.
    blob[2..6].copy_from_slice(&u32::MAX.to_be_bytes());

    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::Keyset(blob)]).unwrap();

    let floor_before = keyset_gen_floor(&sb).unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&victim)).unwrap();
    let floor_after = keyset_gen_floor(&sb).unwrap();

    // The floor must NOT be poisoned by a value from the unauthenticated header.
    assert_ne!(
        floor_after,
        Some(u64::from(u32::MAX)),
        "gen_floor poisoned by unauthenticated header: {:?}",
        floor_after
    );
    assert_eq!(
        floor_after, floor_before,
        "gen_floor must not advance from unauthenticated keyset header"
    );
    // And the keyset object must not count as "applied" (there is nothing to trustedly apply).
    assert_eq!(r.applied, 0, "report={:?}", r);
}

// ---------------------------------------------------------------------------
// Defect 2 (MAJOR): merge/overwrite of a trusted manifest.
// process_manifest previously UPSERTed the manifest BEFORE checking and re-verified the chain
// only up to its own epoch. An equivocating manifest@epoch (validly signed
// by the genesis owner, but with a DIFFERENT member-set) silently overwrote the already-trusted one.
// Fix: an incoming manifest@epoch that differs from the already-stored one is rejected
// (anti-equivocation) instead of being UPSERTed.
// ---------------------------------------------------------------------------
#[test]
fn equivocating_manifest_does_not_overwrite_trusted() {
    let (sb, _kb) = account(&[21u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    let vid = b"vault-eq".to_vec();
    let gen = genesis(&owner);

    // A second legitimate member who IS in the trusted manifest@1.
    let (_sk2, _enc2, member) = create_account(Some(b"x"), test_params()).unwrap();
    let member_pub = genesis(&member);

    // The trusted genesis manifest@1: {owner=Admin, member=Editor}.
    let trusted = build_manifest(
        &owner,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: gen.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: member_pub.clone(),
                role: MemberRole::Editor,
            },
        ],
    )
    .unwrap();
    // Self-check: the manifest is valid as genesis.
    verify_manifest(&trusted, &vid, None, &gen).unwrap();

    // Deliver and apply the trusted manifest@1 on B.
    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::MembershipManifest(trusted.clone())])
        .unwrap();
    let r1 = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    assert_eq!(r1.applied, 1, "trusted manifest not applied: {:?}", r1);
    let stored1 = sb.get_membership_manifest(&vid, 1).unwrap().unwrap();
    assert_eq!(stored1.manifest_blob, trusted.manifest_blob);

    // Equivocating manifest@1: also validly signed by the genesis owner, but the member
    // is DROPPED (a different member-set, the same epoch). Previously it silently overwrote.
    let equivocating = build_manifest(
        &owner,
        &vid,
        1,
        &[Member {
            ed25519_pub: gen.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    assert_ne!(equivocating.manifest_blob, trusted.manifest_blob);

    // The same transport t: the new object gets seq > cursor B → it is actually
    // delivered in the next pull's delta.
    t.push_objects(&[SyncObject::MembershipManifest(equivocating.clone())])
        .unwrap();
    let r2 = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();

    // The stored manifest@1 is UNCHANGED (the member is still there).
    let stored2 = sb.get_membership_manifest(&vid, 1).unwrap().unwrap();
    assert_eq!(
        stored2.manifest_blob, trusted.manifest_blob,
        "trusted manifest was silently overwritten by equivocating one"
    );
    // The equivocating one is NOT applied; it surfaces as a conflict OR a reject (not silently).
    assert_eq!(r2.applied, 0, "equivocating manifest applied: {:?}", r2);
    assert!(
        !r2.conflicts.is_empty() || !r2.rejected.is_empty(),
        "equivocation surfaced silently: {:?}",
        r2
    );
}

// ---------------------------------------------------------------------------
// Defect 3 (MINOR coverage): process_manifest happy-path.
// ---------------------------------------------------------------------------
#[test]
fn manifest_happy_path_applied() {
    let (sb, _kb) = account(&[22u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    let vid = b"vault-hp".to_vec();
    let gen = genesis(&owner);

    let m = build_manifest(
        &owner,
        &vid,
        1,
        &[Member {
            ed25519_pub: gen.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();

    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::MembershipManifest(m.clone())])
        .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    assert_eq!(r.applied, 1, "report={:?}", r);
    assert!(sb.get_membership_manifest(&vid, 1).unwrap().is_some());
}

// ---------------------------------------------------------------------------
// A0: a vault created by a TEAMMATE (genesis-manifest@1 signed by THEIR key, not
// the puller's local keyset) is rejected on sync as AuthorityFailed — until its
// genesis owner is pinned per-vault. After an OOB pin (set_vault_trust_anchor) the
// same manifest applies: the engine anchors authority on the per-vault pin, not on
// the local keyset.
// ---------------------------------------------------------------------------
#[test]
fn teammate_vault_applied_only_after_anchor_pin() {
    // Local puller: keyset kb (≠ owner). ctx.genesis_owner = kb.
    let (sb, kb) = account(&[41u8; 32]);
    // The teammate who created the vault: a different account.
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    let vid = b"vault-teammate".to_vec();
    let owner_pub = genesis(&owner);

    let m = build_manifest(
        &owner,
        &vid,
        1,
        &[Member {
            ed25519_pub: owner_pub.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();

    // (1) without a pin: there is no per-vault anchor → fallback to the local keyset kb ≠ owner →
    // genesis-manifest@1 fails authority (AuthorityFailed), not applied.
    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::MembershipManifest(m.clone())])
        .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&kb)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::AuthorityFailed)),
        "чужой волт без пина должен быть AuthorityFailed: {r:?}"
    );
    assert!(sb.get_membership_manifest(&vid, 1).unwrap().is_none());

    // (2) OOB pin of the teammate's genesis owner. Re-delivery of the same manifest at a new
    // seq (above the cursor) → now the anchor = owner_pub → the manifest applies.
    sb.set_vault_trust_anchor(&vid, &owner_pub).unwrap();
    t.push_objects(&[SyncObject::MembershipManifest(m)])
        .unwrap();
    let r2 = sync_pull(&mut t, &sb, &ctx(&kb)).unwrap();
    assert_eq!(
        r2.applied, 1,
        "после пина manifest должен примениться: {r2:?}"
    );
    assert!(sb.get_membership_manifest(&vid, 1).unwrap().is_some());
}

// ---------------------------------------------------------------------------
// A0 fix (security-review #1): applying a manifest@epoch raises the local vault epoch
// floor (anti-rollback on a member's device, which does not rotate itself) —
// otherwise the server could replay below-epoch records from a revoked write-member.
// ---------------------------------------------------------------------------
#[test]
fn applying_manifest_arms_epoch_floor() {
    let (sb, _kb) = account(&[43u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    let vid = b"vault-floor-arm".to_vec();
    let gen = genesis(&owner);
    assert!(sb.get_vault_epoch_floor(&vid).unwrap().is_none());

    let m = build_manifest(
        &owner,
        &vid,
        1,
        &[Member {
            ed25519_pub: gen,
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::MembershipManifest(m)])
        .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    assert_eq!(r.applied, 1, "{r:?}");
    assert_eq!(
        sb.get_vault_epoch_floor(&vid).unwrap(),
        Some(1),
        "пол эпохи должен подняться до применённой эпохи manifest"
    );
}

// ---------------------------------------------------------------------------
// A0 fix (security-review #2): a pinned anchor ⇒ membership-mode. A teammate-author's
// VaultRecord WITHOUT a synced manifest is NOT applied by the single-owner
// branch (author==anchor) — it requires a verified D1 chain.
// ---------------------------------------------------------------------------
#[test]
fn pinned_vault_rejects_out_of_chain_record() {
    let (sb, _kb) = account(&[44u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    let vid = b"vault-pin-nochain".to_vec();
    let owner_pub = genesis(&owner);

    // the owner creates a vault → its VaultRecord (single-owner, without a manifest).
    let sx = Storage::open_in_memory(&[45u8; 32]).unwrap();
    Vault::create(&sx, &owner, vid.clone(), b"name").unwrap();
    let rec = sx.get_vault(&vid).unwrap().unwrap();

    // sb pins the anchor, but the manifest is not yet synced → membership-mode without a chain.
    sb.set_vault_trust_anchor(&vid, &owner_pub).unwrap();
    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::Vault(rec)]).unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::AuthorityFailed)),
        "запись пиненного волта без цепочки должна быть AuthorityFailed: {r:?}"
    );
    assert!(sb.get_vault(&vid).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Defense-in-depth: process_manifest epoch-floor reject (symmetric with
// process_vault/item/grant/keyset). A manifest below the trusted vault epoch floor =
// a rollback of membership to a stale epoch → EpochBelowFloor, not applied.
// ---------------------------------------------------------------------------
#[test]
fn manifest_below_epoch_floor_rejected() {
    let (sb, _kb) = account(&[27u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    let vid = b"vault-floor".to_vec();
    let gen = genesis(&owner);

    // The vault epoch floor = 5 (as after rotations). A validly-signed manifest@1
    // (below the floor) must be rejected before verify, leaving no record.
    sb.set_vault_epoch_floor(&vid, 5).unwrap();
    let m = build_manifest(
        &owner,
        &vid,
        1,
        &[Member {
            ed25519_pub: gen,
            role: MemberRole::Admin,
        }],
    )
    .unwrap();

    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::MembershipManifest(m)])
        .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::EpochBelowFloor)),
        "manifest ниже пола не отвергнут как EpochBelowFloor: {:?}",
        r
    );
    assert_eq!(r.applied, 0, "report={:?}", r);
    assert!(sb.get_membership_manifest(&vid, 1).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Defect 3 (MINOR coverage): process_manifest forged genesis (author != owner).
// ---------------------------------------------------------------------------
#[test]
fn manifest_forged_genesis_rejected() {
    let (sb, _kb) = account(&[23u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    // The attacker signs a "genesis" manifest@1 with THEIR OWN key — author != owner.
    let (_sk2, _enc2, attacker) = create_account(Some(b"x"), test_params()).unwrap();
    let vid = b"vault-forge".to_vec();
    let gen_owner = genesis(&owner);
    let attacker_pub = genesis(&attacker);

    let forged = build_manifest(
        &attacker,
        &vid,
        1,
        &[Member {
            ed25519_pub: attacker_pub,
            role: MemberRole::Admin,
        }],
    )
    .unwrap();

    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::MembershipManifest(forged)])
        .unwrap();
    // genesis_owner = the legitimate owner; no chain leads from it to the attacker.
    let r = sync_pull(
        &mut t,
        &sb,
        &SyncContext {
            genesis_owner: gen_owner,
            tenant: b"oracle-tenant".to_vec(),
        },
    )
    .unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::AuthorityFailed)),
        "forged genesis manifest not rejected: {:?}",
        r
    );
    assert!(sb.get_membership_manifest(&vid, 1).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Defect 3 (MINOR coverage): broken D1-chain — manifest@2 without manifest@1.
// ---------------------------------------------------------------------------
#[test]
fn manifest_broken_chain_rejected() {
    let (sb, _kb) = account(&[24u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    let vid = b"vault-gap".to_vec();
    let gen = genesis(&owner);

    // manifest@2 is validly signed by the owner, but manifest@1 is missing → a gap.
    let m2 = build_manifest(
        &owner,
        &vid,
        2,
        &[Member {
            ed25519_pub: gen,
            role: MemberRole::Admin,
        }],
    )
    .unwrap();

    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::MembershipManifest(m2)])
        .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::AuthorityFailed)),
        "broken-chain manifest not rejected: {:?}",
        r
    );
    assert!(sb.get_membership_manifest(&vid, 2).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Defect 3 (MINOR coverage): process_grant happy-path.
// ---------------------------------------------------------------------------
#[test]
fn grant_happy_path_applied() {
    let (sb, _kb) = account(&[25u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    let gen = genesis(&owner);

    // verify_grant does NOT decrypt wrapped_vk (only signature + member/role
    // consistency) — any VK is enough to cover the authority path.
    let vid = b"vault-grant".to_vec();
    let vk = SymmetricKey::generate();

    // The recipient is a separate member account, a member@1.
    let (_sk2, _enc2, member) = create_account(Some(b"x"), test_params()).unwrap();
    let member_ed = genesis(&member);
    let member_x = member.encryption.public.to_bytes().to_vec();

    // manifest@1: {owner=Admin, member=Editor}.
    let manifest = build_manifest(
        &owner,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: gen.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: member_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    )
    .unwrap();
    // A VK grant to the recipient, the role matching the manifest (Editor).
    let grant = build_grant(
        &owner,
        &vid,
        &member_x,
        &member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();

    let mut t = InMemoryTransport::new();
    t.push_objects(&[
        SyncObject::MembershipManifest(manifest),
        SyncObject::MembershipGrant(grant),
    ])
    .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    // manifest + grant are applied.
    assert_eq!(r.applied, 2, "report={:?}", r);
    assert_eq!(sb.list_membership_grants(&vid, 1).unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Defect 3 (MINOR coverage): grant author is not admin.
// ---------------------------------------------------------------------------
#[test]
fn grant_author_not_admin_rejected() {
    let (sb, _kb) = account(&[27u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    let gen = genesis(&owner);

    let vid = b"vault-g2".to_vec();
    let vk = SymmetricKey::generate();

    // member is an Editor (NOT admin); will try to issue a grant themselves.
    let (_sk2, _enc2, member) = create_account(Some(b"x"), test_params()).unwrap();
    let member_ed = genesis(&member);
    let member_x = member.encryption.public.to_bytes().to_vec();

    let manifest = build_manifest(
        &owner,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: gen.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: member_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    )
    .unwrap();
    // The grant is signed by the member (Editor) — they are NOT admin → authority fail.
    let grant = build_grant(
        &member,
        &vid,
        &member_x,
        &member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();

    let mut t = InMemoryTransport::new();
    t.push_objects(&[
        SyncObject::MembershipManifest(manifest),
        SyncObject::MembershipGrant(grant),
    ])
    .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::AuthorityFailed)),
        "non-admin grant not rejected: {:?}",
        r
    );
    assert!(sb.list_membership_grants(&vid, 1).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Defect 3 (MINOR coverage): grant recipient is not a member of the set.
// ---------------------------------------------------------------------------
#[test]
fn grant_recipient_not_member_rejected() {
    let (sb, _kb) = account(&[29u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    let gen = genesis(&owner);

    let vid = b"vault-g3".to_vec();
    let vk = SymmetricKey::generate();

    // The recipient is NOT in the manifest (the manifest contains only the owner).
    let (_sk2, _enc2, outsider) = create_account(Some(b"x"), test_params()).unwrap();
    let outsider_ed = genesis(&outsider);
    let outsider_x = outsider.encryption.public.to_bytes().to_vec();

    let manifest = build_manifest(
        &owner,
        &vid,
        1,
        &[Member {
            ed25519_pub: gen.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    // The owner (admin) validly signs the grant, but the recipient is NOT a member.
    let grant = build_grant(
        &owner,
        &vid,
        &outsider_x,
        &outsider_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();

    let mut t = InMemoryTransport::new();
    t.push_objects(&[
        SyncObject::MembershipManifest(manifest),
        SyncObject::MembershipGrant(grant),
    ])
    .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::AuthorityFailed)),
        "grant to non-member not rejected: {:?}",
        r
    );
    assert!(sb.list_membership_grants(&vid, 1).unwrap().is_empty());
}

/// Builds a validly-self-signed audit entry under an arbitrary keyset
/// (the domain matches `process_audit`: AAD = vault_id + "__audit__" + 0).
fn signed_audit(ks: &UnlockedKeyset, entry: &[u8]) -> AuditObject {
    use unissh_crypto::{sign_version, AssociatedData, VersionedObject};
    let aad = AssociatedData::new(Vec::new(), b"__audit__".to_vec(), 0);
    let vo = VersionedObject::from_content(aad, entry);
    let sig = sign_version(&ks.signing.signing, &vo).unwrap();
    AuditObject {
        vault_id: Vec::new(),
        entry_blob: entry.to_vec(),
        signature: sig,
        author_pubkey: ks.signing.verifying.to_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Defect 4 (MINOR audit authority): process_audit previously accepted any
// validly-self-signed entry (author_pubkey is chosen by the sender). Now
// the author must be the trusted instance anchor (genesis_owner).
// ---------------------------------------------------------------------------
#[test]
fn audit_from_owner_applied_attacker_rejected() {
    let (sb, _kb) = account(&[31u8; 32]);
    let (_sk, _enc, owner) = create_account(Some(b"pw"), test_params()).unwrap();
    // The attacker is a different keyset; their entry is validly self-signed, but the author is not the owner.
    let (_sk2, _enc2, attacker) = create_account(Some(b"x"), test_params()).unwrap();

    // (1) an owner-signed entry is applied.
    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::Audit(signed_audit(&owner, b"legit-event"))])
        .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    assert_eq!(r.applied, 1, "owner audit not applied: {:?}", r);

    // (2) an attacker-signed entry (valid self-signature, foreign author)
    // is rejected as AuthorityFailed, NOT applied.
    t.push_objects(&[SyncObject::Audit(signed_audit(&attacker, b"poison-event"))])
        .unwrap();
    let r2 = sync_pull(&mut t, &sb, &ctx(&owner)).unwrap();
    assert!(
        r2.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::AuthorityFailed)),
        "attacker audit not rejected on authority: {:?}",
        r2
    );
    assert_eq!(r2.applied, 0, "attacker audit applied: {:?}", r2);
}

// ---------------------------------------------------------------------------
// A3: per-account state (tag 7). Self-signed by the account (author == local
// keyset), verify-before-apply + LWW by version; a foreign author → AuthorityFailed.
// ---------------------------------------------------------------------------
#[test]
fn account_state_applied_and_lww() {
    let (sb, kb) = account(&[50u8; 32]);
    let author = genesis(&kb);
    let payload = b"opaque-hpke-blob".to_vec();

    let sig = sign_account_state(&kb, 5, &payload).unwrap();
    let obj = AccountStateObject {
        author_pubkey: author.clone(),
        version: 5,
        payload: payload.clone(),
        signature: sig,
    };
    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::AccountState(obj)]).unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&kb)).unwrap();
    assert_eq!(r.applied, 1, "{r:?}");
    let stored = sb.get_account_state(&author).unwrap().unwrap();
    assert_eq!(stored.version, 5);
    assert_eq!(stored.payload, payload);

    // An older version → skipped_stale, the stored one (v5) is untouched.
    let sig2 = sign_account_state(&kb, 3, &payload).unwrap();
    let older = AccountStateObject {
        author_pubkey: author.clone(),
        version: 3,
        payload,
        signature: sig2,
    };
    t.push_objects(&[SyncObject::AccountState(older)]).unwrap();
    let r2 = sync_pull(&mut t, &sb, &ctx(&kb)).unwrap();
    assert!(r2.skipped_stale >= 1, "{r2:?}");
    assert_eq!(sb.get_account_state(&author).unwrap().unwrap().version, 5);
}

// S2: two concurrent account-state edits with the SAME version (both devices took
// cur+1) must converge to one state INDEPENDENTLY of the apply order —
// a deterministic tiebreak by signature (max wins).
#[test]
fn account_state_equal_version_tiebreak_converges() {
    let (_sk, _enc, kb) = create_account(Some(b"pw"), test_params()).unwrap();
    let author = genesis(&kb);
    let pa = b"payload-A".to_vec();
    let pb = b"payload-B-different".to_vec();
    let sig_a = sign_account_state(&kb, 5, &pa).unwrap();
    let sig_b = sign_account_state(&kb, 5, &pb).unwrap();
    assert_ne!(sig_a, sig_b, "разный payload → разная подпись");
    let obj_a = AccountStateObject {
        author_pubkey: author.clone(),
        version: 5,
        payload: pa.clone(),
        signature: sig_a.clone(),
    };
    let obj_b = AccountStateObject {
        author_pubkey: author.clone(),
        version: 5,
        payload: pb.clone(),
        signature: sig_b.clone(),
    };
    let winner_sig = if sig_a > sig_b {
        sig_a.clone()
    } else {
        sig_b.clone()
    };

    // Apply both in the given order on FRESH storage (the same keyset kb).
    let apply_both = |first: &AccountStateObject, second: &AccountStateObject| -> Vec<u8> {
        let sb = Storage::open_in_memory(&[52u8; 32]).unwrap();
        let mut t = InMemoryTransport::new();
        t.push_objects(&[SyncObject::AccountState(first.clone())])
            .unwrap();
        sync_pull(&mut t, &sb, &ctx(&kb)).unwrap();
        t.push_objects(&[SyncObject::AccountState(second.clone())])
            .unwrap();
        sync_pull(&mut t, &sb, &ctx(&kb)).unwrap();
        sb.get_account_state(&author).unwrap().unwrap().signature
    };
    // Both orders → the same (max-sig) state.
    assert_eq!(apply_both(&obj_a, &obj_b), winner_sig, "A→B");
    assert_eq!(apply_both(&obj_b, &obj_a), winner_sig, "B→A");
}

// #6: account-state with the CORRECT author but an INVALID signature → SignatureFailed
// (the crypto gate against a SERVER forging someone else's tag-7). The former forged test short-
// circuited on the author check, never reaching the signature branch (engine.rs:668).
#[test]
fn account_state_bad_signature_rejected() {
    let (sb, kb) = account(&[53u8; 32]);
    let author = genesis(&kb);
    let payload = b"p".to_vec();
    let mut sig = sign_account_state(&kb, 5, &payload).unwrap();
    sig[0] ^= 0xFF; // the author is correct, but the signature no longer matches
    let obj = AccountStateObject {
        author_pubkey: author.clone(),
        version: 5,
        payload,
        signature: sig,
    };
    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::AccountState(obj)]).unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&kb)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::SignatureFailed)),
        "форджед-подпись → SignatureFailed: {r:?}"
    );
    assert!(
        sb.get_account_state(&author).unwrap().is_none(),
        "форджед account-state не применяется"
    );
}

#[test]
fn account_state_wrong_author_rejected() {
    let (sb, kb) = account(&[51u8; 32]);
    let (_s, _e, other) = create_account(Some(b"pw"), test_params()).unwrap();
    // Signed by a DIFFERENT account → author != ctx.genesis_owner(kb) → AuthorityFailed.
    let payload = b"x".to_vec();
    let sig = sign_account_state(&other, 1, &payload).unwrap();
    let obj = AccountStateObject {
        author_pubkey: genesis(&other),
        version: 1,
        payload,
        signature: sig,
    };
    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::AccountState(obj)]).unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&kb)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::AuthorityFailed)),
        "чужое account-state должно быть AuthorityFailed: {r:?}"
    );
    assert!(sb.get_account_state(&genesis(&other)).unwrap().is_none());
}

// A3 sec-review #8: account-state with version > i64::MAX is rejected per-object
// (Malformed), WITHOUT dropping the whole pull; a valid object in the same pull applies.
#[test]
fn account_state_oversized_version_rejected_not_pull_abort() {
    let (sb, kb) = account(&[52u8; 32]);
    let author = genesis(&kb);
    let payload = b"p".to_vec();

    let big_sig = sign_account_state(&kb, u64::MAX, &payload).unwrap();
    let big = AccountStateObject {
        author_pubkey: author.clone(),
        version: u64::MAX,
        payload: payload.clone(),
        signature: big_sig,
    };
    let ok_sig = sign_account_state(&kb, 1, &payload).unwrap();
    let ok = AccountStateObject {
        author_pubkey: author.clone(),
        version: 1,
        payload,
        signature: ok_sig,
    };

    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::AccountState(big), SyncObject::AccountState(ok)])
        .unwrap();
    // the pull is NOT aborted by an error (Ok), despite the inflated version.
    let r = sync_pull(&mut t, &sb, &ctx(&kb)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::Malformed)),
        "раздутая версия должна быть Malformed: {r:?}"
    );
    // the valid v1 is applied (the pull continued after the reject).
    assert_eq!(sb.get_account_state(&author).unwrap().unwrap().version, 1);
}
