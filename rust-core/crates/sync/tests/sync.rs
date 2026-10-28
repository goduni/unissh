//! Integration tests for the sync engine: happy-path + mandatory negatives.
//! The transport is forced to lie (forged/stale/below-cursor/equal-version).
#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use unissh_crypto::KdfParams;
use unissh_keychain::{create_account, UnlockedKeyset};
use unissh_storage::{Storage, SyncTarget};
use unissh_sync::{
    apply_pulled_objects, discard_unpushable, forget_push_refusals, pull_cursor_key,
    reset_pull_cursor, sync_pull, sync_push, sync_push_as, sync_push_vault_data, InMemoryTransport,
    RejectReason, SyncContext, SyncError, SyncObject, SyncTransport, UnpushableReason,
};
use unissh_vault::{sign_account_state, Vault};

/// The synced server's tenant_id for the push filter (1:1 binding of a cloud vault).
/// The seeded vault is bound to it; `sync_push` pushes only vaults with this tenant.
const TENANT: &[u8] = b"tenant-test";

/// Lightened Argon2id parameters for test speed (still Argon2id, but
/// small m/t). `KdfParams` is a public struct with fields; there is NO
/// `interactive()` constructor.
fn test_params() -> KdfParams {
    // ≥ the OWASP minimum (19 MiB / t=2): the sync keyset object is parsed via
    // KdfParams::from_blob, which below the hard floor rejects the blob as Malformed.
    KdfParams {
        mem_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
        salt: vec![1_u8; 16],
    }
}

/// Account = (the instance's Storage, its owner's UnlockedKeyset).
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

/// Creates a cloud vault with one item on a device (storage+keyset), binds it
/// to [`TENANT`] (1:1 binding, otherwise `sync_push` will not hand it off) and returns the vault_id.
fn seed_vault(storage: &Storage, ks: &UnlockedKeyset) -> Vec<u8> {
    let v = Vault::create_with_target(storage, ks, b"vault-1".to_vec(), b"name", SyncTarget::Cloud)
        .unwrap();
    v.put_item(b"item-1", 1, b"secret").unwrap(); // signature (v=1) under the owner
    storage.bind_unbound_cloud_vaults(TENANT).unwrap();
    b"vault-1".to_vec()
}

#[test]
fn happy_path_two_devices() {
    // A creates, pushes; B pulls → sees the vault+item, everything verifies.
    let (sa, ka) = account(&[1_u8; 32]);
    // B is the same ownership: WE USE THE SAME keyset (one account, two devices).
    let sb = Storage::open_in_memory(&[2_u8; 32]).unwrap();
    let _vid = seed_vault(&sa, &ka);

    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    let r = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(r.applied >= 2, "applied={}", r.applied); // vault + item
    assert!(r.rejected.is_empty(), "rejected={:?}", r.rejected);
    assert!(r.conflicts.is_empty());
    assert!(sb.get_vault(b"vault-1").unwrap().is_some());
    assert_eq!(sb.list_items(b"vault-1").unwrap().len(), 1);
}

/// A transport that hands the delta over one object per call, as a server that
/// cuts its pages by size does.
struct PagedServer(InMemoryTransport);

impl SyncTransport for PagedServer {
    fn push_objects(&mut self, objects: &[SyncObject]) -> Result<Vec<u64>, SyncError> {
        self.0.push_objects(objects)
    }
    fn delta_since(&self, cursor: u64) -> Vec<(u64, SyncObject)> {
        self.0.delta_since(cursor).into_iter().take(1).collect()
    }
    fn report_version(&self) -> u64 {
        self.0.report_version()
    }
}

#[test]
fn pull_follows_a_delta_handed_over_in_pages() {
    // The pull took one `delta_since` answer as the whole delta, so a transport
    // had to buffer every page before the engine saw any of it. It now asks
    // again from the cursor until nothing is left.
    let (sa, ka) = account(&[1_u8; 32]);
    let sb = Storage::open_in_memory(&[2_u8; 32]).unwrap();
    seed_vault(&sa, &ka);
    let mut t = PagedServer(InMemoryTransport::new());
    sync_push(&mut t, &sa, TENANT).unwrap();

    let r = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();

    assert!(r.rejected.is_empty(), "rejected={:?}", r.rejected);
    assert_eq!(
        sb.get_sync_cursor(&pull_cursor_key(b"oracle-tenant"))
            .unwrap(),
        Some(t.0.real_max_seq()),
        "the cursor reached the end of the delta"
    );
    assert_eq!(sb.list_items(b"vault-1").unwrap().len(), 1);
}

#[test]
fn dirty_tracking_pushes_only_changes() {
    // The regression this feature fixes: sync_push used to re-send the whole bound
    // vault on every call. Now it sends only DIRTY objects and clears them, so a push
    // with no local changes sends nothing.
    let (sa, ka) = account(&[1_u8; 32]);
    let vid = seed_vault(&sa, &ka); // cloud vault + 1 item, bound to TENANT (both dirty)
    let mut t = InMemoryTransport::new();

    let r1 = sync_push(&mut t, &sa, TENANT).unwrap();
    assert!(r1.pushed >= 2, "new vault + item pushed, got {}", r1.pushed);

    // Nothing changed → no round-trip.
    assert_eq!(
        sync_push(&mut t, &sa, TENANT).unwrap().pushed,
        0,
        "no changes → pushed 0"
    );

    // Edit one item → only that item is dirty → only it is pushed.
    Vault::open(&sa, &ka, &vid)
        .unwrap()
        .put_item(b"item-1", 1, b"changed")
        .unwrap();
    assert_eq!(
        sync_push(&mut t, &sa, TENANT).unwrap().pushed,
        1,
        "only the edited item"
    );
    assert_eq!(
        sync_push(&mut t, &sa, TENANT).unwrap().pushed,
        0,
        "clean again"
    );
}

#[test]
fn pulled_vault_is_born_bound_to_source_tenant() {
    // A vault pulled from a tenant's space is, by construction, bound to that
    // tenant. It must materialize born-bound (sync_tenant = ctx.tenant), not
    // unbound — otherwise it looks like a legacy unbound vault, the auto-bind
    // rebinds + re-dirties it, and it re-pushes as a server-side duplicate
    // (root cause of the mass-duplication incident).
    let (sa, ka) = account(&[1_u8; 32]);
    seed_vault(&sa, &ka);
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    let sb = Storage::open_in_memory(&[2_u8; 32]).unwrap();
    sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();

    let v = sb.get_vault(b"vault-1").unwrap().unwrap();
    assert_eq!(
        v.sync_tenant,
        b"oracle-tenant".to_vec(),
        "a pulled vault is born bound to the tenant it was pulled from"
    );
}

#[test]
fn repull_binds_a_vault_that_landed_unbound() {
    // The user-visible bug: a vault pulled by a client from BEFORE born-bound landed
    // with an empty sync_tenant and reads as "no server" forever — and "Pull from
    // server" does not heal it.
    //
    // Why: `sync_tenant` is deliberately excluded from `vault_content_eq` (so a
    // re-pull stays idempotent), which means an UNBOUND local vault is "content
    // equal" to its bound server copy. The equal-version check therefore returns
    // early, before the born-bound stamp — so the one action a user has to fix this
    // is precisely the action that can never fix it.
    let (sa, ka) = account(&[1_u8; 32]);
    seed_vault(&sa, &ka);
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    let sb = Storage::open_in_memory(&[2_u8; 32]).unwrap();
    sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();

    // Reproduce the state: same vault, same version, sync_tenant empty. This is not
    // a contrivance — it is what a pre-born-bound client left behind, and what
    // `clear_binding_for_tenant` does today when a server is removed. The routing
    // label is not part of the signature, so this changes no version.
    sb.set_vault_tenant(b"vault-1", b"").unwrap();
    assert!(
        sb.get_vault(b"vault-1")
            .unwrap()
            .unwrap()
            .sync_tenant
            .is_empty(),
        "precondition: the local vault is unbound"
    );

    // "Pull from server" — a full re-pull from a reset cursor.
    reset_pull_cursor(&sb, &ctx(&ka).tenant).unwrap();
    sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();

    assert_eq!(
        sb.get_vault(b"vault-1").unwrap().unwrap().sync_tenant,
        b"oracle-tenant".to_vec(),
        "a re-pull must bind a vault that landed unbound — it is the only lever the user has"
    );
}

#[test]
fn apply_pulled_objects_materializes_without_advancing_cursor() {
    // "Pull this vault": objects fetched out-of-band (via ?vault=<id>) are applied
    // through the same verify-before-apply path, materialize born-bound, and DO NOT
    // advance the per-tenant pull cursor.
    let (sa, ka) = account(&[1_u8; 32]);
    seed_vault(&sa, &ka);
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    let sb = Storage::open_in_memory(&[2_u8; 32]).unwrap();
    let objs = t.delta_since(0); // Vec<(u64, SyncObject)> — the vault's objects
    let report = apply_pulled_objects(&sb, &ctx(&ka), objs).unwrap();

    assert!(
        report.applied >= 2,
        "vault + item applied, applied={}",
        report.applied
    );
    let v = sb.get_vault(b"vault-1").unwrap().unwrap();
    assert_eq!(
        v.sync_tenant,
        b"oracle-tenant".to_vec(),
        "targeted apply materializes born-bound too"
    );
    assert_eq!(sb.list_items(b"vault-1").unwrap().len(), 1);

    // The per-tenant pull cursor must be untouched.
    assert_eq!(
        sb.get_sync_cursor(&pull_cursor_key(b"oracle-tenant"))
            .unwrap()
            .unwrap_or(0),
        0,
        "a targeted apply must not advance the pull cursor"
    );
}

#[test]
fn pulled_objects_are_not_re_pushed() {
    // Objects applied by sync_pull go through low-level put_* (not the vault layer),
    // so they never get marked dirty and are never bounced back to the server.
    let (sa, ka) = account(&[1_u8; 32]);
    seed_vault(&sa, &ka);
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    let sb = Storage::open_in_memory(&[2_u8; 32]).unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(r.applied >= 2, "B receives vault + item");
    // The pulled vault is born bound to the tenant it came from (no manual
    // bind_unbound_cloud_vaults needed). Pushing back to that SAME tenant sends
    // nothing, because pulled objects go through low-level put_* and are never
    // marked dirty.
    assert_eq!(
        sync_push(&mut t, &sb, b"oracle-tenant").unwrap().pushed,
        0,
        "pulled objects are not dirty → nothing to push back"
    );
}

#[test]
fn repull_after_cursor_reset_recovers_owner_vault() {
    // Regression: a device pulled a single-owner cloud vault while signed in as a
    // DIFFERENT identity → the vault is rejected on authority, but the reject STILL
    // advances the pull cursor. When the device later becomes the OWNER (re-attach),
    // an incremental pull returns nothing (cursor is stale) and the owner can never
    // recover the vault it can now decrypt. reset_pull_cursor must fix that.
    let (sa, ka) = account(&[1_u8; 32]); // owner
    let (_sb2, kb) = account(&[9_u8; 32]); // some OTHER identity (was on the device first)
    seed_vault(&sa, &ka);

    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    // The device (sb) first pulls as the WRONG identity → vault rejected, cursor burned.
    let sb = Storage::open_in_memory(&[2_u8; 32]).unwrap();
    let r1 = sync_pull(&mut t, &sb, &ctx(&kb)).unwrap();
    assert_eq!(r1.applied, 0);
    assert!(!r1.rejected.is_empty(), "wrong identity → authority reject");
    assert!(sb.get_vault(b"vault-1").unwrap().is_none());

    // Now the device is the OWNER. Incremental pull sees an empty delta (stale cursor).
    let r2 = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert_eq!(
        r2.applied, 0,
        "stale cursor hides the vault from its own owner"
    );
    assert!(sb.get_vault(b"vault-1").unwrap().is_none());

    // Reset the pull cursor → full re-pull as owner → the vault is recovered.
    reset_pull_cursor(&sb, b"oracle-tenant").unwrap();
    let r3 = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(
        r3.applied >= 2,
        "owner re-pull recovers vault+item, applied={}",
        r3.applied
    );
    assert!(
        r3.rejected.is_empty(),
        "owner authority passes, rejected={:?}",
        r3.rejected
    );
    assert!(sb.get_vault(b"vault-1").unwrap().is_some());
    assert_eq!(sb.list_items(b"vault-1").unwrap().len(), 1);
}

#[test]
fn restore_recovers_a_locally_deleted_vault_still_live_on_server() {
    // Owner creates+pushes a cloud vault; a device pulls it, then DELETES it locally
    // (tombstone, version bumps). The delete never reaches the server (link removed →
    // unbound → not pushed). A re-pull can't resurrect it: the server's live copy is
    // now OLDER than the local tombstone (skipped_stale under LWW) and list_vaults
    // hides tombstones. Purging the local record + resetting the cursor lets the
    // re-pull re-materialize the server copy — this is what the "restore" action does.
    let (sa, ka) = account(&[1_u8; 32]);
    seed_vault(&sa, &ka);
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    // device B (same owner keyset) pulls → has the vault + item.
    let sb = Storage::open_in_memory(&[2_u8; 32]).unwrap();
    assert!(sync_pull(&mut t, &sb, &ctx(&ka)).unwrap().applied >= 2);
    assert!(sb.get_vault(b"vault-1").unwrap().is_some());

    // delete it locally → tombstone (version++). Now hidden from list_vaults.
    Vault::open(&sb, &ka, b"vault-1").unwrap().delete().unwrap();
    assert!(sb.get_vault(b"vault-1").unwrap().unwrap().tombstone);
    assert!(sb
        .list_vaults()
        .unwrap()
        .iter()
        .all(|v| v.vault_id != b"vault-1"));

    // a plain re-pull can't bring it back — the server copy is stale vs the tombstone.
    reset_pull_cursor(&sb, b"oracle-tenant").unwrap();
    let r2 = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert_eq!(r2.applied, 0, "LWW keeps the newer local tombstone");
    assert!(sb.get_vault(b"vault-1").unwrap().unwrap().tombstone);

    // restore = purge the local record + reset cursor + re-pull → vault recovered.
    assert_eq!(sb.list_tombstoned_cloud_vaults().unwrap().len(), 1);
    sb.purge_vault_data(b"vault-1").unwrap();
    reset_pull_cursor(&sb, b"oracle-tenant").unwrap();
    let r3 = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(
        r3.applied >= 2,
        "server copy re-materializes, applied={}",
        r3.applied
    );
    assert!(
        sb.list_vaults()
            .unwrap()
            .iter()
            .any(|v| v.vault_id == b"vault-1"),
        "vault visible again"
    );
    assert_eq!(
        sb.list_items(b"vault-1").unwrap().len(),
        1,
        "item recovered too"
    );
}

#[test]
fn forged_unauthorized_object_rejected_not_applied() {
    let (sa, ka) = account(&[1_u8; 32]);
    seed_vault(&sa, &ka);
    let sb = Storage::open_in_memory(&[3_u8; 32]).unwrap();
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    // attacker is a DIFFERENT account. Signs an item in someone else's vault-1 validly
    // under THEIR OWN key, but authority under genesis A will fail.
    let (_s2, _e2, attacker) = create_account(Some(b"x"), test_params()).unwrap();
    let sx = Storage::open_in_memory(&[8_u8; 32]).unwrap();
    let vx = Vault::create(&sx, &attacker, b"vault-1".to_vec(), b"evil").unwrap();
    vx.put_item(b"evil-item", 1, b"payload").unwrap();
    let evil = sx.get_item(b"vault-1", b"evil-item").unwrap().unwrap();
    // injection of a forged item into the mock's delta (server_seq on top of the real ones).
    t.inject(t.real_max_seq() + 1, SyncObject::Item(evil));

    let r = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(
        r.rejected.iter().any(|x| matches!(
            x.reason,
            RejectReason::AuthorityFailed | RejectReason::SignatureFailed
        )),
        "rejected={:?}",
        r.rejected
    );
    // the forged item is NOT applied
    assert!(sb.get_item(b"vault-1", b"evil-item").unwrap().is_none());
}

#[test]
fn epoch_below_floor_rejected() {
    let (sa, ka) = account(&[1_u8; 32]);
    seed_vault(&sa, &ka);
    let sb = Storage::open_in_memory(&[4_u8; 32]).unwrap();
    // Raise the vault epoch floor on B higher than that of the incoming records (key_epoch=0).
    sb.set_vault_epoch_floor(b"vault-1", 5).unwrap();
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    let r = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::EpochBelowFloor)),
        "rejected={:?}",
        r.rejected
    );
    assert!(sb.get_vault(b"vault-1").unwrap().is_none());
}

#[test]
fn stale_version_is_skipped_not_crash() {
    let (sa, ka) = account(&[1_u8; 32]);
    seed_vault(&sa, &ka);
    let sb = Storage::open_in_memory(&[5_u8; 32]).unwrap();
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();
    // B receives v1 of the vault+item.
    sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert_eq!(
        sb.get_item(b"vault-1", b"item-1").unwrap().unwrap().version,
        1
    );

    // B locally advances item-1 to version=2 (an honest signature with its own keyset).
    let vb = Vault::open(&sb, &ka, b"vault-1").unwrap();
    let v2 = vb.put_item(b"item-1", 1, b"newer-on-b").unwrap();
    assert_eq!(v2, 2);
    let v2_content = sb
        .get_item(b"vault-1", b"item-1")
        .unwrap()
        .unwrap()
        .content_blob;

    // A hands off its v1 item again on the SAME transport (server_seq monotonically
    // above cursor B → the object is actually delivered). incoming v=1 < local v=2 →
    // VersionRollback in put_item → skipped_stale (NOT a crash, NOT an error).
    let stale_item = sa.get_item(b"vault-1", b"item-1").unwrap().unwrap();
    assert_eq!(stale_item.version, 1);
    t.push_objects(&[SyncObject::Item(stale_item)]).unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(r.skipped_stale >= 1, "report={:?}", r);
    // the local one (v2) is intact
    let local = sb.get_item(b"vault-1", b"item-1").unwrap().unwrap();
    assert_eq!(local.version, 2);
    assert_eq!(local.content_blob, v2_content);
}

#[test]
fn equal_version_different_content_is_conflict() {
    let (sa, ka) = account(&[1_u8; 32]);
    let vid = seed_vault(&sa, &ka);
    let sb = Storage::open_in_memory(&[6_u8; 32]).unwrap();
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();
    sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();

    // A SECOND valid item version=1 with DIFFERENT content, the same (vault,item).
    // Emulates an independent mint of version 1 on another device — both validly
    // signed by the owner (the same keyset ka), but the content differs.
    let sc = Storage::open_in_memory(&[7_u8; 32]).unwrap();
    let vc = Vault::create(&sc, &ka, vid.clone(), b"name").unwrap();
    vc.put_item(b"item-1", 1, b"DIFFERENT").unwrap();
    let conflicting = sc.get_item(&vid, b"item-1").unwrap().unwrap();
    assert_eq!(conflicting.version, 1);

    // Deliver the conflicting object on the SAME transport (a new server_seq >
    // cursor B) so it actually lands in the delta.
    t.push_objects(&[SyncObject::Item(conflicting.clone())])
        .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(!r.conflicts.is_empty(), "report={:?}", r);
    // the local one is NOT overwritten
    let local = sb.get_item(&vid, b"item-1").unwrap().unwrap();
    assert_ne!(local.content_blob, conflicting.content_blob);
}

#[test]
fn transport_below_cursor_rejected_and_rollback() {
    let (sa, ka) = account(&[1_u8; 32]);
    seed_vault(&sa, &ka);
    let sb = Storage::open_in_memory(&[10_u8; 32]).unwrap();
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();
    sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    let cur = sb
        .get_sync_cursor(&pull_cursor_key(b"oracle-tenant"))
        .unwrap()
        .unwrap();
    assert!(cur > 0);

    // the transport understates report_version → TransportRollback
    t.force_report_version(0);
    let err = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap_err();
    assert!(matches!(err, SyncError::TransportRollback { .. }));
    assert_eq!(
        sb.get_sync_cursor(&pull_cursor_key(b"oracle-tenant"))
            .unwrap(),
        Some(cur)
    );

    // the transport hands off objects with seq <= cursor → BelowCursor reject, not applied.
    t.force_report_version(cur); // report >= cursor → not TransportRollback
    t.force_seq_floor(cur); // all objects are stamped seq == cursor (<= last)
    let r = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::BelowCursor)),
        "rejected={:?}",
        r.rejected
    );
    // the cursor is not lowered
    assert_eq!(
        sb.get_sync_cursor(&pull_cursor_key(b"oracle-tenant"))
            .unwrap(),
        Some(cur)
    );
}

#[test]
fn malformed_object_rejected_rest_processed() {
    // a broken blob → from_bytes Err; the codec must return an error, not panic.
    assert!(SyncObject::from_bytes(&[200, 1, 2]).is_err());
    assert!(SyncObject::from_bytes(&[]).is_err());
}

#[test]
fn keyset_generation_below_floor_rejected() {
    use unissh_keychain::{create_account, raise_keyset_gen_floor};
    let (_sk, enc, _u) = create_account(Some(b"pw"), test_params()).unwrap();
    let sb = Storage::open_in_memory(&[11_u8; 32]).unwrap();
    // raise the floor above the record's generation (enc.generation == 1)
    raise_keyset_gen_floor(&sb, 5).unwrap();
    let (_s, ka) = account(&[12_u8; 32]);
    let mut t = InMemoryTransport::new();
    t.push_objects(&[SyncObject::Keyset(enc.to_bytes().unwrap())])
        .unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(
        r.rejected
            .iter()
            .any(|x| matches!(x.reason, RejectReason::GenerationBelowFloor)),
        "rejected={:?}",
        r.rejected
    );
}

#[test]
fn no_plaintext_in_sync_objects() {
    // SyncObject carries only ciphertext/signatures — NOT the secret's plaintext.
    let (sa, ka) = account(&[13_u8; 32]);
    let v = Vault::create(&sa, &ka, b"vault-x".to_vec(), b"name").unwrap();
    let secret = b"SUPER_SECRET_PLAINTEXT_MARKER";
    v.put_item(b"i", 1, secret).unwrap();
    let rec = sa.get_item(b"vault-x", b"i").unwrap().unwrap();
    let bytes = SyncObject::Item(rec).to_bytes().unwrap();
    // the plaintext marker must NOT appear in the serialized object.
    assert!(!contains_subslice(&bytes, secret));
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// 1:1 binding: a cloud vault bound to tenant A is NOT pushed when syncing with
/// tenant B. We create two cloud vaults on one instance, bind them to different
/// servers, and check that `sync_push(tenant)` hands off exactly "its own" vault.
#[test]
fn cloud_vault_pushed_only_to_its_bound_tenant() {
    const TENANT_A: &[u8] = b"tenant-A";
    const TENANT_B: &[u8] = b"tenant-B";
    let (sa, ka) = account(&[20_u8; 32]);

    // Vault A → bound to server A.
    Vault::create_with_target(&sa, &ka, b"vault-A".to_vec(), b"a", SyncTarget::Cloud).unwrap();
    sa.bind_unbound_cloud_vaults(TENANT_A).unwrap();
    // Vault B → bound to server B (the first is already bound, bind takes only the empty ones).
    Vault::create_with_target(&sa, &ka, b"vault-B".to_vec(), b"b", SyncTarget::Cloud).unwrap();
    sa.bind_unbound_cloud_vaults(TENANT_B).unwrap();
    // A local vault → NOT bound, must not go to any server.
    Vault::create(&sa, &ka, b"vault-local".to_vec(), b"l").unwrap();

    // Sync with tenant A: only vault-A is pushed.
    let mut ta = InMemoryTransport::new();
    sync_push(&mut ta, &sa, TENANT_A).unwrap();
    let pushed_a = pushed_vault_ids(&ta);
    assert!(
        pushed_a.contains(&b"vault-A".to_vec()),
        "A pushes its own vault"
    );
    assert!(
        !pushed_a.contains(&b"vault-B".to_vec()),
        "A must NOT push a vault bound to B"
    );
    assert!(
        !pushed_a.contains(&b"vault-local".to_vec()),
        "A must NOT push a local (unbound) vault"
    );

    // Sync with tenant B: only vault-B is pushed (mirror image).
    let mut tb = InMemoryTransport::new();
    sync_push(&mut tb, &sa, TENANT_B).unwrap();
    let pushed_b = pushed_vault_ids(&tb);
    assert_eq!(
        pushed_b,
        vec![b"vault-B".to_vec()],
        "B pushes only its own vault"
    );
}

/// The vault_ids of all `SyncObject::Vault` actually handed off to the transport (we read the delta
/// from cursor 0). Items go together with "their" vault, so a vault-level
/// check is enough for the binding filter.
fn pushed_vault_ids(t: &InMemoryTransport) -> Vec<Vec<u8>> {
    t.delta_since(0)
        .into_iter()
        .filter_map(|(_, o)| {
            if let SyncObject::Vault(v) = o {
                Some(v.vault_id)
            } else {
                None
            }
        })
        .collect()
}

/// A3.2: sync_push hands off the local account-state (reconstructs it from the storage row).
#[test]
fn sync_push_emits_local_account_state() {
    let (sa, ka) = account(&[9_u8; 32]);
    let author = genesis(&ka);
    let payload = b"sealed-blob".to_vec();
    let sig = sign_account_state(&ka, 7, &payload).unwrap();
    sa.set_account_state(&author, 7, &payload, &sig).unwrap();

    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();
    let pushed = t.delta_since(0);
    assert!(
        pushed
            .iter()
            .any(|(_, o)| matches!(o, SyncObject::AccountState(a) if a.version == 7)),
        "sync_push must hand off the local account-state"
    );
}

/// The first upload of a vault under a second space label of a server must not
/// hand that server the account state and the audit log once more: both are
/// tracked per label, so they stay with the label the device syncs.
#[test]
fn vault_data_push_leaves_account_state_and_audit_to_the_regular_push() {
    let (sa, ka) = account(&[10_u8; 32]);
    seed_vault(&sa, &ka);
    let author = genesis(&ka);
    let payload = b"sealed-blob".to_vec();
    let sig = sign_account_state(&ka, 7, &payload).unwrap();
    sa.set_account_state(&author, 7, &payload, &sig).unwrap();
    sa.append_audit(b"entry", &[1_u8; 67], &author).unwrap();
    let account_wide = |t: &InMemoryTransport| {
        t.delta_since(0)
            .iter()
            .filter(|(_, o)| matches!(o, SyncObject::AccountState(_) | SyncObject::Audit(_)))
            .count() as u64
    };
    let mut t = InMemoryTransport::new();

    sync_push_vault_data(&mut t, &sa, TENANT).unwrap();

    assert_eq!(
        pushed_vault_ids(&t),
        vec![b"vault-1".to_vec()],
        "the vault itself was uploaded"
    );
    assert_eq!(account_wide(&t), 0, "no account state, no audit entry");
    // Their cursors did not move: the regular push still owes both, and now
    // sends nothing else (the vault data is clean).
    let regular = sync_push(&mut t, &sa, TENANT).unwrap();
    assert!(
        account_wide(&t) >= 2,
        "the account state and the audit entry"
    );
    assert_eq!(regular.pushed, account_wide(&t));
}

/// A server with push limits: a request over them is refused whole with
/// [`SyncError::PayloadTooLarge`], as `POST /v1/sync/push` does. Records the
/// object count of every request it was sent, refused ones included.
struct LimitedServer {
    inner: InMemoryTransport,
    max_objects: usize,
    max_object_bytes: usize,
    /// Fail the n-th request (1-based) with a transport error, once.
    fail_request: Option<usize>,
    requests: Vec<usize>,
}

impl LimitedServer {
    fn new(max_objects: usize, max_object_bytes: usize) -> Self {
        Self {
            inner: InMemoryTransport::new(),
            max_objects,
            max_object_bytes,
            fail_request: None,
            requests: Vec::new(),
        }
    }

    /// Ids of the items the server holds, in the order it accepted them.
    fn item_ids(&self) -> Vec<Vec<u8>> {
        self.inner
            .delta_since(0)
            .into_iter()
            .filter_map(|(_, o)| {
                if let SyncObject::Item(i) = o {
                    Some(i.item_id)
                } else {
                    None
                }
            })
            .collect()
    }
}

impl SyncTransport for LimitedServer {
    fn push_objects(&mut self, objects: &[SyncObject]) -> Result<Vec<u64>, SyncError> {
        self.requests.push(objects.len());
        if self.fail_request == Some(self.requests.len()) {
            self.fail_request = None;
            return Err(SyncError::Format);
        }
        let too_big = objects
            .iter()
            .any(|o| o.to_bytes().unwrap().len() > self.max_object_bytes);
        if objects.len() > self.max_objects || too_big {
            return Err(SyncError::PayloadTooLarge);
        }
        self.inner.push_objects(objects)
    }
    fn delta_since(&self, cursor: u64) -> Vec<(u64, SyncObject)> {
        self.inner.delta_since(cursor)
    }
    fn report_version(&self) -> u64 {
        self.inner.report_version()
    }
}

/// A bound cloud vault holding `small` (a few bytes) and `big` (64 KiB), next
/// to a server that takes objects of up to 4 KiB.
fn vault_with_an_oversize_item(db_key: &[u8; 32]) -> (Storage, UnlockedKeyset, LimitedServer) {
    let (s, k) = account(db_key);
    let v =
        Vault::create_with_target(&s, &k, b"vault-1".to_vec(), b"name", SyncTarget::Cloud).unwrap();
    v.put_item(b"big", 1, &vec![7_u8; 64 * 1024]).unwrap();
    v.put_item(b"small", 1, b"secret").unwrap();
    s.bind_unbound_cloud_vaults(TENANT).unwrap();
    (s, k, LimitedServer::new(1000, 4 * 1024))
}

#[test]
fn push_splits_a_vault_over_the_request_byte_budget() {
    // Regression: a whole vault is dirty at once after a bind or a local-to-cloud
    // move, and it all went out in ONE request, which the server refuses past its
    // body limit. Three 400 KiB items do not fit one 1 MiB request.
    let (s, k) = account(&[30_u8; 32]);
    let v =
        Vault::create_with_target(&s, &k, b"vault-1".to_vec(), b"name", SyncTarget::Cloud).unwrap();
    for id in [b"a", b"b", b"c"] {
        v.put_item(id, 1, &vec![1_u8; 400 * 1024]).unwrap();
    }
    s.bind_unbound_cloud_vaults(TENANT).unwrap();
    let mut server = LimitedServer::new(1000, usize::MAX);

    let report = sync_push(&mut server, &s, TENANT).unwrap();

    assert_eq!(report.pushed, 4, "the vault record and its three items");
    assert_eq!(
        server.requests,
        vec![3, 1],
        "two requests, none refused: the record with two items, then the third"
    );
    assert!(
        matches!(
            server.delta_since(0).first(),
            Some((_, SyncObject::Vault(_)))
        ),
        "the vault record still reaches the server before its items"
    );
}

#[test]
fn push_splits_more_objects_than_one_request_carries() {
    let (s, k) = account(&[31_u8; 32]);
    let v =
        Vault::create_with_target(&s, &k, b"vault-1".to_vec(), b"name", SyncTarget::Cloud).unwrap();
    for n in 0..600_u32 {
        v.put_item(format!("item-{n:03}"), 1, b"x").unwrap();
    }
    s.bind_unbound_cloud_vaults(TENANT).unwrap();
    let mut server = LimitedServer::new(1000, usize::MAX);

    let report = sync_push(&mut server, &s, TENANT).unwrap();

    assert_eq!(report.pushed, 601);
    assert_eq!(server.requests, vec![500, 101]);
}

#[test]
fn push_halves_a_request_the_server_refuses_as_too_many_objects() {
    // The server's limits are its own: an operator may have lowered
    // max_objects_per_push below what this client batches by default.
    let (s, k) = account(&[32_u8; 32]);
    let v =
        Vault::create_with_target(&s, &k, b"vault-1".to_vec(), b"name", SyncTarget::Cloud).unwrap();
    for id in [b"a", b"b", b"c"] {
        v.put_item(id, 1, b"x").unwrap();
    }
    s.bind_unbound_cloud_vaults(TENANT).unwrap();
    let mut server = LimitedServer::new(2, usize::MAX);

    let report = sync_push(&mut server, &s, TENANT).unwrap();

    assert_eq!(report.pushed, 4);
    assert!(report.too_large.is_empty());
    assert_eq!(
        server.item_ids(),
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
        "everything arrived, in the original order"
    );
}

#[test]
fn item_too_large_for_the_server_is_reported_and_does_not_block_the_rest() {
    // Regression: one object over the server's max_object_bytes failed the whole
    // push, on every sync, so nothing else of the tenant ever uploaded.
    let (s, _k, mut server) = vault_with_an_oversize_item(&[33_u8; 32]);

    let report = sync_push(&mut server, &s, TENANT).unwrap();

    assert_eq!(report.pushed, 2, "the vault record and the small item");
    assert_eq!(server.item_ids(), vec![b"small".to_vec()]);
    assert_eq!(report.too_large.len(), 1);
    let refused = &report.too_large[0];
    assert_eq!(
        (
            refused.vault_id.as_slice(),
            refused.item_id.as_slice(),
            refused.item_type
        ),
        (b"vault-1".as_slice(), b"big".as_slice(), 1),
        "the refused item is named, with its type"
    );
    assert!(refused.bytes > 64 * 1024);
}

#[test]
fn refused_item_is_not_uploaded_again_but_stays_reported() {
    let (s, _k, mut server) = vault_with_an_oversize_item(&[34_u8; 32]);
    let first = sync_push(&mut server, &s, TENANT).unwrap();
    let requests = server.requests.len();

    let again = sync_push(&mut server, &s, TENANT).unwrap();

    assert_eq!(server.requests.len(), requests, "no request was sent");
    assert_eq!(again.pushed, 0);
    assert_eq!(first.too_large.len(), 1);
    assert_eq!(
        again.too_large, first.too_large,
        "still reported as not uploaded, with everything the first report said"
    );
}

#[test]
fn refused_item_is_offered_again_once_the_refusal_is_forgotten() {
    let (s, _k, mut server) = vault_with_an_oversize_item(&[35_u8; 32]);
    sync_push(&mut server, &s, TENANT).unwrap();
    // The operator raised the limit; the user asks for a retry.
    server.max_object_bytes = usize::MAX;

    forget_push_refusals(&s, TENANT).unwrap();
    let report = sync_push(&mut server, &s, TENANT).unwrap();

    assert_eq!(report.pushed, 1);
    assert!(report.too_large.is_empty());
    assert_eq!(server.item_ids(), vec![b"small".to_vec(), b"big".to_vec()]);
}

#[test]
fn refused_item_is_offered_again_after_it_changes() {
    let (s, k, mut server) = vault_with_an_oversize_item(&[36_u8; 32]);
    sync_push(&mut server, &s, TENANT).unwrap();

    Vault::open(&s, &k, b"vault-1")
        .unwrap()
        .put_item(b"big", 1, b"now small")
        .unwrap();
    let report = sync_push(&mut server, &s, TENANT).unwrap();

    assert_eq!(report.pushed, 1);
    assert!(report.too_large.is_empty());
}

#[test]
fn failed_request_does_not_resend_what_was_already_delivered() {
    let (s, k) = account(&[37_u8; 32]);
    let v =
        Vault::create_with_target(&s, &k, b"vault-1".to_vec(), b"name", SyncTarget::Cloud).unwrap();
    for id in [b"a", b"b", b"c"] {
        v.put_item(id, 1, &vec![1_u8; 400 * 1024]).unwrap();
    }
    s.bind_unbound_cloud_vaults(TENANT).unwrap();
    let mut server = LimitedServer::new(1000, usize::MAX);
    // The first request (record + two items) lands; the second fails.
    server.fail_request = Some(2);

    sync_push(&mut server, &s, TENANT).unwrap_err();
    let retry = sync_push(&mut server, &s, TENANT).unwrap();

    assert_eq!(retry.pushed, 1, "only the item of the failed request");
    assert_eq!(
        server.item_ids(),
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
    );
}

/// A server whose write policy refuses the items with one id, as
/// `POST /v1/sync/push` refuses a Viewer's item: the WHOLE request is refused
/// with [`SyncError::Forbidden`], without saying which object it was.
struct ForbiddingServer {
    inner: InMemoryTransport,
    refused_item: &'static [u8],
    requests: usize,
}

impl ForbiddingServer {
    fn new(refused_item: &'static [u8]) -> Self {
        Self {
            inner: InMemoryTransport::new(),
            refused_item,
            requests: 0,
        }
    }

    /// Ids of the items the server holds, in the order it accepted them.
    fn item_ids(&self) -> Vec<Vec<u8>> {
        self.inner
            .delta_since(0)
            .into_iter()
            .filter_map(|(_, o)| {
                if let SyncObject::Item(i) = o {
                    Some(i.item_id)
                } else {
                    None
                }
            })
            .collect()
    }
}

impl SyncTransport for ForbiddingServer {
    fn push_objects(&mut self, objects: &[SyncObject]) -> Result<Vec<u64>, SyncError> {
        self.requests += 1;
        let refused = objects
            .iter()
            .any(|o| matches!(o, SyncObject::Item(i) if i.item_id == self.refused_item));
        if refused {
            return Err(SyncError::Forbidden);
        }
        self.inner.push_objects(objects)
    }
    fn delta_since(&self, cursor: u64) -> Vec<(u64, SyncObject)> {
        self.inner.delta_since(cursor)
    }
    fn report_version(&self) -> u64 {
        self.inner.report_version()
    }
}

/// A bound cloud vault with the items `viewer-edit` and `fine`, both dirty.
fn vault_with_a_refused_item(db_key: &[u8; 32]) -> (Storage, UnlockedKeyset) {
    let (s, k) = account(db_key);
    let v =
        Vault::create_with_target(&s, &k, b"vault-1".to_vec(), b"name", SyncTarget::Cloud).unwrap();
    v.put_item(b"viewer-edit", 1, b"edit").unwrap();
    v.put_item(b"fine", 1, b"ok").unwrap();
    s.bind_unbound_cloud_vaults(TENANT).unwrap();
    (s, k)
}

#[test]
fn item_the_server_refuses_as_not_permitted_no_longer_wedges_the_push() {
    // #166: one refused item failed every push of the device, so nothing else
    // it changed (nor its account state or audit) ever reached the server.
    let (s, _k) = vault_with_a_refused_item(&[40_u8; 32]);
    let mut server = ForbiddingServer::new(b"viewer-edit");

    let report = sync_push(&mut server, &s, TENANT).unwrap();

    assert_eq!(report.pushed, 2, "the vault record and the other item");
    assert_eq!(server.item_ids(), vec![b"fine".to_vec()]);
    assert_eq!(report.unpushable.len(), 1, "{:?}", report.unpushable);
    let left_out = &report.unpushable[0];
    assert_eq!(
        (left_out.item_id.as_slice(), left_out.reason),
        (b"viewer-edit".as_slice(), UnpushableReason::ServerRefused),
        "the refused item is named, with the reason"
    );
}

#[test]
fn item_refused_as_not_permitted_is_not_sent_again_until_the_refusal_is_forgotten() {
    let (s, _k) = vault_with_a_refused_item(&[41_u8; 32]);
    let mut server = ForbiddingServer::new(b"viewer-edit");
    let first = sync_push(&mut server, &s, TENANT).unwrap();
    let requests = server.requests;

    let again = sync_push(&mut server, &s, TENANT).unwrap();
    assert_eq!(server.requests, requests, "no request was sent");
    assert_eq!(again.unpushable, first.unpushable, "still reported");

    // The account's role was raised; the user asks for a retry.
    server.refused_item = b"none";
    forget_push_refusals(&s, TENANT).unwrap();
    let retry = sync_push(&mut server, &s, TENANT).unwrap();
    assert_eq!(retry.pushed, 1, "the item went up");
    assert!(retry.unpushable.is_empty(), "{:?}", retry.unpushable);
}

#[test]
fn item_its_author_may_not_write_is_left_out_without_a_request() {
    // The check every other member makes on pull: in a vault pinned to another
    // owner, where no membership this device holds lets the account write, the
    // account's edit would be rejected — so it is not sent at all. Another
    // vault's edit goes up as usual.
    let (s, k) = account(&[42_u8; 32]);
    let theirs =
        Vault::create_with_target(&s, &k, b"vault-1".to_vec(), b"name", SyncTarget::Cloud).unwrap();
    theirs.put_item(b"viewer-edit", 1, b"edit").unwrap();
    let mine =
        Vault::create_with_target(&s, &k, b"vault-2".to_vec(), b"name", SyncTarget::Cloud).unwrap();
    mine.put_item(b"fine", 1, b"ok").unwrap();
    s.bind_unbound_cloud_vaults(TENANT).unwrap();
    s.set_vault_trust_anchor(b"vault-1", &[9_u8; 32]).unwrap();
    let mut server = ForbiddingServer::new(b"none");
    let ctx = SyncContext {
        genesis_owner: genesis(&k),
        tenant: TENANT.to_vec(),
    };

    let report = sync_push_as(&mut server, &s, &ctx).unwrap();

    assert_eq!(server.item_ids(), vec![b"fine".to_vec()]);
    assert_eq!(report.unpushable.len(), 1, "{:?}", report.unpushable);
    let left_out = &report.unpushable[0];
    assert_eq!(
        (left_out.item_id.as_slice(), left_out.reason),
        (b"viewer-edit".as_slice(), UnpushableReason::NotAuthorized),
        "the left-out item is named, with the reason"
    );
}

#[test]
fn discard_restores_the_server_copy_and_keeps_other_dirty_items() {
    let (s, k) = vault_with_a_refused_item(&[43_u8; 32]);
    let own = genesis(&k);
    let ctx = SyncContext {
        genesis_owner: own.clone(),
        tenant: TENANT.to_vec(),
    };
    // Both items reach the server at version 1.
    let mut server = ForbiddingServer::new(b"none");
    sync_push(&mut server, &s, TENANT).unwrap();
    // Then the server stops permitting edits of one of them; another edit
    // waits for the next sync.
    let vault = Vault::open(&s, &k, b"vault-1").unwrap();
    vault.put_item(b"viewer-edit", 1, b"edit 2").unwrap();
    server.refused_item = b"viewer-edit";
    sync_push(&mut server, &s, TENANT).unwrap();
    vault.put_item(b"fine", 1, b"ok 2").unwrap();

    let dropped = discard_unpushable(&s, b"vault-1", &own).unwrap();
    assert_eq!(dropped.len(), 1, "{dropped:?}");
    assert_eq!(dropped[0].item_id, b"viewer-edit".to_vec());
    // The targeted pull of the vault brings the server's copy back.
    apply_pulled_objects(&s, &ctx, server.inner.delta_since(0)).unwrap();

    let restored = s.get_item(b"vault-1", b"viewer-edit").unwrap().unwrap();
    assert_eq!(restored.version, 1, "the server's copy");
    let dirty: Vec<(Vec<u8>, u64)> = s
        .list_dirty_bound_item_versions(TENANT)
        .unwrap()
        .into_iter()
        .map(|h| (h.item_id, h.version))
        .collect();
    assert_eq!(
        dirty,
        vec![(b"fine".to_vec(), 2)],
        "the other unsent edit is kept"
    );
}
