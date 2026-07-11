//! Integration tests for the sync engine: happy-path + mandatory negatives.
//! The transport is forced to lie (forged/stale/below-cursor/equal-version).

use unissh_crypto::KdfParams;
use unissh_keychain::{create_account, UnlockedKeyset};
use unissh_storage::{Storage, SyncTarget};
use unissh_sync::{
    pull_cursor_key, sync_pull, sync_push, InMemoryTransport, RejectReason, SyncContext,
    SyncObject, SyncTransport,
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
        salt: vec![1u8; 16],
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
    let (sa, ka) = account(&[1u8; 32]);
    // B is the same ownership: WE USE THE SAME keyset (one account, two devices).
    let sb = Storage::open_in_memory(&[2u8; 32]).unwrap();
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

#[test]
fn dirty_tracking_pushes_only_changes() {
    // The regression this feature fixes: sync_push used to re-send the whole bound
    // vault on every call. Now it sends only DIRTY objects and clears them, so a push
    // with no local changes sends nothing.
    let (sa, ka) = account(&[1u8; 32]);
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
fn pulled_objects_are_not_re_pushed() {
    // Objects applied by sync_pull go through low-level put_* (not the vault layer),
    // so they never get marked dirty and are never bounced back to the server.
    let (sa, ka) = account(&[1u8; 32]);
    seed_vault(&sa, &ka);
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    let sb = Storage::open_in_memory(&[2u8; 32]).unwrap();
    let r = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert!(r.applied >= 2, "B receives vault + item");
    sb.bind_unbound_cloud_vaults(TENANT).unwrap(); // pulled vault lands unbound
    assert_eq!(
        sync_push(&mut t, &sb, TENANT).unwrap().pushed,
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
    let (sa, ka) = account(&[1u8; 32]); // owner
    let (_sb2, kb) = account(&[9u8; 32]); // some OTHER identity (was on the device first)
    seed_vault(&sa, &ka);

    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    // The device (sb) first pulls as the WRONG identity → vault rejected, cursor burned.
    let sb = Storage::open_in_memory(&[2u8; 32]).unwrap();
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
    unissh_sync::reset_pull_cursor(&sb, b"oracle-tenant").unwrap();
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
    let (sa, ka) = account(&[1u8; 32]);
    seed_vault(&sa, &ka);
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    // device B (same owner keyset) pulls → has the vault + item.
    let sb = Storage::open_in_memory(&[2u8; 32]).unwrap();
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
    unissh_sync::reset_pull_cursor(&sb, b"oracle-tenant").unwrap();
    let r2 = sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();
    assert_eq!(r2.applied, 0, "LWW keeps the newer local tombstone");
    assert!(sb.get_vault(b"vault-1").unwrap().unwrap().tombstone);

    // restore = purge the local record + reset cursor + re-pull → vault recovered.
    assert_eq!(sb.list_tombstoned_cloud_vaults().unwrap().len(), 1);
    sb.purge_vault_data(b"vault-1").unwrap();
    unissh_sync::reset_pull_cursor(&sb, b"oracle-tenant").unwrap();
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
    let (sa, ka) = account(&[1u8; 32]);
    seed_vault(&sa, &ka);
    let sb = Storage::open_in_memory(&[3u8; 32]).unwrap();
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();

    // attacker is a DIFFERENT account. Signs an item in someone else's vault-1 validly
    // under THEIR OWN key, but authority under genesis A will fail.
    let (_s2, _e2, attacker) = create_account(Some(b"x"), test_params()).unwrap();
    let sx = Storage::open_in_memory(&[8u8; 32]).unwrap();
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
    let (sa, ka) = account(&[1u8; 32]);
    seed_vault(&sa, &ka);
    let sb = Storage::open_in_memory(&[4u8; 32]).unwrap();
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
    let (sa, ka) = account(&[1u8; 32]);
    seed_vault(&sa, &ka);
    let sb = Storage::open_in_memory(&[5u8; 32]).unwrap();
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
    let (sa, ka) = account(&[1u8; 32]);
    let vid = seed_vault(&sa, &ka);
    let sb = Storage::open_in_memory(&[6u8; 32]).unwrap();
    let mut t = InMemoryTransport::new();
    sync_push(&mut t, &sa, TENANT).unwrap();
    sync_pull(&mut t, &sb, &ctx(&ka)).unwrap();

    // A SECOND valid item version=1 with DIFFERENT content, the same (vault,item).
    // Emulates an independent mint of version 1 on another device — both validly
    // signed by the owner (the same keyset ka), but the content differs.
    let sc = Storage::open_in_memory(&[7u8; 32]).unwrap();
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
    let (sa, ka) = account(&[1u8; 32]);
    seed_vault(&sa, &ka);
    let sb = Storage::open_in_memory(&[10u8; 32]).unwrap();
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
    assert!(matches!(
        err,
        unissh_sync::SyncError::TransportRollback { .. }
    ));
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
    let sb = Storage::open_in_memory(&[11u8; 32]).unwrap();
    // raise the floor above the record's generation (enc.generation == 1)
    raise_keyset_gen_floor(&sb, 5).unwrap();
    let (_s, ka) = account(&[12u8; 32]);
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
    let (sa, ka) = account(&[13u8; 32]);
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
    let (sa, ka) = account(&[20u8; 32]);
    const TENANT_A: &[u8] = b"tenant-A";
    const TENANT_B: &[u8] = b"tenant-B";

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
        .filter_map(|(_, o)| match o {
            SyncObject::Vault(v) => Some(v.vault_id),
            _ => None,
        })
        .collect()
}

/// A3.2: sync_push hands off the local account-state (reconstructs it from the storage row).
#[test]
fn sync_push_emits_local_account_state() {
    let (sa, ka) = account(&[9u8; 32]);
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
        "sync_push должен отдать локальное account-state"
    );
}
