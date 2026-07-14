//! Storage tests: instance isolation, round-trip, tombstone, monotonicity.

use unissh_storage::{CachePolicy, ItemRecord, Storage, SyncTarget, VaultRecord};

fn key(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn vault(id: &[u8], version: u64) -> VaultRecord {
    VaultRecord {
        vault_id: id.to_vec(),
        sync_target: SyncTarget::Local,
        name_blob: b"enc-name".to_vec(),
        wrapped_vk: b"wrapped-vk".to_vec(),
        version,
        tombstone: false,
        signature: b"sig".to_vec(),
        author_pubkey: b"pub".to_vec(),
        key_epoch: 0,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    }
}

fn item(vault_id: &[u8], item_id: &[u8], version: u64, tombstone: bool) -> ItemRecord {
    ItemRecord {
        vault_id: vault_id.to_vec(),
        item_id: item_id.to_vec(),
        item_type: 1,
        content_blob: b"ciphertext".to_vec(),
        wrapped_item_key: b"wrapped-key".to_vec(),
        version,
        tombstone,
        signature: b"sig".to_vec(),
        author_pubkey: b"pub".to_vec(),
        created_at: 0,
        updated_at: 0,
        key_epoch: 0,
    }
}

#[test]
fn vault_cloud_epoch_cache_policy_roundtrip() {
    let s = Storage::open_in_memory(&key(0x41)).unwrap();
    let mut v = vault(b"vc", 1);
    v.sync_target = SyncTarget::Cloud;
    v.key_epoch = 3;
    v.cache_policy = CachePolicy::OnlineOnly;
    v.sync_tenant = b"tenant-A".to_vec();
    s.put_vault(&v).unwrap();

    let got = s.get_vault(b"vc").unwrap().unwrap();
    assert_eq!(got.sync_target, SyncTarget::Cloud);
    assert_eq!(got.key_epoch, 3);
    assert_eq!(got.cache_policy, CachePolicy::OnlineOnly);
    assert_eq!(got.sync_tenant, b"tenant-A".to_vec());
    assert_eq!(got, v);
    // list_vaults returns the new fields too.
    let listed = s.list_vaults().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].cache_policy, CachePolicy::OnlineOnly);
}

#[test]
fn binding_an_already_synced_vault_redirties_it_for_push() {
    // Regression for "I bound my vault to a server but it never uploaded": binding is a
    // routing-label change that touched no `dirty` flag, so a previously-synced vault
    // (dirty cleared) never re-pushed its record to the newly-bound server.
    let s = Storage::open_in_memory(&key(0x42)).unwrap();
    let mut v = vault(b"vb", 1);
    v.sync_target = SyncTarget::Cloud;
    v.sync_tenant = b"tenant-A".to_vec();
    s.put_vault(&v).unwrap();
    s.put_item(&item(b"vb", b"i1", 1, false)).unwrap();

    // Simulate a completed push to A: the whole vault is clean.
    s.clear_dirty_for_tenant(b"tenant-A").unwrap();
    assert!(
        s.list_dirty_bound_vaults(b"tenant-A").unwrap().is_empty(),
        "clean after the push to A"
    );

    // Re-bind the already-synced vault to a NEW server B.
    s.set_vault_tenant(b"vb", b"tenant-B").unwrap();

    // The fix: binding re-dirties the vault AND its contents, so a push to B uploads them.
    let vaults = s.list_dirty_bound_vaults(b"tenant-B").unwrap();
    assert_eq!(vaults.len(), 1, "the bound vault record is dirty for B");
    assert_eq!(vaults[0].vault_id, b"vb".to_vec());
    let items = s.list_dirty_bound_items(b"tenant-B").unwrap();
    assert_eq!(items.len(), 1, "the bound vault's item is dirty for B");
}

#[test]
fn pulled_empty_sync_tenant_does_not_clobber_binding() {
    // Regression: a pulled (wire) vault record carries an empty sync_tenant. A
    // higher-version put_vault must NOT erase an existing local binding, else the
    // cloud vault silently unbinds and stops syncing (the CRITICAL review finding).
    let s = Storage::open_in_memory(&key(0x45)).unwrap();
    let mut v = vault(b"vb", 1);
    v.sync_target = SyncTarget::Cloud;
    v.sync_tenant = b"tenant-A".to_vec();
    s.put_vault(&v).unwrap();

    // A higher-version update with empty sync_tenant (the normal pull case).
    let mut pulled = vault(b"vb", 2);
    pulled.sync_target = SyncTarget::Cloud;
    pulled.sync_tenant = Vec::new();
    s.put_vault(&pulled).unwrap();

    let got = s.get_vault(b"vb").unwrap().unwrap();
    assert_eq!(got.version, 2, "the version update did apply");
    assert_eq!(
        got.sync_tenant,
        b"tenant-A".to_vec(),
        "binding preserved across an empty-tenant pull"
    );

    // A non-empty incoming tenant still overwrites (a legitimate rebind).
    let mut rebind = vault(b"vb", 3);
    rebind.sync_target = SyncTarget::Cloud;
    rebind.sync_tenant = b"tenant-B".to_vec();
    s.put_vault(&rebind).unwrap();
    assert_eq!(
        s.get_vault(b"vb").unwrap().unwrap().sync_tenant,
        b"tenant-B".to_vec()
    );
}

#[test]
fn set_vault_tenant_targets_one_and_clear_binding_targets_a_tenant() {
    let s = Storage::open_in_memory(&key(0x46)).unwrap();
    let mut c1 = vault(b"c1", 1);
    c1.sync_target = SyncTarget::Cloud;
    let mut c2 = vault(b"c2", 1);
    c2.sync_target = SyncTarget::Cloud;
    c2.sync_tenant = b"tenant-A".to_vec();
    let local = vault(b"lo", 1); // SyncTarget::Local
    s.put_vault(&c1).unwrap();
    s.put_vault(&c2).unwrap();
    s.put_vault(&local).unwrap();

    // set_vault_tenant binds ONLY c1 (not c2, not the local vault).
    s.set_vault_tenant(b"c1", b"tenant-B").unwrap();
    assert_eq!(
        s.get_vault(b"c1").unwrap().unwrap().sync_tenant,
        b"tenant-B".to_vec()
    );
    assert_eq!(
        s.get_vault(b"c2").unwrap().unwrap().sync_tenant,
        b"tenant-A".to_vec()
    );
    assert!(s.get_vault(b"lo").unwrap().unwrap().sync_tenant.is_empty());

    // clear_binding_for_tenant clears only vaults bound to that tenant.
    let n = s.clear_binding_for_tenant(b"tenant-A").unwrap();
    assert_eq!(n, 1);
    assert!(
        s.get_vault(b"c2").unwrap().unwrap().sync_tenant.is_empty(),
        "c2 now unbound"
    );
    assert_eq!(
        s.get_vault(b"c1").unwrap().unwrap().sync_tenant,
        b"tenant-B".to_vec(),
        "c1 untouched"
    );
}

#[test]
fn vault_bad_enum_values_are_errors_not_panics() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("badenum.db");
    let k = key(0x42);
    {
        let s = Storage::open(&p, &k).unwrap();
        s.put_vault(&vault(b"v", 1)).unwrap();
    }
    // Corrupt sync_target/cache_policy to invalid values with a raw UPDATE.
    {
        let conn = raw_open(&p, &k);
        conn.execute(
            "UPDATE vaults SET sync_target = 99 WHERE vault_id = X'76'",
            [],
        )
        .unwrap();
    }
    let s = Storage::open(&p, &k).unwrap();
    // map_vault_row → IntegralValueOutOfRange (via rusqlite::Error), not a panic.
    let err = s.get_vault(b"v").unwrap_err();
    assert!(matches!(err, unissh_storage::StorageError::Sqlite(_)));

    {
        let conn = raw_open(&p, &k);
        conn.execute(
            "UPDATE vaults SET sync_target = 0, cache_policy = 99 WHERE vault_id = X'76'",
            [],
        )
        .unwrap();
    }
    let s = Storage::open(&p, &k).unwrap();
    let err = s.get_vault(b"v").unwrap_err();
    assert!(matches!(err, unissh_storage::StorageError::Sqlite(_)));
}

#[test]
fn vault_and_item_roundtrip() {
    let s = Storage::open_in_memory(&key(1)).unwrap();
    s.put_vault(&vault(b"v1", 1)).unwrap();
    s.put_item(&item(b"v1", b"i1", 1, false)).unwrap();

    assert_eq!(s.get_vault(b"v1").unwrap().unwrap(), vault(b"v1", 1));
    // Storage sets the timestamps (created_at/updated_at), so we
    // compare the record with them zeroed out.
    let mut got = s.get_item(b"v1", b"i1").unwrap().unwrap();
    assert!(got.created_at > 0 && got.updated_at > 0);
    got.created_at = 0;
    got.updated_at = 0;
    assert_eq!(got, item(b"v1", b"i1", 1, false));
    assert_eq!(s.list_vaults().unwrap().len(), 1);
    assert_eq!(s.list_items(b"v1").unwrap().len(), 1);
}

#[test]
fn item_key_epoch_roundtrips_through_put_and_history() {
    let s = Storage::open_in_memory(&key(0x43)).unwrap();
    s.put_vault(&vault(b"v", 1)).unwrap();

    let mut it = item(b"v", b"i", 1, false);
    it.key_epoch = 2;
    it.signature = vec![0u8; 67];
    it.author_pubkey = vec![0u8; 32];
    s.put_item(&it).unwrap();
    assert_eq!(s.get_item(b"v", b"i").unwrap().unwrap().key_epoch, 2);

    // Archiving preserves the key_epoch of the version being archived.
    let mut it2 = item(b"v", b"i", 2, false);
    it2.key_epoch = 3;
    it2.signature = vec![0u8; 67];
    it2.author_pubkey = vec![0u8; 32];
    s.archive_and_put(&it2, 10).unwrap();

    // The current version is epoch 3.
    assert_eq!(s.get_item(b"v", b"i").unwrap().unwrap().key_epoch, 3);
    // In history — the previous version with epoch 2.
    let hist = s.list_item_history(b"v", b"i").unwrap();
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].version, 1);
    assert_eq!(hist[0].key_epoch, 2);
}

#[test]
fn item_timestamps_created_preserved_updated_advances() {
    let s = Storage::open_in_memory(&key(7)).unwrap();
    s.put_item(&item(b"v", b"i", 1, false)).unwrap();
    let first = s.get_item(b"v", b"i").unwrap().unwrap();
    assert!(first.created_at > 0);
    assert_eq!(first.created_at, first.updated_at);

    // Update: created_at is preserved, updated_at does not decrease.
    s.put_item(&item(b"v", b"i", 2, false)).unwrap();
    let second = s.get_item(b"v", b"i").unwrap().unwrap();
    assert_eq!(second.created_at, first.created_at);
    assert!(second.updated_at >= first.updated_at);
}

#[test]
fn instance_isolation_separate_files() {
    let dir = tempfile::tempdir().unwrap();
    let p1 = dir.path().join("inst1.db");
    let p2 = dir.path().join("inst2.db");

    {
        let s1 = Storage::open(&p1, &key(0xA1)).unwrap();
        s1.put_vault(&vault(b"v-in-1", 1)).unwrap();
    }
    {
        let s2 = Storage::open(&p2, &key(0xB2)).unwrap();
        // a different instance — empty
        assert!(s2.list_vaults().unwrap().is_empty());
        assert!(s2.get_vault(b"v-in-1").unwrap().is_none());
    }
    // reopening the first one with the same key — the data is still there
    let s1 = Storage::open(&p1, &key(0xA1)).unwrap();
    assert_eq!(s1.list_vaults().unwrap().len(), 1);
}

#[test]
fn wrong_key_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("inst.db");
    {
        let s = Storage::open(&p, &key(0x11)).unwrap();
        s.put_vault(&vault(b"v", 1)).unwrap();
    }
    // wrong key → WrongKeyOrCorrupt
    let err = Storage::open(&p, &key(0x22)).unwrap_err();
    assert!(matches!(
        err,
        unissh_storage::StorageError::WrongKeyOrCorrupt
    ));
}

#[test]
fn version_monotonicity_enforced() {
    let s = Storage::open_in_memory(&key(2)).unwrap();
    s.put_item(&item(b"v", b"i", 1, false)).unwrap();
    s.put_item(&item(b"v", b"i", 2, false)).unwrap(); // forward — ok

    // rolling back
    let err = s.put_item(&item(b"v", b"i", 1, false)).unwrap_err();
    assert!(matches!(
        err,
        unissh_storage::StorageError::VersionRollback {
            current: 2,
            attempted: 1
        }
    ));
    // the same version — also a rollback
    assert!(s.put_item(&item(b"v", b"i", 2, false)).is_err());

    // the current version stayed at 2
    assert_eq!(s.get_item(b"v", b"i").unwrap().unwrap().version, 2);
}

#[test]
fn tombstone_soft_delete() {
    let s = Storage::open_in_memory(&key(3)).unwrap();
    s.put_item(&item(b"v", b"i", 1, false)).unwrap();
    // deletion = writing a tombstone with an increased version
    s.put_item(&item(b"v", b"i", 2, true)).unwrap();

    // in the regular list the item disappeared
    assert!(s.list_items(b"v").unwrap().is_empty());
    // but the record (tombstone) is reachable directly and in the list for sync
    let got = s.get_item(b"v", b"i").unwrap().unwrap();
    assert!(got.tombstone);
    assert_eq!(got.version, 2);
    assert_eq!(s.list_items_including_tombstones(b"v").unwrap().len(), 1);
}

#[test]
fn vault_tombstone_excluded_from_list() {
    let s = Storage::open_in_memory(&key(4)).unwrap();
    s.put_vault(&vault(b"v", 1)).unwrap();
    let mut dead = vault(b"v", 2);
    dead.tombstone = true;
    s.put_vault(&dead).unwrap();
    assert!(s.list_vaults().unwrap().is_empty());
    assert!(s.get_vault(b"v").unwrap().unwrap().tombstone);
}

#[test]
fn known_hosts_tofu() {
    let s = Storage::open_in_memory(&key(5)).unwrap();
    // TOFU: nothing is pinned the first time
    assert!(s.get_known_host("example.com", 22).unwrap().is_none());
    s.put_known_host("example.com", 22, b"ssh-ed25519 AAAA...")
        .unwrap();
    assert_eq!(
        s.get_known_host("example.com", 22).unwrap().unwrap(),
        b"ssh-ed25519 AAAA..."
    );
    // different ports — different records
    assert!(s.get_known_host("example.com", 2222).unwrap().is_none());
}

#[test]
fn meta_roundtrip() {
    let s = Storage::open_in_memory(&key(6)).unwrap();
    s.set_meta("instance_id", b"dev-contour").unwrap();
    assert_eq!(s.get_meta("instance_id").unwrap().unwrap(), b"dev-contour");
    assert!(s.get_meta("missing").unwrap().is_none());
}

#[test]
fn version_out_of_range_rejected() {
    let s = Storage::open_in_memory(&key(9)).unwrap();
    let mut it = item(b"v", b"i", 1, false);
    it.version = u64::MAX; // > i64::MAX
    assert!(matches!(
        s.put_item(&it).unwrap_err(),
        unissh_storage::StorageError::VersionOutOfRange
    ));
}

#[test]
fn check_consistency_ok_for_clean_db() {
    let st = Storage::open_in_memory(&key(20)).unwrap();
    // Realistic signature/author lengths for the vault too (check_consistency
    // used not to audit vaults, so the helper with dummy `b"sig"`/`b"pub"` passed; now
    // the structural audit covers vault records as well).
    let mut v = vault(b"v", 1);
    v.signature = vec![0u8; 67];
    v.author_pubkey = vec![0u8; 32];
    st.put_vault(&v).unwrap();
    let mut it = item(b"v", b"i", 1, false);
    it.signature = vec![0u8; 67];
    it.author_pubkey = vec![0u8; 32];
    st.put_item(&it).unwrap();

    let report = st.check_consistency().unwrap();
    assert!(report.integrity_ok);
    assert!(report.ok, "issues: {:?}", report.issues);
    assert!(report.issues.is_empty());
}

#[test]
fn check_consistency_flags_orphan_item() {
    let st = Storage::open_in_memory(&key(21)).unwrap();
    // the item references a non-existent vault
    let mut it = item(b"ghost", b"i", 1, false);
    it.signature = vec![0u8; 67];
    it.author_pubkey = vec![0u8; 32];
    st.put_item(&it).unwrap();

    let report = st.check_consistency().unwrap();
    assert!(!report.ok);
    assert!(report
        .issues
        .iter()
        .any(|i| i.kind == unissh_storage::ConsistencyKind::OrphanItem));
}

#[test]
fn check_consistency_flags_bad_record() {
    let st = Storage::open_in_memory(&key(22)).unwrap();
    st.put_vault(&vault(b"v", 1)).unwrap();
    // author_pubkey is not 32 bytes, version 0, a tombstone with non-empty content
    let bad = ItemRecord {
        vault_id: b"v".to_vec(),
        item_id: b"bad".to_vec(),
        item_type: 1,
        content_blob: b"not-empty".to_vec(),
        wrapped_item_key: vec![],
        version: 0,
        tombstone: true,
        signature: vec![0u8; 10],
        author_pubkey: vec![0u8; 5],
        created_at: 0,
        updated_at: 0,
        key_epoch: 0,
    };
    st.put_item(&bad).unwrap();

    let report = st.check_consistency().unwrap();
    assert!(!report.ok);
    let kinds: Vec<_> = report.issues.iter().map(|i| i.kind).collect();
    assert!(kinds.contains(&unissh_storage::ConsistencyKind::BadVersion));
    assert!(kinds.contains(&unissh_storage::ConsistencyKind::BadAuthorLen));
    assert!(kinds.contains(&unissh_storage::ConsistencyKind::TombstoneNotEmpty));
    // the report contains no secrets: detail strings have no plaintext/ciphertext blob
    for iss in &report.issues {
        assert!(!iss.detail.contains("not-empty"));
    }
}

fn hist_item(content: &[u8], version: u64) -> ItemRecord {
    let mut it = item(b"v", b"pw", version, false);
    it.content_blob = content.to_vec();
    it.signature = vec![0u8; 67];
    it.author_pubkey = vec![0u8; 32];
    it
}

#[test]
fn item_history_archives_prior_versions() {
    let st = Storage::open_in_memory(&key(30)).unwrap();
    st.put_vault(&vault(b"v", 1)).unwrap();
    st.archive_and_put(&hist_item(b"v1", 1), 10).unwrap(); // the first one — nothing to archive
    st.archive_and_put(&hist_item(b"v2", 2), 10).unwrap(); // archives v1
    st.archive_and_put(&hist_item(b"v3", 3), 10).unwrap(); // archives v2

    let hist = st.list_item_history(b"v", b"pw").unwrap();
    let versions: Vec<u64> = hist.iter().map(|r| r.version).collect();
    assert_eq!(versions, vec![2, 1]); // newest-first; v3 is current, not in history
    assert_eq!(hist[0].content_blob, b"v2");
    // the current item is v3
    assert_eq!(st.get_item(b"v", b"pw").unwrap().unwrap().version, 3);
}

#[test]
fn item_history_retention_trims() {
    let st = Storage::open_in_memory(&key(31)).unwrap();
    st.put_vault(&vault(b"v", 1)).unwrap();
    for v in 1..=5 {
        st.archive_and_put(&hist_item(format!("v{v}").as_bytes(), v), 2)
            .unwrap();
    }
    // v1..v4 archived, retention 2 → the 2 newest remain
    let versions: Vec<u64> = st
        .list_item_history(b"v", b"pw")
        .unwrap()
        .iter()
        .map(|r| r.version)
        .collect();
    assert_eq!(versions, vec![4, 3]);
}

#[test]
fn clear_item_history_empties() {
    let st = Storage::open_in_memory(&key(32)).unwrap();
    st.put_vault(&vault(b"v", 1)).unwrap();
    st.archive_and_put(&hist_item(b"a", 1), 10).unwrap();
    st.archive_and_put(&hist_item(b"b", 2), 10).unwrap();
    assert_eq!(st.list_item_history(b"v", b"pw").unwrap().len(), 1);
    st.clear_item_history(b"v", b"pw").unwrap();
    assert!(st.list_item_history(b"v", b"pw").unwrap().is_empty());
}

#[test]
fn put_item_and_clear_history_is_atomic_pair() {
    let st = Storage::open_in_memory(&key(33)).unwrap();
    st.put_vault(&vault(b"v", 1)).unwrap();
    st.archive_and_put(&hist_item(b"v1", 1), 10).unwrap();
    st.archive_and_put(&hist_item(b"v2", 2), 10).unwrap();
    assert!(!st.list_item_history(b"v", b"pw").unwrap().is_empty());

    // tombstone + clearing the history in a single call
    let mut tomb = hist_item(b"", 3);
    tomb.tombstone = true;
    tomb.content_blob = Vec::new();
    st.put_item_and_clear_history(&tomb).unwrap();

    assert!(st.list_item_history(b"v", b"pw").unwrap().is_empty());
    assert!(st.get_item(b"v", b"pw").unwrap().unwrap().tombstone);
}

// --- membership manifests + grants (P2 storage; verification — P3) ---

#[test]
fn membership_manifest_roundtrip_and_upsert() {
    use unissh_storage::MembershipManifest;
    let s = Storage::open_in_memory(&key(0x50)).unwrap();

    let m = MembershipManifest {
        vault_id: b"v".to_vec(),
        key_epoch: 1,
        manifest_blob: b"signed-manifest".to_vec(),
        signature: vec![0u8; 64],
        author_pubkey: vec![0u8; 32],
    };
    s.put_membership_manifest(&m).unwrap();
    assert_eq!(s.get_membership_manifest(b"v", 1).unwrap().unwrap(), m);
    // a different epoch — a separate record
    assert!(s.get_membership_manifest(b"v", 2).unwrap().is_none());

    // UPSERT on (vault_id, key_epoch): a repeated put of the same epoch overwrites.
    let mut m2 = m.clone();
    m2.manifest_blob = b"updated".to_vec();
    s.put_membership_manifest(&m2).unwrap();
    assert_eq!(
        s.get_membership_manifest(b"v", 1)
            .unwrap()
            .unwrap()
            .manifest_blob,
        b"updated"
    );
}

#[test]
fn membership_grants_list_and_upsert_and_remove() {
    use unissh_storage::{MemberRole, MembershipGrant};
    let s = Storage::open_in_memory(&key(0x51)).unwrap();

    let g1 = MembershipGrant {
        vault_id: b"v".to_vec(),
        member_pubkey: b"alice".to_vec(),
        key_epoch: 1,
        role: MemberRole::Editor,
        not_after: 0,
        wrapped_vk: b"wvk-alice".to_vec(),
        signature: vec![0u8; 64],
        author_pubkey: vec![0u8; 32],
    };
    let g2 = MembershipGrant {
        vault_id: b"v".to_vec(),
        member_pubkey: b"bob".to_vec(),
        key_epoch: 1,
        role: MemberRole::Viewer,
        not_after: 0,
        wrapped_vk: b"wvk-bob".to_vec(),
        signature: vec![0u8; 64],
        author_pubkey: vec![0u8; 32],
    };
    s.put_membership_grant(&g1).unwrap();
    s.put_membership_grant(&g2).unwrap();

    let mut listed = s.list_membership_grants(b"v", 1).unwrap();
    assert_eq!(listed.len(), 2);
    listed.sort_by(|a, b| a.member_pubkey.cmp(&b.member_pubkey));
    assert_eq!(listed[0].member_pubkey, b"alice");
    assert_eq!(listed[0].role, MemberRole::Editor);
    assert_eq!(listed[1].member_pubkey, b"bob");

    // a different epoch — empty
    assert!(s.list_membership_grants(b"v", 2).unwrap().is_empty());

    // UPSERT on (vault_id, member_pubkey, key_epoch).
    let mut g1b = g1.clone();
    g1b.role = MemberRole::Admin;
    g1b.wrapped_vk = b"wvk-alice-2".to_vec();
    s.put_membership_grant(&g1b).unwrap();
    let after = s.list_membership_grants(b"v", 1).unwrap();
    assert_eq!(after.len(), 2);
    let alice = after.iter().find(|g| g.member_pubkey == b"alice").unwrap();
    assert_eq!(alice.role, MemberRole::Admin);
    assert_eq!(alice.wrapped_vk, b"wvk-alice-2");

    // remove → bool
    assert!(s.remove_membership_grant(b"v", b"bob", 1).unwrap());
    assert!(!s.remove_membership_grant(b"v", b"bob", 1).unwrap());
    assert_eq!(s.list_membership_grants(b"v", 1).unwrap().len(), 1);
}

#[test]
fn member_role_from_i64_rejects_unknown() {
    use unissh_storage::MemberRole;
    assert_eq!(MemberRole::from_i64(0), Some(MemberRole::Viewer));
    assert_eq!(MemberRole::from_i64(1), Some(MemberRole::Editor));
    assert_eq!(MemberRole::from_i64(2), Some(MemberRole::Admin));
    assert_eq!(MemberRole::from_i64(99), None);
}

// --- pinning of the member pubkey (spec §13 item 12) ---

#[test]
fn pinned_member_keys_crud() {
    let s = Storage::open_in_memory(&key(0x52)).unwrap();

    // nothing is pinned
    assert!(s.get_pinned_member_key(b"acct-a").unwrap().is_none());
    assert!(s.list_pinned_member_keys().unwrap().is_empty());

    s.pin_member_key(b"acct-a", b"pubkey-a", "SHA256:aaa")
        .unwrap();
    s.pin_member_key(b"acct-b", b"pubkey-b", "SHA256:bbb")
        .unwrap();

    let a = s.get_pinned_member_key(b"acct-a").unwrap().unwrap();
    assert_eq!(a.account_id, b"acct-a");
    assert_eq!(a.member_pubkey, b"pubkey-a");
    assert_eq!(a.fingerprint, "SHA256:aaa");
    assert!(a.added_at > 0);

    assert_eq!(s.list_pinned_member_keys().unwrap().len(), 2);

    // UPSERT on account_id: re-pinning overwrites the key/fingerprint.
    s.pin_member_key(b"acct-a", b"pubkey-a2", "SHA256:a2")
        .unwrap();
    let a2 = s.get_pinned_member_key(b"acct-a").unwrap().unwrap();
    assert_eq!(a2.member_pubkey, b"pubkey-a2");
    assert_eq!(a2.fingerprint, "SHA256:a2");
    assert_eq!(s.list_pinned_member_keys().unwrap().len(), 2);

    // remove → bool
    assert!(s.remove_pinned_member_key(b"acct-b").unwrap());
    assert!(!s.remove_pinned_member_key(b"acct-b").unwrap());
    assert_eq!(s.list_pinned_member_keys().unwrap().len(), 1);
}

// --- append-only audit log (storage of signed records) ---

#[test]
fn audit_log_append_and_list_monotonic() {
    let s = Storage::open_in_memory(&key(0x53)).unwrap();

    // empty
    assert!(s.list_audit(0).unwrap().is_empty());

    let seq1 = s.append_audit(b"entry-1", &[0u8; 64], &[0u8; 32]).unwrap();
    let seq2 = s.append_audit(b"entry-2", &[1u8; 64], &[1u8; 32]).unwrap();
    assert!(seq2 > seq1, "seq must grow monotonically");

    let all = s.list_audit(0).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].seq, seq1);
    assert_eq!(all[0].entry_blob, b"entry-1");
    assert_eq!(all[1].seq, seq2);
    assert!(all[0].recorded_at > 0);
    // ascending order of seq
    assert!(all[0].seq < all[1].seq);

    // since_seq=N returns only seq > N
    let tail = s.list_audit(seq1).unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].seq, seq2);
}

#[test]
fn audit_log_list_past_end_is_empty_not_panic() {
    let s = Storage::open_in_memory(&key(0x54)).unwrap();
    s.append_audit(b"e", &[0u8; 64], &[0u8; 32]).unwrap();
    // since_seq past the end → empty, not a panic
    assert!(s.list_audit(u64::MAX).unwrap().is_empty());
}

// --- sync-state: cursor and epoch floor (spec §13 item 2) ---

#[test]
fn sync_cursor_roundtrip_and_overwrite() {
    let s = Storage::open_in_memory(&key(0x55)).unwrap();
    assert!(s.get_sync_cursor("global").unwrap().is_none());

    s.set_sync_cursor("global", 42).unwrap();
    assert_eq!(s.get_sync_cursor("global").unwrap(), Some(42));
    // different keys are independent
    assert!(s.get_sync_cursor("other").unwrap().is_none());
    // overwrite
    s.set_sync_cursor("global", 100).unwrap();
    assert_eq!(s.get_sync_cursor("global").unwrap(), Some(100));
}

#[test]
fn vault_epoch_floor_roundtrip_and_overwrite() {
    let s = Storage::open_in_memory(&key(0x56)).unwrap();
    assert!(s.get_vault_epoch_floor(b"v").unwrap().is_none());

    s.set_vault_epoch_floor(b"v", 3).unwrap();
    assert_eq!(s.get_vault_epoch_floor(b"v").unwrap(), Some(3));
    // different vaults are independent
    assert!(s.get_vault_epoch_floor(b"other").unwrap().is_none());
    // raw storage: storage does not forbid writing a smaller value
    // (floor monotonicity is enforced by the vault/sync layer, P4/P6).
    s.set_vault_epoch_floor(b"v", 2).unwrap();
    assert_eq!(s.get_vault_epoch_floor(b"v").unwrap(), Some(2));
}

#[test]
fn vault_trust_anchor_roundtrip_and_purge() {
    let s = Storage::open_in_memory(&key(0x5a)).unwrap();
    assert!(s.get_vault_trust_anchor(b"v").unwrap().is_none());

    let owner = vec![0xAAu8; 32];
    s.set_vault_trust_anchor(b"v", &owner).unwrap();
    let a = s.get_vault_trust_anchor(b"v").unwrap().unwrap();
    assert_eq!(a.vault_id, b"v");
    assert_eq!(a.genesis_owner_pubkey, owner);
    // different vaults are independent
    assert!(s.get_vault_trust_anchor(b"other").unwrap().is_none());
    // purging the vault removes the anchor too
    s.purge_vault_data(b"v").unwrap();
    assert!(s.get_vault_trust_anchor(b"v").unwrap().is_none());
}

// --- upgrade v3 -> v4 (schema migration) ---

/// Opens a raw SQLCipher connection to the file with the same key as `Storage`.
fn raw_open(path: &std::path::Path, k: &[u8; 32]) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    let pragma = format!("PRAGMA key = \"x'{}'\";", hex::encode(k));
    conn.execute_batch(&pragma).unwrap();
    conn
}

/// Builds a V3-schema DB "by hand" (v1+v2+v3 DDL without the V4 columns), `user_version=3`,
/// and inserts one vault row and one item row (old format, without `key_epoch`).
fn build_v3_db(path: &std::path::Path, k: &[u8; 32]) {
    let conn = raw_open(path, k);
    conn.execute_batch(
        r#"
        BEGIN;
        CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
        CREATE TABLE vaults (
            vault_id BLOB PRIMARY KEY, sync_target INTEGER NOT NULL,
            name_blob BLOB NOT NULL, wrapped_vk BLOB NOT NULL, version INTEGER NOT NULL,
            tombstone INTEGER NOT NULL, signature BLOB NOT NULL, author_pubkey BLOB NOT NULL
        );
        CREATE TABLE items (
            vault_id BLOB NOT NULL, item_id BLOB NOT NULL, item_type INTEGER NOT NULL,
            content_blob BLOB NOT NULL, wrapped_item_key BLOB NOT NULL, version INTEGER NOT NULL,
            tombstone INTEGER NOT NULL, signature BLOB NOT NULL, author_pubkey BLOB NOT NULL,
            server_seq INTEGER, created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (vault_id, item_id)
        );
        CREATE TABLE item_history (
            hseq INTEGER PRIMARY KEY AUTOINCREMENT, vault_id BLOB NOT NULL, item_id BLOB NOT NULL,
            item_type INTEGER NOT NULL, content_blob BLOB NOT NULL, wrapped_item_key BLOB NOT NULL,
            version INTEGER NOT NULL, tombstone INTEGER NOT NULL, signature BLOB NOT NULL,
            author_pubkey BLOB NOT NULL, created_at INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0, UNIQUE (vault_id, item_id, version)
        );
        CREATE TABLE known_hosts (
            host TEXT NOT NULL, port INTEGER NOT NULL, host_key BLOB NOT NULL,
            added_at INTEGER NOT NULL, PRIMARY KEY (host, port)
        );
        INSERT INTO vaults (vault_id, sync_target, name_blob, wrapped_vk, version, tombstone, signature, author_pubkey)
            VALUES (X'7631', 0, X'6e616d65', X'766b', 5, 0, X'736967', X'617574686f72');
        INSERT INTO items (vault_id, item_id, item_type, content_blob, wrapped_item_key, version, tombstone, signature, author_pubkey, created_at, updated_at)
            VALUES (X'7631', X'6931', 1, X'636f6e74656e74', X'77696b', 7, 0, X'736967', X'617574686f72', 11, 22);
        PRAGMA user_version = 3;
        COMMIT;
        "#,
    )
    .unwrap();
}

#[test]
fn upgrade_v3_to_v5_preserves_data_and_adds_tables() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("v3.db");
    let k = key(0x40);
    build_v3_db(&p, &k);

    // Reopen through Storage → migrations V4 … V9.
    let s = Storage::open(&p, &k).unwrap();
    assert_eq!(s.schema_version(), 9);

    // The old data is still there (vault and item are read with defaulted new fields).
    let v = s.get_vault(b"v1").unwrap().unwrap();
    assert_eq!(v.version, 5);
    // Legacy vault: sync_tenant gets the default X'' (unbound) — safe.
    assert!(v.sync_tenant.is_empty());
    let it = s.get_item(b"v1", b"i1").unwrap().unwrap();
    assert_eq!(it.version, 7);

    // The new tables exist (a raw SELECT count does not fail).
    let conn = raw_open(&p, &k);
    for table in [
        "membership_manifests",
        "membership_grants",
        "pinned_member_keys",
        "audit_log",
        "vault_epoch_floor",
        "vault_trust_anchor",
        "account_state",
        "sync_state",
        "cert_meta",
    ] {
        let sql = format!("SELECT count(*) FROM {table}");
        let n: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "table {table} should exist and be empty");
    }
    // The new columns are present on vaults/items/item_history.
    let uv: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(uv, 9);
    for (table, col) in [
        ("vaults", "key_epoch"),
        ("vaults", "cache_policy"),
        ("vaults", "sync_tenant"),
        ("items", "key_epoch"),
        ("item_history", "key_epoch"),
        ("membership_grants", "not_after"), // V6
    ] {
        let sql = format!("SELECT {col} FROM {table} LIMIT 1");
        // Does not fail on a missing column.
        let _ = conn.query_row(&sql, [], |r| r.get::<_, Option<i64>>(0));
        assert!(
            conn.prepare(&sql).is_ok(),
            "column {table}.{col} should exist"
        );
    }
}

#[test]
fn check_consistency_flags_stale_history() {
    let st = Storage::open_in_memory(&key(34)).unwrap();
    st.put_vault(&vault(b"v", 1)).unwrap();
    st.archive_and_put(&hist_item(b"v1", 1), 10).unwrap();
    st.archive_and_put(&hist_item(b"v2", 2), 10).unwrap();
    // delete the item directly (tombstone) WITHOUT clearing history — corrupting the invariant
    let mut tomb = hist_item(b"", 3);
    tomb.tombstone = true;
    tomb.content_blob = Vec::new();
    st.put_item(&tomb).unwrap();

    let report = st.check_consistency().unwrap();
    assert!(report
        .issues
        .iter()
        .any(|i| i.kind == unissh_storage::ConsistencyKind::StaleHistory));
}
