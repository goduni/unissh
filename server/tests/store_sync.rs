//! Store level §15.1: instance-wide monotonic/append-only server_seq, push
//! idempotency, membership-filtered delta. SQLite in-memory.

use unissh_server::codec::parse_open;
use unissh_server::store::sync_repo::PushObj;
use unissh_server::store::{Store, Val};
use unissh_storage::{
    CachePolicy, ItemRecord, MemberRole, MembershipGrant, MembershipManifest, SyncTarget,
    VaultRecord,
};
use unissh_sync::{AccountStateObject, AuditObject, SyncObject};

fn push_obj(o: SyncObject) -> PushObj {
    let bytes = o.to_bytes().unwrap();
    let parsed = parse_open(&bytes).unwrap();
    PushObj { bytes, parsed }
}

fn audit(tag: u8) -> SyncObject {
    SyncObject::Audit(AuditObject {
        vault_id: vec![],
        entry_blob: vec![tag],
        signature: vec![1u8; 67],
        author_pubkey: vec![2u8; 32],
    })
}

fn vault(owner: u8, version: u64) -> SyncObject {
    SyncObject::Vault(VaultRecord {
        vault_id: b"vault-1".to_vec(),
        sync_target: SyncTarget::Cloud,
        name_blob: vec![1, 2, 3],
        wrapped_vk: vec![4, 5, 6],
        version,
        tombstone: false,
        signature: vec![9u8; 67],
        author_pubkey: vec![owner; 32],
        key_epoch: 1,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    })
}

async fn fresh_store() -> Store {
    let s = Store::connect_sqlite(":memory:", 1).await.unwrap();
    s.migrate().await.unwrap();
    s.ensure_instance(1).await.unwrap();
    s
}

#[tokio::test]
async fn monotonic_seq_order_and_first_is_one() {
    let s = fresh_store().await;

    let r = s
        .push_objects(
            None,
            b"h1",
            vec![push_obj(audit(1)), push_obj(audit(2)), push_obj(audit(3))],
            100,
        )
        .await
        .unwrap();
    assert_eq!(
        r.server_seq,
        vec![1, 2, 3],
        "first object gets seq 1, in input order"
    );
    assert!(!r.replayed);

    // second push continues monotonically
    let r2 = s
        .push_objects(None, b"h2", vec![push_obj(audit(4))], 101)
        .await
        .unwrap();
    assert_eq!(r2.server_seq, vec![4]);
    assert_eq!(
        s.report_version().await.unwrap(),
        4,
        "report_version == max seq"
    );

    // delta returns all, seq>cursor ASC
    let d = s.delta_since(0, 100, &[0u8; 32], 1_000_000).await.unwrap();
    assert_eq!(
        d.iter().map(|x| x.server_seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    let d2 = s.delta_since(2, 100, &[0u8; 32], 1_000_000).await.unwrap();
    assert_eq!(
        d2.iter().map(|x| x.server_seq).collect::<Vec<_>>(),
        vec![3, 4]
    );
}

#[tokio::test]
async fn idempotent_replay_returns_same_seqs_no_dups() {
    let s = fresh_store().await;

    let mk = || vec![push_obj(audit(1)), push_obj(audit(2))];
    let first = s
        .push_objects(Some(b"idem-1"), b"body-hash", mk(), 100)
        .await
        .unwrap();
    assert_eq!(first.server_seq, vec![1, 2]);
    assert!(!first.replayed);

    // replay same key + same body → same seqs, no new rows, next_seq unchanged
    let replay = s
        .push_objects(Some(b"idem-1"), b"body-hash", mk(), 100)
        .await
        .unwrap();
    assert_eq!(
        replay.server_seq,
        vec![1, 2],
        "replay returns the same seqs"
    );
    assert!(replay.replayed);
    assert_eq!(
        s.report_version().await.unwrap(),
        2,
        "next_seq did not advance on replay"
    );

    let count = s
        .fetch_scalar_i64("SELECT COUNT(*) FROM objects", vec![])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count, 2, "no duplicate rows inserted on replay");

    // same key, different body → 409 conflict
    let err = s
        .push_objects(Some(b"idem-1"), b"different-hash", mk(), 100)
        .await
        .unwrap_err();
    assert_eq!(err.code, unissh_server::ErrorCode::Conflict);
}

/// FIX: a personal vault first materialized via push (no prior `/v1/vaults/claim`) binds
/// `owner_account_id` to the author's account, so `can_admin_vault` recognizes the owner —
/// parity with claim. Without it the column stayed NULL and the owner could not attach a
/// selective `vault_intent` to an invite for their own vault.
#[tokio::test]
async fn push_created_personal_vault_binds_owner_account() {
    use unissh_server::ids;

    let s = fresh_store().await;

    // An account whose canonical keyset authors the vault.
    let account_id = ids::random_id16().to_vec();
    let ed = ids::random_bytes32().to_vec();
    let x = ids::random_bytes32().to_vec();
    s.create_account(&account_id, &ed, &x, None, None, false, &[], &[], None, None, 1)
        .await
        .unwrap();

    // Push a Vault object authored by that keyset (no prior claim) → personal vault.
    let vobj = SyncObject::Vault(VaultRecord {
        vault_id: b"push-personal".to_vec(),
        sync_target: SyncTarget::Cloud,
        name_blob: vec![1, 2, 3],
        wrapped_vk: vec![4, 5, 6],
        version: 1,
        tombstone: false,
        signature: vec![9u8; 67],
        author_pubkey: ed.clone(),
        key_epoch: 1,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    });
    s.push_objects(None, b"pv", vec![push_obj(vobj)], 100)
        .await
        .unwrap();

    // The author's account now admins its own push-created personal vault; a different
    // account does not.
    assert!(
        s.can_admin_vault(&account_id, b"push-personal")
            .await
            .unwrap(),
        "push-created personal vault is admin-able by its owner account"
    );
    let other = ids::random_id16().to_vec();
    assert!(
        !s.can_admin_vault(&other, b"push-personal").await.unwrap(),
        "a different account cannot admin it"
    );
}

#[tokio::test]
async fn vault_claim_rule_owner_immutable() {
    let s = fresh_store().await;

    // First Vault fixes owner = 0xAA.
    s.push_objects(None, b"h1", vec![push_obj(vault(0xAA, 1))], 100)
        .await
        .unwrap();
    // Same owner, higher version → ok.
    s.push_objects(None, b"h2", vec![push_obj(vault(0xAA, 2))], 101)
        .await
        .unwrap();
    // Different owner → claim-rule conflict.
    let err = s
        .push_objects(None, b"h3", vec![push_obj(vault(0xBB, 3))], 102)
        .await
        .unwrap_err();
    assert_eq!(err.code, unissh_server::ErrorCode::Conflict);
}

// --- A1: delta membership filter ---

fn vault_owned(vault_id: &[u8], owner: &[u8]) -> SyncObject {
    SyncObject::Vault(VaultRecord {
        vault_id: vault_id.to_vec(),
        sync_target: SyncTarget::Cloud,
        name_blob: vec![1, 2, 3],
        wrapped_vk: vec![4, 5, 6],
        version: 1,
        tombstone: false,
        signature: vec![9u8; 67],
        author_pubkey: owner.to_vec(),
        key_epoch: 1,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    })
}

fn manifest(vault_id: &[u8], epoch: u64, author: &[u8]) -> SyncObject {
    SyncObject::MembershipManifest(MembershipManifest {
        vault_id: vault_id.to_vec(),
        key_epoch: epoch,
        manifest_blob: vec![1, 2, 3, 4],
        signature: vec![7u8; 67],
        author_pubkey: author.to_vec(),
    })
}

fn grant(vault_id: &[u8], member: &[u8], epoch: u64, author: &[u8]) -> SyncObject {
    SyncObject::MembershipGrant(MembershipGrant {
        vault_id: vault_id.to_vec(),
        member_pubkey: member.to_vec(),
        key_epoch: epoch,
        role: MemberRole::Editor,
        not_after: 0, // <=0 = no expiry
        wrapped_vk: vec![5u8; 48],
        signature: vec![8u8; 67],
        author_pubkey: author.to_vec(),
    })
}

/// The owner sees the objects of their own vault + vault-less ones (audit), but NOT another's vault;
/// a stranger — only vault-less ones.
#[tokio::test]
async fn delta_filters_by_vault_membership() {
    let s = fresh_store().await;

    let owner1 = [0x11u8; 32];
    let owner2 = [0x22u8; 32];
    let stranger = [0x99u8; 32];

    s.push_objects(
        None,
        b"r1",
        vec![push_obj(vault_owned(b"vault-1", &owner1))],
        100,
    )
    .await
    .unwrap();
    s.push_objects(
        None,
        b"r2",
        vec![push_obj(vault_owned(b"vault-2", &owner2))],
        100,
    )
    .await
    .unwrap();
    s.push_objects(None, b"r3", vec![push_obj(audit(9))], 100)
        .await
        .unwrap();

    // owner1: vault-1 + audit = 2; NOT vault-2.
    assert_eq!(
        s.delta_since(0, 100, &owner1, 200).await.unwrap().len(),
        2,
        "owner1 sees its own vault + vault-less audit, not another's vault"
    );
    // owner2: vault-2 + audit = 2.
    assert_eq!(s.delta_since(0, 100, &owner2, 200).await.unwrap().len(), 2);
    // stranger: only audit = 1.
    assert_eq!(
        s.delta_since(0, 100, &stranger, 200).await.unwrap().len(),
        1,
        "a stranger sees only vault-less objects, not a single vault"
    );
}

/// An active grant for the manifest's latest epoch gives the member visibility of the vault's objects.
#[tokio::test]
async fn delta_grant_grants_visibility() {
    let s = fresh_store().await;

    let owner = [0x11u8; 32];
    let member = [0x33u8; 32];

    s.push_objects(
        None,
        b"g1",
        vec![
            push_obj(vault_owned(b"vault-1", &owner)),
            push_obj(manifest(b"vault-1", 1, &owner)),
            push_obj(grant(b"vault-1", &member, 1, &owner)),
        ],
        100,
    )
    .await
    .unwrap();

    // a member (not the owner) with an active grant@epoch=latest sees the vault's objects.
    assert_eq!(
        s.delta_since(0, 100, &member, 200).await.unwrap().len(),
        3,
        "a member with an active grant sees vault+manifest+grant"
    );
    // a stranger without a grant — nothing (no vault-less objects).
    assert_eq!(
        s.delta_since(0, 100, &[0x99u8; 32], 200)
            .await
            .unwrap()
            .len(),
        0
    );
}

/// #10: republishing a grant does NOT resurrect revoked access.
#[tokio::test]
async fn replayed_grant_does_not_resurrect_revoked_access() {
    let s = fresh_store().await;
    let owner = [0x11u8; 32];
    let member = [0x33u8; 32];

    s.push_objects(
        None,
        b"g1",
        vec![
            push_obj(vault_owned(b"vault-1", &owner)),
            push_obj(manifest(b"vault-1", 1, &owner)),
            push_obj(grant(b"vault-1", &member, 1, &owner)),
        ],
        100,
    )
    .await
    .unwrap();
    assert!(
        s.member_has_active_grant(b"vault-1", 1, &member, 200)
            .await
            .unwrap(),
        "a fresh grant is active"
    );

    // Offboarding: revoke epoch 1 (like revoke_epoch in grants_publish).
    s.exec(
        "UPDATE membership_grants SET revoked = 1 WHERE vault_id = ? AND key_epoch = ?",
        vec![Val::b(b"vault-1".to_vec()), Val::I(1)],
    )
    .await
    .unwrap();
    assert!(
        !s.member_has_active_grant(b"vault-1", 1, &member, 200)
            .await
            .unwrap(),
        "after revocation — not active"
    );

    // Replaying the same grant@1 publication (retry/malicious) does NOT resurrect access.
    s.push_objects(
        None,
        b"g1-replay",
        vec![push_obj(grant(b"vault-1", &member, 1, &owner))],
        100,
    )
    .await
    .unwrap();
    assert!(
        !s.member_has_active_grant(b"vault-1", 1, &member, 200)
            .await
            .unwrap(),
        "replaying the grant does not resurrect revoked access (#10)"
    );
}

/// #7: delta stale-epoch — a member with a grant on an OLD epoch loses visibility after rotation.
#[tokio::test]
async fn delta_stale_epoch_grant_loses_visibility() {
    let s = fresh_store().await;
    let owner = [0x11u8; 32];
    let member = [0x33u8; 32];

    s.push_objects(
        None,
        b"e1",
        vec![
            push_obj(vault_owned(b"vault-1", &owner)),
            push_obj(manifest(b"vault-1", 1, &owner)),
            push_obj(grant(b"vault-1", &member, 1, &owner)),
        ],
        100,
    )
    .await
    .unwrap();
    assert_eq!(
        s.delta_since(0, 100, &member, 200).await.unwrap().len(),
        3,
        "member@1 sees objects while epoch 1 is active"
    );

    // Rotation: publish manifest@2 (the member is NOT re-issued for epoch 2).
    s.push_objects(
        None,
        b"e2",
        vec![push_obj(manifest(b"vault-1", 2, &owner))],
        101,
    )
    .await
    .unwrap();
    // MAX(manifest)=2, the member's grant is on epoch 1 → the filter cuts it off.
    assert_eq!(
        s.delta_since(0, 100, &member, 200).await.unwrap().len(),
        0,
        "a member with a stale grant@1 loses visibility after rotation to @2 (#7)"
    );
}

/// #11: delta grant-expiry — a grant with an expired not_after stops delivering objects.
#[tokio::test]
async fn delta_expired_grant_stops_delivering() {
    let s = fresh_store().await;
    let owner = [0x11u8; 32];
    let member = [0x33u8; 32];

    let mut g = grant(b"vault-1", &member, 1, &owner);
    if let SyncObject::MembershipGrant(ref mut mg) = g {
        mg.not_after = 150; // expires at t=150
    }
    s.push_objects(
        None,
        b"x1",
        vec![
            push_obj(vault_owned(b"vault-1", &owner)),
            push_obj(manifest(b"vault-1", 1, &owner)),
            push_obj(g),
        ],
        100,
    )
    .await
    .unwrap();
    // now=140 < 150 → the grant is still active.
    assert_eq!(
        s.delta_since(0, 100, &member, 140).await.unwrap().len(),
        3,
        "before not_after expires the member sees objects"
    );
    // now=200 > 150 → the grant expired → no visibility.
    assert_eq!(
        s.delta_since(0, 100, &member, 200).await.unwrap().len(),
        0,
        "after not_after the grant expired, no visibility (#11)"
    );
}

fn keyset() -> SyncObject {
    SyncObject::Keyset(vec![2, 0, 0, 0, 1, 9, 9, 9])
}

fn item_no_vault() -> SyncObject {
    SyncObject::Item(ItemRecord {
        vault_id: vec![], // empty vault_id on a vault-scoped tag — a bypass attempt
        item_id: b"orphan".to_vec(),
        item_type: 1,
        content_blob: vec![7, 7, 7],
        wrapped_item_key: vec![8, 8],
        version: 1,
        tombstone: false,
        signature: vec![6u8; 67],
        author_pubkey: vec![0xAB; 32],
        created_at: 0,
        updated_at: 0,
        key_epoch: 1,
    })
}

/// A vault-scoped object (Item, tag=2) with an EMPTY vault_id is NOT treated as "vault-less".
#[tokio::test]
async fn empty_vault_id_vault_scoped_object_not_broadcast() {
    let s = fresh_store().await;

    s.push_objects(
        None,
        b"e1",
        vec![push_obj(item_no_vault()), push_obj(keyset())],
        100,
    )
    .await
    .unwrap();

    // the stranger sees ONLY the keyset (genuinely vault-less), not the Item with an empty vault_id.
    let rows = s.delta_since(0, 100, &[0x99u8; 32], 200).await.unwrap();
    assert_eq!(
        rows.len(),
        1,
        "a stranger sees the keyset, but NOT an Item with an empty vault_id"
    );
}

fn item_in_vault(vault_id: &[u8], item_id: &[u8]) -> SyncObject {
    SyncObject::Item(ItemRecord {
        vault_id: vault_id.to_vec(),
        item_id: item_id.to_vec(),
        item_type: 1,
        content_blob: vec![7, 7, 7],
        wrapped_item_key: vec![8, 8],
        version: 1,
        tombstone: false,
        signature: vec![6u8; 67],
        author_pubkey: vec![0x11; 32],
        created_at: 0,
        updated_at: 0,
        key_epoch: 1,
    })
}

/// A1b: grant activation re-emits the vault's current set (vault+item) on fresh seqs.
#[tokio::test]
async fn grant_activation_reemits_vault_objects_above_cursor() {
    let s = fresh_store().await;
    let owner = [0x11u8; 32];
    let member = [0x33u8; 32];

    // The owner creates vault v + item (seqs 1,2) BEFORE membership.
    s.push_objects(
        None,
        b"p1",
        vec![
            push_obj(vault_owned(b"v", &owner)),
            push_obj(item_in_vault(b"v", b"i1")),
        ],
        100,
    )
    .await
    .unwrap();

    // The member's cursor is already here (it passed the v-objects at seq 1,2).
    let cursor = s.report_version().await.unwrap();
    assert_eq!(cursor, 2);

    // Publish manifest@1 + a grant for the member → grants_publish re-emits the v-objects.
    s.grants_publish(
        b"v",
        &push_obj(manifest(b"v", 1, &owner)),
        &[push_obj(grant(b"v", &member, 1, &owner))],
        None,
        100,
    )
    .await
    .unwrap();

    // The member with cursor=2 does a delta: should receive the vault record + item on fresh seq > 2.
    let rows = s.delta_since(cursor, 100, &member, 200).await.unwrap();
    let tags: Vec<u8> = rows
        .iter()
        .map(|r| parse_open(&r.object_bytes).unwrap().tag_u8)
        .collect();
    assert!(
        tags.contains(&1),
        "re-emit must deliver the vault record above the cursor: {tags:?}"
    );
    assert!(
        tags.contains(&2),
        "re-emit must deliver the item above the cursor: {tags:?}"
    );
}

fn account_state(author: &[u8], version: u64) -> SyncObject {
    SyncObject::AccountState(AccountStateObject {
        author_pubkey: author.to_vec(),
        version,
        payload: vec![1, 2, 3],
        signature: vec![9u8; 67],
    })
}

/// A3: account-state (tag 7) is visible in the delta ONLY to the devices of its own account.
#[tokio::test]
async fn delta_account_state_visible_only_to_author() {
    let s = fresh_store().await;
    let alice = [0xA1u8; 32];
    let bob = [0xB2u8; 32];

    s.push_objects(None, b"as1", vec![push_obj(account_state(&alice, 1))], 100)
        .await
        .unwrap();

    // Alice (the author) sees her own account-state.
    assert_eq!(
        s.delta_since(0, 100, &alice, 200).await.unwrap().len(),
        1,
        "the author sees their own account-state"
    );
    // Bob (a different account) does NOT see another's account-state.
    assert_eq!(
        s.delta_since(0, 100, &bob, 200).await.unwrap().len(),
        0,
        "a stranger does not see another account's account-state"
    );
}

async fn account_state_row_count(s: &Store, author: &[u8]) -> i64 {
    s.fetch_scalar_i64(
        "SELECT COUNT(*) FROM objects WHERE object_tag = 7 AND author_pubkey = ?",
        vec![Val::b(author.to_vec())],
    )
    .await
    .unwrap()
    .unwrap()
}

/// S3: account-state compaction — strictly older versions of the same author are pruned.
#[tokio::test]
async fn account_state_older_versions_compacted() {
    let s = fresh_store().await;
    let author = [0xA1u8; 32];

    // Three consecutive bumps: v1→v2→v3.
    for v in 1..=3u64 {
        let idem = format!("as{v}");
        s.push_objects(
            None,
            idem.as_bytes(),
            vec![push_obj(account_state(&author, v))],
            100,
        )
        .await
        .unwrap();
    }

    // Exactly one tag-7 row of the author remains — the latest version.
    assert_eq!(
        account_state_row_count(&s, &author).await,
        1,
        "older account-state versions are compacted"
    );
    let ver = s
        .fetch_scalar_i64(
            "SELECT MAX(obj_version) FROM objects WHERE object_tag = 7 AND author_pubkey = ?",
            vec![Val::b(author.to_vec())],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ver, 3, "the latest version remains");

    // An equal version from a second device is NOT pruned.
    let sibling = SyncObject::AccountState(AccountStateObject {
        author_pubkey: author.to_vec(),
        version: 3,
        payload: vec![7, 7, 7],
        signature: vec![1u8; 67],
    });
    s.push_objects(None, b"as3b", vec![push_obj(sibling)], 100)
        .await
        .unwrap();
    assert_eq!(
        account_state_row_count(&s, &author).await,
        2,
        "equal versions are both retained (tiebreak on the client)"
    );

    // A stale version of another author is not affected by our author's compaction.
    let other = [0xB2u8; 32];
    s.push_objects(None, b"ob1", vec![push_obj(account_state(&other, 1))], 100)
        .await
        .unwrap();
    assert_eq!(
        account_state_row_count(&s, &other).await,
        1,
        "compaction is scoped by author_pubkey"
    );
}
