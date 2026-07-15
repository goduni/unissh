//! v2 invites (intents, CAS redeem) + pending_actions queue (v2 staged schema).

use unissh_server::Store;
use unissh_server::ids;
use unissh_server::store::Val;

async fn store_v2() -> Store {
    let s = Store::connect_sqlite(":memory:", 1).await.unwrap();
    s.migrate().await.unwrap();
    s
}

#[tokio::test]
async fn invite_redeem_is_single_use_cas() {
    let s = store_v2().await;
    let iid = ids::random_id16().to_vec();
    let tok = ids::random_bytes32();
    let hash = ids::sha256(&tok);
    s.create_invite_v2(
        &iid,
        &hash,
        r#"[{"space_id":"QQ==","role":"member"}]"#,
        "[]",
        10_000,
        None,
        1,
    )
    .await
    .unwrap();

    let winner = ids::random_id16().to_vec();
    let mut tx = s.begin().await.unwrap();
    let row = s
        .redeem_invite_v2_cas(&mut tx, &hash, &winner, 5)
        .await
        .unwrap();
    assert!(row.is_some(), "first redeem wins");
    tx.commit().await.unwrap();

    let mut tx2 = s.begin().await.unwrap();
    assert!(
        s.redeem_invite_v2_cas(&mut tx2, &hash, &winner, 6)
            .await
            .unwrap()
            .is_none()
    );
    tx2.rollback().await.unwrap();
}

#[tokio::test]
async fn expired_invite_does_not_redeem() {
    let s = store_v2().await;
    let iid = ids::random_id16().to_vec();
    let tok = ids::random_bytes32();
    let hash = ids::sha256(&tok);
    s.create_invite_v2(&iid, &hash, "[]", "[]", 100, None, 1)
        .await
        .unwrap();
    let mut tx = s.begin().await.unwrap();
    assert!(
        s.redeem_invite_v2_cas(&mut tx, &hash, b"acct", 200)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn pending_queue_visibility_and_done_marking() {
    let s = store_v2().await;
    let vault = ids::random_id16().to_vec();
    let admin_ed = ids::random_bytes32().to_vec();
    let member = ids::random_id16().to_vec();
    let member_ed = ids::random_bytes32().to_vec();

    // vault snapshot @ latest_epoch=3 + a live Admin grant for admin_ed at epoch 3
    s.exec(
        "INSERT INTO vaults (vault_id, owner_pubkey, latest_version, latest_epoch, sync_target, cache_policy, created_at) \
         VALUES (?, ?, 1, 3, 1, 0, 1)",
        vec![Val::B(vault.clone()), Val::B(admin_ed.clone())],
    ).await.unwrap();
    s.exec(
        "INSERT INTO membership_grants (vault_id, member_pubkey, key_epoch, role, wrapped_vk, signature, author_pubkey, revoked, server_seq, received_at) \
         VALUES (?, ?, 3, 2, ?, ?, ?, 0, 1, 1)",
        vec![Val::B(vault.clone()), Val::B(admin_ed.clone()), Val::B(vec![0]), Val::B(vec![0]), Val::B(admin_ed.clone())],
    ).await.unwrap();
    // the member account (for the ed25519 → account_id join in done-marking)
    s.exec(
        "INSERT INTO accounts (account_id, ed25519_pub, x25519_pub, status, is_owner, reg_payload, reg_signature, created_at) \
         VALUES (?, ?, ?, 'active', 0, ?, ?, 1)",
        vec![Val::B(member.clone()), Val::B(member_ed.clone()), Val::B(ids::random_bytes32().to_vec()), Val::B(vec![1]), Val::B(vec![2])],
    ).await.unwrap();

    let aid = ids::random_id16().to_vec();
    let mut tx = s.begin().await.unwrap();
    s.pending_enqueue(
        &mut tx,
        &aid,
        "grant",
        &vault,
        &member,
        Some(1),
        "invite",
        Some(b"mac"),
        10,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let q = s.pending_for_admin(&admin_ed).await.unwrap();
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].kind, "grant");

    // a keyset with no admin grant sees nothing
    assert!(
        s.pending_for_admin(&ids::random_bytes32())
            .await
            .unwrap()
            .is_empty()
    );

    let mut tx = s.begin().await.unwrap();
    let n = s
        .pending_mark_grants_done(&mut tx, &vault, std::slice::from_ref(&member_ed), 4, 20)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 1);
    assert!(s.pending_for_admin(&admin_ed).await.unwrap().is_empty());
}
