//! spaces + membership + directory (v2 staged schema).

use unissh_server::Store;
use unissh_server::ids;
use unissh_server::store::Val;

async fn store_v2() -> Store {
    let s = Store::connect_sqlite(":memory:", 1).await.unwrap();
    s.migrate().await.unwrap();
    s
}

async fn mk_account(s: &Store, handle: &str) -> Vec<u8> {
    let id = ids::random_id16().to_vec();
    s.exec(
        "INSERT INTO accounts (account_id, ed25519_pub, x25519_pub, handle, status, is_owner, \
         reg_payload, reg_signature, created_at) VALUES (?, ?, ?, ?, 'active', 0, ?, ?, 1)",
        vec![
            Val::B(id.clone()),
            Val::B(ids::random_bytes32().to_vec()),
            Val::B(ids::random_bytes32().to_vec()),
            Val::t(handle),
            Val::B(vec![1]),
            Val::B(vec![2]),
        ],
    )
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn membership_roles_and_directory() {
    let s = store_v2().await;
    let alice = mk_account(&s, "alice").await;
    let bob = mk_account(&s, "bob").await;

    let sid = ids::random_id16().to_vec();
    let mut tx = s.begin().await.unwrap();
    s.create_space(&mut tx, &sid, "Backend", Some(&alice), 10)
        .await
        .unwrap();
    s.space_member_add(&mut tx, &sid, &alice, "admin", None, 10)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert!(s.is_space_admin(&sid, &alice).await.unwrap());
    assert!(!s.is_space_member(&sid, &bob).await.unwrap());

    let mut tx = s.begin().await.unwrap();
    s.space_member_add(&mut tx, &sid, &bob, "member", Some(&alice), 20)
        .await
        .unwrap();
    // idempotent re-add must not error
    s.space_member_add(&mut tx, &sid, &bob, "member", Some(&alice), 21)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert!(s.is_space_member(&sid, &bob).await.unwrap());
    assert!(!s.is_space_admin(&sid, &bob).await.unwrap());
    s.space_member_set_role(&sid, &bob, "admin").await.unwrap();
    assert!(s.is_space_admin(&sid, &bob).await.unwrap());

    assert_eq!(s.list_space_members(&sid).await.unwrap().len(), 2);
    assert_eq!(s.list_spaces_for(&bob).await.unwrap()[0].name, "Backend");
    assert_eq!(s.directory_list().await.unwrap().len(), 2);

    assert_eq!(s.space_member_remove(&sid, &bob).await.unwrap(), 1);
    assert!(!s.is_space_member(&sid, &bob).await.unwrap());
}
