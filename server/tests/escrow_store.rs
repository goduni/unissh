//! Escrow columns on keyset_blobs (Phase 2): set_escrow attaches the K_auth
//! hash + Argon2id salt/params to an uploaded keyset row; get_escrow_by_handle
//! resolves a handle → its latest keyset generation, returning blob + escrow.

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
async fn escrow_round_trips_by_handle() {
    let s = store_v2().await;
    let alice = mk_account(&s, "alice").await;

    let blob = b"keyset-ciphertext".to_vec();
    let ed = ids::random_bytes32().to_vec();
    let x = ids::random_bytes32().to_vec();
    s.put_keyset(&alice, 1, &blob, &ed, &x, 1000).await.unwrap();

    let k_auth_hash = ids::sha256(b"K_auth").to_vec();
    let salt = ids::random_bytes32().to_vec();
    s.set_escrow(&alice, 1, &k_auth_hash, &salt, 65536, 3, 1)
        .await
        .unwrap();

    let row = s
        .get_escrow_by_handle("alice")
        .await
        .unwrap()
        .expect("alice has an escrow-enabled keyset");
    assert_eq!(row.keyset_bytes, blob);
    assert_eq!(row.generation, 1);
    assert_eq!(row.account_id, alice);
    assert_eq!(row.k_auth_hash.as_deref(), Some(&k_auth_hash[..]));
    assert_eq!(row.argon_salt.as_deref(), Some(&salt[..]));
    assert_eq!(row.argon_mem_kib, Some(65536));
    assert_eq!(row.argon_iterations, Some(3));
    assert_eq!(row.argon_parallelism, Some(1));
}

#[tokio::test]
async fn escrow_resolves_latest_generation() {
    let s = store_v2().await;
    let alice = mk_account(&s, "alice").await;
    let ed = ids::random_bytes32().to_vec();
    let x = ids::random_bytes32().to_vec();

    s.put_keyset(&alice, 1, b"gen1", &ed, &x, 1000)
        .await
        .unwrap();
    s.put_keyset(&alice, 2, b"gen2", &ed, &x, 2000)
        .await
        .unwrap();
    let salt = ids::random_bytes32().to_vec();
    let k_auth_hash = ids::sha256(b"K_auth-2").to_vec();
    s.set_escrow(&alice, 2, &k_auth_hash, &salt, 19456, 2, 1)
        .await
        .unwrap();

    let row = s.get_escrow_by_handle("alice").await.unwrap().unwrap();
    assert_eq!(row.generation, 2, "resolves MAX(generation)");
    assert_eq!(row.keyset_bytes, b"gen2");
    assert_eq!(row.k_auth_hash.as_deref(), Some(&k_auth_hash[..]));
}

#[tokio::test]
async fn unknown_handle_is_none() {
    let s = store_v2().await;
    assert!(s.get_escrow_by_handle("ghost").await.unwrap().is_none());
}

#[tokio::test]
async fn account_without_keyset_is_none() {
    let s = store_v2().await;
    let _ = mk_account(&s, "nobody").await;
    assert!(s.get_escrow_by_handle("nobody").await.unwrap().is_none());
}
