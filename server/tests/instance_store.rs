//! instance singleton: ensure / setup-code / claim CAS / seq bump (v2 staged schema).

use unissh_server::Store;
use unissh_server::ids;

async fn store_v2() -> Store {
    let s = Store::connect_sqlite(":memory:", 1).await.unwrap();
    s.migrate().await.unwrap();
    s
}

#[test]
fn setup_code_format() {
    let code = ids::generate_setup_code(&[0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45]);
    assert_eq!(code, "ABCD-EF01-2345");
}

#[tokio::test]
async fn ensure_is_idempotent_and_claim_is_single_winner() {
    let s = store_v2().await;
    let a = s.ensure_instance(1000).await.unwrap();
    let b = s.ensure_instance(2000).await.unwrap();
    assert_eq!(a.instance_id, b.instance_id, "singleton");
    assert_eq!(a.claimed, 0);

    let hash = ids::sha256(b"AAAA-BBBB-CCCC");
    s.set_setup_code_hash(&hash).await.unwrap();
    assert_eq!(
        s.instance().await.unwrap().setup_code_hash.as_deref(),
        Some(&hash[..])
    );

    let owner = ids::random_id16().to_vec();
    let mut tx = s.begin().await.unwrap();
    assert!(
        s.claim_instance_cas(&mut tx, &owner, Some("Acme"), &hash)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let other = ids::random_id16().to_vec();
    let mut tx2 = s.begin().await.unwrap();
    assert!(
        !s.claim_instance_cas(&mut tx2, &other, None, &hash)
            .await
            .unwrap(),
        "second claim loses"
    );
    tx2.rollback().await.unwrap();

    let row = s.instance().await.unwrap();
    assert_eq!(row.claimed, 1);
    assert_eq!(row.owner_account_id.as_deref(), Some(&owner[..]));
    assert!(row.setup_code_hash.is_none(), "code cleared on claim");
    assert_eq!(row.name.as_deref(), Some("Acme"));
}

#[tokio::test]
async fn seq_bump_never_lowers() {
    let s = store_v2().await;
    s.ensure_instance(1).await.unwrap();
    assert_eq!(s.bump_instance_seq_to(100).await.unwrap(), (0, 100));
    assert_eq!(s.bump_instance_seq_to(50).await.unwrap(), (100, 100));
    assert_eq!(s.bump_instance_seq_by(7).await.unwrap(), (100, 107));
}

/// The rotation guarantee: a code replaced between the handler's check and the CAS
/// cannot still claim. Without the hash in the CAS's WHERE, this passes with the
/// stale hash and the "previous code is now invalid" promise is a lie.
#[tokio::test]
async fn claim_cas_rejects_a_stale_setup_code_hash() {
    let s = store_v2().await;
    s.ensure_instance(1000).await.unwrap();
    let old = ids::sha256(b"OLD1-OLD1-OLD1");
    s.set_setup_code_hash(&old).await.unwrap();
    // …a rotation lands…
    let fresh = ids::sha256(b"NEW1-NEW1-NEW1");
    s.set_setup_code_hash(&fresh).await.unwrap();

    let owner = ids::random_id16().to_vec();
    let mut tx = s.begin().await.unwrap();
    assert!(
        !s.claim_instance_cas(&mut tx, &owner, None, &old)
            .await
            .unwrap(),
        "a claim validated against the rotated-away code must lose"
    );
    tx.rollback().await.unwrap();
    assert_eq!(s.instance().await.unwrap().claimed, 0, "still unclaimed");

    let mut tx2 = s.begin().await.unwrap();
    assert!(
        s.claim_instance_cas(&mut tx2, &owner, None, &fresh)
            .await
            .unwrap(),
        "the live code still claims"
    );
    tx2.commit().await.unwrap();
}
