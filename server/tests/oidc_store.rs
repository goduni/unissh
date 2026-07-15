//! OIDC schema/model seam (Phase 5): accounts carry an optional external SSO
//! identity `(external_issuer, external_subject)`, and sessions record how they
//! were authenticated (`auth_source`) plus, for OIDC, a reassertion deadline
//! (`reassert_expires`). These tests round-trip both through the store.

use unissh_server::Store;
use unissh_server::ids;

async fn store_v2() -> Store {
    let s = Store::connect_sqlite(":memory:", 1).await.unwrap();
    s.migrate().await.unwrap();
    s
}

/// Create an account (keyset or SSO-bound), returning its account_id + ed/x keys.
async fn mk_account(
    s: &Store,
    issuer: Option<&str>,
    subject: Option<&str>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let account_id = ids::random_id16().to_vec();
    let ed = ids::random_bytes32().to_vec();
    let x = ids::random_bytes32().to_vec();
    s.create_account(
        &account_id,
        &ed,
        &x,
        None,
        None,
        false,
        &[1],
        &[2],
        issuer,
        subject,
        1000,
    )
    .await
    .unwrap();
    (account_id, ed, x)
}

#[tokio::test]
async fn external_identity_round_trips() {
    let s = store_v2().await;
    let (sso_id, ..) = mk_account(&s, Some("https://idp"), Some("u123")).await;

    let row = s
        .get_account_by_external("https://idp", "u123")
        .await
        .unwrap()
        .expect("SSO-bound account resolves by (issuer, subject)");
    assert_eq!(row.account_id, sso_id);
    assert_eq!(row.external_issuer.as_deref(), Some("https://idp"));
    assert_eq!(row.external_subject.as_deref(), Some("u123"));
}

#[tokio::test]
async fn keyset_account_has_no_external_identity() {
    let s = store_v2().await;
    let (keyset_id, ..) = mk_account(&s, None, None).await;

    // A keyset account is not reachable by any (issuer, subject) probe...
    assert!(
        s.get_account_by_external("https://idp", "u123")
            .await
            .unwrap()
            .is_none()
    );
    // ...and its own AccountRow reports NULL external fields.
    let row = s
        .get_account_by_id(&keyset_id)
        .await
        .unwrap()
        .expect("keyset account exists");
    assert_eq!(row.external_issuer, None);
    assert_eq!(row.external_subject, None);
}

#[tokio::test]
async fn oidc_session_records_auth_source_and_reassert() {
    let s = store_v2().await;
    let (account_id, ed, x) = mk_account(&s, Some("https://idp"), Some("u456")).await;
    let device_id = ids::random_id16().to_vec();
    s.create_device(&account_id, &device_id, &ed, &x, "app", None, None, 1000)
        .await
        .unwrap();

    let session_id = ids::random_id16().to_vec();
    let reassert = 1000 + 604_800;
    s.create_session(
        &session_id,
        &account_id,
        &device_id,
        &ids::sha256(b"access"),
        &ids::sha256(b"refresh"),
        1900,
        1_000_000,
        "oidc",
        Some(reassert),
        1000,
    )
    .await
    .unwrap();

    let row = s
        .find_session_by_id(&session_id)
        .await
        .unwrap()
        .expect("session round-trips");
    assert_eq!(row.auth_source, "oidc");
    assert_eq!(row.reassert_expires, Some(reassert));
}

#[tokio::test]
async fn keyset_session_defaults_are_null() {
    let s = store_v2().await;
    let (account_id, ed, x) = mk_account(&s, None, None).await;
    let device_id = ids::random_id16().to_vec();
    s.create_device(&account_id, &device_id, &ed, &x, "app", None, None, 1000)
        .await
        .unwrap();

    let session_id = ids::random_id16().to_vec();
    s.create_session(
        &session_id,
        &account_id,
        &device_id,
        &ids::sha256(b"access"),
        &ids::sha256(b"refresh"),
        1900,
        1_000_000,
        "keyset",
        None,
        1000,
    )
    .await
    .unwrap();

    let row = s.find_session_by_id(&session_id).await.unwrap().unwrap();
    assert_eq!(row.auth_source, "keyset");
    assert_eq!(row.reassert_expires, None);
}
