//! Setup-code recovery: classification for the CLI + rotation while unclaimed.
//!
//! The generated code is printed once, to the boot log — only its sha256 is
//! persisted. These cover the path that gives an operator a new one after that
//! log line is gone, without dropping the database.

use unissh_server::{SetupCodeState, Store, ids, rotate_setup_code, setup_code_state};

async fn store_v2() -> Store {
    let s = Store::connect_sqlite(":memory:", 1).await.unwrap();
    s.migrate().await.unwrap();
    s
}

async fn stored_hash(s: &Store) -> Option<Vec<u8>> {
    s.instance().await.unwrap().setup_code_hash
}

#[tokio::test]
async fn classifies_an_unclaimed_instance_by_what_it_holds() {
    let s = store_v2().await;
    s.ensure_instance(1000).await.unwrap();

    // Nothing issued yet — the first boot has not run.
    assert_eq!(
        setup_code_state(&s, false).await.unwrap(),
        SetupCodeState::NotIssued
    );
    // Same row, but the operator pinned a code: they already hold the value.
    assert_eq!(
        setup_code_state(&s, true).await.unwrap(),
        SetupCodeState::Pinned
    );

    s.set_setup_code_hash(&ids::sha256(b"AAAA-BBBB-CCCC"))
        .await
        .unwrap();
    assert_eq!(
        setup_code_state(&s, false).await.unwrap(),
        SetupCodeState::Issued
    );
}

#[tokio::test]
async fn rotate_mints_a_code_the_server_will_accept() {
    let s = store_v2().await;
    s.ensure_instance(1000).await.unwrap();

    let code = rotate_setup_code(&s).await.unwrap();

    // "XXXX-XXXX-XXXX" — the shape the claim endpoint and the client expect.
    assert_eq!(code.len(), 14);
    assert!(
        code.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'),
        "unexpected alphabet in {code}"
    );
    // What claim compares against is sha256(code), so this is the whole contract.
    assert_eq!(
        stored_hash(&s).await.as_deref(),
        Some(&ids::sha256(code.as_bytes())[..])
    );
}

#[tokio::test]
async fn rotate_invalidates_the_previous_code() {
    let s = store_v2().await;
    s.ensure_instance(1000).await.unwrap();

    let first = rotate_setup_code(&s).await.unwrap();
    let second = rotate_setup_code(&s).await.unwrap();

    assert_ne!(first, second, "rotation must not hand back the same code");
    let live = stored_hash(&s).await.unwrap();
    assert_eq!(live, ids::sha256(second.as_bytes()));
    assert_ne!(
        live,
        ids::sha256(first.as_bytes()),
        "the old code must stop working"
    );
}

#[tokio::test]
async fn rotate_refuses_on_a_claimed_instance() {
    let s = store_v2().await;
    s.ensure_instance(1000).await.unwrap();
    s.exec("UPDATE instance SET claimed = 1 WHERE id = 1", vec![])
        .await
        .unwrap();

    // `set_setup_code_hash` is a silent no-op once claimed, so the guard has to be
    // an explicit read-back — otherwise this hands out a code that opens nothing.
    assert!(
        rotate_setup_code(&s).await.is_err(),
        "a claimed instance must not issue a setup code"
    );
    assert!(stored_hash(&s).await.is_none(), "no hash may be written");

    // Claimed outranks a pinned config: there is no live code either way.
    assert_eq!(
        setup_code_state(&s, false).await.unwrap(),
        SetupCodeState::Claimed
    );
    assert_eq!(
        setup_code_state(&s, true).await.unwrap(),
        SetupCodeState::Claimed
    );
}
