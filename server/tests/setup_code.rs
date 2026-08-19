//! Setup-code recovery: classification for the CLI + rotation while unclaimed.
//!
//! The generated code is printed once, to the boot log — only its sha256 is
//! persisted. These cover the path that gives an operator a new one after that
//! log line is gone, without dropping the database.

use unissh_server::{
    SetupCodeState, Store, apply_pinned_setup_code, ids, rotate_setup_code, setup_code_state,
};

mod common;

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
    let pinned = ids::sha256(b"PIN1-PIN1-PIN1");

    // Nothing issued yet — the first boot has not run.
    assert_eq!(
        setup_code_state(&s, None).await.unwrap(),
        SetupCodeState::NotIssued
    );
    // A pinned code the server has not applied yet is NOT the live one. Reporting
    // it as live would hand the operator a code the claim endpoint rejects.
    assert_eq!(
        setup_code_state(&s, Some(&pinned)).await.unwrap(),
        SetupCodeState::PinnedStale
    );

    s.set_setup_code_hash(&ids::sha256(b"AAAA-BBBB-CCCC"))
        .await
        .unwrap();
    assert_eq!(
        setup_code_state(&s, None).await.unwrap(),
        SetupCodeState::Issued
    );
    // Pinned, but the row holds a DIFFERENT code — the operator edited the pinned
    // value and has not restarted. Still stale, not "use your value".
    assert_eq!(
        setup_code_state(&s, Some(&pinned)).await.unwrap(),
        SetupCodeState::PinnedStale
    );

    // Once a boot (or --rotate) applies it, the pinned value is the live one.
    s.set_setup_code_hash(&pinned).await.unwrap();
    assert_eq!(
        setup_code_state(&s, Some(&pinned)).await.unwrap(),
        SetupCodeState::Pinned
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
        setup_code_state(&s, None).await.unwrap(),
        SetupCodeState::Claimed
    );
    assert_eq!(
        setup_code_state(&s, Some(&ids::sha256(b"PIN1-PIN1-PIN1")))
            .await
            .unwrap(),
        SetupCodeState::Claimed
    );
}

#[tokio::test]
async fn applying_a_pinned_code_makes_it_live_without_a_restart() {
    let s = store_v2().await;
    s.ensure_instance(1000).await.unwrap();
    s.set_setup_code_hash(&ids::sha256(b"OLD1-OLD1-OLD1"))
        .await
        .unwrap();

    apply_pinned_setup_code(&s, "PIN1-PIN1-PIN1").await.unwrap();

    let live = stored_hash(&s).await.unwrap();
    assert_eq!(live, ids::sha256(b"PIN1-PIN1-PIN1"));
    assert_eq!(
        setup_code_state(&s, Some(&ids::sha256(b"PIN1-PIN1-PIN1")))
            .await
            .unwrap(),
        SetupCodeState::Pinned
    );
}

/// The contract the whole feature rests on, end to end: an operator who lost the
/// boot log rotates, and the code they are handed CLAIMS — while the code the
/// server held a moment earlier no longer does. Everything above this only proves
/// the store round-trips a hash.
#[tokio::test]
async fn a_rotated_code_claims_and_the_previous_one_stops_working() {
    // No pinned code, so the instance is in the state the report describes: a
    // generated code exists, and its plaintext is gone with the boot log.
    let app = common::spawn_with(|c| c.setup.code = String::new()).await;
    let stale = "AAAA-BBBB-CCCC";
    app.state
        .store
        .set_setup_code_hash(&ids::sha256(stale.as_bytes()))
        .await
        .unwrap();

    let fresh = rotate_setup_code(&app.state.store).await.unwrap();

    let claim = |code: &str| {
        let id = common::make_identity();
        let body = serde_json::json!({
            "setup_code": code,
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
            "handle": "owner",
        });
        app.client
            .post(format!("{}/v1/claim", app.base))
            .json(&body)
            .send()
    };

    let bad = claim(stale).await.unwrap();
    assert_eq!(bad.status(), 403, "the rotated-away code must not claim");

    let good = claim(&fresh).await.unwrap();
    assert_eq!(good.status(), 201, "the rotated code must claim");

    // And the claim consumed it: the hash is cleared, so the state flips.
    assert_eq!(
        setup_code_state(&app.state.store, None).await.unwrap(),
        SetupCodeState::Claimed
    );
}
