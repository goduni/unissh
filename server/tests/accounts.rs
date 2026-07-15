//! Account identity §6.1: human identifiers (display_name/handle), instance-owner
//! (promote/demote + anti-lockout), shared-keyset multi-device. Instance-scoped (v2).

mod common;

use common::{Identity, SETUP_CODE, make_identity, spawn};
use serde_json::{Value, json};
use unissh_server::ids::b64;

/// Claim the instance carrying explicit human identifiers.
async fn claim_named(
    app: &common::TestApp,
    id: &Identity,
    display_name: Option<&str>,
    handle: Option<&str>,
) -> Value {
    let r = app
        .client
        .post(format!("{}/v1/claim", app.base))
        .json(&json!({
            "setup_code": SETUP_CODE,
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
            "display_name": display_name,
            "handle": handle,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "claim should succeed");
    r.json().await.unwrap()
}

async fn accounts(app: &common::TestApp, bearer: &str) -> reqwest::Response {
    app.client
        .get(format!("{}/v1/accounts", app.base))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn claim_carries_human_identity() {
    let app = spawn().await;
    let admin = make_identity();
    let c = claim_named(&app, &admin, Some("Вася (admin)"), Some("vasya")).await;
    let bearer = app
        .login(
            &admin,
            c["account_id"].as_str().unwrap(),
            c["device_id"].as_str().unwrap(),
        )
        .await;

    let list: Value = accounts(&app, &bearer).await.json().await.unwrap();
    let arr = list["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["display_name"], "Вася (admin)");
    assert_eq!(arr[0]["handle"], "vasya");
    assert_eq!(arr[0]["is_owner"], true);
    assert_eq!(arr[0]["member_pubkey"], b64(&admin.ed));
    // x25519_pub — open metadata, needed by the UI for HPKE re-wrap of the VK on grant rotation.
    assert_eq!(arr[0]["x25519_pub"], b64(&admin.x));
    assert_eq!(arr[0]["device_count"], 1);
}

#[tokio::test]
async fn owner_promote_demote_with_anti_lockout() {
    let app = spawn().await;
    let admin = make_identity();
    let c = claim_named(&app, &admin, Some("Genesis"), None).await;
    let admin_acct = c["account_id"].as_str().unwrap().to_string();
    let admin_bearer = app
        .login(&admin, &admin_acct, c["device_id"].as_str().unwrap())
        .await;

    // A second account, initially not an owner (seeded directly).
    let bob = make_identity();
    let (bob_acct_bytes, bob_dev_bytes, _) = app.seed_device(&bob.ed, &bob.x, "org", false).await;
    let bob_acct = b64(&bob_acct_bytes);
    let bob_bearer = app.login(&bob, &bob_acct, &b64(&bob_dev_bytes)).await;

    // bob is not an owner → cannot list accounts.
    assert_eq!(accounts(&app, &bob_bearer).await.status(), 403);

    let set = |bearer: &str, acct: &str, is_owner: bool| {
        app.client
            .post(format!("{}/v1/owner/set", app.base))
            .header("Authorization", format!("Bearer {bearer}"))
            .json(&json!({ "account_id": acct, "is_owner": is_owner }))
            .send()
    };

    // owner promotes bob → bob can now list accounts.
    assert_eq!(
        set(&admin_bearer, &bob_acct, true).await.unwrap().status(),
        204
    );
    assert_eq!(accounts(&app, &bob_bearer).await.status(), 200);

    // owner demotes bob → 403 again.
    assert_eq!(
        set(&admin_bearer, &bob_acct, false).await.unwrap().status(),
        204
    );
    assert_eq!(
        accounts(&app, &bob_bearer).await.status(),
        403,
        "demoted → not owner"
    );

    // cannot demote the claim owner.
    let self_demote = set(&admin_bearer, &admin_acct, false).await.unwrap();
    assert_eq!(self_demote.status(), 403, "claim owner cannot be demoted");
}

#[tokio::test]
async fn second_device_shares_keyset_and_authenticates() {
    let app = spawn().await;
    let acct = make_identity();
    let c = claim_named(&app, &acct, Some("Игорь"), Some("igor")).await;
    let acct_id = c["account_id"].as_str().unwrap().to_string();
    let dev1 = c["device_id"].as_str().unwrap().to_string();
    let bearer1 = app.login(&acct, &acct_id, &dev1).await;

    // add a second device under the same account (shares the keyset)
    let add: Value = app
        .client
        .post(format!("{}/v1/devices/add", app.base))
        .header("Authorization", format!("Bearer {bearer1}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let dev2 = add["device_id"].as_str().unwrap().to_string();
    assert_ne!(dev2, dev1);

    // the NEW device authenticates with the SAME keyset (shared identity)
    let bearer2 = app.login(&acct, &acct_id, &dev2).await;
    let v = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("Authorization", format!("Bearer {bearer2}"))
        .send()
        .await
        .unwrap();
    assert_eq!(v.status(), 200, "second device (shared keyset) can act");

    // device_count now 2 under one account (one member-id)
    let list: Value = accounts(&app, &bearer1).await.json().await.unwrap();
    assert_eq!(list["accounts"][0]["device_count"], 2);
    assert_eq!(
        list["accounts"].as_array().unwrap().len(),
        1,
        "still one account/identity"
    );
}

#[tokio::test]
async fn profile_update_and_handle_conflict() {
    let app = spawn().await;
    let admin = make_identity();
    let c = claim_named(&app, &admin, None, None).await;
    let admin_bearer = app
        .login(
            &admin,
            c["account_id"].as_str().unwrap(),
            c["device_id"].as_str().unwrap(),
        )
        .await;

    // set own profile
    let upd = app
        .client
        .post(format!("{}/v1/account/profile", app.base))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&json!({ "display_name": "Renamed", "handle": "chief" }))
        .send()
        .await
        .unwrap();
    assert_eq!(upd.status(), 204);
    let list: Value = accounts(&app, &admin_bearer).await.json().await.unwrap();
    assert_eq!(list["accounts"][0]["display_name"], "Renamed");
    assert_eq!(list["accounts"][0]["handle"], "chief");

    // another member takes the handle "bob"; admin trying to grab it → 409
    let bob = make_identity();
    let (bob_acct, _dev, _) = app.seed_device(&bob.ed, &bob.x, "org", false).await;
    app.state
        .store
        .update_account_profile(&bob_acct, None, Some("bob"))
        .await
        .unwrap();

    let clash = app
        .client
        .post(format!("{}/v1/account/profile", app.base))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&json!({ "handle": "bob" }))
        .send()
        .await
        .unwrap();
    assert_eq!(clash.status(), 409, "handle already taken");
}
