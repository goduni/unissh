//! v2 claim flow: unclaimed info → claim → single winner → owner auth works.

mod common;
use common::{claim_owner, spawn_with};
use serde_json::Value;

#[tokio::test]
async fn claim_lifecycle() {
    let app = spawn_with(|_| {}).await;
    let id = common::make_identity();

    let info: Value = app
        .client
        .get(format!("{}/v1/instance", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["claimed"], false);
    assert_eq!(info["auth"][0], "password");

    // wrong code → 403
    let r = app
        .client
        .post(format!("{}/v1/claim", app.base))
        .json(&serde_json::json!({
            "setup_code": "WRON-GCOD-E999",
            "registration_payload": id.payload_b64, "registration_signature": id.sig_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    let claimed = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    assert!(claimed["space_id"].as_str().is_some());

    // second claim → 409
    let id2 = common::make_identity();
    let r = app
        .client
        .post(format!("{}/v1/claim", app.base))
        .json(&serde_json::json!({
            "setup_code": common::SETUP_CODE,
            "registration_payload": id2.payload_b64, "registration_signature": id2.sig_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);

    let info: Value = app
        .client
        .get(format!("{}/v1/instance", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["claimed"], true);

    // owner can authenticate (challenge host == instance_id) and hit an owner surface
    let tok = common::login_v2(
        &app,
        &id,
        claimed["account_id"].as_str().unwrap(),
        claimed["device_id"].as_str().unwrap(),
    )
    .await;
    let r = app
        .client
        .get(format!("{}/v1/accounts", app.base))
        .bearer_auth(&tok)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}
