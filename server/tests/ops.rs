//! Break-glass ops surface (`/v1/ops/*`): token auth (`X-UniSSH-Ops-Token`),
//! instance overview + anti-rollback seq-bump. Server-trusted, not a keyset.

mod common;

use common::{TestApp, claim_owner, make_identity, spawn_with};
use serde_json::{Value, json};

async fn ops_get(app: &TestApp, path: &str, token: Option<&str>) -> reqwest::Response {
    let mut req = app.client.get(format!("{}{}", app.base, path));
    if let Some(t) = token {
        req = req.header("X-UniSSH-Ops-Token", t);
    }
    req.send().await.unwrap()
}

#[tokio::test]
async fn ops_token_gates_console() {
    let app = spawn_with(|c| c.ops.token = "opssecret".into()).await;
    let id = make_identity();
    claim_owner(&app, &id.payload_b64, &id.sig_b64).await;

    // missing token → 401; wrong token → 401
    assert_eq!(ops_get(&app, "/v1/ops/overview", None).await.status(), 401);
    assert_eq!(
        ops_get(&app, "/v1/ops/overview", Some("nope"))
            .await
            .status(),
        401
    );

    // correct token → instance overview
    let ov: Value = ops_get(&app, "/v1/ops/overview", Some("opssecret"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(ov["accounts"], 1);
    assert_eq!(ov["objects"], 0);
    assert_eq!(ov["instance_generation"], 0);

    // instance detail
    let inst: Value = ops_get(&app, "/v1/ops/instance", Some("opssecret"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(inst["generation"], 0);

    // instance-wide seq-bump
    let bump: Value = app
        .client
        .post(format!("{}/v1/ops/seq-bump", app.base))
        .header("X-UniSSH-Ops-Token", "opssecret")
        .json(&json!({ "by": 5 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bump["old"], 0);
    assert_eq!(bump["new"], 5);
}

#[tokio::test]
async fn ops_disabled_when_no_token_configured() {
    let app = spawn_with(|_| {}).await; // ops.token empty
    // any token presented → still disabled (403)
    assert_eq!(
        ops_get(&app, "/v1/ops/overview", Some("anything"))
            .await
            .status(),
        403
    );
}
