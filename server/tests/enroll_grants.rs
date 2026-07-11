//! Enrollment grants (§4.9b): per-engineer single-use revocable bootstrap credentials.
//! The operator (ops-token) issues a grant → the engineer redeems it at /v1/bootstrap, creating
//! their OWN tenant. We check: a closed bootstrap without a grant is rejected; issue→redeem
//! creates a tenant; single-use; revocation before/after use; pinned tier;
//! expiry; and ATOMICITY — losing the genesis race rolls back the grant redemption.

mod common;

use common::{Identity, TestApp, make_identity, spawn_with};
use serde_json::{Value, json};
use unissh_server::ids::b64;

const OPS: &str = "opssecret";

/// Closed bootstrap (token="", allow_open=false) — ONLY a grant can authorize.
async fn spawn_closed() -> TestApp {
    spawn_with(|c| {
        c.ops.token = OPS.into();
    })
    .await
}

async fn mint(
    app: &TestApp,
    label: &str,
    tier: Option<&str>,
    ttl: Option<i64>,
) -> (String, String) {
    let mut body = json!({ "label": label });
    if let Some(t) = tier {
        body["tier"] = json!(t);
    }
    if let Some(s) = ttl {
        body["ttl_seconds"] = json!(s);
    }
    let r = app
        .client
        .post(format!("{}/v1/ops/enroll/create", app.base))
        .header("X-UniSSH-Ops-Token", OPS)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "mint should succeed");
    let v: Value = r.json().await.unwrap();
    (
        v["grant_id"].as_str().unwrap().to_string(),
        v["token"].as_str().unwrap().to_string(),
    )
}

async fn redeem(
    app: &TestApp,
    tid: &[u8],
    id: &Identity,
    token: &str,
    tier: Option<&str>,
) -> reqwest::Response {
    let mut body = json!({
        "registration_payload": id.payload_b64,
        "registration_signature": id.sig_b64,
        "tenant_bootstrap_token": token,
        "handle": "genesis",
    });
    if let Some(t) = tier {
        body["tier"] = json!(t);
    }
    app.client
        .post(format!("{}/v1/bootstrap", app.base))
        .header("UniSSH-Tenant", b64(tid))
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn revoke(app: &TestApp, grant_id: &str) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/ops/enroll/revoke", app.base))
        .header("X-UniSSH-Ops-Token", OPS)
        .json(&json!({ "grant_id": grant_id }))
        .send()
        .await
        .unwrap()
}

async fn grants(app: &TestApp) -> Vec<Value> {
    let v: Value = app
        .client
        .get(format!("{}/v1/ops/enroll", app.base))
        .header("X-UniSSH-Ops-Token", OPS)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["grants"].as_array().unwrap().clone()
}

fn find<'a>(gs: &'a [Value], gid: &str) -> &'a Value {
    gs.iter().find(|g| g["grant_id"] == json!(gid)).unwrap()
}

#[tokio::test]
async fn closed_bootstrap_needs_a_grant_then_redeem_creates_tenant() {
    let app = spawn_closed().await;
    // No grant, closed instance → rejected.
    let no = redeem(&app, b"tid-noauth-000000", &make_identity(), "", None).await;
    assert_eq!(no.status(), 403, "closed bootstrap rejects without a grant");

    let (gid, token) = mint(&app, "alice@corp", None, None).await;
    let r = redeem(&app, b"tid-alice-0000000", &make_identity(), &token, None).await;
    assert_eq!(r.status(), 201);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["owned"], json!(true), "redeemer owns their new space");
    assert_eq!(v["role"], json!("admin"));

    let g = find(&grants(&app).await, &gid).clone();
    assert_eq!(g["state"], json!("redeemed"));
    assert_eq!(g["label"], json!("alice@corp"), "attribution preserved");
    assert!(
        g["redeemed_tenant"].is_string(),
        "bound to the minted tenant"
    );
}

#[tokio::test]
async fn grant_is_single_use() {
    let app = spawn_closed().await;
    let (_gid, token) = mint(&app, "bob", None, None).await;
    assert_eq!(
        redeem(&app, b"tid-bob-a00000000", &make_identity(), &token, None)
            .await
            .status(),
        201
    );
    // Same secret, fresh tenant → already consumed.
    let r2 = redeem(&app, b"tid-bob-b00000000", &make_identity(), &token, None).await;
    assert_eq!(r2.status(), 410, "a grant redeems exactly once");
}

#[tokio::test]
async fn revoke_before_use_blocks_and_double_revoke_conflicts() {
    let app = spawn_closed().await;
    let (gid, token) = mint(&app, "carol", None, None).await;
    assert_eq!(revoke(&app, &gid).await.status(), 204);
    let r = redeem(&app, b"tid-carol-0000000", &make_identity(), &token, None).await;
    assert_eq!(r.status(), 410, "revoked grant cannot be redeemed");
    assert_eq!(
        revoke(&app, &gid).await.status(),
        409,
        "already-revoked → 409"
    );
}

#[tokio::test]
async fn revoke_after_use_conflicts_and_unknown_is_404() {
    let app = spawn_closed().await;
    let (gid, token) = mint(&app, "dave", None, None).await;
    assert_eq!(
        redeem(&app, b"tid-dave-00000000", &make_identity(), &token, None)
            .await
            .status(),
        201
    );
    assert_eq!(
        revoke(&app, &gid).await.status(),
        409,
        "used grant can't be revoked"
    );
    assert_eq!(revoke(&app, &b64(b"nope-nope-nope16")).await.status(), 404);
}

#[tokio::test]
async fn grant_tier_pins_over_request() {
    let app = spawn_closed().await;
    let (_gid, token) = mint(&app, "eve", Some("personal"), None).await;
    let tid = b"tid-eve-000000000";
    // Redeemer asks for org; the grant pins personal → personal wins.
    assert_eq!(
        redeem(&app, tid, &make_identity(), &token, Some("org"))
            .await
            .status(),
        201
    );
    let v: Value = app
        .client
        .get(format!("{}/v1/ops/tenants", app.base))
        .header("X-UniSSH-Ops-Token", OPS)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let t = v["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tenant_id"] == json!(b64(tid)))
        .unwrap();
    assert_eq!(
        t["tier"],
        json!("personal"),
        "grant-pinned tier wins over request"
    );
}

#[tokio::test]
async fn expired_grant_blocks_redeem() {
    let app = spawn_closed().await;
    let (_gid, token) = mint(&app, "frank", None, Some(10)).await;
    app.clock.advance(20); // past the TTL
    let r = redeem(&app, b"tid-frank-0000000", &make_identity(), &token, None).await;
    assert_eq!(r.status(), 410, "expired grant cannot be redeemed");
}

#[tokio::test]
async fn lost_genesis_race_rolls_back_grant() {
    // A grant redeemed against an ALREADY-bootstrapped tenant must 409 AND stay pending —
    // the in-transaction redeem rolls back together with the lost genesis CAS.
    let app = spawn_closed().await;
    let (_g1, t1) = mint(&app, "first", None, None).await;
    let tid = b"tid-shared-0000000";
    assert_eq!(
        redeem(&app, tid, &make_identity(), &t1, None)
            .await
            .status(),
        201
    );

    let (g2, t2) = mint(&app, "second", None, None).await;
    // Redeem grant2 against the SAME, already-bootstrapped tenant → genesis CAS loses.
    assert_eq!(
        redeem(&app, tid, &make_identity(), &t2, None)
            .await
            .status(),
        409
    );
    assert_eq!(
        find(&grants(&app).await, &g2)["state"],
        json!("pending"),
        "grant consumption rolled back with the lost race"
    );
    // …and grant2 is still usable for a fresh tenant.
    assert_eq!(
        redeem(&app, b"tid-second-000000", &make_identity(), &t2, None)
            .await
            .status(),
        201
    );
}

#[tokio::test]
async fn enroll_endpoints_require_ops_token() {
    let app = spawn_closed().await;
    let r = app
        .client
        .post(format!("{}/v1/ops/enroll/create", app.base))
        .json(&json!({ "label": "x" }))
        .send()
        .await
        .unwrap();
    assert!(
        r.status() == 401 || r.status() == 403,
        "mint requires the ops token, got {}",
        r.status()
    );
}
