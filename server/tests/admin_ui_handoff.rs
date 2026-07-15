//! Server-side changes backing the admin-panel handoff (P1.2/P1.3/P2.6/P2.8):
//! /v1/admin/health, /v1/admin/metrics/summary, CORS, hot-reload limits.
//! Instance-scoped (v2).

mod common;

use common::{Identity, TestApp, claim_owner, make_identity, spawn};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

async fn claim_admin(app: &TestApp) -> (Identity, String, String) {
    let id = make_identity();
    let c = claim_owner(app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();
    let bearer = app
        .login(&id, &account_id, c["device_id"].as_str().unwrap())
        .await;
    (id, account_id, bearer)
}

// ---- P1.2 health ----

#[tokio::test]
async fn admin_health_reports_uptime_pool_janitor_tls() {
    let app = spawn().await;
    let (_id, _acct, bearer) = claim_admin(&app).await;

    // uptime grows with the clock; janitor last_run is wired to the atomic.
    app.clock.advance(50);
    app.state
        .last_janitor_run
        .store(app.now(), Ordering::Relaxed);

    let h: Value = app
        .client
        .get(format!("{}/v1/admin/health", app.base))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(h["status"], "ok");
    assert_eq!(h["uptime_seconds"], 50);
    assert_eq!(h["db"]["reachable"], true);
    assert_eq!(h["db"]["backend"], "sqlite");
    assert!(h["db"]["pool"]["max"].as_i64().unwrap() >= 1);
    assert!(h["db"]["pool"]["in_use"].as_i64().is_some());
    assert_eq!(h["janitor"]["last_run"], app.now());
    assert_eq!(h["tls"], "proxy"); // no in-process cert/key → terminated upstream
    assert!(h["version"].is_string());
}

#[tokio::test]
async fn admin_health_requires_owner() {
    let app = spawn().await;
    // Claimed, but no Authorization → 401 (OwnerCtx resolves the bearer first).
    let _ = claim_admin(&app).await;
    let r = app
        .client
        .get(format!("{}/v1/admin/health", app.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

// ---- P1.3 metrics/summary (disabled path; recorder not installed in tests) ----

#[tokio::test]
async fn admin_metrics_summary_disabled_without_recorder() {
    let app = spawn().await;
    let (_id, _acct, bearer) = claim_admin(&app).await;
    let m: Value = app
        .client
        .get(format!("{}/v1/admin/metrics/summary", app.base))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(m["enabled"], false);
    assert!(m["series"].is_null());
}

// ---- P2.6 CORS ----

#[tokio::test]
async fn cors_preflight_allowed_for_configured_origin() {
    let app = spawn_with_cors().await;

    let resp = app
        .client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/v1/accounts", app.base),
        )
        .header("Origin", "https://admin.example.com")
        .header("Access-Control-Request-Method", "GET")
        .header("Access-Control-Request-Headers", "authorization")
        .send()
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "preflight should short-circuit 2xx"
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "https://admin.example.com"
    );
    let allow_headers = resp
        .headers()
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    assert!(allow_headers.contains("authorization"));
}

async fn spawn_with_cors() -> TestApp {
    common::spawn_with(|c| {
        c.server.cors_allowed_origins = vec!["https://admin.example.com".into()];
    })
    .await
}

#[tokio::test]
async fn cors_absent_when_unconfigured() {
    let app = spawn().await;
    let resp = app
        .client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/v1/accounts", app.base),
        )
        .header("Origin", "https://admin.example.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();
    // No CORS layer → no allow-origin header (preflight not honored).
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

// ---- P2.8 hot-reload object limits ----

#[tokio::test]
async fn config_hot_reload_object_limits_enforced() {
    let app = spawn().await;
    let (_id, _acct, bearer) = claim_admin(&app).await;
    let auth = || format!("Bearer {bearer}");

    // Shrink max_object_bytes via hot-reload.
    let put: Value = app
        .client
        .put(format!("{}/v1/admin/config", app.base))
        .header("Authorization", auth())
        .json(&json!({ "max_object_bytes": 10 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(put["max_object_bytes"], 10);

    // config_get reflects the live value.
    let cfg: Value = app
        .client
        .get(format!("{}/v1/admin/config", app.base))
        .header("Authorization", auth())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfg["limits"]["max_object_bytes"], 10);

    // A 100-byte object now exceeds the live cap → 413 (size checked before parse).
    let big = unissh_server::ids::b64(&[0u8; 100]);
    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", auth())
        .json(&json!({ "objects": [big] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        413,
        "object over hot-reloaded cap must be rejected"
    );

    // Zero is rejected as invalid.
    let bad = app
        .client
        .put(format!("{}/v1/admin/config", app.base))
        .header("Authorization", auth())
        .json(&json!({ "max_object_bytes": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
}
