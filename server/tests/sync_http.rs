//! HTTP level §5.0/§5.1: middleware (auth/rate-limit) + sync endpoints
//! (push/delta/version) via a real server. Instance-scoped (v2).

mod common;

use common::{spawn, spawn_with};
use serde_json::json;
use unissh_server::ids;
use unissh_storage::{CachePolicy, SyncTarget, VaultRecord};
use unissh_sync::{AuditObject, SyncObject};

fn audit_b64(tag: u8) -> String {
    ids::b64(
        &SyncObject::Audit(AuditObject {
            vault_id: vec![],
            entry_blob: vec![tag],
            signature: vec![1u8; 67],
            author_pubkey: vec![2u8; 32],
        })
        .to_bytes()
        .unwrap(),
    )
}

fn vault_b64(owner: u8, version: u64) -> String {
    ids::b64(
        &SyncObject::Vault(VaultRecord {
            vault_id: b"vault-1".to_vec(),
            sync_target: SyncTarget::Cloud,
            name_blob: vec![1, 2, 3],
            wrapped_vk: vec![4, 5, 6],
            version,
            tombstone: false,
            signature: vec![9u8; 67],
            author_pubkey: vec![owner; 32],
            key_epoch: 1,
            cache_policy: CachePolicy::OfflineAllowed,
            sync_tenant: Vec::new(),
        })
        .to_bytes()
        .unwrap(),
    )
}

#[tokio::test]
async fn rejects_bad_bearer() {
    let app = spawn().await;
    app.seed_session("personal").await;
    let r = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("Authorization", "Bearer not-a-real-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers().get("unissh-api-version").unwrap(), "1");
}

#[tokio::test]
async fn push_delta_version_roundtrip() {
    let app = spawn().await;
    let s = app.seed_session("personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);

    // push 3 objects
    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", &bearer)
        .json(&json!({ "objects": [audit_b64(1), audit_b64(2), audit_b64(3)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["server_seq"], json!([1, 2, 3]));

    // version
    let v: serde_json::Value = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("Authorization", &bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["report_version"], 3);

    // delta from cursor 0
    let d: serde_json::Value = app
        .client
        .get(format!("{}/v1/sync/delta?cursor=0&limit=2", app.base))
        .header("Authorization", &bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(d["items"].as_array().unwrap().len(), 2);
    assert_eq!(d["has_more"], true);
    assert_eq!(d["next_cursor"], 2);
}

#[tokio::test]
async fn idempotent_push_over_http() {
    let app = spawn().await;
    let s = app.seed_session("personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);
    let payload = json!({ "objects": [audit_b64(1), audit_b64(2)] });

    let send = |idem: &str| {
        app.client
            .post(format!("{}/v1/sync/push", app.base))
            .header("Authorization", &bearer)
            .header("Idempotency-Key", idem)
            .json(&payload)
            .send()
    };

    let b1: serde_json::Value = send("key-1").await.unwrap().json().await.unwrap();
    assert_eq!(b1["server_seq"], json!([1, 2]));
    // replay → same seqs, no advance
    let b2: serde_json::Value = send("key-1").await.unwrap().json().await.unwrap();
    assert_eq!(b2["server_seq"], json!([1, 2]));
    let v: serde_json::Value = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("Authorization", &bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        v["report_version"], 2,
        "idempotent replay must not advance next_seq"
    );
}

#[tokio::test]
async fn claim_rule_conflict_over_http() {
    let app = spawn().await;
    let s = app.seed_session("personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);
    let post = |objs: serde_json::Value| {
        app.client
            .post(format!("{}/v1/sync/push", app.base))
            .header("Authorization", &bearer)
            .json(&objs)
            .send()
    };
    let r1 = post(json!({"objects":[vault_b64(0xAA,1)]})).await.unwrap();
    assert_eq!(r1.status(), 200);
    let r2 = post(json!({"objects":[vault_b64(0xBB,2)]})).await.unwrap();
    assert_eq!(r2.status(), 409, "different owner → claim-rule conflict");
}

#[tokio::test]
async fn rate_limit_429() {
    let app = spawn_with(|c| {
        c.limits.rate_limit_per_ip_rps = 1;
        c.limits.rate_limit_burst = 2;
    })
    .await;
    // No auth needed: rate-limit runs before auth on /v1. Clock frozen → no refill.
    let url = format!("{}/v1/sync/version", app.base);
    let hit = || app.client.get(&url).send();
    let s1 = hit().await.unwrap().status();
    let s2 = hit().await.unwrap().status();
    let s3 = hit().await.unwrap().status();
    assert_ne!(s1, 429);
    assert_ne!(s2, 429);
    assert_eq!(s3, 429, "burst=2 → 3rd request rate-limited");
}
