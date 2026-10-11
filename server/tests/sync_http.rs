//! HTTP level §5.0/§5.1: middleware (auth/rate-limit) + sync endpoints
//! (push/delta/version) via a real server. Instance-scoped (v2).
#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

mod common;

use common::{spawn, spawn_with};
use serde_json::json;
use unissh_server::ids;
use unissh_storage::{CachePolicy, SyncTarget, VaultRecord};
use unissh_sync::{AuditObject, SyncObject};

fn audit_b64(tag: u8) -> String {
    audit_sized_b64(tag, 1)
}

/// An audit object whose entry blob is `blob_len` bytes of `tag`: 116 bytes of
/// framing, signature and author on top of the blob.
fn audit_sized_b64(tag: u8, blob_len: usize) -> String {
    ids::b64(
        &SyncObject::Audit(AuditObject {
            vault_id: vec![],
            entry_blob: vec![tag; blob_len],
            signature: vec![1_u8; 67],
            author_pubkey: vec![2_u8; 32],
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
            signature: vec![9_u8; 67],
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

/// A Cloud vault owned by `author` (its author_pubkey), base64 for a push body.
fn owned_vault_b64(author: &[u8], vault_id: &[u8], version: u64) -> String {
    ids::b64(
        &SyncObject::Vault(VaultRecord {
            vault_id: vault_id.to_vec(),
            sync_target: SyncTarget::Cloud,
            name_blob: vec![1, 2, 3],
            wrapped_vk: vec![4, 5, 6],
            version,
            tombstone: false,
            signature: vec![9_u8; 67],
            author_pubkey: author.to_vec(),
            key_epoch: 1,
            cache_policy: CachePolicy::OfflineAllowed,
            sync_tenant: Vec::new(),
        })
        .to_bytes()
        .unwrap(),
    )
}

/// Phase 4: `GET /v1/vaults` catalog lists only the caller's accessible vaults, with
/// the latest record bytes; a different device sees none of them.
#[tokio::test]
async fn vault_catalog_lists_only_callers_vaults() {
    let app = spawn().await;
    let s = app.seed_session("personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);

    // A Cloud vault owned by the caller (author == caller device key).
    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", &bearer)
        .json(&json!({ "objects": [owned_vault_b64(&s.ed25519_pub, b"vault-cat", 1)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let cat: serde_json::Value = app
        .client
        .get(format!("{}/v1/vaults", app.base))
        .header("Authorization", &bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let vaults = cat["vaults"].as_array().unwrap();
    assert_eq!(vaults.len(), 1, "caller sees exactly their one vault");
    // hex of b"vault-cat"
    assert_eq!(vaults[0]["vault_id"], "7661756c742d636174");
    assert_eq!(vaults[0]["latest_version"], 1);
    assert_eq!(vaults[0]["tombstone"], false);
    assert!(
        vaults[0]["record"].is_string(),
        "the latest record bytes are included for name display"
    );

    // A different device (different key) sees nothing.
    let s2 = app.seed_session("personal").await;
    let cat2: serde_json::Value = app
        .client
        .get(format!("{}/v1/vaults", app.base))
        .header("Authorization", format!("Bearer {}", s2.access_token_b64))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        cat2["vaults"].as_array().unwrap().len(),
        0,
        "a different account sees none of the caller's vaults"
    );
}

/// Phase 4: `GET /v1/sync/delta?vault=<hex>` restricts the delta to that one vault.
#[tokio::test]
async fn delta_vault_filter_returns_only_that_vault() {
    let app = spawn().await;
    let s = app.seed_session("personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);

    // Two owned vaults: b"va" (hex 7661) and b"vb" (hex 7662).
    app.client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", &bearer)
        .json(&json!({ "objects": [
            owned_vault_b64(&s.ed25519_pub, b"va", 1),
            owned_vault_b64(&s.ed25519_pub, b"vb", 1),
        ] }))
        .send()
        .await
        .unwrap();

    let d: serde_json::Value = app
        .client
        .get(format!("{}/v1/sync/delta?cursor=0&vault=7661", app.base))
        .header("Authorization", &bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        d["items"].as_array().unwrap().len(),
        1,
        "the vault filter returns only va's object, not vb's"
    );
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

/// The default limits admit the largest object a client legitimately pushes (a
/// full session recording) in a request of its own, and nothing bigger.
/// Regression: the default object limit was 1 MiB, and whatever
/// `limits.max_body_bytes` said, a body over 2 MiB never reached the handler.
#[tokio::test]
async fn default_limits_admit_the_largest_client_object_and_nothing_bigger() {
    let app = spawn().await;
    let s = app.seed_session("personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);
    let largest = unissh_sync::LARGEST_CLIENT_OBJECT_BYTES;

    // Size is checked before the object is parsed: zeros of a permitted size
    // get as far as the parser, which rejects them as malformed (400).
    for (len, expected) in [(largest, 400_u16), (largest + 1, 413)] {
        let status = app
            .client
            .post(format!("{}/v1/sync/push", app.base))
            .header("Authorization", &bearer)
            .json(&json!({ "objects": [ids::b64(&vec![0_u8; len])] }))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, expected, "an object of {len} bytes");
    }
}

/// Only the push route takes a body up to `limits.max_body_bytes`; a route that
/// answers without a session stops at the framework's 2 MiB. Regression: the
/// large limit was set on the whole router, so anyone could make the server
/// buffer 24 MiB per request.
#[tokio::test]
async fn unauthenticated_route_refuses_a_body_over_the_default_limit() {
    let app = spawn().await;
    // One byte over 2 MiB, in a field the handler would read.
    let (head, tail) = ("{\"device_id\":\"", "\"}");
    let fill = 2 * 1024 * 1024 + 1 - head.len() - tail.len();
    let body = format!("{head}{}{tail}", "A".repeat(fill));

    let r = app
        .client
        .post(format!("{}/v1/auth/challenge", app.base))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
}

/// A delta page is cut at `limits.delta_max_page_bytes`, never below one row, and
/// `has_more` / `next_cursor` lead a reader through all of it. Regression: pages
/// were bounded by row count only, so a page of large objects had no size bound.
#[tokio::test]
async fn delta_page_is_cut_at_the_byte_budget() {
    // Room for two small objects (117 bytes each), not three.
    let app = spawn_with(|c| c.limits.delta_max_page_bytes = 250).await;
    let s = app.seed_session("personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);
    let objects = json!({ "objects": [
        audit_sized_b64(1, 300), // over the budget on its own
        audit_b64(2),
        audit_b64(3),
        audit_b64(4),
    ] });
    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", &bearer)
        .json(&objects)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let mut pages = Vec::new();
    let mut cursor = 0_u64;
    loop {
        let d: serde_json::Value = app
            .client
            .get(format!("{}/v1/sync/delta?cursor={cursor}", app.base))
            .header("Authorization", &bearer)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let seqs: Vec<u64> = d["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["server_seq"].as_u64().unwrap())
            .collect();
        pages.push(seqs);
        if d["has_more"] != true {
            break;
        }
        cursor = d["next_cursor"].as_u64().unwrap();
        assert!(pages.len() < 10, "the cursor does not advance");
    }
    assert_eq!(
        pages,
        [vec![1], vec![2, 3], vec![4]],
        "the oversize object alone, then pages within the budget"
    );
}

/// `has_more` means a row remains, not "the page came back full": a final page
/// that happens to hold exactly `limit` rows ends the delta.
#[tokio::test]
async fn delta_final_page_does_not_claim_more() {
    let app = spawn().await;
    let s = app.seed_session("personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);
    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", &bearer)
        .json(&json!({ "objects": [audit_b64(1), audit_b64(2)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

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
    assert_eq!(d["has_more"], false);
    assert_eq!(d["next_cursor"], 2);
}
