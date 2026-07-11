//! Postgres integration §15.1 (gated on UNISSH_TEST_PG): the same dual-dialect code
//! on a live Postgres — the store level (seq/idempotency/isolation/claim) and
//! the HTTP level (push/delta/version). Without the env var the test is skipped.

mod common;

use common::spawn_with;
use serde_json::json;
use unissh_server::codec::parse_open;
use unissh_server::store::Store;
use unissh_server::store::sync_repo::PushObj;
use unissh_sync::{AuditObject, SyncObject};

fn pg_url() -> Option<String> {
    std::env::var("UNISSH_TEST_PG").ok()
}

fn audit(tag: u8) -> PushObj {
    let o = SyncObject::Audit(AuditObject {
        vault_id: vec![],
        entry_blob: vec![tag],
        signature: vec![1u8; 67],
        author_pubkey: vec![2u8; 32],
    });
    let bytes = o.to_bytes().unwrap();
    let parsed = parse_open(&bytes).unwrap();
    PushObj { bytes, parsed }
}

/// Unique tenant ids per run, so tests don't collide in a shared PG.
fn tid(suffix: &str) -> Vec<u8> {
    let mut v = b"pg-tenant-".to_vec();
    v.extend_from_slice(suffix.as_bytes());
    v.resize(16, 0);
    v
}

#[tokio::test]
async fn postgres_store_parity() {
    let Some(url) = pg_url() else {
        eprintln!("SKIP postgres_store_parity: set UNISSH_TEST_PG=postgres://...");
        return;
    };
    let store = Store::connect_postgres(&url, 8).await.expect("connect pg");
    store.migrate().await.expect("migrate pg");

    let ta = tid("seqA");
    store.create_tenant(&ta, "personal", 100).await.unwrap();

    // monotonic seq, input order
    let r = store
        .push_objects(&ta, None, b"h1", vec![audit(1), audit(2), audit(3)], 100)
        .await
        .unwrap();
    assert_eq!(r.server_seq, vec![1, 2, 3]);
    assert_eq!(store.report_version(&ta).await.unwrap(), 3);

    // idempotent replay (FOR UPDATE path on PG)
    let first = store
        .push_objects(&ta, Some(b"k"), b"body", vec![audit(9)], 101)
        .await
        .unwrap();
    let replay = store
        .push_objects(&ta, Some(b"k"), b"body", vec![audit(9)], 101)
        .await
        .unwrap();
    assert_eq!(first.server_seq, replay.server_seq);
    assert!(replay.replayed);
    assert_eq!(
        store.report_version(&ta).await.unwrap(),
        4,
        "replay did not advance"
    );

    // isolation: separate tenant has independent namespace
    let tb = tid("seqB");
    store.create_tenant(&tb, "personal", 100).await.unwrap();
    assert_eq!(store.report_version(&tb).await.unwrap(), 0);
    assert!(
        store
            .delta_since(&tb, 0, 100, &[0u8; 32], 1_000_000)
            .await
            .unwrap()
            .is_empty()
    );

    // claim-rule conflict on PG
    let tc = tid("claim");
    store.create_tenant(&tc, "personal", 100).await.unwrap();
    let v = |owner: u8| {
        let o = SyncObject::Vault(unissh_storage::VaultRecord {
            vault_id: b"vpg".to_vec(),
            sync_target: unissh_storage::SyncTarget::Cloud,
            name_blob: vec![1],
            wrapped_vk: vec![2],
            version: 1,
            tombstone: false,
            signature: vec![9u8; 67],
            author_pubkey: vec![owner; 32],
            key_epoch: 1,
            cache_policy: unissh_storage::CachePolicy::OfflineAllowed,
            sync_tenant: Vec::new(),
        });
        let bytes = o.to_bytes().unwrap();
        let parsed = parse_open(&bytes).unwrap();
        PushObj { bytes, parsed }
    };
    store
        .push_objects(&tc, None, b"h", vec![v(0xAA)], 100)
        .await
        .unwrap();
    let err = store
        .push_objects(&tc, None, b"h2", vec![v(0xBB)], 101)
        .await
        .unwrap_err();
    assert_eq!(err.code, unissh_server::ErrorCode::Conflict);
}

#[tokio::test]
async fn postgres_http_stack() {
    let Some(url) = pg_url() else {
        eprintln!("SKIP postgres_http_stack: set UNISSH_TEST_PG=postgres://...");
        return;
    };
    let app = spawn_with(|c| {
        c.db.backend = "postgres".into();
        c.db.url = url.clone();
    })
    .await;

    let t = tid("http");
    let s = app.seed_session(&t, "personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);
    let th = unissh_server::ids::b64(&t);

    let a = |tag: u8| unissh_server::ids::b64(&audit(tag).bytes);

    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("UniSSH-Tenant", &th)
        .header("Authorization", &bearer)
        .json(&json!({ "objects": [a(1), a(2)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["server_seq"], json!([1, 2]));

    let v: serde_json::Value = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("UniSSH-Tenant", &th)
        .header("Authorization", &bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["report_version"], 2);
}
