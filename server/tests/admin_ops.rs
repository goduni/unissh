//! Admin surface (`/v1/admin/*`): overview, account disable (+ auth enforcement,
//! anti-lockout), devices/sessions/vaults/objects/relay/keysets listings, read-only
//! config (masked), seq-bump, migrations, audit chain. All require the instance
//! owner (OwnerCtx). ZK: metadata, not content. Instance-scoped (v2).

mod common;

use common::{TestApp, claim_owner, make_identity, spawn};
use serde_json::{Value, json};
use unissh_server::ids::b64;
use unissh_storage::{CachePolicy, SyncTarget, VaultRecord};
use unissh_sync::{AuditObject, SyncObject};

struct Owner {
    bearer: String,
    account_id: String,
    ed: [u8; 32],
}

async fn claim_admin(app: &TestApp) -> Owner {
    let id = make_identity();
    let c = claim_owner(app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();
    let bearer = app
        .login(&id, &account_id, c["device_id"].as_str().unwrap())
        .await;
    Owner {
        bearer,
        account_id,
        ed: id.ed,
    }
}

/// Seed a non-owner member with an optional handle; return (account_id, bearer).
async fn add_member(app: &TestApp, handle: Option<&str>) -> (String, String) {
    let m = make_identity();
    let (acct_bytes, dev_bytes, _) = app.seed_device(&m.ed, &m.x, "org", false).await;
    if let Some(h) = handle {
        app.state
            .store
            .update_account_profile(&acct_bytes, None, Some(h))
            .await
            .unwrap();
    }
    let acct = b64(&acct_bytes);
    let bearer = app.login(&m, &acct, &b64(&dev_bytes)).await;
    (acct, bearer)
}

async fn get_json(app: &TestApp, path: &str, bearer: &str) -> Value {
    get_q(app, path, &[], bearer).await
}

/// Percent-encode a query value.
fn pe(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

async fn get_q(app: &TestApp, path: &str, query: &[(&str, &str)], bearer: &str) -> Value {
    let mut url = format!("{}{}", app.base, path);
    if !query.is_empty() {
        let qs: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{k}={}", pe(v)))
            .collect();
        url.push('?');
        url.push_str(&qs.join("&"));
    }
    app.client
        .get(url)
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Audit object authored by `author` (must equal the instance owner to be accepted).
fn audit_obj(tag: u8, author: &[u8]) -> String {
    b64(&SyncObject::Audit(AuditObject {
        vault_id: vec![],
        entry_blob: vec![tag],
        signature: vec![1u8; 67],
        author_pubkey: author.to_vec(),
    })
    .to_bytes()
    .unwrap())
}

fn vault_b64(owner: u8, version: u64) -> String {
    b64(&SyncObject::Vault(VaultRecord {
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
    .unwrap())
}

// ---- overview + auth enforcement ----

#[tokio::test]
async fn non_owner_cannot_reach_admin() {
    let app = spawn().await;
    let _a = claim_admin(&app).await;
    let (_acct, member_bearer) = add_member(&app, Some("ed")).await;

    let r = app
        .client
        .get(format!("{}/v1/admin/overview", app.base))
        .header("Authorization", format!("Bearer {member_bearer}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "a member is not the instance owner");
}

// ---- account disable + enforcement + anti-lockout ----

#[tokio::test]
async fn disable_account_blocks_sessions_with_anti_lockout() {
    let app = spawn().await;
    let a = claim_admin(&app).await;
    let (bob_acct, bob_bearer) = add_member(&app, Some("bob")).await;

    let bob_version = |bearer: &str| {
        app.client
            .get(format!("{}/v1/sync/version", app.base))
            .header("Authorization", format!("Bearer {bearer}"))
            .send()
    };
    assert_eq!(bob_version(&bob_bearer).await.unwrap().status(), 200);

    let set_status = |acct: &str, disabled: bool| {
        app.client
            .post(format!("{}/v1/admin/account/status", app.base))
            .header("Authorization", format!("Bearer {}", a.bearer))
            .json(&json!({ "account_id": acct, "disabled": disabled }))
            .send()
    };
    assert_eq!(set_status(&bob_acct, true).await.unwrap().status(), 204);

    // bob's existing session is now rejected
    assert_eq!(bob_version(&bob_bearer).await.unwrap().status(), 401);

    // re-enable → works again
    assert_eq!(set_status(&bob_acct, false).await.unwrap().status(), 204);
    assert_eq!(bob_version(&bob_bearer).await.unwrap().status(), 200);

    // cannot disable the claim owner
    assert_eq!(
        set_status(&a.account_id, true).await.unwrap().status(),
        403,
        "claim owner cannot be disabled"
    );
}

// ---- devices / sessions ----

#[tokio::test]
async fn devices_sessions_list_and_revoke() {
    let app = spawn().await;
    let a = claim_admin(&app).await;

    let devs = get_q(
        &app,
        "/v1/admin/devices",
        &[("account_id", &a.account_id)],
        &a.bearer,
    )
    .await;
    let darr = devs["devices"].as_array().unwrap();
    assert_eq!(darr.len(), 1);
    assert_eq!(darr[0]["status"], "active");
    assert_eq!(darr[0]["active_sessions"], 1);

    let sess = get_json(&app, "/v1/admin/sessions", &a.bearer).await;
    let sarr = sess["sessions"].as_array().unwrap();
    assert_eq!(sarr.len(), 1);
    let sid = sarr[0]["session_id"].as_str().unwrap().to_string();

    // revoke that session
    let r = app
        .client
        .post(format!("{}/v1/admin/session/revoke", app.base))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "session_id": sid }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // that bearer is now dead
    let dead = app
        .client
        .get(format!("{}/v1/admin/overview", app.base))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .send()
        .await
        .unwrap();
    assert_eq!(
        dead.status(),
        401,
        "revoked session can no longer authenticate"
    );
}

// ---- invites (empty listing; v2 create arrives in Task 8) ----

#[tokio::test]
async fn invites_list_empty() {
    let app = spawn().await;
    let a = claim_admin(&app).await;
    let list = get_json(&app, "/v1/admin/invites", &a.bearer).await;
    assert_eq!(list["invites"].as_array().unwrap().len(), 0);
}

// ---- vaults ----

#[tokio::test]
async fn vaults_listing() {
    let app = spawn().await;
    let a = claim_admin(&app).await;

    let vault_id = b64(b"vault-x");
    let claim = app
        .client
        .post(format!("{}/v1/vaults/claim", app.base))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "vault_id": vault_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(claim.status(), 200);

    let list = get_json(&app, "/v1/admin/vaults", &a.bearer).await;
    let arr = list["vaults"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["vault_id"], vault_id);

    let detail = get_q(
        &app,
        "/v1/admin/vault",
        &[("vault_id", &vault_id)],
        &a.bearer,
    )
    .await;
    assert_eq!(detail["vault_id"], vault_id);
    assert_eq!(detail["tombstone"], false);
}

// ---- objects metadata (ZK: no content leak) ----

#[tokio::test]
async fn objects_metadata_no_content_leak() {
    let app = spawn().await;
    let a = claim_admin(&app).await;

    // push 2 objects through the real sync path (audit author == instance owner)
    let author = a.ed.to_vec();
    let push = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "objects": [audit_obj(1, &author), audit_obj(2, &author)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(push.status(), 200);

    // page 1: limit 1
    let p1 = get_q(&app, "/v1/admin/objects", &[("limit", "1")], &a.bearer).await;
    let items = p1["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["server_seq"], 1);
    assert!(items[0]["blob_len"].as_i64().unwrap() > 0);
    assert_eq!(p1["has_more"], true);
    assert_eq!(p1["next_cursor"], 1);
    // ZK: NO raw bytes
    assert!(items[0].get("object").is_none());
    assert!(items[0].get("object_bytes").is_none());

    // page 2: follow cursor
    let p2 = get_q(
        &app,
        "/v1/admin/objects",
        &[("limit", "1"), ("cursor", "1")],
        &a.bearer,
    )
    .await;
    assert_eq!(p2["items"][0]["server_seq"], 2);
}

// ---- relay / keysets observation ----

#[tokio::test]
async fn relay_and_keysets_observation() {
    let app = spawn().await;
    let a = claim_admin(&app).await;

    // open a relay channel
    let resp = app
        .client
        .post(format!("{}/v1/relay/open", app.base))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .send()
        .await
        .unwrap();
    let st = resp.status();
    let open: Value = resp.json().await.unwrap();
    assert_eq!(st, 200, "relay/open failed: {open}");
    let chan = open["channel_id"].as_str().unwrap().to_string();

    let relay = get_json(&app, "/v1/admin/relay", &a.bearer).await;
    let chans = relay["channels"].as_array().unwrap();
    assert_eq!(chans.len(), 1);
    assert_eq!(chans[0]["channel_id"], chan);
    assert!(
        chans[0].get("msg1").is_none(),
        "ZK: relay messages not exposed"
    );

    // fresh account has no keyset generations
    let ks = get_q(
        &app,
        "/v1/admin/keysets",
        &[("account_id", &a.account_id)],
        &a.bearer,
    )
    .await;
    assert_eq!(ks["keysets"].as_array().unwrap().len(), 0);
}

// ---- config (read-only, masked) ----

#[tokio::test]
async fn config_masks_secrets() {
    let app = common::spawn_with(|c| {
        c.server.tls_key = "PRIVATEKEY".into();
    })
    .await;
    let a = claim_admin(&app).await;

    let cfg = get_json(&app, "/v1/admin/config", &a.bearer).await;
    assert_eq!(cfg["server"]["tls_key"], "***", "secret masked");
    assert_eq!(cfg["db"]["url"], "***", "db url (may carry creds) masked");
    assert_eq!(
        cfg["limits"]["max_objects_per_push"], 1000,
        "non-secret visible"
    );
    // The setup code is masked (present but not disclosed).
    assert_eq!(cfg["setup"]["code"], "***");
}

// ---- seq-bump over HTTP ----

#[tokio::test]
async fn seq_bump_http_raises_only() {
    let app = spawn().await;
    let a = claim_admin(&app).await;

    let bump = |body: Value| {
        app.client
            .post(format!("{}/v1/admin/seq-bump", app.base))
            .header("Authorization", format!("Bearer {}", a.bearer))
            .json(&body)
            .send()
    };

    let r1: Value = bump(json!({ "by": 1000 }))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r1["old"], 0);
    assert_eq!(r1["new"], 1000);

    let v = get_json(&app, "/v1/sync/version", &a.bearer).await;
    assert_eq!(v["report_version"], 1000);

    // `to` below current never lowers
    let r2: Value = bump(json!({ "to": 1 }))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r2["old"], 1000);
    assert_eq!(r2["new"], 1000);
}

// ---- migrations ----

#[tokio::test]
async fn migrations_listed() {
    let app = spawn().await;
    let a = claim_admin(&app).await;

    let m = get_json(&app, "/v1/admin/migrations", &a.bearer).await;
    let arr = m["migrations"].as_array().unwrap();
    assert!(!arr.is_empty(), "at least 0001_init");
    assert_eq!(arr[0]["version"].as_i64().unwrap(), 1);
}

// ---- audit tamper-evident hash-chain ----

#[tokio::test]
async fn audit_chain_verifies_and_detects_tampering() {
    let app = spawn().await;
    let a = claim_admin(&app).await;

    // login already wrote one server-observed audit row (seq 1);
    // a client-signed audit append (author == owner) adds one more.
    let obj = audit_obj(7, &a.ed);
    let ap = app
        .client
        .post(format!("{}/v1/audit", app.base))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "audit_object": obj }))
        .send()
        .await
        .unwrap();
    assert_eq!(ap.status(), 201);

    let v = get_json(&app, "/v1/admin/audit/verify", &a.bearer).await;
    assert_eq!(v["ok"], true, "intact chain verifies");
    assert!(v["count"].as_i64().unwrap() >= 2);
    assert!(v["broken_at"].is_null());
    assert!(v["head_hash"].is_string());

    // tamper a row directly in the store → chain must break at that seq
    app.state
        .store
        .exec(
            "UPDATE audit_log SET entry_blob = ? WHERE seq = 1",
            vec![unissh_server::store::Val::B(b"TAMPERED".to_vec())],
        )
        .await
        .unwrap();

    let v2 = get_json(&app, "/v1/admin/audit/verify", &a.bearer).await;
    assert_eq!(v2["ok"], false, "tampering detected");
    assert_eq!(v2["broken_at"], 1);
}

// ---- config hot-reload (validate_signatures) + metrics summary ----

#[tokio::test]
async fn config_hot_reload_toggles_signature_validation() {
    let app = spawn().await;
    let a = claim_admin(&app).await;

    let push_forged = || {
        // Vault with a bogus signature — rejected only when validate is on
        app.client
            .post(format!("{}/v1/sync/push", app.base))
            .header("Authorization", format!("Bearer {}", a.bearer))
            .json(&json!({ "objects": [vault_b64(0xAA, 1)] }))
            .send()
    };

    let put_validate = |on: bool| {
        app.client
            .put(format!("{}/v1/admin/config", app.base))
            .header("Authorization", format!("Bearer {}", a.bearer))
            .json(&json!({ "validate_signatures": on }))
            .send()
    };

    // harness default: validate_signatures = false → forged push accepted
    assert_eq!(push_forged().await.unwrap().status(), 200);

    // hot-enable validation → forged push now rejected (no restart)
    let p = put_validate(true).await.unwrap();
    assert_eq!(p.status(), 200);
    let body: Value = p.json().await.unwrap();
    assert_eq!(body["validate_signatures"], true);
    assert!(push_forged().await.unwrap().status().is_client_error());

    // GET reflects the live value
    let cfg = get_json(&app, "/v1/admin/config", &a.bearer).await;
    assert_eq!(cfg["sync"]["validate_signatures"], true);

    // hot-disable again → accepted
    assert_eq!(put_validate(false).await.unwrap().status(), 200);
    assert_eq!(push_forged().await.unwrap().status(), 200);
}

#[tokio::test]
async fn metrics_summary_reports_disabled_in_harness() {
    let app = spawn().await;
    let a = claim_admin(&app).await;
    let m = get_json(&app, "/v1/admin/metrics", &a.bearer).await;
    // harness builds state with metrics=None
    assert_eq!(m["enabled"], false);
    assert!(m["prometheus"].is_null());
}

// ---- whole-DB-snapshot anti-rollback generation (§16) ----

#[tokio::test]
async fn instance_generation_tracks_writes() {
    let app = spawn().await;
    let a = claim_admin(&app).await;

    let ov0 = get_json(&app, "/v1/admin/overview", &a.bearer).await;
    assert_eq!(ov0["instance_generation"], 0);

    // push 2 objects → next_seq 0→2 → instance generation 2
    let author = a.ed.to_vec();
    let push = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "objects": [audit_obj(1, &author), audit_obj(2, &author)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(push.status(), 200);

    let inst = get_json(&app, "/v1/admin/instance", &a.bearer).await;
    assert_eq!(inst["generation"], 2);
    assert_eq!(inst["min_floor"], 0);

    let ov1 = get_json(&app, "/v1/admin/overview", &a.bearer).await;
    assert_eq!(ov1["instance_generation"], 2);
}
