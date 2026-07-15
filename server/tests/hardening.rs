//! Regressions for fixes from the adversarial review: structural invariants on push,
//! self-revoke guard, host-binding auth.

mod common;

use common::{make_identity, spawn, spawn_with};
use serde_json::json;
use unissh_crypto::{AssociatedData, Ed25519Keypair, VersionedObject, sign_version};
use unissh_server::ids::b64;
use unissh_storage::{CachePolicy, SyncTarget, VaultRecord};
use unissh_sync::SyncObject;

fn vault(target: SyncTarget) -> String {
    b64(&SyncObject::Vault(VaultRecord {
        vault_id: b"v-harden".to_vec(),
        sync_target: target,
        name_blob: vec![1],
        wrapped_vk: vec![2],
        version: 1,
        tombstone: false,
        signature: vec![9u8; 67],
        author_pubkey: vec![0xAA; 32],
        key_epoch: 1,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    })
    .to_bytes()
    .unwrap())
}

#[tokio::test]
async fn local_vault_rejected_on_push() {
    let app = spawn().await;
    let s = app.seed_session("personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);

    // Cloud → accepted
    let ok = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", &bearer)
        .json(&json!({ "objects": [vault(SyncTarget::Cloud)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // Local → rejected (only Cloud reaches the server, §4.3/§5.4)
    let bad = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", &bearer)
        .json(&json!({ "objects": [vault(SyncTarget::Local)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400, "Local-target vault must be rejected");
}

#[tokio::test]
async fn grants_publish_self_revoke_rejected() {
    let app = spawn().await;
    // A real keypair: grants_publish verifies the manifest's signature unconditionally,
    // so the test must pass the signature check to reach the self-revoke 409.
    let admin_kp = Ed25519Keypair::generate();
    let admin = admin_kp.verifying.to_bytes().to_vec();
    let (_a, _d, bearer) = app.seed_device(&admin, &[1u8; 32], "org", true).await;
    app.state
        .store
        .claim_vault(
            b"v-harden",
            &admin,
            None,
            None,
            "selective",
            None,
            false,
            app.now(),
        )
        .await
        .unwrap();

    // manifest@5; revoke_epoch == new_epoch == 5 → conflict
    let mut blob = b"unissh-manifest-v1".to_vec();
    blob.extend_from_slice(&5u64.to_be_bytes());
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob.push(2);
    blob.extend_from_slice(&(admin.len() as u16).to_be_bytes());
    blob.extend_from_slice(&admin);
    let mut mobj = vec![3u8];
    let put = |o: &mut Vec<u8>, b: &[u8]| {
        o.extend_from_slice(&(b.len() as u32).to_be_bytes());
        o.extend_from_slice(b);
    };
    put(&mut mobj, b"v-harden");
    mobj.extend_from_slice(&5u64.to_be_bytes());
    put(&mut mobj, &blob);
    let sig = sign_version(
        &admin_kp.signing,
        &VersionedObject::from_content(
            AssociatedData::new(b"v-harden".to_vec(), b"__manifest__".to_vec(), 5),
            &blob,
        ),
    )
    .unwrap();
    put(&mut mobj, &sig);
    put(&mut mobj, &admin);

    let r = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({ "manifest": b64(&mobj), "grants": [], "revoke_epoch": 5, "new_epoch": 5 }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        409,
        "revoke_epoch == new_epoch must be rejected"
    );
}

/// Setup-security: the unauthenticated `POST /v1/claim` is behind the per-IP rate
/// limiter (it lives under the rate-limited `/v1` router). With a tiny burst and the
/// clock frozen (no refill), repeated claims must eventually get a `429`. Rate limiting
/// runs before handler logic, so a dummy/invalid body is fine.
#[tokio::test]
async fn claim_is_rate_limited() {
    let app = spawn_with(|c| {
        c.limits.rate_limit_per_ip_rps = 1;
        c.limits.rate_limit_burst = 2;
    })
    .await;
    // A well-formed-but-bogus claim body: rate-limit fires before the handler parses it.
    let body = json!({
        "setup_code": "nope",
        "registration_payload": "nope",
        "registration_signature": "nope",
    });
    let hit = || {
        app.client
            .post(format!("{}/v1/claim", app.base))
            .json(&body)
            .send()
    };
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(hit().await.unwrap().status());
    }
    assert!(
        statuses.iter().any(|s| *s == 429),
        "burst=2 + frozen clock → repeated POST /v1/claim must be rate-limited (got {statuses:?})"
    );
}

/// Escrow-security: the PUBLIC `POST /v1/escrow/fetch` lives under the same per-IP
/// rate limiter as the rest of `/v1`, so an attacker cannot grind `K_auth` guesses
/// against a handle unthrottled. With a tiny burst and the clock frozen (no refill),
/// repeated fetches must eventually get a `429`. Rate limiting runs before handler
/// logic, so a well-formed-but-doomed body (bogus handle + all-zero credential) is fine.
#[tokio::test]
async fn escrow_fetch_is_rate_limited() {
    let app = spawn_with(|c| {
        c.limits.rate_limit_per_ip_rps = 1;
        c.limits.rate_limit_burst = 2;
    })
    .await;
    let body = json!({ "handle": "ghost", "k_auth": b64(&[0u8; 32]) });
    let hit = || {
        app.client
            .post(format!("{}/v1/escrow/fetch", app.base))
            .json(&body)
            .send()
    };
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(hit().await.unwrap().status());
    }
    assert!(
        statuses.iter().any(|s| *s == 429),
        "burst=2 + frozen clock → repeated POST /v1/escrow/fetch must be rate-limited (got {statuses:?})"
    );
}

/// Setup-security: on an UNCLAIMED instance a claim with a valid registration
/// payload+signature but the WRONG setup code is rejected `403` (the constant-time
/// setup-code compare fails before any state change), and the instance stays unclaimed.
/// The security-observable outcome is: reject + no state change (timing is not testable
/// in a unit test).
#[tokio::test]
async fn wrong_setup_code_is_rejected_without_leak() {
    let app = spawn().await;
    let id = make_identity();

    let r = app
        .client
        .post(format!("{}/v1/claim", app.base))
        .json(&json!({
            "setup_code": "WRONG-CODE-9999",
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "wrong setup code must be rejected 403");

    // No state change: the instance is still unclaimed.
    let info: serde_json::Value = app
        .client
        .get(format!("{}/v1/instance", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        info["claimed"], false,
        "a rejected claim must not claim the instance"
    );
}

/// Setup-security: `GET /v1/instance` on an unclaimed instance exposes ONLY the allowed
/// public fields and nothing sensitive — no setup code (or its hash), no owner account,
/// no sync sequence.
#[tokio::test]
async fn instance_info_unclaimed_leaks_nothing() {
    let app = spawn().await;
    let info: serde_json::Value = app
        .client
        .get(format!("{}/v1/instance", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(info["claimed"], false, "fresh instance is unclaimed");
    assert!(
        info["auth"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "password"),
        "auth must advertise password"
    );

    let obj = info.as_object().expect("instance info is a JSON object");
    // The exact allowed key set — nothing more, nothing less.
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["auth", "claimed", "instance_id", "name", "version"],
        "instance info must expose exactly the allowed fields"
    );
    // Defense-in-depth: no sensitive field may ever appear.
    for forbidden in [
        "setup_code",
        "setup_code_hash",
        "owner_account_id",
        "next_seq",
    ] {
        assert!(
            obj.get(forbidden).is_none(),
            "instance info must not leak `{forbidden}`"
        );
    }
}
