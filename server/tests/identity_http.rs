//! Identity/auth §5.3/§6 via a live server with REAL core crypto (registration +
//! server-auth signatures). Covers claim→challenge→verify→authenticated push,
//! single-use nonce, keyset no-downgrade, PAKE relay verbatim, refresh rotation +
//! reuse detection. Instance-scoped (v2).
#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

mod common;

use common::{
    Identity, claim_owner, login_tokens_v2, login_v2, make_identity, spawn, spawn_with,
    try_login_v2,
};
use serde_json::{Value, json};
use unissh_crypto::{ServerAuthChallenge as CoreChal, sign_server_auth};
use unissh_server::ids::{self, b64, unb64};
use unissh_server::store::Val;
use unissh_server::store::instance_repo::DEAD_DEVICE_RETENTION_SECONDS;

async fn claim(app: &common::TestApp, id: &Identity) -> Value {
    claim_owner(app, &id.payload_b64, &id.sig_b64).await
}

/// POST /v1/session/refresh with the given refresh token.
async fn refresh(app: &common::TestApp, refresh_token: &str) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/session/refresh", app.base))
        .json(&json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn claim_login_and_authenticated_push() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let account_id = c["account_id"].as_str().unwrap().to_owned();
    let device_id = c["device_id"].as_str().unwrap().to_owned();

    let access = login_v2(&app, &id, &account_id, &device_id).await;

    // authenticated /v1/sync/version works with the minted token
    let v: Value = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("Authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["report_version"], 0);
}

#[tokio::test]
async fn nonce_is_single_use() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let account_id = c["account_id"].as_str().unwrap().to_owned();
    let device_id = c["device_id"].as_str().unwrap().to_owned();

    // get a challenge, sign it, verify twice
    let chal: Value = app
        .client
        .post(format!("{}/v1/auth/challenge", app.base))
        .json(&json!({ "account_id": account_id, "device_id": device_id, "key_id": b64(b"k1") }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let core_chal = CoreChal {
        host: unb64(chal["host"].as_str().unwrap()).unwrap(),
        account_id: unb64(chal["account_id"].as_str().unwrap()).unwrap(),
        device_id: unb64(chal["device_id"].as_str().unwrap()).unwrap(),
        key_id: unb64(chal["key_id"].as_str().unwrap()).unwrap(),
        nonce: unb64(chal["nonce"].as_str().unwrap()).unwrap(),
        expiry: chal["expiry"].as_u64().unwrap(),
    };
    let sig = b64(&sign_server_auth(&id.kp.signing, &core_chal).unwrap());
    let verify = || {
        app.client
            .post(format!("{}/v1/auth/verify", app.base))
            .json(&json!({ "challenge": chal, "signature": sig }))
            .send()
    };
    assert_eq!(verify().await.unwrap().status(), 200);
    assert_eq!(
        verify().await.unwrap().status(),
        401,
        "nonce reuse must fail"
    );
}

#[tokio::test]
async fn keyset_no_downgrade() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let access = login_v2(
        &app,
        &id,
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    )
    .await;

    // real EncryptedKeyset (gen 1) from the core
    let (_sk, ks, _u) =
        unissh_keychain::create_account(None, unissh_keychain::KdfParams::recommended()).unwrap();
    let gen1 = ks.to_bytes().unwrap();
    // simulate gen 2 by bumping the generation header bytes [2..6] (server parses header only)
    let mut gen2 = gen1.clone();
    gen2[2..6].copy_from_slice(&2_u32.to_be_bytes());

    let put = |blob: &[u8]| {
        app.client
            .put(format!("{}/v1/keyset", app.base))
            .header("Authorization", format!("Bearer {access}"))
            .json(&json!({ "keyset_blob": b64(blob) }))
            .send()
    };
    assert_eq!(put(&gen1).await.unwrap().status(), 200);
    assert_eq!(
        put(&gen1).await.unwrap().status(),
        409,
        "same generation → no-downgrade"
    );
    assert_eq!(put(&gen2).await.unwrap().status(), 200);

    let got: Value = app
        .client
        .get(format!("{}/v1/keyset", app.base))
        .header("Authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got["generation"], 2, "GET returns max generation");
}

#[tokio::test]
async fn keyset_put_stores_optional_escrow() {
    let app = spawn().await;
    let id = make_identity();
    // claim → the owner account is created with handle "owner" (get_escrow_by_handle key)
    let c = claim(&app, &id).await;
    let access = login_v2(
        &app,
        &id,
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    )
    .await;

    // real EncryptedKeyset (gen 1) from the core; gen 2 by bumping the header bytes.
    let (_sk, ks, _u) =
        unissh_keychain::create_account(None, unissh_keychain::KdfParams::recommended()).unwrap();
    let gen1 = ks.to_bytes().unwrap();
    let mut gen2 = gen1.clone();
    gen2[2..6].copy_from_slice(&2_u32.to_be_bytes());

    let put_keyset = |body: Value| {
        app.client
            .put(format!("{}/v1/keyset", app.base))
            .header("Authorization", format!("Bearer {access}"))
            .json(&body)
            .send()
    };

    // --- A plain PUT (no escrow) still 200s and leaves the escrow columns NULL. ---
    let r = put_keyset(json!({ "keyset_blob": b64(&gen1) }))
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "plain keyset PUT (no escrow) still 200s");

    let row = app
        .state
        .store
        .get_escrow_by_handle("owner")
        .await
        .unwrap()
        .expect("owner has an uploaded keyset");
    assert_eq!(row.generation, 1);
    assert!(
        row.k_auth_hash.is_none(),
        "a plain PUT leaves the K_auth hash NULL"
    );
    assert!(
        row.argon_salt.is_none(),
        "a plain PUT leaves the Argon salt NULL"
    );

    // --- An escrow-enrolling PUT (gen 2) stores sha256(K_auth) + the Argon params. ---
    // Params MUST be `KdfParams::recommended()` (64 MiB / t=3 / p=1, 16-byte salt): the
    // enroll handler rejects anything else so a real enrollment can never be distinguished
    // from a decoy (enumeration resistance).
    let k_auth_raw = vec![9_u8; 40];
    let salt = vec![3_u8; 16];
    let r = put_keyset(json!({
        "keyset_blob": b64(&gen2),
        "escrow": {
            "k_auth": b64(&k_auth_raw),
            "argon_salt": b64(&salt),
            "argon_mem_kib": 65536,
            "argon_iterations": 3,
            "argon_parallelism": 1,
        }
    }))
    .await
    .unwrap();
    assert_eq!(r.status(), 200, "escrow-enrolling keyset PUT 200s");
    let body: Value = r.json().await.unwrap();
    assert_eq!(
        body["generation"], 2,
        "response shape unchanged (still just generation)"
    );

    // The server stores ONLY sha256(K_auth) — never the raw credential — plus params.
    let row = app
        .state
        .store
        .get_escrow_by_handle("owner")
        .await
        .unwrap()
        .expect("owner has an escrow-enabled keyset");
    assert_eq!(
        row.generation, 2,
        "escrow is attached to the latest generation"
    );
    assert_eq!(
        row.k_auth_hash.as_deref(),
        Some(&ids::sha256(&k_auth_raw)[..]),
        "stored hash is sha256 of the raw K_auth, not the raw bytes"
    );
    assert_ne!(
        row.k_auth_hash.as_deref(),
        Some(&*k_auth_raw),
        "the raw K_auth is never persisted"
    );
    assert_eq!(row.argon_salt.as_deref(), Some(&*salt), "salt round-trips");
    assert_eq!(row.argon_mem_kib, Some(65536));
    assert_eq!(row.argon_iterations, Some(3));
    assert_eq!(row.argon_parallelism, Some(1));
}

/// The escrow enroll handler REJECTS any Argon params that are not
/// `KdfParams::recommended()` (64 MiB / t=3 / p=1) with a 400 — an off-spec enrollment
/// would otherwise make a real account distinguishable from a same-shaped decoy (see
/// `modules::escrow`). All shipped FFI/wasm clients enroll at the recommended defaults,
/// so this is a no-regression guard.
#[tokio::test]
async fn escrow_enroll_rejects_off_spec_argon_params() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let access = login_v2(
        &app,
        &id,
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    )
    .await;

    // A real EncryptedKeyset (gen 1) from the core — the enroll gate runs before the
    // keyset is stored, so a rejected off-spec PUT leaves no keyset behind (both PUTs
    // below re-use gen 1).
    let (_sk, ks, _u) =
        unissh_keychain::create_account(None, unissh_keychain::KdfParams::recommended()).unwrap();
    let gen1 = ks.to_bytes().unwrap();
    let put = |body: Value| {
        app.client
            .put(format!("{}/v1/keyset", app.base))
            .header("Authorization", format!("Bearer {access}"))
            .json(&body)
            .send()
    };

    // Off-spec cost (OWASP minimum, not the recommended default) → 400.
    let weak = put(json!({
        "keyset_blob": b64(&gen1),
        "escrow": {
            "k_auth": b64(&[9_u8; 40]),
            "argon_salt": b64(&[3_u8; 16]),
            "argon_mem_kib": 19456,
            "argon_iterations": 2,
            "argon_parallelism": 1,
        }
    }))
    .await
    .unwrap();
    assert_eq!(
        weak.status(),
        400,
        "off-spec Argon params are rejected at enroll (enumeration resistance)"
    );

    // A non-16-byte salt is likewise rejected (the decoy salt is always 16 bytes).
    let bad_salt = put(json!({
        "keyset_blob": b64(&gen1),
        "escrow": {
            "k_auth": b64(&[9_u8; 40]),
            "argon_salt": b64(&[3_u8; 24]),
            "argon_mem_kib": 65536,
            "argon_iterations": 3,
            "argon_parallelism": 1,
        }
    }))
    .await
    .unwrap();
    assert_eq!(
        bad_salt.status(),
        400,
        "a non-16-byte escrow salt is rejected"
    );
}

#[tokio::test]
async fn pake_relay_verbatim() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let access = login_v2(
        &app,
        &id,
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    )
    .await;

    let open: Value = app
        .client
        .post(format!("{}/v1/relay/open", app.base))
        .header("Authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let channel = open["channel_id"].as_str().unwrap().to_owned();

    let msg1 = b64(&[1_u8, 2, 3, 4, 5]);
    let s = app
        .client
        .post(format!("{}/v1/relay/msg1", app.base))
        .json(&json!({ "channel_id": channel, "msg1": msg1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(s.status(), 200);

    // poll returns the verbatim msg1
    let polled: Value = app
        .client
        .get(format!(
            "{}/v1/relay/poll?channel_id={}&want=msg1",
            app.base,
            urlencode(&channel)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(polled["msg1"], msg1, "relay stores/forwards verbatim");

    // polling absent msg2 → 204
    let r = app
        .client
        .get(format!(
            "{}/v1/relay/poll?channel_id={}&want=msg2",
            app.base,
            urlencode(&channel)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

// ---- session refresh: rotation + reuse detection (F9/F27) ----

/// Claim + authenticate, returning the freshly minted token set.
async fn claim_and_tokens(app: &common::TestApp) -> Value {
    let id = make_identity();
    let c = claim(app, &id).await;
    login_tokens_v2(
        app,
        &id,
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    )
    .await
}

fn rt(tokens: &Value) -> String {
    tokens["refresh_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn refresh_rotates_tokens_and_new_access_works() {
    let app = spawn().await;
    let t0 = claim_and_tokens(&app).await;

    let r = refresh(&app, &rt(&t0)).await;
    assert_eq!(r.status(), 200, "valid refresh should succeed");
    let t1: Value = r.json().await.unwrap();
    assert_ne!(rt(&t0), rt(&t1), "refresh token must rotate");
    assert_eq!(
        t0["session_id"], t1["session_id"],
        "rotation keeps the same session"
    );

    // The rotated access token authenticates.
    let access1 = t1["access_token"].as_str().unwrap();
    let v = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("Authorization", format!("Bearer {access1}"))
        .send()
        .await
        .unwrap();
    assert_eq!(v.status(), 200, "rotated access token must work");
}

#[tokio::test]
async fn refresh_reuse_of_rotated_token_revokes_session() {
    let app = spawn().await;
    let t0 = claim_and_tokens(&app).await;

    let r1 = refresh(&app, &rt(&t0)).await;
    assert_eq!(r1.status(), 200);
    let t1: Value = r1.json().await.unwrap();

    // Re-presenting the just-rotated (previous) token is reuse → 401.
    let reuse = refresh(&app, &rt(&t0)).await;
    assert_eq!(reuse.status(), 401, "reuse of a rotated token is rejected");

    // …and it revokes the WHOLE session: the current (rt1) token is now dead too.
    let after = refresh(&app, &rt(&t1)).await;
    assert_eq!(
        after.status(),
        401,
        "reuse must revoke the whole session lineage"
    );
}

#[tokio::test]
async fn refresh_reuse_of_older_generation_revokes_session() {
    // F9 core: detection must reach tokens OLDER than the immediately-previous one.
    let app = spawn().await;
    let t0 = claim_and_tokens(&app).await;

    let t1: Value = refresh(&app, &rt(&t0)).await.json().await.unwrap();
    let t2: Value = refresh(&app, &rt(&t1)).await.json().await.unwrap();

    // rt0 is now TWO generations behind current (rt2). It must still be caught as reuse.
    let reuse = refresh(&app, &rt(&t0)).await;
    assert_eq!(
        reuse.status(),
        401,
        "reuse of a 2-generations-old token must be detected"
    );

    // The whole session is revoked: the current token (rt2) no longer rotates.
    let after = refresh(&app, &rt(&t2)).await;
    assert_eq!(
        after.status(),
        401,
        "old-generation reuse revokes the session"
    );
}

#[tokio::test]
async fn refresh_rejects_malformed_and_unknown_tokens() {
    let app = spawn().await;
    drop(claim_and_tokens(&app).await);

    // Wrong length (not session_id(16)||secret(32)) → 401, no panic.
    assert_eq!(refresh(&app, &b64(b"too-short")).await.status(), 401);
    // Well-formed length but unknown session id → 401.
    assert_eq!(refresh(&app, &b64(&[7_u8; 48])).await.status(), 401);
}

// ---- OIDC reassertion gate (Phase 5, Task 3) ----

/// Seed an account+device+session directly in the store and return its refresh token
/// (`session_id(16) || secret(32)`, base64). `reassert_expires` is set explicitly so
/// the assertion does not depend on config; `auth_source` selects the gate path.
async fn seed_refreshable_session(
    app: &common::TestApp,
    auth_source: &str,
    reassert_expires: Option<i64>,
) -> String {
    let s = &app.state.store;
    let now = app.now();
    let account_id = ids::random_id16().to_vec();
    let device_id = ids::random_id16().to_vec();
    let ed = ids::random_bytes32().to_vec();
    let x = ids::random_bytes32().to_vec();
    let (issuer, subject) = if auth_source == "oidc" {
        (Some("https://idp"), Some("sub-1"))
    } else {
        (None, None)
    };
    s.create_account(
        &account_id,
        &ed,
        &x,
        None,
        None,
        false,
        &[],
        &[],
        issuer,
        subject,
        now,
    )
    .await
    .unwrap();
    s.create_device(&account_id, &device_id, &ed, &x, "app", None, None, now)
        .await
        .unwrap();

    let session_id = ids::random_id16();
    let mut refresh_token = session_id.to_vec();
    refresh_token.extend_from_slice(&ids::random_bytes32());
    s.create_session(
        &session_id,
        &account_id,
        &device_id,
        &ids::sha256(&ids::random_bytes32()),
        &ids::sha256(&refresh_token),
        now + 900,
        now + 1_000_000,
        auth_source,
        reassert_expires,
        now,
    )
    .await
    .unwrap();
    b64(&refresh_token)
}

#[tokio::test]
async fn oidc_session_refresh_requires_reassertion_past_deadline() {
    // An OIDC session rotates freely until its reassert deadline; past it, refresh is
    // rejected and the client must re-run the OIDC flow to mint a fresh window.
    let app = spawn().await;
    let deadline = app.now() + 100;
    let rt0 = seed_refreshable_session(&app, "oidc", Some(deadline)).await;

    // Before the deadline: rotates like any session (and preserves auth_source/reassert).
    let r0 = refresh(&app, &rt0).await;
    assert_eq!(
        r0.status(),
        200,
        "oidc session refreshes before its reassert deadline"
    );
    let rt1 = rt(&r0.json().await.unwrap());

    // Past the deadline: refresh is rejected.
    app.clock.advance(200);
    let r1 = refresh(&app, &rt1).await;
    assert_eq!(
        r1.status(),
        401,
        "oidc refresh past the reassert deadline must be rejected"
    );
}

#[tokio::test]
async fn keyset_session_refresh_ignores_reassertion() {
    // Control: a keyset session (auth_source != "oidc", reassert_expires NULL) is
    // untouched by the gate — the same clock advance that kills an OIDC session leaves
    // it refreshing normally.
    let app = spawn().await;
    let rt0 = seed_refreshable_session(&app, "keyset", None).await;

    app.clock.advance(200);
    let r = refresh(&app, &rt0).await;
    assert_eq!(
        r.status(),
        200,
        "keyset session refreshes regardless of any reassert window"
    );
}

/// POST /v1/devices/label as `access`.
async fn label_device(app: &common::TestApp, access: &str, body: Value) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/devices/label", app.base))
        .bearer_auth(access)
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// The caller's own devices with their labels, from GET /v1/devices.
async fn own_labels(app: &common::TestApp, access: &str) -> Vec<Value> {
    let v: Value = app
        .client
        .get(format!("{}/v1/devices", app.base))
        .bearer_auth(access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["label"].clone())
        .collect()
}

/// A device that joined without a label (invite, pairing) names itself; the
/// label is trimmed, and an empty one clears it.
#[tokio::test]
async fn a_device_labels_itself_and_can_clear_the_label() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let access = login_v2(
        &app,
        &id,
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    )
    .await;

    let r = label_device(&app, &access, json!({ "label": "  CLI · Linux " })).await;
    assert_eq!(r.status(), 204);
    assert_eq!(own_labels(&app, &access).await, [json!("CLI · Linux")]);

    let r = label_device(&app, &access, json!({ "label": "" })).await;
    assert_eq!(r.status(), 204);
    assert_eq!(own_labels(&app, &access).await, [Value::Null]);
}

/// The label is open metadata in every listing: bounded like the self-enroll one.
#[tokio::test]
async fn a_device_label_over_128_chars_is_refused() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let access = login_v2(
        &app,
        &id,
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    )
    .await;
    let r = label_device(&app, &access, json!({ "label": "x".repeat(129) })).await;
    assert_eq!(r.status(), 400);
    assert_eq!(
        own_labels(&app, &access).await,
        [Value::Null],
        "nothing was written"
    );
}

/// A label is what the owner goes by when revoking: characters that would hide
/// or reorder its text are refused, so one device cannot pass for another.
#[tokio::test]
async fn a_device_label_that_could_pass_for_another_is_refused() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let access = login_v2(
        &app,
        &id,
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    )
    .await;
    for label in ["Desktop \u{202E}soScam", "CLI\x1b[2J", "Lap\u{2066}top"] {
        let r = label_device(&app, &access, json!({ "label": label })).await;
        assert_eq!(r.status(), 400, "{label:?} is refused");
    }
    assert_eq!(own_labels(&app, &access).await, [Value::Null]);
}

// ---- devices nobody can sign in as: pairings that never ran, revoked, expired ----

/// POST /v1/devices/add as `access` (what "Add device" does first): the id.
async fn add_device(app: &common::TestApp, access: &str) -> String {
    let r = app
        .client
        .post(format!("{}/v1/devices/add", app.base))
        .bearer_auth(access)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "devices/add should succeed");
    let v: Value = r.json().await.unwrap();
    v["device_id"].as_str().unwrap().to_owned()
}

/// The ids in the caller's own Devices list (GET /v1/devices), sorted.
async fn own_devices(app: &common::TestApp, access: &str) -> Vec<String> {
    let v: Value = app
        .client
        .get(format!("{}/v1/devices", app.base))
        .bearer_auth(access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut ids: Vec<String> = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["device_id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

/// `(device_id, status)` of an account's devices in the owner's panel, sorted.
async fn panel_devices(
    app: &common::TestApp,
    access: &str,
    account: &str,
) -> Vec<(String, String)> {
    let v: Value = app
        .client
        .get(format!(
            "{}/v1/admin/devices?account_id={}",
            app.base,
            urlencode(account)
        ))
        .bearer_auth(access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut rows: Vec<(String, String)> = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["device_id"].as_str().unwrap().to_owned(),
                d["status"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    rows.sort();
    rows
}

/// One janitor run at the current test time.
async fn sweep(app: &common::TestApp) {
    let now = app.now();
    app.state
        .store
        .cleanup_expired(now, now - 86_400)
        .await
        .unwrap();
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// The account's device count as the owner sees it: in the accounts list and
/// on the overview (one account here, so both count the same devices).
async fn device_counts(app: &common::TestApp, access: &str) -> (i64, i64) {
    let get = |path: &str| {
        app.client
            .get(format!("{}{path}", app.base))
            .bearer_auth(access)
            .send()
    };
    let accounts: Value = get("/v1/accounts").await.unwrap().json().await.unwrap();
    let overview: Value = get("/v1/admin/overview")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        accounts["accounts"][0]["device_count"].as_i64().unwrap(),
        overview["devices"].as_i64().unwrap(),
    )
}

/// "Add device" creates the device before the pairing runs, so it is not one of
/// the account's devices until it signs in.
#[tokio::test]
async fn a_device_added_for_a_pairing_counts_once_it_signs_in() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let (acct, dev1) = (
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    );
    let access = login_v2(&app, &id, acct, dev1).await;

    let dev2 = add_device(&app, &access).await;
    assert_eq!(own_devices(&app, &access).await, [dev1]);
    assert_eq!(
        panel_devices(&app, &access, acct).await,
        [(dev1.to_owned(), "active".to_owned())]
    );
    assert_eq!(device_counts(&app, &access).await, (1, 1));

    login_v2(&app, &id, acct, &dev2).await;
    assert_eq!(
        own_devices(&app, &access).await,
        sorted(vec![dev1.to_owned(), dev2])
    );
    assert_eq!(device_counts(&app, &access).await, (2, 2));
}

/// Two first sign-ins of one pairing device at once both get in: the one that
/// finds the device already activated is not refused for it.
#[tokio::test]
async fn a_pairing_device_activated_alongside_still_signs_in() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let (acct, dev1) = (
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    );
    let access = login_v2(&app, &id, acct, dev1).await;
    let dev2 = unb64(&add_device(&app, &access).await).unwrap();
    let store = &app.state.store;
    let now = app.now();
    assert!(store.activate_pending_device(&dev2, now).await.unwrap());
    assert!(store.activate_pending_device(&dev2, now).await.unwrap());
}

/// Revoking a device that never signed in deletes it: it never was a device.
#[tokio::test]
async fn revoking_a_pairing_device_deletes_it() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let (acct, dev1) = (
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    );
    let access = login_v2(&app, &id, acct, dev1).await;
    let dev2 = add_device(&app, &access).await;
    let r = app
        .client
        .post(format!("{}/v1/session/device-revoke", app.base))
        .bearer_auth(&access)
        .json(&json!({ "device_id": dev2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(
        try_login_v2(&app, &id, acct, &dev2).await.status(),
        404,
        "the device is gone"
    );
    assert_eq!(
        panel_devices(&app, &access, acct).await,
        [(dev1.to_owned(), "active".to_owned())]
    );
}

/// A pairing that is cancelled or fails leaves nothing behind: its device cannot
/// sign in after a week, and the next janitor run deletes it.
#[tokio::test]
async fn a_pairing_that_never_signs_in_leaves_no_device() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let (acct, dev1) = (
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    );
    let access = login_v2(&app, &id, acct, dev1).await;
    let dev2 = add_device(&app, &access).await;

    app.clock.advance(7 * 86_400 + 1);
    assert_eq!(try_login_v2(&app, &id, acct, &dev2).await.status(), 401);
    sweep(&app).await;
    assert_eq!(
        try_login_v2(&app, &id, acct, &dev2).await.status(),
        404,
        "the device is gone"
    );
    login_v2(&app, &id, acct, dev1).await;
}

/// A revoked device leaves the account's own list at once. The owner's panel
/// shows it as revoked for the retention; then the janitor deletes it, with the
/// sessions still pointing at it.
#[tokio::test]
async fn a_revoked_device_is_dropped_after_the_retention() {
    // Sessions outlive the retention here, so deleting the device must take them.
    let app =
        spawn_with(|c| c.session.refresh_ttl_seconds = 3 * DEAD_DEVICE_RETENTION_SECONDS).await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let (acct, dev1) = (
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    );
    let access = login_v2(&app, &id, acct, dev1).await;
    let dev2 = add_device(&app, &access).await;
    login_v2(&app, &id, acct, &dev2).await;

    let r = app
        .client
        .post(format!("{}/v1/session/device-revoke", app.base))
        .bearer_auth(&access)
        .json(&json!({ "device_id": dev2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(own_devices(&app, &access).await, [dev1]);
    assert!(
        panel_devices(&app, &access, acct)
            .await
            .contains(&(dev2.clone(), "revoked".to_owned()))
    );

    app.clock.advance(DEAD_DEVICE_RETENTION_SECONDS - 60);
    sweep(&app).await;
    let access = login_v2(&app, &id, acct, dev1).await;
    assert_eq!(panel_devices(&app, &access, acct).await.len(), 2, "kept");

    app.clock.advance(120);
    sweep(&app).await;
    assert_eq!(
        panel_devices(&app, &access, acct).await,
        [(dev1.to_owned(), "active".to_owned())]
    );
}

/// A device past its expiry (a 30-day panel device) shows as expired to the
/// owner, not at all in the account's own list, and goes after the retention.
#[tokio::test]
async fn an_expired_device_shows_as_expired_then_goes() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let (acct, dev1) = (
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    );
    let access = login_v2(&app, &id, acct, dev1).await;
    let web = ids::random_id16().to_vec();
    let now = app.now();
    app.state
        .store
        .create_device(
            &unb64(acct).unwrap(),
            &web,
            &id.ed,
            &id.x,
            "web",
            Some("Admin panel · Firefox"),
            Some(now + 60),
            now,
        )
        .await
        .unwrap();
    let web = b64(&web);

    app.clock.advance(61);
    assert_eq!(own_devices(&app, &access).await, [dev1]);
    assert!(
        panel_devices(&app, &access, acct)
            .await
            .contains(&(web.clone(), "expired".to_owned()))
    );

    app.clock.advance(DEAD_DEVICE_RETENTION_SECONDS);
    sweep(&app).await;
    let access = login_v2(&app, &id, acct, dev1).await;
    assert_eq!(
        panel_devices(&app, &access, acct).await,
        [(dev1.to_owned(), "active".to_owned())]
    );
}

/// A device revoked before revocation recorded its time is dropped too: the
/// retention starts at the first janitor run that sees it.
#[tokio::test]
async fn a_device_revoked_before_the_upgrade_is_dropped_after_the_retention() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim(&app, &id).await;
    let (acct, dev1) = (
        c["account_id"].as_str().unwrap(),
        c["device_id"].as_str().unwrap(),
    );
    let access = login_v2(&app, &id, acct, dev1).await;
    let dev2 = add_device(&app, &access).await;
    login_v2(&app, &id, acct, &dev2).await;
    app.state
        .store
        .exec(
            "UPDATE devices SET status = 'revoked', expires_at = NULL WHERE device_id = ?",
            vec![Val::b(unb64(&dev2).unwrap())],
        )
        .await
        .unwrap();

    sweep(&app).await;
    app.clock.advance(DEAD_DEVICE_RETENTION_SECONDS - 60);
    sweep(&app).await;
    let access = login_v2(&app, &id, acct, dev1).await;
    assert_eq!(panel_devices(&app, &access, acct).await.len(), 2, "kept");

    app.clock.advance(120);
    sweep(&app).await;
    assert_eq!(
        panel_devices(&app, &access, acct).await,
        [(dev1.to_owned(), "active".to_owned())]
    );
}
