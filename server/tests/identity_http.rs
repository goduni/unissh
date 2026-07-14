//! Identity/auth §5.3/§6 via a live server with REAL core crypto (registration +
//! server-auth signatures). Covers claim→challenge→verify→authenticated push,
//! single-use nonce, keyset no-downgrade, PAKE relay verbatim, refresh rotation +
//! reuse detection. Instance-scoped (v2).

mod common;

use common::{Identity, claim_owner, login_tokens_v2, login_v2, make_identity, spawn};
use serde_json::{Value, json};
use unissh_crypto::{ServerAuthChallenge as CoreChal, sign_server_auth};
use unissh_server::ids::{self, b64, unb64};

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
    let account_id = c["account_id"].as_str().unwrap().to_string();
    let device_id = c["device_id"].as_str().unwrap().to_string();

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
    let account_id = c["account_id"].as_str().unwrap().to_string();
    let device_id = c["device_id"].as_str().unwrap().to_string();

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
    gen2[2..6].copy_from_slice(&2u32.to_be_bytes());

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
    gen2[2..6].copy_from_slice(&2u32.to_be_bytes());

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
    let k_auth_raw = vec![9u8; 40];
    let salt = vec![3u8; 16];
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
        Some(&k_auth_raw[..]),
        "the raw K_auth is never persisted"
    );
    assert_eq!(
        row.argon_salt.as_deref(),
        Some(&salt[..]),
        "salt round-trips"
    );
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
            "k_auth": b64(&vec![9u8; 40]),
            "argon_salt": b64(&vec![3u8; 16]),
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
            "k_auth": b64(&vec![9u8; 40]),
            "argon_salt": b64(&vec![3u8; 24]),
            "argon_mem_kib": 65536,
            "argon_iterations": 3,
            "argon_parallelism": 1,
        }
    }))
    .await
    .unwrap();
    assert_eq!(bad_salt.status(), 400, "a non-16-byte escrow salt is rejected");
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
    let channel = open["channel_id"].as_str().unwrap().to_string();

    let msg1 = b64(&[1u8, 2, 3, 4, 5]);
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
    tokens["refresh_token"].as_str().unwrap().to_string()
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
    let _ = claim_and_tokens(&app).await;

    // Wrong length (not session_id(16)||secret(32)) → 401, no panic.
    assert_eq!(refresh(&app, &b64(b"too-short")).await.status(), 401);
    // Well-formed length but unknown session id → 401.
    assert_eq!(refresh(&app, &b64(&[7u8; 48])).await.status(), 401);
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
    s.create_device(&account_id, &device_id, &ed, &x, now)
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
