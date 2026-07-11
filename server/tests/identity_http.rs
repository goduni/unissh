//! Identity/auth/onboarding §5.3/§6 via a live server with REAL core crypto
//! (registration + server-auth signatures). Covers bootstrap→challenge→verify→
//! authenticated push, single-use nonce, invite single-use, keyset no-downgrade,
//! PAKE relay verbatim.

mod common;

use common::spawn_with;
use serde_json::{Value, json};
use unissh_crypto::{
    Ed25519Keypair, RegistrationPayload as CoreReg, ServerAuthChallenge as CoreChal, X25519Keypair,
    sign_registration, sign_server_auth,
};
use unissh_server::crypto::RegistrationPayload as SrvReg;
use unissh_server::ids::{b64, unb64};

const TID: &[u8] = b"tenant-ident-001";

struct Identity {
    kp: Ed25519Keypair,
    payload_b64: String,
    sig_b64: String,
}

fn make_identity() -> Identity {
    let kp = Ed25519Keypair::generate();
    let xk = X25519Keypair::generate();
    let ed = kp.verifying.to_bytes();
    let x = xk.public.to_bytes();
    let candidate = vec![0u8; 16];
    let core = CoreReg {
        account_id: candidate.clone(),
        x25519_pub: x,
        ed25519_pub: ed,
    };
    let sig = sign_registration(&kp.signing, &core).unwrap();
    let srv = SrvReg {
        account_id: candidate,
        x25519_pub: x,
        ed25519_pub: ed,
    };
    Identity {
        kp,
        payload_b64: b64(&srv.canonical().unwrap()),
        sig_b64: b64(&sig),
    }
}

async fn bootstrap(app: &common::TestApp, id: &Identity) -> Value {
    app.client
        .post(format!("{}/v1/bootstrap", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
            "tier": "org",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Full auth flow: challenge → signature → verify → access token.
async fn login(app: &common::TestApp, id: &Identity, account_id: &str, device_id: &str) -> String {
    auth_tokens(app, id, account_id, device_id).await["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Like [`login`], but returns the WHOLE token set (access + refresh + session_id) —
/// for refresh-rotation/reuse-detection tests.
async fn auth_tokens(
    app: &common::TestApp,
    id: &Identity,
    account_id: &str,
    device_id: &str,
) -> Value {
    let chal: Value = app
        .client
        .post(format!("{}/v1/auth/challenge", app.base))
        .header("UniSSH-Tenant", b64(TID))
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
    let sig = sign_server_auth(&id.kp.signing, &core_chal).unwrap();

    let resp = app
        .client
        .post(format!("{}/v1/auth/verify", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({ "challenge": chal, "signature": b64(&sig) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "auth/verify should succeed");
    resp.json().await.unwrap()
}

/// POST /v1/session/refresh with the given refresh token.
async fn refresh(app: &common::TestApp, refresh_token: &str) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/session/refresh", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn bootstrap_login_and_authenticated_push() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let id = make_identity();
    let b = bootstrap(&app, &id).await;
    assert_eq!(b["role"], "admin");
    let account_id = b["account_id"].as_str().unwrap().to_string();
    let device_id = b["device_id"].as_str().unwrap().to_string();

    let access = login(&app, &id, &account_id, &device_id).await;

    // authenticated /v1/sync/version works with the minted token
    let v: Value = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("UniSSH-Tenant", b64(TID))
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
async fn second_bootstrap_conflicts() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let id1 = make_identity();
    let r1 = bootstrap(&app, &id1).await;
    assert_eq!(r1["role"], "admin");
    // second bootstrap on the same tenant → 409
    let id2 = make_identity();
    let resp = app
        .client
        .post(format!("{}/v1/bootstrap", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({
            "registration_payload": id2.payload_b64,
            "registration_signature": id2.sig_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn nonce_is_single_use() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let id = make_identity();
    let b = bootstrap(&app, &id).await;
    let account_id = b["account_id"].as_str().unwrap().to_string();
    let device_id = b["device_id"].as_str().unwrap().to_string();

    // get a challenge, sign it, verify twice
    let chal: Value = app
        .client
        .post(format!("{}/v1/auth/challenge", app.base))
        .header("UniSSH-Tenant", b64(TID))
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
            .header("UniSSH-Tenant", b64(TID))
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
async fn invite_issue_and_single_use_register() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let admin = make_identity();
    let b = bootstrap(&app, &admin).await;
    let access = login(
        &app,
        &admin,
        b["account_id"].as_str().unwrap(),
        b["device_id"].as_str().unwrap(),
    )
    .await;

    // admin issues an editor invite
    let inv: Value = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {access}"))
        .json(&json!({ "role": "editor" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = inv["token"].as_str().unwrap().to_string();

    // preview does not consume
    let prev = app
        .client
        .post(format!("{}/v1/invite/redeem", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({ "invite_token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(prev.status(), 200);

    // register a new member with the token
    let member = make_identity();
    let reg = |id: &Identity, tok: &str| {
        app.client
            .post(format!("{}/v1/register", app.base))
            .header("UniSSH-Tenant", b64(TID))
            .json(&json!({
                "invite_token": tok,
                "registration_payload": id.payload_b64,
                "registration_signature": id.sig_b64,
            }))
            .send()
    };
    let r1 = reg(&member, &token).await.unwrap();
    assert_eq!(r1.status(), 201);
    let body: Value = r1.json().await.unwrap();
    assert_eq!(body["role"], "editor");

    // second use of the same token → gone (single-use)
    let member2 = make_identity();
    let r2 = reg(&member2, &token).await.unwrap();
    assert_eq!(r2.status(), 410, "invite is single-use");
}

#[tokio::test]
async fn reattach_adds_device_without_invite() {
    // A returning member whose device link was removed re-runs "join" with the
    // SAME keyset. The server must re-attach (add a device to the existing account)
    // WITHOUT an invite — never mint a second account — and the new device must be
    // able to authenticate. A stranger keyset with no invite is still refused.
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let id = make_identity();
    let b = bootstrap(&app, &id).await;
    let account_id = b["account_id"].as_str().unwrap().to_string();
    let first_device = b["device_id"].as_str().unwrap().to_string();

    let register = |id: &Identity, tok: &str| {
        app.client
            .post(format!("{}/v1/register", app.base))
            .header("UniSSH-Tenant", b64(TID))
            .json(&json!({
                "invite_token": tok,
                "registration_payload": id.payload_b64,
                "registration_signature": id.sig_b64,
            }))
            .send()
    };

    // same keyset + EMPTY invite → re-attach (200), same account, fresh device.
    let resp = register(&id, "").await.unwrap();
    assert_eq!(resp.status(), 200, "re-attach without invite");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["account_id"], account_id,
        "same account, not a new one"
    );
    let new_device = body["device_id"].as_str().unwrap().to_string();
    assert_ne!(new_device, first_device, "a fresh device id");
    assert_eq!(body["role"], "admin", "keeps instance-admin");
    assert_eq!(
        body["owned"], true,
        "bootstrapper owns the space → owned restored"
    );

    // the re-attached device can actually authenticate (challenge/verify).
    let _access = login(&app, &id, &account_id, &new_device).await;

    // an UNKNOWN keyset with an empty invite is refused — joining needs an invite.
    let stranger = make_identity();
    let refused = register(&stranger, "").await.unwrap();
    assert_eq!(refused.status(), 404, "new member needs an invite");
}

#[tokio::test]
async fn keyset_no_downgrade() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let id = make_identity();
    let b = bootstrap(&app, &id).await;
    let access = login(
        &app,
        &id,
        b["account_id"].as_str().unwrap(),
        b["device_id"].as_str().unwrap(),
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
            .header("UniSSH-Tenant", b64(TID))
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
        .header("UniSSH-Tenant", b64(TID))
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
async fn pake_relay_verbatim() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let id = make_identity();
    let b = bootstrap(&app, &id).await;
    let access = login(
        &app,
        &id,
        b["account_id"].as_str().unwrap(),
        b["device_id"].as_str().unwrap(),
    )
    .await;

    let open: Value = app
        .client
        .post(format!("{}/v1/relay/open", app.base))
        .header("UniSSH-Tenant", b64(TID))
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
        .header("UniSSH-Tenant", b64(TID))
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
        .header("UniSSH-Tenant", b64(TID))
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
        .header("UniSSH-Tenant", b64(TID))
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

/// Bootstrap + authenticate, returning the freshly minted token set.
async fn boot_and_tokens(app: &common::TestApp) -> Value {
    let id = make_identity();
    let b = bootstrap(app, &id).await;
    auth_tokens(
        app,
        &id,
        b["account_id"].as_str().unwrap(),
        b["device_id"].as_str().unwrap(),
    )
    .await
}

fn rt(tokens: &Value) -> String {
    tokens["refresh_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn refresh_rotates_tokens_and_new_access_works() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let t0 = boot_and_tokens(&app).await;

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
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {access1}"))
        .send()
        .await
        .unwrap();
    assert_eq!(v.status(), 200, "rotated access token must work");
}

#[tokio::test]
async fn refresh_reuse_of_rotated_token_revokes_session() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let t0 = boot_and_tokens(&app).await;

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
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let t0 = boot_and_tokens(&app).await;

    let t1: Value = refresh(&app, &rt(&t0)).await.json().await.unwrap();
    let t2: Value = refresh(&app, &rt(&t1)).await.json().await.unwrap();

    // rt0 is now TWO generations behind current (rt2) — the old single-step `prev`
    // scheme would have missed it. It must still be caught as reuse.
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
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let _ = boot_and_tokens(&app).await;

    // Wrong length (not session_id(16)||secret(32)) → 401, no panic.
    assert_eq!(refresh(&app, &b64(b"too-short")).await.status(), 401);
    // Well-formed length but unknown session id → 401.
    assert_eq!(refresh(&app, &b64(&[7u8; 48])).await.status(), 401);
}
