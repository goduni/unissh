//! `POST /v1/devices/self-enroll` (Phase: escrow fresh-device sign-in). A PUBLIC,
//! no-session endpoint that registers a NEW device for an EXISTING account,
//! authenticated ONLY by a keyset-signed registration (same self-attestation as
//! claim/join/oidc). This unblocks "log in on a fresh device via escrow": escrow
//! unlocks the keyset, but a device with no session cannot use the Bearer-gated
//! `/v1/devices/add`. Instance-scoped (v2), REAL core crypto.

mod common;

use common::{TestApp, claim_owner, login_tokens_v2, login_v2, make_identity, spawn};
use serde_json::{Value, json};
use unissh_crypto::{
    RegistrationPayload as CoreReg, ServerAuthChallenge as CoreChal, X25519Keypair,
    sign_registration, sign_server_auth,
};
use unissh_server::crypto::RegistrationPayload as SrvReg;
use unissh_server::ids;
use unissh_server::store::Val;

/// POST /v1/devices/self-enroll with a raw payload/signature pair.
async fn self_enroll(app: &TestApp, payload_b64: &str, sig_b64: &str) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/devices/self-enroll", app.base))
        .json(&json!({
            "registration_payload": payload_b64,
            "registration_signature": sig_b64,
        }))
        .send()
        .await
        .unwrap()
}

/// Count the devices bound to an account (base64 id).
async fn device_count(app: &TestApp, account_id_b64: &str) -> i64 {
    let acct = ids::unb64(account_id_b64).unwrap();
    app.state
        .store
        .fetch_scalar_i64(
            "SELECT COUNT(*) FROM devices WHERE account_id = ?",
            vec![Val::b(&acct[..])],
        )
        .await
        .unwrap()
        .unwrap_or(0)
}

/// Happy path: the SAME account's keyset self-enrolls a second device, which then
/// completes the full challenge/verify login and leaves the account with 2 devices.
#[tokio::test]
async fn self_enroll_happy_path_new_device_can_login() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();
    let claim_device = c["device_id"].as_str().unwrap().to_string();

    assert_eq!(
        device_count(&app, &account_id).await,
        1,
        "claim seeds 1 device"
    );

    // Self-enroll a fresh device with the SAME keyset (no session/bearer).
    let r = self_enroll(&app, &id.payload_b64, &id.sig_b64).await;
    assert_eq!(r.status(), 201, "self-enroll should be 201 CREATED");
    let body: Value = r.json().await.unwrap();
    assert_eq!(
        body["account_id"], account_id,
        "resolved account must match the claim account"
    );
    let new_device = body["device_id"].as_str().unwrap().to_string();
    assert_ne!(new_device, claim_device, "a DISTINCT device id");

    assert_eq!(
        device_count(&app, &account_id).await,
        2,
        "account now has 2 devices under one identity"
    );

    // The NEW device authenticates with the SAME keyset (challenge → verify → token).
    let access = login_v2(&app, &id, &account_id, &new_device).await;
    let v = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("Authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        v.status(),
        200,
        "self-enrolled device can act with its token"
    );
}

/// A `kind = "web"` (browser panel) self-enroll creates a device recorded as
/// kind='web' AND carrying a non-null `expires_at`, so browser devices auto-expire
/// (the Bearer path enforces `device.expires_at`). App devices, by contrast, never
/// expire (see the happy-path test, which self-enrolls with the default kind).
#[tokio::test]
async fn self_enroll_web_device_is_kind_web_and_expires() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();

    let r = app
        .client
        .post(format!("{}/v1/devices/self-enroll", app.base))
        .json(&json!({
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
            "kind": "web",
            "label": "Admin panel",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "web self-enroll should be 201 CREATED");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["account_id"], account_id);
    let device_id = ids::unb64(body["device_id"].as_str().unwrap()).unwrap();

    // The created device is recorded as kind='web' with a non-null expires_at.
    let matched = app
        .state
        .store
        .fetch_scalar_i64(
            "SELECT COUNT(*) FROM devices \
             WHERE device_id = ? AND kind = 'web' AND expires_at IS NOT NULL",
            vec![Val::b(&device_id[..])],
        )
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(
        matched, 1,
        "web self-enroll creates a kind='web' device with a non-null expires_at"
    );
}

/// An unrecognized `kind` is rejected up front with 400 and adds no device.
#[tokio::test]
async fn self_enroll_bad_kind_400() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();

    let r = app
        .client
        .post(format!("{}/v1/devices/self-enroll", app.base))
        .json(&json!({
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
            "kind": "toaster",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400, "unrecognized kind → malformed");
    assert_eq!(
        device_count(&app, &account_id).await,
        1,
        "no device added for a rejected kind"
    );
}

/// A keyset that was never claimed/joined → 404 (no such account). The valid signature
/// proves the caller already holds this keyset, so 404 leaks nothing.
#[tokio::test]
async fn self_enroll_unknown_keyset_404() {
    let app = spawn().await;
    // Claim as a DIFFERENT identity so the instance is live but this keyset is unknown.
    let owner = make_identity();
    claim_owner(&app, &owner.payload_b64, &owner.sig_b64).await;

    let stranger = make_identity();
    let r = self_enroll(&app, &stranger.payload_b64, &stranger.sig_b64).await;
    assert_eq!(r.status(), 404, "unknown keyset → not found");
}

/// A valid payload with a signature from a DIFFERENT key → rejected before any account
/// lookup (401 unauthenticated).
#[tokio::test]
async fn self_enroll_bad_signature_rejected() {
    let app = spawn().await;
    let id = make_identity();
    claim_owner(&app, &id.payload_b64, &id.sig_b64).await;

    // id's payload, but a signature produced by another key over another payload.
    let other = make_identity();
    let r = self_enroll(&app, &id.payload_b64, &other.sig_b64).await;
    assert_eq!(
        r.status(),
        401,
        "signature not by the payload's keyset → unauthenticated"
    );
}

/// A payload whose ed25519 matches the account but whose x25519 differs (self-signed
/// with the account's ed key) → 400: the canonical keyset is one identity.
#[tokio::test]
async fn self_enroll_x_key_mismatch_400() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();

    // A fresh, unrelated x25519 key; ed stays id's, signed by id's ed key → the sig is
    // valid over THIS (rebound) payload, but x no longer matches the account's binding.
    let other_x = X25519Keypair::generate().public.to_bytes();
    let acct_field = vec![0u8; 16];
    let core = CoreReg {
        account_id: acct_field.clone(),
        x25519_pub: other_x,
        ed25519_pub: id.ed,
    };
    let sig = sign_registration(&id.kp.signing, &core).unwrap();
    let srv = SrvReg {
        account_id: acct_field,
        x25519_pub: other_x,
        ed25519_pub: id.ed,
    };
    let payload_b64 = ids::b64(&srv.canonical().unwrap());
    let sig_b64 = ids::b64(&sig);

    let r = self_enroll(&app, &payload_b64, &sig_b64).await;
    assert_eq!(r.status(), 400, "x25519 key mismatch → malformed");

    // No device was added on the rejected path.
    assert_eq!(device_count(&app, &account_id).await, 1);
}

/// A suspended account cannot silently gain a fresh device → 403.
#[tokio::test]
async fn self_enroll_suspended_account_403() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();

    // Suspend the account directly in the store (harness stand-in for the admin path).
    let acct = ids::unb64(&account_id).unwrap();
    app.state
        .store
        .set_account_status(&acct, "suspended")
        .await
        .unwrap();

    let r = self_enroll(&app, &id.payload_b64, &id.sig_b64).await;
    assert_eq!(r.status(), 403, "suspended account → forbidden");
    assert_eq!(
        device_count(&app, &account_id).await,
        1,
        "no device added for a suspended account"
    );
}

/// A `label` past the 128-char cap → 400, no device added (bounds the open metadata so a
/// keyset holder can't bloat the devices table / listings).
#[tokio::test]
async fn self_enroll_label_too_long_400() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();

    let r = app
        .client
        .post(format!("{}/v1/devices/self-enroll", app.base))
        .json(&json!({
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
            "label": "x".repeat(129),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400, "over-long label → malformed");
    assert_eq!(
        device_count(&app, &account_id).await,
        1,
        "no device added for a rejected label"
    );
}

/// Force a device past its `expires_at`: `auth/verify` must fail fast (401) rather than
/// mint a session that every Bearer call would then reject — the fix that lets the panel
/// drop a stale link and self-enroll a fresh device instead of looping.
#[tokio::test]
async fn expired_device_cannot_log_in() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();
    let device_b64 = c["device_id"].as_str().unwrap().to_string();

    let device_id = ids::unb64(&device_b64).unwrap();
    app.state
        .store
        .exec(
            "UPDATE devices SET expires_at = ? WHERE device_id = ?",
            vec![Val::I(1), Val::b(&device_id[..])],
        )
        .await
        .unwrap();

    // challenge issues a nonce (no expiry gate); verify is where the expired device dies.
    let chal: Value = app
        .client
        .post(format!("{}/v1/auth/challenge", app.base))
        .json(&json!({
            "account_id": account_id, "device_id": device_b64, "key_id": ids::b64(b"k1")
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let g = |k: &str| ids::unb64(chal[k].as_str().unwrap()).unwrap();
    let core_chal = CoreChal {
        host: g("host"),
        account_id: g("account_id"),
        device_id: g("device_id"),
        key_id: g("key_id"),
        nonce: g("nonce"),
        expiry: chal["expiry"].as_u64().unwrap(),
    };
    let sig = sign_server_auth(&id.kp.signing, &core_chal).unwrap();
    let resp = app
        .client
        .post(format!("{}/v1/auth/verify", app.base))
        .json(&json!({ "challenge": chal, "signature": ids::b64(&sig) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "expired device must not mint a session");
}

/// An expired device can't keep rotating tokens either: after `expires_at` passes, a
/// `session/refresh` with a previously-valid refresh token is refused (401).
#[tokio::test]
async fn expired_device_cannot_refresh() {
    let app = spawn().await;
    let id = make_identity();
    let c = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();
    let device_b64 = c["device_id"].as_str().unwrap().to_string();

    // A valid session first (device not yet expired), then expire the device.
    let tokens = login_tokens_v2(&app, &id, &account_id, &device_b64).await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    let device_id = ids::unb64(&device_b64).unwrap();
    app.state
        .store
        .exec(
            "UPDATE devices SET expires_at = ? WHERE device_id = ?",
            vec![Val::I(1), Val::b(&device_id[..])],
        )
        .await
        .unwrap();

    let resp = app
        .client
        .post(format!("{}/v1/session/refresh", app.base))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "expired device cannot rotate tokens");
}
