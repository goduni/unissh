//! `POST /v1/devices/self-enroll` (Phase: escrow fresh-device sign-in). A PUBLIC,
//! no-session endpoint that registers a NEW device for an EXISTING account,
//! authenticated ONLY by a keyset-signed registration (same self-attestation as
//! claim/join/oidc). This unblocks "log in on a fresh device via escrow": escrow
//! unlocks the keyset, but a device with no session cannot use the Bearer-gated
//! `/v1/devices/add`. Instance-scoped (v2), REAL core crypto.

mod common;

use common::{TestApp, claim_owner, login_v2, make_identity, spawn};
use serde_json::{Value, json};
use unissh_crypto::{RegistrationPayload as CoreReg, X25519Keypair, sign_registration};
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
