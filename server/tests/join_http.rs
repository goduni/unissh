//! v2 one-link invites + join (§ Task 8). An owner mints an invite carrying space
//! (and optional vault) intents; a DISTINCT joiner previews it (read-only — the
//! invite is NOT consumed) then redeems it over `/v1/join` (unauthenticated — the
//! registration signature IS the credential). The token is single-use (CAS), and a
//! second invite redeemed by the SAME keyset reuses the account (200, no new
//! account). A non-space-admin cannot mint an invite for that space (403).

mod common;

use common::{claim_owner, make_identity, spawn, spawn_with};
use serde_json::{Value, json};
use unissh_server::ids::b64;

#[tokio::test]
async fn join_new_then_existing_keyset_and_admin_gate() {
    let app = spawn().await;

    // --- Owner claims + logs in. ---
    let owner = make_identity();
    let claimed = claim_owner(&app, &owner.payload_b64, &owner.sig_b64).await;
    let owner_acct = claimed["account_id"].as_str().unwrap().to_string();
    let owner_dev = claimed["device_id"].as_str().unwrap().to_string();
    let owner_tok = common::login_v2(&app, &owner, &owner_acct, &owner_dev).await;

    // --- Owner creates space "Backend" (creator is auto-admin). ---
    let r = app
        .client
        .post(format!("{}/v1/spaces", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "name": "Backend" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let backend_id = r.json::<Value>().await.unwrap()["space_id"]
        .as_str()
        .unwrap()
        .to_string();

    // --- Owner mints an invite for Backend(member). ---
    let r = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "space_intents": [{ "space_id": backend_id, "role": "member" }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "owner mints invite for a space it admins");
    let inv: Value = r.json().await.unwrap();
    let token = inv["token"].as_str().unwrap().to_string();
    assert!(inv["invite_id"].is_string());
    // public_url empty by default → url is JSON null.
    assert!(inv["url"].is_null(), "url null when public_url unset");

    // --- A DISTINCT joiner previews (read-only, does NOT consume). ---
    let joiner = make_identity();
    let r = app
        .client
        .post(format!("{}/v1/join/preview", app.base))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "preview");
    let prev: Value = r.json().await.unwrap();
    let pspaces = prev["spaces"].as_array().unwrap();
    assert_eq!(pspaces.len(), 1);
    assert_eq!(pspaces[0]["name"], "Backend");
    assert_eq!(pspaces[0]["role"], "member");
    assert_eq!(pspaces[0]["space_id"], backend_id);

    // --- Joiner redeems the invite (+ some binding_mac bytes) → 201 (new account). ---
    let r = app
        .client
        .post(format!("{}/v1/join", app.base))
        .json(&json!({
            "invite_token": token,
            "registration_payload": joiner.payload_b64,
            "registration_signature": joiner.sig_b64,
            "binding_mac": b64(&[9u8, 8, 7, 6]),
            "handle": "joiner",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "join creates a new account");
    let jr: Value = r.json().await.unwrap();
    let joiner_acct = jr["account_id"].as_str().unwrap().to_string();
    let joiner_dev = jr["device_id"].as_str().unwrap().to_string();
    let jspaces = jr["spaces"].as_array().unwrap();
    assert_eq!(jspaces.len(), 1);
    assert_eq!(jspaces[0], backend_id);

    // --- Joiner authenticates; GET /v1/spaces shows Backend as member. ---
    let joiner_tok = common::login_v2(&app, &joiner, &joiner_acct, &joiner_dev).await;
    let spaces: Value = app
        .client
        .get(format!("{}/v1/spaces", app.base))
        .bearer_auth(&joiner_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let list = spaces["spaces"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], "Backend");
    assert_eq!(list[0]["role"], "member");

    // --- Single-use: a second join with the same token → gone (410). ---
    let r = app
        .client
        .post(format!("{}/v1/join", app.base))
        .json(&json!({
            "invite_token": token,
            "registration_payload": joiner.payload_b64,
            "registration_signature": joiner.sig_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 410, "single-use invite: second join is gone");

    // --- Existing-keyset reuse: owner mints a SECOND invite (another space);
    //     the SAME joiner keyset joins → 200, SAME account_id, membership added. ---
    let r = app
        .client
        .post(format!("{}/v1/spaces", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "name": "Frontend" }))
        .send()
        .await
        .unwrap();
    let frontend_id = r.json::<Value>().await.unwrap()["space_id"]
        .as_str()
        .unwrap()
        .to_string();

    let r = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "space_intents": [{ "space_id": frontend_id, "role": "member" }] }))
        .send()
        .await
        .unwrap();
    let token2 = r.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let r = app
        .client
        .post(format!("{}/v1/join", app.base))
        .json(&json!({
            "invite_token": token2,
            "registration_payload": joiner.payload_b64,
            "registration_signature": joiner.sig_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "existing keyset → reuse (no new account)");
    let jr2: Value = r.json().await.unwrap();
    assert_eq!(
        jr2["account_id"].as_str().unwrap(),
        joiner_acct,
        "same account reused"
    );
    assert!(
        jr2["device_id"].is_string(),
        "a fresh device is minted even on reuse"
    );
    assert_eq!(jr2["spaces"].as_array().unwrap(), &vec![json!(frontend_id)]);

    // Membership was added: the joiner now belongs to both spaces.
    let spaces: Value = app
        .client
        .get(format!("{}/v1/spaces", app.base))
        .bearer_auth(&joiner_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = spaces["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"Backend") && names.contains(&"Frontend"));

    // --- Admin gate: the joiner is a plain MEMBER of Backend, not its admin, so it
    //     cannot mint an invite for Backend (403). ---
    let r = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .bearer_auth(&joiner_tok)
        .json(&json!({ "space_intents": [{ "space_id": backend_id, "role": "member" }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "non-space-admin cannot mint an invite");
}

#[tokio::test]
async fn invite_url_rendered_when_public_url_set() {
    let app = spawn_with(|c| c.server.public_url = "https://ssh.example.com".into()).await;
    let owner = make_identity();
    let claimed = claim_owner(&app, &owner.payload_b64, &owner.sig_b64).await;
    let owner_tok = common::login_v2(
        &app,
        &owner,
        claimed["account_id"].as_str().unwrap(),
        claimed["device_id"].as_str().unwrap(),
    )
    .await;

    // The claim seeded a "Main" space with the owner as admin.
    let spaces: Value = app
        .client
        .get(format!("{}/v1/spaces", app.base))
        .bearer_auth(&owner_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let main_id = spaces["spaces"][0]["space_id"]
        .as_str()
        .unwrap()
        .to_string();

    let r = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({
            "space_intents": [{ "space_id": main_id, "role": "admin" }],
            "ttl_seconds": 3600,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let inv: Value = r.json().await.unwrap();
    let token = inv["token"].as_str().unwrap();
    assert_eq!(
        inv["url"].as_str().unwrap(),
        format!("https://ssh.example.com/join#{token}"),
        "url = public_url/join#token"
    );
    assert_eq!(inv["expires_at"].as_i64().unwrap(), app.now() + 3600);
}
