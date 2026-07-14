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

/// Whole-branch review FIX: `vault_intents` must be admin-authorized just like
/// `space_intents`. Otherwise a space-admin could mint an invite pre-authorizing a
/// `grant` to a vault they have NO authority over — the row would land in the real
/// vault-admin's `/v1/pending` queue (confused-deputy). The caller here (owner) ALWAYS
/// passes the space-intent gate for "Backend", so every 403 below is unambiguously the
/// vault-intent gate firing.
#[tokio::test]
async fn invite_vault_intent_admin_gate() {
    let app = spawn().await;

    // Owner claims + logs in, creates "Backend" (creator is auto-admin).
    let owner = make_identity();
    let claimed = claim_owner(&app, &owner.payload_b64, &owner.sig_b64).await;
    let owner_acct = claimed["account_id"].as_str().unwrap().to_string();
    let owner_dev = claimed["device_id"].as_str().unwrap().to_string();
    let owner_tok = common::login_v2(&app, &owner, &owner_acct, &owner_dev).await;

    let backend_id = app
        .client
        .post(format!("{}/v1/spaces", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "name": "Backend" }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["space_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Owner claims a SPACE vault in Backend → owner admins it (admin of its space).
    let vault_ok = b64(&[1u8; 16]);
    let r = app
        .client
        .post(format!("{}/v1/vaults/claim", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({
            "vault_id": vault_ok,
            "space_id": backend_id,
            "access_policy": "space_wide",
            "space_wide_role": 1,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "owner claims a Backend space vault");

    // POSITIVE: a vault_intent for a vault the caller DOES admin → 201.
    let r = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({
            "space_intents": [{ "space_id": backend_id, "role": "member" }],
            "vault_intents": [{ "vault_id": vault_ok, "role": 1 }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        201,
        "vault_intent for an admined vault is accepted"
    );

    // A DISTINCT (seeded) account owns a PERSONAL vault — the owner has no authority
    // over it. (seed_session is the store seam the other spaces tests use for a second
    // principal; a personal claim needs only an authenticated session.)
    let other = app.seed_session("").await;
    let personal = b64(&[2u8; 16]);
    let r = app
        .client
        .post(format!("{}/v1/vaults/claim", app.base))
        .bearer_auth(&other.access_token_b64)
        .json(&json!({ "vault_id": personal }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "other account claims its own personal vault"
    );

    // NEGATIVE: owner (space gate passes for Backend) references another account's
    // personal vault in a vault_intent → 403 from the vault gate.
    let r = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({
            "space_intents": [{ "space_id": backend_id, "role": "member" }],
            "vault_intents": [{ "vault_id": personal, "role": 2 }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        403,
        "cannot grant a personal vault owned by another account"
    );

    // NEGATIVE: a vault_intent for a NONEXISTENT vault is rejected too (403).
    let r = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({
            "space_intents": [{ "space_id": backend_id, "role": "member" }],
            "vault_intents": [{ "vault_id": b64(&[9u8; 16]), "role": 0 }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "cannot grant a nonexistent vault");
}

/// FIX (invite revoke): a still-pending invite can be cancelled so its (possibly leaked)
/// token can no longer be redeemed. Unknown id → 404; a caller who could not have minted
/// it → 403; revoke then redeem → 410; a second revoke → 409.
#[tokio::test]
async fn invite_revoke_blocks_redeem() {
    let app = spawn().await;
    let owner = make_identity();
    let claimed = claim_owner(&app, &owner.payload_b64, &owner.sig_b64).await;
    let owner_acct = claimed["account_id"].as_str().unwrap().to_string();
    let owner_dev = claimed["device_id"].as_str().unwrap().to_string();
    let owner_tok = common::login_v2(&app, &owner, &owner_acct, &owner_dev).await;

    // Owner creates "Backend" and mints an invite for it.
    let backend_id = app
        .client
        .post(format!("{}/v1/spaces", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "name": "Backend" }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["space_id"]
        .as_str()
        .unwrap()
        .to_string();
    let inv: Value = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "space_intents": [{ "space_id": backend_id, "role": "member" }] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let invite_id = inv["invite_id"].as_str().unwrap().to_string();
    let token = inv["token"].as_str().unwrap().to_string();

    let revoke = |bearer: &str, id: String| {
        app.client
            .post(format!("{}/v1/invite/revoke", app.base))
            .bearer_auth(bearer)
            .json(&json!({ "invite_id": id }))
            .send()
    };

    // Unknown invite id → 404 (even for the owner).
    assert_eq!(
        revoke(&owner_tok, b64(&[9u8; 16])).await.unwrap().status(),
        404,
        "unknown invite id → 404"
    );

    // A caller who is not admin of the invite's space (and not the instance owner) → 403.
    let outsider = app.seed_session("").await;
    assert_eq!(
        revoke(&outsider.access_token_b64, invite_id.clone())
            .await
            .unwrap()
            .status(),
        403,
        "non-admin cannot revoke"
    );

    // Owner revokes → 204.
    assert_eq!(
        revoke(&owner_tok, invite_id.clone())
            .await
            .unwrap()
            .status(),
        204,
        "owner revokes the invite"
    );

    // Redeeming the now-revoked token fails cleanly (gone).
    let joiner = make_identity();
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
    assert_eq!(r.status(), 410, "a revoked invite cannot be redeemed");

    // A second revoke → 409 (no longer pending).
    assert_eq!(
        revoke(&owner_tok, invite_id.clone())
            .await
            .unwrap()
            .status(),
        409,
        "already-revoked invite → 409"
    );
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
