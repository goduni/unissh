//! Task 9: the vault-admin crypto to-do queue (`GET /v1/pending`) end to end, plus
//! the server marking rows done ITSELF by observing published manifests/grants
//! (auto-done) and enqueuing `revoke` on directory changes (member-remove).
//!
//! This closes a Task-8 coverage gap: a joiner joining a `space_wide` cloud vault's
//! space must surface a `grant` action to that vault's admin — carrying the joiner's
//! member_pubkey + x25519_pub so the admin can wrap the VK and verify binding.

mod common;

use common::{
    claim_owner, grant_signed, make_identity, manifest_blob, manifest_signed, spawn, vault_object,
};
use serde_json::{Value, json};
use unissh_server::ids::b64;

/// A cloud vault_id (16 bytes) claimed by the owner as `space_wide`.
const VAULT: &[u8] = b"vault-pending-01";

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

async fn get_pending(app: &common::TestApp, tok: &str) -> Value {
    app.client
        .get(format!("{}/v1/pending", app.base))
        .bearer_auth(tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Publish `manifest + grants` at `new_epoch` (optionally revoking `revoke_epoch`).
async fn publish(
    app: &common::TestApp,
    tok: &str,
    id: &common::Identity,
    epoch: u64,
    members: &[(Vec<u8>, u8)],
    revoke_epoch: Option<i64>,
) {
    // Bump the vault's latest_epoch to `epoch` by pushing a Cloud Vault object — the
    // pending admin-visibility query joins on `vaults.latest_epoch`, which a manifest
    // publish alone does not move.
    let pr = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .bearer_auth(tok)
        .json(&json!({ "objects": [b64(&vault_object(&id.ed, VAULT, epoch, epoch))] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        pr.status(),
        200,
        "owner pushes the vault object @epoch {epoch}"
    );

    let blob = manifest_blob(epoch, members);
    let grants: Vec<String> = members
        .iter()
        .map(|(ed, role)| b64(&grant_signed(&id.kp, VAULT, ed, epoch, *role)))
        .collect();
    let mut body = json!({
        "manifest": b64(&manifest_signed(&id.kp, VAULT, epoch, &blob)),
        "grants": grants,
        "new_epoch": epoch,
    });
    if let Some(re) = revoke_epoch {
        body["revoke_epoch"] = json!(re);
    }
    let r = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .bearer_auth(tok)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "grants/publish @epoch {epoch}");
}

#[tokio::test]
async fn pending_grant_surfaces_on_join_and_auto_done_on_publish_and_revoke_on_remove() {
    let app = spawn().await;

    // --- Owner claims + logs in. ---
    let owner = make_identity();
    let claimed = claim_owner(&app, &owner.payload_b64, &owner.sig_b64).await;
    let owner_acct = claimed["account_id"].as_str().unwrap().to_string();
    let owner_dev = claimed["device_id"].as_str().unwrap().to_string();
    let owner_tok = common::login_v2(&app, &owner, &owner_acct, &owner_dev).await;

    // --- Owner creates space "Backend" (creator is auto-admin). ---
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

    // --- Owner claims a CLOUD vault in Backend as space_wide (crypto role editor=1). ---
    let claim = app
        .client
        .post(format!("{}/v1/vaults/claim", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({
            "vault_id": b64(VAULT),
            "space_id": backend_id,
            "access_policy": "space_wide",
            "space_wide_role": 1,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(claim.status(), 200);
    assert!(
        claim.json::<Value>().await.unwrap()["claimed"]
            .as_bool()
            .unwrap()
    );

    // --- Owner publishes manifest@1 making themselves the vault Admin (role 2). ---
    publish(&app, &owner_tok, &owner, 1, &[(owner.ed.to_vec(), 2)], None).await;

    // Nothing queued yet.
    assert!(
        get_pending(&app, &owner_tok).await["actions"]
            .as_array()
            .unwrap()
            .is_empty(),
        "no pending actions before anyone joins"
    );

    // --- Owner mints an invite for Backend(member). ---
    let token = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "space_intents": [{ "space_id": backend_id, "role": "member" }] }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    // --- A DISTINCT joiner redeems the invite → joins Backend. ---
    let joiner = make_identity();
    let jr = app
        .client
        .post(format!("{}/v1/join", app.base))
        .json(&json!({
            "invite_token": token,
            "registration_payload": joiner.payload_b64,
            "registration_signature": joiner.sig_b64,
            "handle": "joiner",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(jr.status(), 201);
    let joiner_acct = jr.json::<Value>().await.unwrap()["account_id"]
        .as_str()
        .unwrap()
        .to_string();

    // === Task-8 GAP: the join must surface a `grant` action to the vault admin. ===
    let pend = get_pending(&app, &owner_tok).await;
    let acts = pend["actions"].as_array().unwrap();
    assert_eq!(
        acts.len(),
        1,
        "owner sees the joiner's space-wide grant to fulfil"
    );
    let a = &acts[0];
    assert_eq!(a["kind"], "grant");
    assert_eq!(a["source"], "policy", "space_wide vault → policy grant");
    assert_eq!(a["vault_id"], b64(VAULT));
    assert_eq!(a["account_id"], joiner_acct);
    assert_eq!(a["crypto_role"], 1, "carries the space_wide role (editor)");
    assert_eq!(
        a["member_pubkey"],
        b64(&joiner.ed),
        "carries the joiner's ed25519 (binding verify)"
    );
    assert_eq!(
        a["x25519_pub"],
        b64(&joiner.x),
        "carries the joiner's x25519 (VK wrap)"
    );

    // --- Owner publishes epoch 2 INCLUDING the joiner → the server auto-marks done. ---
    publish(
        &app,
        &owner_tok,
        &owner,
        2,
        &[(owner.ed.to_vec(), 2), (joiner.ed.to_vec(), 1)],
        None,
    )
    .await;
    assert!(
        get_pending(&app, &owner_tok).await["actions"]
            .as_array()
            .unwrap()
            .is_empty(),
        "grant auto-done once the joiner appears in the published grant set"
    );

    // --- Owner removes the joiner from Backend → a `revoke` action is enqueued. ---
    let rm = app
        .client
        .post(format!("{}/v1/spaces/members/remove", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "space_id": backend_id, "account_id": joiner_acct }))
        .send()
        .await
        .unwrap();
    assert_eq!(rm.status(), 204);

    let pend = get_pending(&app, &owner_tok).await;
    let acts = pend["actions"].as_array().unwrap();
    assert_eq!(
        acts.len(),
        1,
        "removing a member enqueues a revoke for the admin"
    );
    assert_eq!(acts[0]["kind"], "revoke");
    assert_eq!(acts[0]["source"], "directory");
    assert_eq!(acts[0]["vault_id"], b64(VAULT));
    assert_eq!(acts[0]["account_id"], joiner_acct);

    // --- Owner rotates to epoch 3 (revoke epoch 2) EXCLUDING the joiner → queue empty. ---
    publish(
        &app,
        &owner_tok,
        &owner,
        3,
        &[(owner.ed.to_vec(), 2)],
        Some(2),
    )
    .await;
    assert!(
        get_pending(&app, &owner_tok).await["actions"]
            .as_array()
            .unwrap()
            .is_empty(),
        "revoke auto-done once the rotation excludes the removed member"
    );

    // Sanity: grants/get still confirms only the owner remains at the latest epoch.
    let g: Value = app
        .client
        .get(format!(
            "{}/v1/grants?vault_id={}",
            app.base,
            urlencode(&b64(VAULT))
        ))
        .bearer_auth(&owner_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(g["key_epoch"], 3);
    assert_eq!(
        g["grants"].as_array().unwrap().len(),
        1,
        "only the owner remains"
    );
}
