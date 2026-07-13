//! v2 spaces/members/directory HTTP surface (§ Task 7): owner creates a space,
//! lists memberships with roles, runs the membership lifecycle (add → read →
//! role → remove) and reads the shared directory. The SECOND account is seeded
//! through the store seam (`TestApp::seed_session`) because there is no HTTP join
//! endpoint until Task 8 — the endpoints under test are all exercised over HTTP;
//! only the second account's *creation* uses the store handle the harness exposes.

mod common;

use common::{claim_owner, spawn};
use serde_json::{Value, json};
use unissh_server::ids::b64;

#[tokio::test]
async fn spaces_members_directory_lifecycle() {
    let app = spawn().await;
    let id = common::make_identity();
    let claimed = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let owner_acct = claimed["account_id"].as_str().unwrap().to_string();
    let tok = common::login_v2(
        &app,
        &id,
        &owner_acct,
        claimed["device_id"].as_str().unwrap(),
    )
    .await;

    let get = |path: String, bearer: &str| {
        app.client
            .get(format!("{}{}", app.base, path))
            .bearer_auth(bearer)
            .send()
    };
    let post = |path: &str, bearer: &str, body: Value| {
        app.client
            .post(format!("{}/v1/{}", app.base, path))
            .bearer_auth(bearer)
            .json(&body)
            .send()
    };

    // --- GET /v1/spaces: the claim seeded "Main", owner is its admin ---
    let spaces: Value = get("/v1/spaces".into(), &tok)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let list = spaces["spaces"].as_array().unwrap();
    assert_eq!(list.len(), 1, "only Main after claim");
    assert_eq!(list[0]["name"], "Main");
    assert_eq!(list[0]["role"], "admin");

    // --- POST /v1/spaces (owner) → 201, creator auto-added as admin ---
    let r = post("spaces", &tok, json!({ "name": "Backend" }))
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "owner creates space");
    let backend_id = r.json::<Value>().await.unwrap()["space_id"]
        .as_str()
        .unwrap()
        .to_string();

    let spaces: Value = get("/v1/spaces".into(), &tok)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let list = spaces["spaces"].as_array().unwrap();
    assert_eq!(list.len(), 2, "Main + Backend");
    let names: Vec<&str> = list.iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"Main") && names.contains(&"Backend"));
    assert!(
        list.iter().all(|s| s["role"] == "admin"),
        "owner is admin of both"
    );

    // --- role validation: a bad role is rejected (400) ---
    let r = post(
        "spaces/members",
        &tok,
        json!({ "space_id": backend_id, "account_id": owner_acct, "role": "superuser" }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 400, "invalid role → malformed");

    // --- admin guard: owner is NOT admin of an unknown space → 403 ---
    let fake_space = b64(&[9u8; 16]);
    let r = post(
        "spaces/members",
        &tok,
        json!({ "space_id": fake_space, "account_id": owner_acct, "role": "member" }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 403, "not admin of unknown space");

    // --- seed a SECOND account via the store seam (no HTTP join until Task 8) ---
    let member = app.seed_session("").await;
    let member_acct = b64(&member.account_id);
    let member_tok = member.access_token_b64.clone();

    // owner adds the member to Backend as "member" → 204
    let r = post(
        "spaces/members",
        &tok,
        json!({ "space_id": backend_id, "account_id": member_acct, "role": "member" }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 204, "admin adds member");

    // the member now sees Backend with role "member"
    let m_spaces: Value = get("/v1/spaces".into(), &member_tok)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ml = m_spaces["spaces"].as_array().unwrap();
    assert_eq!(ml.len(), 1);
    assert_eq!(ml[0]["name"], "Backend");
    assert_eq!(ml[0]["role"], "member");

    // GET /v1/spaces/members?space_id= (admin) → both members, with handles/pubkeys
    let ms: Value = get(format!("/v1/spaces/members?space_id={backend_id}"), &tok)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let members = ms["members"].as_array().unwrap();
    assert_eq!(members.len(), 2);
    let owner_row = members
        .iter()
        .find(|m| m["account_id"] == owner_acct)
        .unwrap();
    assert_eq!(owner_row["role"], "admin");
    assert_eq!(owner_row["handle"], "owner");
    assert!(
        owner_row["member_pubkey"].is_string(),
        "member_pubkey present"
    );
    let member_row = members
        .iter()
        .find(|m| m["account_id"] == member_acct)
        .unwrap();
    assert_eq!(member_row["role"], "member");

    // a plain member MAY read the member list (space member gate)
    let r = get(
        format!("/v1/spaces/members?space_id={backend_id}"),
        &member_tok,
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 200, "member reads member list");

    // a non-admin member CANNOT change roles → 403
    let r = post(
        "spaces/members/role",
        &member_tok,
        json!({ "space_id": backend_id, "account_id": owner_acct, "role": "member" }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 403, "member cannot set roles");

    // a bad role on the role endpoint is rejected (400)
    let r = post(
        "spaces/members/role",
        &tok,
        json!({ "space_id": backend_id, "account_id": member_acct, "role": "boss" }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 400, "invalid role on set-role");

    // owner promotes the member to admin → 204, reflected in the member's listing
    let r = post(
        "spaces/members/role",
        &tok,
        json!({ "space_id": backend_id, "account_id": member_acct, "role": "admin" }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 204, "admin promotes member");
    let m_spaces: Value = get("/v1/spaces".into(), &member_tok)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(m_spaces["spaces"][0]["role"], "admin", "promotion visible");

    // owner removes the member → 204; Backend disappears from the member's listing
    let r = post(
        "spaces/members/remove",
        &tok,
        json!({ "space_id": backend_id, "account_id": member_acct }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 204, "admin removes member");
    let m_spaces: Value = get("/v1/spaces".into(), &member_tok)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        m_spaces["spaces"].as_array().unwrap().len(),
        0,
        "member no longer in any space"
    );

    // --- GET /v1/directory (any authenticated caller) → both accounts ---
    let dir: Value = get("/v1/directory".into(), &tok)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let accts = dir["accounts"].as_array().unwrap();
    assert_eq!(accts.len(), 2, "owner + seeded account");
    let owner_dir = accts
        .iter()
        .find(|a| a["account_id"] == owner_acct)
        .unwrap();
    assert_eq!(owner_dir["handle"], "owner");
    assert!(owner_dir["member_pubkey"].is_string());
    assert!(owner_dir["x25519_pub"].is_string());
    assert_eq!(owner_dir["status"], "active");

    // the directory is readable by a plain member too (company model)
    let r = get("/v1/directory".into(), &member_tok).await.unwrap();
    assert_eq!(r.status(), 200);
    let dir2: Value = r.json().await.unwrap();
    assert_eq!(dir2["accounts"].as_array().unwrap().len(), 2);
}
