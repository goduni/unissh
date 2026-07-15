//! Key-binding attestations HTTP surface (v2 §Task 10): a space admin attests a
//! member's key binding; the server stores the opaque blob+signature VERBATIM (it
//! never verifies the attestation itself — clients do, ZK discipline).
//!
//! Two principals in ONE space: the owner (auto-admin of the space it creates) and
//! a second account seeded through the store seam (`TestApp::seed_session`) and
//! added to that same space as a plain `member` over HTTP — mirroring
//! `spaces_http.rs`. The guard (`shares_admin_space`) then holds: owner is an admin
//! sharing a space with the target; the plain member is not.

mod common;

use common::{claim_owner, spawn};
use serde_json::{Value, json};
use unissh_server::ids::b64;

/// Percent-encode a standard-base64 id for a query string (a raw '+' would decode to
/// a space server-side). Same treatment as `spaces_http.rs`.
fn q(id: &str) -> String {
    id.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

#[tokio::test]
async fn attestations_put_list_guard_and_upsert() {
    let app = spawn().await;
    let id = common::make_identity();
    let claimed = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let owner_acct = claimed["account_id"].as_str().unwrap().to_string();
    let owner_tok = common::login_v2(
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

    // --- owner creates a space; it is auto-added as its admin ---
    let r = post("spaces", &owner_tok, json!({ "name": "Team" }))
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "owner creates space");
    let team_id = r.json::<Value>().await.unwrap()["space_id"]
        .as_str()
        .unwrap()
        .to_string();

    // --- second account (via the store seam) added to Team as a plain member ---
    let member = app.seed_session("").await;
    let member_acct = b64(&member.account_id);
    let member_tok = member.access_token_b64.clone();
    let r = post(
        "spaces/members",
        &owner_tok,
        json!({ "space_id": team_id, "account_id": member_acct, "role": "member" }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 204, "admin adds the member");

    let blob1 = b64(b"attestation-blob-one");
    let sig1 = b64(&[0x11u8; 64]);

    // --- owner (admin sharing Team with the target) attests the member → 204 ---
    let r = post(
        "attestations",
        &owner_tok,
        json!({ "account_id": member_acct, "blob": blob1, "signature": sig1 }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 204, "space admin may attest a co-member");

    // --- GET returns it, with the owner's device ed25519 as attestor_pubkey ---
    let listing: Value = get(
        format!("/v1/attestations?account_id={}", q(&member_acct)),
        &owner_tok,
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let atts = listing["attestations"].as_array().unwrap();
    assert_eq!(atts.len(), 1, "one attestation for the member");
    assert_eq!(
        atts[0]["attestor_pubkey"],
        b64(&id.ed),
        "attestor_pubkey = the owner's device ed25519"
    );
    assert_eq!(atts[0]["blob"], blob1, "blob stored verbatim");
    assert_eq!(atts[0]["signature"], sig1, "signature stored verbatim");
    assert!(atts[0]["created_at"].is_i64(), "created_at present");

    // --- a plain member (not an admin of any shared space) attesting → 403 ---
    let r = post(
        "attestations",
        &member_tok,
        json!({ "account_id": owner_acct, "blob": blob1, "signature": sig1 }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 403, "a non-admin member cannot attest");

    // that rejected attempt stored nothing (owner still has no attestation)
    let owner_listing: Value = get(
        format!("/v1/attestations?account_id={}", q(&owner_acct)),
        &owner_tok,
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(
        owner_listing["attestations"].as_array().unwrap().len(),
        0,
        "forbidden attest wrote nothing"
    );

    // --- re-attest (same owner+target) UPSERTS: list stays length 1, new blob ---
    let blob2 = b64(b"attestation-blob-two-rotated");
    let sig2 = b64(&[0x22u8; 64]);
    let r = post(
        "attestations",
        &owner_tok,
        json!({ "account_id": member_acct, "blob": blob2, "signature": sig2 }),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 204, "re-attest succeeds");

    let listing: Value = get(
        format!("/v1/attestations?account_id={}", q(&member_acct)),
        &owner_tok,
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let atts = listing["attestations"].as_array().unwrap();
    assert_eq!(
        atts.len(),
        1,
        "upsert keeps a single row per (target, attestor)"
    );
    assert_eq!(
        atts[0]["blob"], blob2,
        "blob replaced by the re-attestation"
    );
    assert_eq!(atts[0]["signature"], sig2, "signature replaced too");
}
