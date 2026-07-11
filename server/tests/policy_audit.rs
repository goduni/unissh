//! Phase 6 §5.5/§9/§10/§11: RBAC write-accept matrix, grants/publish + grants/get
//! (read-deny + revoke), audit append (genesis) + admin-query.

mod common;

use common::{spawn, spawn_with};
use serde_json::{Value, json};
use unissh_crypto::{AssociatedData, Ed25519Keypair, VersionedObject, sign_version};
use unissh_server::codec::parse_open;
use unissh_server::ids::b64;
use unissh_server::modules::policy::write_accept;
use unissh_server::store::sync_repo::PushObj;

const TID: &[u8] = b"tenant-policy-01";

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

// A real record signature (parity with the core), to exercise the grants_publish path where
// manifest/grant signatures are now verified UNCONDITIONALLY. The dummy-sig manifest_obj
// below is only good for write_accept-direct tests (they don't parse the signature).
fn sig_over(
    kp: &Ed25519Keypair,
    vault: &[u8],
    item: &[u8],
    version: u64,
    content: &[u8],
) -> Vec<u8> {
    let vo = VersionedObject::from_content(
        AssociatedData::new(vault.to_vec(), item.to_vec(), version),
        content,
    );
    sign_version(&kp.signing, &vo).unwrap()
}

/// A genuinely signed manifest object (tag 3), author = `kp`.
fn manifest_signed(kp: &Ed25519Keypair, vault: &[u8], epoch: u64, blob: &[u8]) -> Vec<u8> {
    let sig = sig_over(kp, vault, b"__manifest__", epoch, blob);
    let mut out = vec![3u8];
    put(&mut out, vault);
    out.extend_from_slice(&epoch.to_be_bytes());
    put(&mut out, blob);
    put(&mut out, &sig);
    put(&mut out, &kp.verifying.to_bytes());
    out
}

/// A genuinely signed grant object (tag 4), author = `kp`.
fn grant_signed(kp: &Ed25519Keypair, vault: &[u8], member: &[u8], epoch: u64, role: u8) -> Vec<u8> {
    let wrapped_vk = vec![9u8; 48];
    let mut content = b"unissh-grant-v1".to_vec();
    content.push(role);
    content.extend_from_slice(&0i64.to_be_bytes()); // not_after = 0 (no expiry)
    content.extend_from_slice(&wrapped_vk);
    let sig = sig_over(kp, vault, member, epoch, &content);
    let mut out = vec![4u8];
    put(&mut out, vault);
    put(&mut out, member);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push(role);
    out.extend_from_slice(&0i64.to_be_bytes());
    put(&mut out, &wrapped_vk);
    put(&mut out, &sig);
    put(&mut out, &kp.verifying.to_bytes());
    out
}

fn manifest_blob(epoch: u64, members: &[(Vec<u8>, u8)]) -> Vec<u8> {
    let mut ms = members.to_vec();
    ms.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = b"unissh-manifest-v1".to_vec();
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&(ms.len() as u32).to_be_bytes());
    for (ed, role) in &ms {
        out.push(*role);
        out.extend_from_slice(&(ed.len() as u16).to_be_bytes());
        out.extend_from_slice(ed);
    }
    out
}

fn manifest_obj(vault: &[u8], epoch: u64, blob: &[u8], author: &[u8]) -> Vec<u8> {
    let mut out = vec![3u8];
    put(&mut out, vault);
    out.extend_from_slice(&epoch.to_be_bytes());
    put(&mut out, blob);
    put(&mut out, &[1u8; 67]);
    put(&mut out, author);
    out
}

fn item_obj(vault: &[u8], item: &[u8], epoch: u64, author: &[u8]) -> Vec<u8> {
    let mut out = vec![2u8];
    put(&mut out, vault);
    put(&mut out, item);
    out.extend_from_slice(&1u32.to_be_bytes()); // item_type
    put(&mut out, &[5u8; 8]); // content
    put(&mut out, &[6u8; 8]); // wrapped_item_key
    out.extend_from_slice(&1u64.to_be_bytes()); // version
    out.push(0); // tombstone
    put(&mut out, &[7u8; 67]); // sig
    put(&mut out, author);
    out.extend_from_slice(&epoch.to_be_bytes()); // key_epoch
    out
}

fn audit_obj(author: &[u8]) -> Vec<u8> {
    let mut out = vec![5u8];
    put(&mut out, &[]); // vault_id (empty in v1)
    put(&mut out, b"audit-event"); // entry_blob
    put(&mut out, &[1u8; 67]); // sig
    put(&mut out, author);
    out
}

fn pobj(bytes: Vec<u8>) -> PushObj {
    let parsed = parse_open(&bytes).unwrap();
    PushObj { bytes, parsed }
}

const VAULT: &[u8] = b"vault-policy-aaa";

#[tokio::test]
async fn write_accept_rbac_matrix() {
    let app = spawn().await;
    let admin = vec![0xA0u8; 32];
    let editor = vec![0xE0u8; 32];
    let viewer = vec![0x70u8; 32];
    let stranger = vec![0x5Au8; 32];

    // genesis owner = admin; org tier.
    app.seed_device(TID, &admin, &[1u8; 32], "org", true).await;
    // owner claims the vault namespace (admin == owner).
    app.state
        .store
        .claim_vault(TID, VAULT, &admin, app.now())
        .await
        .unwrap();

    // publish manifest@1 with roles.
    let blob = manifest_blob(
        1,
        &[(admin.clone(), 2), (editor.clone(), 1), (viewer.clone(), 0)],
    );
    let m = pobj(manifest_obj(VAULT, 1, &blob, &admin));
    app.state
        .store
        .grants_publish(TID, VAULT, &m, &[], None, app.now())
        .await
        .unwrap();

    // editor Item → accepted
    write_accept(
        &app.state,
        TID,
        &editor,
        &[pobj(item_obj(VAULT, b"i1", 1, &editor))],
        false,
    )
    .await
    .expect("editor may write items");
    // viewer Item → forbidden
    assert!(
        write_accept(
            &app.state,
            TID,
            &viewer,
            &[pobj(item_obj(VAULT, b"i2", 1, &viewer))],
            false
        )
        .await
        .is_err(),
        "viewer cannot write"
    );
    // stranger (non-member) Item → forbidden
    assert!(
        write_accept(
            &app.state,
            TID,
            &stranger,
            &[pobj(item_obj(VAULT, b"i3", 1, &stranger))],
            false
        )
        .await
        .is_err(),
        "non-member cannot write"
    );
    // non-admin publishing a manifest → forbidden
    assert!(
        write_accept(
            &app.state,
            TID,
            &editor,
            &[pobj(manifest_obj(VAULT, 2, &blob, &editor))],
            false
        )
        .await
        .is_err(),
        "editor cannot publish membership records"
    );
    // audit authored by non-genesis → forbidden
    assert!(
        write_accept(&app.state, TID, &editor, &[pobj(audit_obj(&editor))], false)
            .await
            .is_err(),
        "audit author must be genesis"
    );
    // audit authored by genesis(admin) → ok
    write_accept(&app.state, TID, &admin, &[pobj(audit_obj(&admin))], false)
        .await
        .expect("genesis audit ok");
}

/// S5: under `acl_only` (validate_signatures off) the authorship of ACL objects
/// (manifest/grant) is still checked — otherwise the delta visibility filter would trust
/// forged grants; other tiers (Item) are skipped (the client re-verifies).
#[tokio::test]
async fn write_accept_acl_only_enforces_membership_authorship() {
    let app = spawn().await;
    let admin = vec![0xA1u8; 32];
    let editor = vec![0xB2u8; 32];
    let stranger = vec![0xE5u8; 32];
    // genesis owner = admin (creates the tenant); then admin claims the vault — otherwise
    // author_role grants Admin to anyone ("the first push establishes ownership").
    app.seed_device(TID, &admin, &[1u8; 32], "org", true).await;
    app.state
        .store
        .claim_vault(TID, VAULT, &admin, app.now())
        .await
        .unwrap();
    // manifest@1 {admin:admin, editor:editor}.
    let blob = manifest_blob(1, &[(admin.clone(), 2), (editor.clone(), 1)]);
    let m = pobj(manifest_obj(VAULT, 1, &blob, &admin));
    app.state
        .store
        .grants_publish(TID, VAULT, &m, &[], None, app.now())
        .await
        .unwrap();
    // acl_only=true: a non-admin (editor) manifest is STILL rejected.
    assert!(
        write_accept(
            &app.state,
            TID,
            &editor,
            &[pobj(manifest_obj(VAULT, 2, &blob, &editor))],
            true
        )
        .await
        .is_err(),
        "acl_only still rejects a non-admin membership record"
    );
    // acl_only=true: a non-member writes an Item → ACCEPTED (skipped, the client re-verifies).
    write_accept(
        &app.state,
        TID,
        &stranger,
        &[pobj(item_obj(VAULT, b"i1", 1, &stranger))],
        true,
    )
    .await
    .expect("acl_only skips non-ACL items");
}

#[tokio::test]
async fn grants_publish_get_and_revoke() {
    let app = spawn().await;
    let admin_kp = Ed25519Keypair::generate();
    let admin = admin_kp.verifying.to_bytes().to_vec();
    let member = vec![0xB2u8; 32];

    let (_acc, _dev, admin_bearer) = app.seed_device(TID, &admin, &[1u8; 32], "org", true).await;
    let (_acc2, _dev2, member_bearer) = app
        .seed_device(TID, &member, &[2u8; 32], "org", false)
        .await;
    app.state
        .store
        .claim_vault(TID, VAULT, &admin, app.now())
        .await
        .unwrap();

    // admin publishes manifest@1 {admin:admin, member:editor} + member grant
    let blob = manifest_blob(1, &[(admin.clone(), 2), (member.clone(), 1)]);
    let publish = json!({
        "manifest": b64(&manifest_signed(&admin_kp, VAULT, 1, &blob)),
        "grants": [ b64(&grant_signed(&admin_kp, VAULT, &member, 1, 1)) ],
        "new_epoch": 1,
    });
    let r = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&publish)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // member GET /grants → manifest + their grant
    let g: Value = app
        .client
        .get(format!(
            "{}/v1/grants?vault_id={}",
            app.base,
            urlencode(&b64(VAULT))
        ))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {member_bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(g["key_epoch"], 1);
    assert_eq!(g["grants"].as_array().unwrap().len(), 1);

    // rotate to epoch 2 WITHOUT the member + revoke epoch 1 (offboarding)
    let blob2 = manifest_blob(2, &[(admin.clone(), 2)]);
    let publish2 = json!({
        "manifest": b64(&manifest_signed(&admin_kp, VAULT, 2, &blob2)),
        "grants": [],
        "revoke_epoch": 1,
        "new_epoch": 2,
    });
    let r2 = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&publish2)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200);

    // revoked member: GET grants@1 now read-denied (their grant revoked)
    let denied = app
        .client
        .get(format!(
            "{}/v1/grants?vault_id={}&key_epoch=1",
            app.base,
            urlencode(&b64(VAULT))
        ))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {member_bearer}"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403, "revoked member read-denied");

    // admin GET grants@2 → no member grants (offboarded)
    let g2: Value = app
        .client
        .get(format!(
            "{}/v1/grants?vault_id={}&key_epoch=2",
            app.base,
            urlencode(&b64(VAULT))
        ))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(g2["grants"].as_array().unwrap().len(), 0);
}

/// S6: grants_get does not reveal a vault's existence to a non-member. A non-member's request to
/// an EXISTING vault (of which they are not a member) and to a NON-EXISTENT vault both give the same
/// 403 — otherwise a revoked member who knows the vault_id could detect the vault's liveness by
/// 403/404 (existence-oracle).
#[tokio::test]
async fn grants_get_hides_existence_from_non_member() {
    let app = spawn().await;
    let admin_kp = Ed25519Keypair::generate();
    let admin = admin_kp.verifying.to_bytes().to_vec();
    let stranger = vec![0xC3u8; 32];
    let (_a, _d, admin_bearer) = app.seed_device(TID, &admin, &[1u8; 32], "org", true).await;
    let (_s, _sd, stranger_bearer) = app
        .seed_device(TID, &stranger, &[2u8; 32], "org", false)
        .await;
    app.state
        .store
        .claim_vault(TID, VAULT, &admin, app.now())
        .await
        .unwrap();

    // VAULT exists (manifest@1), but stranger is not a member.
    let blob = manifest_blob(1, &[(admin.clone(), 2)]);
    let publish = json!({
        "manifest": b64(&manifest_signed(&admin_kp, VAULT, 1, &blob)),
        "grants": [],
        "new_epoch": 1,
    });
    let r = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&publish)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // A non-member of an existing vault → 403.
    let existing = app
        .client
        .get(format!(
            "{}/v1/grants?vault_id={}",
            app.base,
            urlencode(&b64(VAULT))
        ))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {stranger_bearer}"))
        .send()
        .await
        .unwrap();
    // A non-existent vault → the SAME 403 (previously a 404 "no manifest for vault").
    let ghost_id = vec![0x99u8; 32];
    let ghost = app
        .client
        .get(format!(
            "{}/v1/grants?vault_id={}",
            app.base,
            urlencode(&b64(&ghost_id))
        ))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {stranger_bearer}"))
        .send()
        .await
        .unwrap();
    assert_eq!(existing.status(), 403, "не-член существующего волта → 403");
    assert_eq!(
        ghost.status(),
        403,
        "несуществующий волт → тот же 403 (без existence-oracle)"
    );
}

/// S4: an instance-admin (delegated is_admin, NOT the vault owner) cannot
/// publish grants — grants_publish requires vault-admin authorship, not
/// just require_admin.
#[tokio::test]
async fn grants_publish_rejects_non_vault_admin() {
    let app = spawn().await;
    let owner = vec![0xA1u8; 32];
    // A real keypair: the manifest must pass verify_record_sig (a valid
    // self-signature) to reach the author_role check and get a 403 — otherwise
    // the test would catch a 400 on the signature, not a role refusal.
    let delegated_kp = Ed25519Keypair::generate();
    let delegated = delegated_kp.verifying.to_bytes().to_vec();
    // The vault owner (also an instance-admin) + claim.
    let (_a, _d, _owner_bearer) = app.seed_device(TID, &owner, &[1u8; 32], "org", true).await;
    // A delegated instance-admin (is_admin=true), but NOT a member/owner of the vault.
    let (_a2, _d2, delegated_bearer) = app
        .seed_device(TID, &delegated, &[4u8; 32], "org", true)
        .await;
    app.state
        .store
        .claim_vault(TID, VAULT, &owner, app.now())
        .await
        .unwrap();
    // The delegated one publishes a manifest authored by itself → 403.
    let blob = manifest_blob(1, &[(delegated.clone(), 2)]);
    let publish = json!({
        "manifest": b64(&manifest_signed(&delegated_kp, VAULT, 1, &blob)),
        "grants": [],
        "new_epoch": 1,
    });
    let r = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {delegated_bearer}"))
        .json(&publish)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        403,
        "a delegated instance-admin who isn't a vault admin cannot publish grants"
    );
}

/// #4/#5: grants_publish verifies the manifest's signature UNCONDITIONALLY. A forged
/// author_pubkey (a dummy signature under a stranger's key) is rejected BEFORE author_role —
/// otherwise an instance-admin who doesn't own the vault would forge author=owner and
/// publish an ACL into someone else's vault (the delta filter trusts materialized ACLs).
#[tokio::test]
async fn grants_publish_rejects_forged_manifest_signature() {
    let app = spawn().await;
    let owner_kp = Ed25519Keypair::generate();
    let owner = owner_kp.verifying.to_bytes().to_vec();
    let attacker = vec![0xEEu8; 32];
    // The attacker is an instance-admin (is_admin), but NOT the vault owner.
    let (_a, _d, attacker_bearer) = app
        .seed_device(TID, &attacker, &[7u8; 32], "org", true)
        .await;
    app.state
        .store
        .claim_vault(TID, VAULT, &owner, app.now())
        .await
        .unwrap();

    // author_pubkey is forged as owner, but the signature is fake (no owner key).
    let blob = manifest_blob(1, &[(owner.clone(), 2)]);
    let publish = json!({
        "manifest": b64(&manifest_obj(VAULT, 1, &blob, &owner)), // dummy sig [1;67]
        "grants": [],
        "new_epoch": 1,
    });
    let r = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {attacker_bearer}"))
        .json(&publish)
        .send()
        .await
        .unwrap();
    assert_ne!(
        r.status(),
        200,
        "форджед-подпись не должна публиковаться (иначе обход vault-admin через spoof author_pubkey)"
    );
    assert!(r.status().is_client_error());
}

#[tokio::test]
async fn audit_append_genesis_and_admin_query() {
    let app = spawn().await;
    let admin = vec![0xC3u8; 32];
    let (_a, _d, admin_bearer) = app.seed_device(TID, &admin, &[1u8; 32], "org", true).await;

    // genesis-authored audit append → ok
    let ok = app
        .client
        .post(format!("{}/v1/audit", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&json!({ "audit_object": b64(&audit_obj(&admin)) }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 201);

    // non-genesis author → 403
    let bad = app
        .client
        .post(format!("{}/v1/audit", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&json!({ "audit_object": b64(&audit_obj(&[0xFFu8; 32])) }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 403);

    // admin query returns entries
    let q: Value = app
        .client
        .get(format!("{}/v1/audit?since_seq=0", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        q["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["source"] == "client-signed")
    );
}

#[tokio::test]
async fn audit_query_admin_only() {
    let app = spawn_with(|_| {}).await;
    let member = vec![0xD4u8; 32];
    let (_a, _d, member_bearer) = app
        .seed_device(TID, &member, &[2u8; 32], "org", false)
        .await;
    let r = app
        .client
        .get(format!("{}/v1/audit?since_seq=0", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {member_bearer}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "non-admin cannot query audit");
}

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}
