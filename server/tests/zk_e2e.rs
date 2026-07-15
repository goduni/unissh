//! Phase 7 §15.3: zero-knowledge dump (ciphertext only), per-account isolation
//! over HTTP, end-to-end member lifecycle (vault → add member → sees via delta/
//! grants → revoke+rotate → read-deny), plus the v2 join→grant delta-visibility
//! proof (Task 11).

mod common;

use common::spawn;
use serde_json::{Value, json};
use unissh_crypto::{
    AssociatedData, Ed25519Keypair, SymmetricKey, VersionedObject, aead_encrypt, sign_version,
};
use unissh_server::codec::parse_open;
use unissh_server::ids::b64;
use unissh_server::store::sync_repo::PushObj;
use unissh_storage::{CachePolicy, ItemRecord, SyncTarget, VaultRecord};
use unissh_sync::SyncObject;

const VAULT: &[u8] = b"vault-zke2e-aaaa";

// ---- object builders (open metadata + opaque blobs) ----

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
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
// grants_publish verifies manifest/grant signatures unconditionally → we sign
// for real (parity with the core), author = kp.
fn manifest_obj(kp: &Ed25519Keypair, vault: &[u8], epoch: u64, blob: &[u8]) -> String {
    let sig = sign_version(
        &kp.signing,
        &VersionedObject::from_content(
            AssociatedData::new(vault.to_vec(), b"__manifest__".to_vec(), epoch),
            blob,
        ),
    )
    .unwrap();
    let mut out = vec![3u8];
    put(&mut out, vault);
    out.extend_from_slice(&epoch.to_be_bytes());
    put(&mut out, blob);
    put(&mut out, &sig);
    put(&mut out, &kp.verifying.to_bytes());
    b64(&out)
}
fn grant_obj(kp: &Ed25519Keypair, vault: &[u8], member: &[u8], epoch: u64, role: u8) -> String {
    let wrapped_vk = vec![9u8; 48];
    let mut content = b"unissh-grant-v1".to_vec();
    content.push(role);
    content.extend_from_slice(&0i64.to_be_bytes());
    content.extend_from_slice(&wrapped_vk);
    let sig = sign_version(
        &kp.signing,
        &VersionedObject::from_content(
            AssociatedData::new(vault.to_vec(), member.to_vec(), epoch),
            &content,
        ),
    )
    .unwrap();
    let mut out = vec![4u8];
    put(&mut out, vault);
    put(&mut out, member);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push(role);
    out.extend_from_slice(&0i64.to_be_bytes()); // not_after (8 BE) — no expiry
    put(&mut out, &wrapped_vk);
    put(&mut out, &sig);
    put(&mut out, &kp.verifying.to_bytes());
    b64(&out)
}
fn vault_obj(author: &[u8]) -> String {
    b64(&SyncObject::Vault(VaultRecord {
        vault_id: VAULT.to_vec(),
        sync_target: SyncTarget::Cloud,
        name_blob: vec![0xEE; 12],
        wrapped_vk: vec![0xDD; 16],
        version: 1,
        tombstone: false,
        signature: vec![9u8; 67],
        author_pubkey: author.to_vec(),
        key_epoch: 1,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    })
    .to_bytes()
    .unwrap())
}

// ---- ZK dump ----

#[tokio::test]
async fn zk_dump_contains_only_ciphertext() {
    let app = spawn().await;
    let s = app.seed_session("personal").await;

    const MARKER: &[u8] = b"SUPERSECRET-PLAINTEXT-MUST-NOT-LEAK";
    // The client encrypts the content BEFORE sending; the server sees only ciphertext.
    let key = SymmetricKey::generate();
    let aad = AssociatedData::new(VAULT.to_vec(), b"i1".to_vec(), 1);
    let ciphertext = aead_encrypt(&key, MARKER, &aad).unwrap();
    assert!(!ciphertext.windows(MARKER.len()).any(|w| w == MARKER));

    let item = SyncObject::Item(ItemRecord {
        vault_id: VAULT.to_vec(),
        item_id: b"i1".to_vec(),
        item_type: 1,
        content_blob: ciphertext.clone(),
        wrapped_item_key: vec![1, 2, 3],
        version: 1,
        tombstone: false,
        signature: vec![7u8; 67],
        author_pubkey: s.ed25519_pub.clone(),
        created_at: 0,
        updated_at: 0,
        key_epoch: 1,
    });
    let bytes = item.to_bytes().unwrap();
    let parsed = parse_open(&bytes).unwrap();
    app.state
        .store
        .push_objects(None, b"h", vec![PushObj { bytes, parsed }], app.now())
        .await
        .unwrap();

    let dump = app.state.store.dump_blobs().await.unwrap();
    assert!(
        !dump.windows(MARKER.len()).any(|w| w == MARKER),
        "DB dump must NOT contain plaintext marker (zero-knowledge)"
    );
    assert!(
        dump.windows(ciphertext.len())
            .any(|w| w == ciphertext.as_slice()),
        "ciphertext IS stored verbatim (sanity)"
    );
}

// ---- end-to-end member lifecycle ----

#[tokio::test]
async fn e2e_member_lifecycle_add_sync_revoke_rotate() {
    let app = spawn().await;
    let admin_kp = Ed25519Keypair::generate();
    let admin = admin_kp.verifying.to_bytes().to_vec();
    let member = vec![0xB8u8; 32];
    let (_a, _d, admin_bearer) = app.seed_device(&admin, &[1u8; 32], "org", true).await;
    let (_a2, _d2, member_bearer) = app.seed_device(&member, &[2u8; 32], "org", false).await;

    let admin_auth = format!("Bearer {admin_bearer}");
    let member_auth = format!("Bearer {member_bearer}");

    // admin claims vault + pushes the Vault record
    app.state
        .store
        .claim_vault(
            VAULT,
            &admin,
            None,
            None,
            "selective",
            None,
            false,
            app.now(),
        )
        .await
        .unwrap();
    let pr = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", &admin_auth)
        .json(&json!({ "objects": [vault_obj(&admin)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(pr.status(), 200, "admin (owner) can push the vault");

    // admin adds member as editor @epoch 1
    let blob1 = manifest_blob(1, &[(admin.clone(), 2), (member.clone(), 1)]);
    let pubresp = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .header("Authorization", &admin_auth)
        .json(&json!({
            "manifest": manifest_obj(&admin_kp, VAULT, 1, &blob1),
            "grants": [ grant_obj(&admin_kp, VAULT, &member, 1, 1) ],
            "new_epoch": 1,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(pubresp.status(), 200);

    // member sees their grant
    let g: Value = app
        .client
        .get(format!(
            "{}/v1/grants?vault_id={}",
            app.base,
            urlencode(&b64(VAULT))
        ))
        .header("Authorization", &member_auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        g["grants"].as_array().unwrap().len(),
        1,
        "member sees their grant"
    );

    // member syncs and sees the vault metadata via delta
    let d: Value = app
        .client
        .get(format!("{}/v1/sync/delta?cursor=0", app.base))
        .header("Authorization", &member_auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !d["items"].as_array().unwrap().is_empty(),
        "member pulls vault metadata"
    );

    // admin revokes member: rotate to epoch 2 (admin only) + revoke epoch 1
    let blob2 = manifest_blob(2, &[(admin.clone(), 2)]);
    let rot = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .header("Authorization", &admin_auth)
        .json(&json!({
            "manifest": manifest_obj(&admin_kp, VAULT, 2, &blob2),
            "grants": [],
            "revoke_epoch": 1,
            "new_epoch": 2,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rot.status(), 200);

    // revoked member: read-denied on the old epoch's grants
    let denied = app
        .client
        .get(format!(
            "{}/v1/grants?vault_id={}&key_epoch=1",
            app.base,
            urlencode(&b64(VAULT))
        ))
        .header("Authorization", &member_auth)
        .send()
        .await
        .unwrap();
    assert_eq!(
        denied.status(),
        403,
        "revoked member can no longer read grants"
    );

    // new epoch present; member offboarded (no grant)
    let g2: Value = app
        .client
        .get(format!(
            "{}/v1/grants?vault_id={}",
            app.base,
            urlencode(&b64(VAULT))
        ))
        .header("Authorization", &admin_auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(g2["key_epoch"], 2, "latest epoch is the rotated one");
    assert_eq!(
        g2["grants"].as_array().unwrap().len(),
        0,
        "member offboarded at new epoch"
    );
}

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

// ---- v2 phase proof: join → grant → delta visibility (Task 11) ----

/// The base64 `object` strings in a device's FULL `/v1/sync/delta` (from cursor 0).
async fn delta_object_strings(app: &common::TestApp, tok: &str) -> Vec<String> {
    let d: Value = app
        .client
        .get(format!("{}/v1/sync/delta?cursor=0", app.base))
        .bearer_auth(tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    d["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|it| it["object"].as_str().unwrap().to_string())
        .collect()
}

/// Task 11 — the v2 phase proof: A1 grant-based delta visibility, end to end in the
/// "one account, many spaces" model. The owner claims the instance, creates a space,
/// and mints a one-link invite; a DISTINCT joiner redeems it as a BRAND-NEW account.
/// The owner pushes a secret Cloud Vault + Item; the joiner's `/v1/sync/delta` must
/// NOT surface that vault's objects until the owner publishes a manifest+grant that
/// includes the joiner — after which the SAME secret object round-trips to the
/// joiner's delta. Reuses the real-crypto manifest/grant/vault helpers in
/// `tests/common` (shared from policy_audit/pending_http).
#[tokio::test]
async fn e2e_v2_join_then_grant_flips_delta_visibility() {
    const E2E_VAULT: &[u8] = b"vault-v2e2e-aaaa";
    let app = spawn().await;

    // --- Owner claims the instance + logs in. ---
    let owner = common::make_identity();
    let claimed = common::claim_owner(&app, &owner.payload_b64, &owner.sig_b64).await;
    let owner_acct = claimed["account_id"].as_str().unwrap().to_string();
    let owner_dev = claimed["device_id"].as_str().unwrap().to_string();
    let owner_tok = common::login_v2(&app, &owner, &owner_acct, &owner_dev).await;

    // --- Owner creates a space "Backend" (creator is auto-admin). ---
    let space_id = app
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

    // --- Owner mints a one-link invite; a DISTINCT joiner redeems it → NEW account. ---
    let token = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "space_intents": [{ "space_id": space_id, "role": "member" }] }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let joiner = common::make_identity();
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
    assert_eq!(jr.status(), 201, "join creates a brand-new account");
    let jrb = jr.json::<Value>().await.unwrap();
    let joiner_acct = jrb["account_id"].as_str().unwrap().to_string();
    let joiner_dev = jrb["device_id"].as_str().unwrap().to_string();
    let joiner_tok = common::login_v2(&app, &joiner, &joiner_acct, &joiner_dev).await;

    // --- Owner claims a CLOUD vault (selective) in Backend, then pushes a SECRET
    //     Vault + Item. The item content is client-side AEAD ciphertext — the server
    //     only ever sees ciphertext. ---
    let claim = app
        .client
        .post(format!("{}/v1/vaults/claim", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({
            "vault_id": b64(E2E_VAULT),
            "space_id": space_id,
            "access_policy": "selective",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(claim.status(), 200, "owner claims the cloud vault");

    const MARKER: &[u8] = b"V2-E2E-SECRET-ITEM-PLAINTEXT";
    let key = SymmetricKey::generate();
    let aad = AssociatedData::new(E2E_VAULT.to_vec(), b"secret-item".to_vec(), 1);
    let ciphertext = aead_encrypt(&key, MARKER, &aad).unwrap();
    let secret_item = SyncObject::Item(ItemRecord {
        vault_id: E2E_VAULT.to_vec(),
        item_id: b"secret-item".to_vec(),
        item_type: 1,
        content_blob: ciphertext,
        wrapped_item_key: vec![1, 2, 3],
        version: 1,
        tombstone: false,
        signature: vec![7u8; 67],
        author_pubkey: owner.ed.to_vec(),
        created_at: 0,
        updated_at: 0,
        key_epoch: 1,
    })
    .to_bytes()
    .unwrap();
    let secret_item_b64 = b64(&secret_item);

    let pr = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({ "objects": [
            b64(&common::vault_object(&owner.ed, E2E_VAULT, 1, 1)),
            secret_item_b64,
        ] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        pr.status(),
        200,
        "owner (vault owner) pushes the secret vault+item"
    );

    // --- Owner publishes manifest@1 = {owner:Admin} + grant{owner}. Latest epoch = 1;
    //     the joiner holds NO grant yet. ---
    let blob1 = manifest_blob(1, &[(owner.ed.to_vec(), 2)]);
    let pub1 = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({
            "manifest": b64(&common::manifest_signed(&owner.kp, E2E_VAULT, 1, &blob1)),
            "grants": [ b64(&common::grant_signed(&owner.kp, E2E_VAULT, &owner.ed, 1, 2)) ],
            "new_epoch": 1,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(pub1.status(), 200, "owner publishes epoch 1 (owner only)");

    // === BEFORE the joiner's grant: the joiner's delta must NOT surface the secret. ===
    let before = delta_object_strings(&app, &joiner_tok).await;
    assert!(
        !before.contains(&secret_item_b64),
        "A1: joiner has NO grant → the owner's secret item is NOT in the joiner's delta"
    );

    // --- Owner publishes manifest@2 = {owner:Admin, joiner:member} + grants{owner, joiner}.
    //     The vault's MAX manifest epoch is now 2, and the joiner holds a live grant@2. ---
    let blob2 = manifest_blob(2, &[(owner.ed.to_vec(), 2), (joiner.ed.to_vec(), 1)]);
    let pub2 = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .bearer_auth(&owner_tok)
        .json(&json!({
            "manifest": b64(&common::manifest_signed(&owner.kp, E2E_VAULT, 2, &blob2)),
            "grants": [
                b64(&common::grant_signed(&owner.kp, E2E_VAULT, &owner.ed, 2, 2)),
                b64(&common::grant_signed(&owner.kp, E2E_VAULT, &joiner.ed, 2, 1)),
            ],
            "new_epoch": 2,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        pub2.status(),
        200,
        "owner publishes epoch 2 including the joiner"
    );

    // === AFTER the grant: the SAME secret object round-trips to the joiner's delta. ===
    let after = delta_object_strings(&app, &joiner_tok).await;
    assert!(
        after.contains(&secret_item_b64),
        "A1: joiner now holds a live grant @latest epoch → the owner's secret item \
         IS in the joiner's delta"
    );
}
