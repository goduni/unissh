//! Phase 7 §15.3: zero-knowledge dump (ciphertext only), per-tenant isolation
//! over HTTP, end-to-end member lifecycle (vault → add member → sees via delta/
//! grants → revoke+rotate → read-deny).

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
