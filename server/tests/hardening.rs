//! Regressions for fixes from the adversarial review: structural invariants on push,
//! self-revoke guard, host-binding auth.

mod common;

use common::spawn;
use serde_json::json;
use unissh_crypto::{AssociatedData, Ed25519Keypair, VersionedObject, sign_version};
use unissh_server::ids::b64;
use unissh_storage::{CachePolicy, SyncTarget, VaultRecord};
use unissh_sync::SyncObject;

fn vault(target: SyncTarget) -> String {
    b64(&SyncObject::Vault(VaultRecord {
        vault_id: b"v-harden".to_vec(),
        sync_target: target,
        name_blob: vec![1],
        wrapped_vk: vec![2],
        version: 1,
        tombstone: false,
        signature: vec![9u8; 67],
        author_pubkey: vec![0xAA; 32],
        key_epoch: 1,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    })
    .to_bytes()
    .unwrap())
}

#[tokio::test]
async fn local_vault_rejected_on_push() {
    let app = spawn().await;
    let s = app.seed_session("personal").await;
    let bearer = format!("Bearer {}", s.access_token_b64);

    // Cloud → accepted
    let ok = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", &bearer)
        .json(&json!({ "objects": [vault(SyncTarget::Cloud)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // Local → rejected (only Cloud reaches the server, §4.3/§5.4)
    let bad = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", &bearer)
        .json(&json!({ "objects": [vault(SyncTarget::Local)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400, "Local-target vault must be rejected");
}

#[tokio::test]
async fn grants_publish_self_revoke_rejected() {
    let app = spawn().await;
    // A real keypair: grants_publish verifies the manifest's signature unconditionally,
    // so the test must pass the signature check to reach the self-revoke 409.
    let admin_kp = Ed25519Keypair::generate();
    let admin = admin_kp.verifying.to_bytes().to_vec();
    let (_a, _d, bearer) = app.seed_device(&admin, &[1u8; 32], "org", true).await;
    app.state
        .store
        .claim_vault(
            b"v-harden",
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

    // manifest@5; revoke_epoch == new_epoch == 5 → conflict
    let mut blob = b"unissh-manifest-v1".to_vec();
    blob.extend_from_slice(&5u64.to_be_bytes());
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob.push(2);
    blob.extend_from_slice(&(admin.len() as u16).to_be_bytes());
    blob.extend_from_slice(&admin);
    let mut mobj = vec![3u8];
    let put = |o: &mut Vec<u8>, b: &[u8]| {
        o.extend_from_slice(&(b.len() as u32).to_be_bytes());
        o.extend_from_slice(b);
    };
    put(&mut mobj, b"v-harden");
    mobj.extend_from_slice(&5u64.to_be_bytes());
    put(&mut mobj, &blob);
    let sig = sign_version(
        &admin_kp.signing,
        &VersionedObject::from_content(
            AssociatedData::new(b"v-harden".to_vec(), b"__manifest__".to_vec(), 5),
            &blob,
        ),
    )
    .unwrap();
    put(&mut mobj, &sig);
    put(&mut mobj, &admin);

    let r = app
        .client
        .post(format!("{}/v1/grants/publish", app.base))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({ "manifest": b64(&mobj), "grants": [], "revoke_epoch": 5, "new_epoch": 5 }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        409,
        "revoke_epoch == new_epoch must be rejected"
    );
}
