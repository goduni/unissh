//! §2.4 server-side record-signature verification: with `validate_signatures=true`
//! the server accepts records REALLY signed by the core and rejects forged/garbage ones.
//! Signatures are built with the core `sign_version` with exact AAD/content (parity).

mod common;

use common::spawn_with;
use serde_json::json;
use unissh_crypto::{AssociatedData, Ed25519Keypair, VersionedObject, sign_version};
use unissh_server::ids::b64;
use unissh_storage::{
    CachePolicy, ItemRecord, MemberRole, MembershipGrant, MembershipManifest, SyncTarget,
    VaultRecord,
};
use unissh_sync::SyncObject;

const VID: &[u8] = b"v-recsig-aaaaaaa";
const GRANT_DOMAIN: &[u8] = b"unissh-grant-v1";

fn sig_over(
    kp: &Ed25519Keypair,
    vault_id: &[u8],
    item_id: &[u8],
    version: u64,
    content: &[u8],
) -> Vec<u8> {
    let vo = VersionedObject::from_content(
        AssociatedData::new(vault_id.to_vec(), item_id.to_vec(), version),
        content,
    );
    sign_version(&kp.signing, &vo).unwrap()
}

fn vault_obj(kp: &Ed25519Keypair) -> SyncObject {
    let name_blob = vec![0xEE; 10];
    let wrapped_vk = vec![0xDD; 12];
    let mut content = wrapped_vk.clone();
    content.extend_from_slice(&name_blob);
    let sig = sig_over(kp, VID, b"__vault__", 1, &content);
    SyncObject::Vault(VaultRecord {
        vault_id: VID.to_vec(),
        sync_target: SyncTarget::Cloud,
        name_blob,
        wrapped_vk,
        version: 1,
        tombstone: false,
        signature: sig,
        author_pubkey: kp.verifying.to_bytes().to_vec(),
        key_epoch: 1,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    })
}

fn item_obj(kp: &Ed25519Keypair) -> SyncObject {
    let content_blob = vec![1, 2, 3, 4, 5, 6];
    let sig = sig_over(kp, VID, b"i-1", 1, &content_blob);
    SyncObject::Item(ItemRecord {
        vault_id: VID.to_vec(),
        item_id: b"i-1".to_vec(),
        item_type: 1,
        content_blob,
        wrapped_item_key: vec![9, 9],
        version: 1,
        tombstone: false,
        signature: sig,
        author_pubkey: kp.verifying.to_bytes().to_vec(),
        created_at: 0,
        updated_at: 0,
        key_epoch: 1,
    })
}

fn manifest_obj(kp: &Ed25519Keypair) -> SyncObject {
    let manifest_blob = vec![0x55; 20]; // the signed content = manifest_blob as-is
    let sig = sig_over(kp, VID, b"__manifest__", 3, &manifest_blob);
    SyncObject::MembershipManifest(MembershipManifest {
        vault_id: VID.to_vec(),
        key_epoch: 3,
        manifest_blob,
        signature: sig,
        author_pubkey: kp.verifying.to_bytes().to_vec(),
    })
}

fn grant_obj(kp: &Ed25519Keypair) -> SyncObject {
    let member = vec![0xB0; 32];
    let wrapped_vk = vec![0x44; 16];
    let mut content = GRANT_DOMAIN.to_vec();
    content.push(1); // MemberRole::Editor -> 1
    content.extend_from_slice(&0i64.to_be_bytes()); // not_after (8 BE) — matches new signed content
    content.extend_from_slice(&wrapped_vk);
    let sig = sig_over(kp, VID, &member, 3, &content);
    SyncObject::MembershipGrant(MembershipGrant {
        vault_id: VID.to_vec(),
        member_pubkey: member,
        key_epoch: 3,
        role: MemberRole::Editor,
        not_after: 0,
        wrapped_vk,
        signature: sig,
        author_pubkey: kp.verifying.to_bytes().to_vec(),
    })
}

fn push_body(objs: &[SyncObject]) -> serde_json::Value {
    json!({ "objects": objs.iter().map(|o| b64(&o.to_bytes().unwrap())).collect::<Vec<_>>() })
}

#[tokio::test]
async fn validate_accepts_real_signatures() {
    let app = spawn_with(|c| c.sync.validate_signatures = true).await;
    let s = app.seed_session("personal").await;
    let kp = Ed25519Keypair::generate();

    let objs = vec![
        vault_obj(&kp),
        item_obj(&kp),
        manifest_obj(&kp),
        grant_obj(&kp),
    ];
    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", format!("Bearer {}", s.access_token_b64))
        .json(&push_body(&objs))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "all 4 real-signed records must verify");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["server_seq"], json!([1, 2, 3, 4]));
}

#[tokio::test]
async fn validate_rejects_tampered_signature() {
    let app = spawn_with(|c| c.sync.validate_signatures = true).await;
    let s = app.seed_session("personal").await;
    let kp = Ed25519Keypair::generate();

    // tamper: sign the content, then change name_blob (the content digest won't match)
    let name_blob = vec![0xEE; 10];
    let wrapped_vk = vec![0xDD; 12];
    let mut content = wrapped_vk.clone();
    content.extend_from_slice(&name_blob);
    let sig = sig_over(&kp, VID, b"__vault__", 1, &content);
    let tampered = SyncObject::Vault(VaultRecord {
        vault_id: VID.to_vec(),
        sync_target: SyncTarget::Cloud,
        name_blob: vec![0x00; 10], // ← changed after signing
        wrapped_vk,
        version: 1,
        tombstone: false,
        signature: sig,
        author_pubkey: kp.verifying.to_bytes().to_vec(),
        key_epoch: 1,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    });

    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", format!("Bearer {}", s.access_token_b64))
        .json(&push_body(&[tampered]))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        400,
        "tampered content must fail signature verification"
    );
}

#[tokio::test]
async fn validate_rejects_forged_author() {
    let app = spawn_with(|c| c.sync.validate_signatures = true).await;
    let s = app.seed_session("personal").await;
    let signer = Ed25519Keypair::generate();
    let other = Ed25519Keypair::generate();

    // signed by the signer, but author_pubkey is swapped for a stranger's key
    let mut obj = vault_obj(&signer);
    if let SyncObject::Vault(ref mut v) = obj {
        v.author_pubkey = other.verifying.to_bytes().to_vec();
    }
    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", format!("Bearer {}", s.access_token_b64))
        .json(&push_body(&[obj]))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        400,
        "forged author (sig/author mismatch) must be rejected"
    );
}

#[tokio::test]
async fn passthrough_accepts_unsigned_when_validate_off() {
    // validate=false → synthetic objects with dummy signatures are accepted.
    let app = spawn_with(|c| c.sync.validate_signatures = false).await;
    let s = app.seed_session("personal").await;
    let dummy = SyncObject::Item(ItemRecord {
        vault_id: VID.to_vec(),
        item_id: b"i-x".to_vec(),
        item_type: 1,
        content_blob: vec![1, 2, 3],
        wrapped_item_key: vec![4],
        version: 1,
        tombstone: false,
        signature: vec![7u8; 67],
        author_pubkey: vec![8u8; 32],
        created_at: 0,
        updated_at: 0,
        key_epoch: 1,
    });
    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("Authorization", format!("Bearer {}", s.access_token_b64))
        .json(&push_body(&[dummy]))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "passthrough accepts unsigned blobs");
}
