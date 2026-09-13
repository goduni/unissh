//! P7 — FFI exposure of Veha-2 operations: cloud vault, membership, rotation/purge,
//! identity/auth, cache-policy, audit, onboarding Path A/B, sync via callback.
//!
//! Hard constraint: the new methods do NOT hand out plaintext private
//! keys — only public keys/fingerprints/signatures/opaque blobs.

use std::sync::Arc;
use unissh_ffi::{Core, FfiMemberRole};

/// base64 `tenant_id` of the test server that cloud vaults bind to
/// (1:1 binding). `sync_now`/`sync_push` filter the push by it.
const TENANT: &str = "dGVuYW50LXRlc3Q="; // base64("tenant-test")

fn new_core(dir: &std::path::Path) -> Arc<Core> {
    Core::new(
        dir.join("inst.db").to_str().unwrap().to_string(),
        dir.join("keyset.bin").to_str().unwrap().to_string(),
    )
}

#[test]
fn create_cloud_vault_returns_uuid_hex_and_lists() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    let vid = core
        .create_cloud_vault("Shared".to_string(), TENANT.to_string())
        .unwrap();
    // vault_id = UUIDv4 (16 bytes) in hex = 32 hex chars
    assert_eq!(vid.len(), 32);
    assert!(hex::decode(&vid).is_ok());

    // the vault is visible in the list (name decrypted)
    let vaults = core.list_vaults().unwrap();
    assert!(vaults.iter().any(|v| v.name == "Shared"));

    // on a locked core — Locked
    core.lock();
    assert!(matches!(
        core.create_cloud_vault("X".to_string(), TENANT.to_string()),
        Err(unissh_ffi::FfiError::Locked)
    ));
}

#[test]
fn membership_add_list_fingerprint_pin() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("Team".to_string(), TENANT.to_string())
        .unwrap();

    // fixed public keys of the "member" (32 bytes each) — public material
    let member_ed = "11".repeat(32);
    let member_x = "22".repeat(32);

    core.add_member(
        vid.clone(),
        member_ed.clone(),
        member_x.clone(),
        FfiMemberRole::Editor,
    )
    .unwrap();

    let members = core.list_members(vid.clone()).unwrap();
    // owner (Admin) + new member (Editor)
    assert_eq!(members.len(), 2);
    assert!(members
        .iter()
        .any(|m| m.ed25519_pub_hex == member_ed && matches!(m.role, FfiMemberRole::Editor)));
    let me = members
        .iter()
        .find(|m| m.ed25519_pub_hex == member_ed)
        .unwrap();
    assert_eq!(me.fingerprint.len(), 64); // hex(SHA-256)

    // standalone fingerprint matches the one in the list
    let fp = core.member_fingerprint(member_ed.clone()).unwrap();
    assert_eq!(fp, me.fingerprint);

    // OOB pin: first time ok (TOFU), repeat with the same key — ok
    core.confirm_member_pin("acct-bob".to_string(), member_ed.clone())
        .unwrap();
    core.confirm_member_pin("acct-bob".to_string(), member_ed.clone())
        .unwrap();
    // a different key under the same account_id → error (PinMismatch)
    assert!(core
        .confirm_member_pin("acct-bob".to_string(), "33".repeat(32))
        .is_err());
}

#[test]
fn set_personal_vault_rejects_shared_vault() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("Team".to_string(), TENANT.to_string())
        .unwrap();
    // Solo vault (no members yet) → can be made personal.
    core.set_personal_vault(vid.clone()).unwrap();
    // Add a member → the vault becomes shared (2 members) → set_personal_vault
    // refuses (otherwise personal identities/bindings would leak to the team, B5.3).
    core.add_member(
        vid.clone(),
        "11".repeat(32),
        "22".repeat(32),
        FfiMemberRole::Editor,
    )
    .unwrap();
    assert_eq!(core.list_members(vid.clone()).unwrap().len(), 2);
    assert!(core.set_personal_vault(vid.clone()).is_err());
}

#[test]
fn local_vault_can_be_personal() {
    // A purely-local (offline) vault is a valid personal vault — the most private
    // option (identities never leave the device). set/get must accept its arbitrary
    // UTF-8 id, not just a hex cloud id, and get must echo it in list_vaults form so
    // the UI's "is this the personal vault?" match succeeds.
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("personal-local".to_string(), "Personal".to_string())
        .unwrap();
    core.set_personal_vault("personal-local".to_string())
        .unwrap();
    assert_eq!(
        core.get_personal_vault().unwrap().as_deref(),
        Some("personal-local"),
        "local personal-vault id round-trips (UTF-8, matching list_vaults)"
    );
}

#[test]
fn rotate_vk_and_purge_cloud_vault() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("R".to_string(), TENANT.to_string())
        .unwrap();

    // owner (Admin) + bob (Editor)
    let bob_ed = "44".repeat(32);
    let bob_x = "55".repeat(32);
    core.add_member(
        vid.clone(),
        bob_ed.clone(),
        bob_x.clone(),
        FfiMemberRole::Editor,
    )
    .unwrap();

    // rotation: keep ONLY the owner (revoke bob). The owner is always retained
    // by the core as Admin → we pass an empty list of "additional remaining members".
    let new_epoch = core.rotate_vk(vid.clone(), vec![]).unwrap();
    assert!(new_epoch >= 2);

    // verify_chain ok
    let report = core.verify_chain(vid.clone()).unwrap();
    assert!(report.ok, "verify_chain should be ok: {report:?}");

    // bob is no longer a member in the new epoch
    let members = core.list_members(vid.clone()).unwrap();
    assert!(members.iter().all(|m| m.ed25519_pub_hex != bob_ed));

    // purge → the vault disappears from the list
    core.purge_vault(vid.clone()).unwrap();
    let vaults = core.list_vaults().unwrap();
    assert!(vaults.iter().all(|v| v.name != "R"));
}

#[test]
fn identity_account_id_registration_and_server_auth() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    // account-id is stable across calls (generated once and persisted)
    let aid1 = core.account_id().unwrap();
    let aid2 = core.account_id().unwrap();
    assert_eq!(aid1, aid2);
    assert_eq!(aid1.len(), 32); // 16 bytes hex

    // registration blob is non-empty
    let reg = core.build_registration().unwrap();
    assert!(!reg.is_empty());

    // server-auth signature is non-empty (domain unissh-server-auth-v1)
    let sig = core
        .sign_server_challenge(
            "vault.example.com".to_string(),
            aid1.clone(),
            "device-1".to_string(),
            "key-1".to_string(),
            b"server-nonce".to_vec(),
            9999999999,
        )
        .unwrap();
    assert!(!sig.is_empty());

    // on a locked core — Locked
    core.lock();
    assert!(matches!(
        core.account_id(),
        Err(unissh_ffi::FfiError::Locked)
    ));
    assert!(matches!(
        core.build_registration(),
        Err(unissh_ffi::FfiError::Locked)
    ));
}

#[test]
fn cache_policy_get_set_and_audit() {
    use unissh_ffi::FfiCachePolicy;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("C".to_string(), TENANT.to_string())
        .unwrap();

    // default — OfflineAllowed
    assert!(matches!(
        core.get_cache_policy(vid.clone()).unwrap(),
        FfiCachePolicy::OfflineAllowed
    ));
    core.set_cache_policy(vid.clone(), FfiCachePolicy::OnlineOnly)
        .unwrap();
    assert!(matches!(
        core.get_cache_policy(vid.clone()).unwrap(),
        FfiCachePolicy::OnlineOnly
    ));

    // audit: append an opaque signed triple → query sees it
    let entry = b"signed-audit-event".to_vec();
    let sig = vec![7u8; 67];
    let author = "66".repeat(32);
    core.audit_append(vid.clone(), entry.clone(), sig.clone(), author.clone())
        .unwrap();
    let entries = core.audit_query(0).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_blob, entry);
    assert_eq!(entries[0].author_pubkey_hex, author);
    assert!(entries[0].seq >= 1);

    // since_seq filters
    let after = core.audit_query(entries[0].seq).unwrap();
    assert!(after.is_empty());
}

#[test]
fn onboarding_path_a_unlock_from_server_blob() {
    // Device A: create an account with a password, grab the Secret Key + keyset blob.
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path());
    let secret = core_a.create_account(Some("pw".to_string())).unwrap();
    core_a
        .create_vault("v".to_string(), "V".to_string())
        .unwrap();
    // keyset blob A = contents of the keyset sidecar (already encrypted under the Unlock Key).
    let keyset_blob = std::fs::read(dir_a.path().join("keyset.bin")).unwrap();

    // Device B: empty instance, accepts the keyset blob "from the server" (Path A).
    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path());
    assert!(!dir_b.path().join("inst.db").exists());
    core_b
        .unlock_from_server_blob(keyset_blob.clone(), Some("pw".to_string()), secret.clone())
        .unwrap();
    assert!(core_b.is_unlocked());

    // Recovery creates the DB with the recovered keyset's key. It remains
    // usable after the process exits, without the server or a new identity.
    core_b
        .create_vault("local".into(), "Recovered".into())
        .unwrap();
    core_b.lock();
    drop(core_b);
    let restarted = new_core(dir_b.path());
    restarted.unlock(Some("pw".into()), secret.clone()).unwrap();
    assert!(restarted
        .list_vaults()
        .unwrap()
        .iter()
        .any(|v| v.name == "Recovered"));

    // a corrupt keyset blob → a typed error, not a panic
    let dir_c = tempfile::tempdir().unwrap();
    let core_c = new_core(dir_c.path());
    assert!(core_c
        .unlock_from_server_blob(vec![1, 2, 3], Some("pw".to_string()), secret.clone())
        .is_err());

    // wrong password → InvalidCredentials
    let dir_d = tempfile::tempdir().unwrap();
    let core_d = new_core(dir_d.path());
    assert!(matches!(
        core_d.unlock_from_server_blob(keyset_blob, Some("wrong".to_string()), secret),
        Err(unissh_ffi::FfiError::InvalidCredentials)
    ));
}

#[test]
fn onboarding_path_a_refuses_another_identity_without_damaging_local_data() {
    let remote_dir = tempfile::tempdir().unwrap();
    let remote = new_core(remote_dir.path());
    let remote_secret = remote.create_account(Some("same password".into())).unwrap();
    let remote_blob = std::fs::read(remote_dir.path().join("keyset.bin")).unwrap();

    let local_dir = tempfile::tempdir().unwrap();
    let local = new_core(local_dir.path());
    let local_secret = local.create_account(Some("same password".into())).unwrap();
    local
        .create_vault("local".into(), "Keep me".into())
        .unwrap();
    let local_blob = std::fs::read(local_dir.path().join("keyset.bin")).unwrap();

    let error = local
        .unlock_from_server_blob(remote_blob, Some("same password".into()), remote_secret)
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("wrong database key or corrupt database"));
    assert_eq!(
        std::fs::read(local_dir.path().join("keyset.bin")).unwrap(),
        local_blob
    );
    assert!(local
        .list_vaults()
        .unwrap()
        .iter()
        .any(|v| v.name == "Keep me"));
    local.lock();
    drop(local);
    let restarted = new_core(local_dir.path());
    restarted
        .unlock(Some("same password".into()), local_secret)
        .unwrap();
    assert!(restarted
        .list_vaults()
        .unwrap()
        .iter()
        .any(|v| v.name == "Keep me"));
}

/// NEGATIVE (anti-rollback, server-tz §13.13b): `unlock_from_server_blob` must
/// REJECT a stale keyset blob (generation below the trusted floor) BEFORE accepting
/// it, not only raise the floor afterward. The previous version accepted such a blob.
#[test]
fn unlock_from_server_blob_rejects_stale_generation() {
    // Device A: account (gen 1) → capture the OLD blob → change password (gen 2).
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path());
    let secret = core_a.create_account(Some("pw1".to_string())).unwrap();
    let stale_blob = std::fs::read(dir_a.path().join("keyset.bin")).unwrap(); // gen 1
    core_a
        .change_password(
            Some("pw1".to_string()),
            Some("pw2".to_string()),
            secret.clone(),
        )
        .unwrap();
    let fresh_blob = std::fs::read(dir_a.path().join("keyset.bin")).unwrap(); // gen 2

    // Device B: accepts the FRESH blob (gen 2) — the floor is raised to 2.
    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path());
    core_b
        .unlock_from_server_blob(fresh_blob, Some("pw2".to_string()), secret.clone())
        .unwrap();
    core_b.lock();

    // A malicious server slips in the OLD blob (gen 1 < floor 2) with the correct old
    // password — it must be rejected as a rollback (not InvalidCredentials).
    let err = core_b
        .unlock_from_server_blob(stale_blob, Some("pw1".to_string()), secret)
        .unwrap_err();
    assert!(
        matches!(err, unissh_ffi::FfiError::Other { .. }),
        "stale generation must be rejected (rollback), got {err:?}"
    );
    assert!(!core_b.is_unlocked(), "state must not be established");
}

/// NEGATIVE (anti-rollback, server-tz §13.13b): after `change_password` the old
/// (lower-generation) keyset blob must no longer be accepted on this
/// device — `change_password` must raise the trusted floor. The previous version
/// didn't raise the floor, and the old blob went through.
#[test]
fn change_password_raises_floor_rejecting_old_blob() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    let secret = core.create_account(Some("old".to_string())).unwrap();
    // gen 1 blob BEFORE the password change.
    let old_blob = std::fs::read(dir.path().join("keyset.bin")).unwrap();

    // Password change (in the unlocked state): gen → 2, floor → 2.
    core.change_password(
        Some("old".to_string()),
        Some("new".to_string()),
        secret.clone(),
    )
    .unwrap();

    // The old blob (gen 1 < floor 2), even with the correct old password, is rejected
    // via the same inst.db (anti-rollback floor in storage-meta).
    core.lock();
    let err = core
        .unlock_from_server_blob(old_blob, Some("old".to_string()), secret.clone())
        .unwrap_err();
    assert!(
        matches!(err, unissh_ffi::FfiError::Other { .. }),
        "the old blob after change_password must be rejected, got {err:?}"
    );
    assert!(!core.is_unlocked());

    // And the fresh blob (gen 2) with the new password — unlocks.
    let fresh_blob = std::fs::read(dir.path().join("keyset.bin")).unwrap();
    core.unlock_from_server_blob(fresh_blob, Some("new".to_string()), secret)
        .unwrap();
    assert!(core.is_unlocked());
}

/// NEGATIVE (anti-rollback, server-tz §13.13b): the local `Core::unlock` must
/// REJECT a stale keyset sidecar (generation below the trusted floor) — just
/// like `unlock_from_server_blob`. After a password change the floor is raised; an
/// attacker with disk access swaps the sidecar for an OLD (lower-generation) blob with
/// the correct old password — that's a downgrade, and a normal unlock must reject it.
#[test]
fn local_unlock_rejects_stale_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    let secret = core.create_account(Some("pw1".to_string())).unwrap();
    // gen 1 blob BEFORE the password change (captured for the downgrade attack).
    let stale_blob = std::fs::read(dir.path().join("keyset.bin")).unwrap();

    // Password change (in the unlocked state): gen → 2, floor → 2.
    core.change_password(
        Some("pw1".to_string()),
        Some("pw2".to_string()),
        secret.clone(),
    )
    .unwrap();

    // POSITIVE: a normal unlock with the current (gen 2 ≥ floor 2) sidecar — unlocks.
    core.lock();
    core.unlock(Some("pw2".to_string()), secret.clone())
        .unwrap();
    assert!(core.is_unlocked());

    // The attacker swaps the sidecar for the OLD blob (gen 1 < floor 2) and tries to unlock
    // with the correct old password → refused as a rollback (FfiError::Other), not InvalidCredentials.
    core.lock();
    std::fs::write(dir.path().join("keyset.bin"), &stale_blob).unwrap();
    let err = core
        .unlock(Some("pw1".to_string()), secret.clone())
        .unwrap_err();
    assert!(
        matches!(err, unissh_ffi::FfiError::Other { .. }),
        "a stale sidecar must be rejected (rollback), got {err:?}"
    );
    assert!(
        !core.is_unlocked(),
        "state must not be established on refusal"
    );
}

#[test]
fn onboarding_path_b_pake_device_to_device() {
    use unissh_ffi::{OnboardInitiatorHandle, OnboardResponderHandle};

    // Device A (initiator): an existing unlocked account.
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path());
    let sk_a = core_a.create_account(Some("pw-a".to_string())).unwrap();

    let code = b"123456".to_vec(); // short OOB code, shown to the user

    // initiator.start → handle + msg1 (relayed to the responder)
    let init = OnboardInitiatorHandle::start(code.clone());
    let msg1 = init.msg();

    // responder.respond(code, msg1) → handle + msg2 (relayed back)
    let resp = OnboardResponderHandle::respond(code.clone(), msg1).unwrap();
    let msg2 = resp.msg();

    // initiator.confirm_and_seal(msg2, sk_a) on core_a → msg3 (sealed keyset + shared SK)
    let msg3 = core_a
        .onboard_confirm_and_seal(init, msg2, sk_a.clone())
        .unwrap();

    // responder.finish_install(msg3, password) on the NEW device B
    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path());
    let sk_b = core_b
        .onboard_finish_install(resp, msg3, Some("pw-b".to_string()))
        .unwrap();
    assert!(core_b.is_unlocked());

    // Model A: device B received the SAME account Secret Key as A.
    assert_eq!(sk_a, sk_b, "shared account Secret Key on both devices");
    // And the keyset B wrote to disk really unlocks with this shared key after a
    // "restart" (a fresh Core on the same files) — otherwise the device would be locked out.
    let core_b2 = new_core(dir_b.path());
    core_b2
        .unlock(Some("pw-b".to_string()), sk_b.clone())
        .unwrap();
    assert!(core_b2.is_unlocked());

    // wrong code → ConfirmationFailed somewhere along the confirm path
    let init2 = OnboardInitiatorHandle::start(b"111111".to_vec());
    let resp2 = OnboardResponderHandle::respond(b"999999".to_vec(), init2.msg()).unwrap();
    assert!(core_a
        .onboard_confirm_and_seal(init2, resp2.msg(), sk_a.clone())
        .is_err());

    // single-use: a repeated call on a consumed handle — error
    let init3 = OnboardInitiatorHandle::start(code.clone());
    let resp3 = OnboardResponderHandle::respond(code, init3.msg()).unwrap();
    let m2b = resp3.msg();
    let _ = core_a.onboard_confirm_and_seal(init3.clone(), m2b.clone(), sk_a.clone());
    assert!(core_a
        .onboard_confirm_and_seal(init3, m2b, sk_a.clone())
        .is_err());
}

mod sync_backend {
    use std::sync::Mutex;
    use unissh_ffi::{FfiError, FfiSyncTransport, SyncDeltaItem};
    use unissh_sync::{InMemoryTransport, SyncObject, SyncTransport};

    /// "Application" side: a foreign implementation of the callback over a shared
    /// InMemoryTransport (server model). Several devices share a single Arc.
    pub struct AppTransport {
        pub inner: Mutex<InMemoryTransport>,
    }

    impl FfiSyncTransport for AppTransport {
        fn push_objects(&self, objects: Vec<Vec<u8>>) -> Result<Vec<u64>, FfiError> {
            let mut objs = Vec::with_capacity(objects.len());
            for b in &objects {
                objs.push(
                    SyncObject::from_bytes(b)
                        .map_err(|e| FfiError::Other { msg: e.to_string() })?,
                );
            }
            let mut t = self.inner.lock().unwrap();
            t.push_objects(&objs)
                .map_err(|e| FfiError::Other { msg: e.to_string() })
        }
        fn delta_since(&self, cursor: u64) -> Vec<SyncDeltaItem> {
            let t = self.inner.lock().unwrap();
            t.delta_since(cursor)
                .into_iter()
                .map(|(server_seq, o)| SyncDeltaItem {
                    server_seq,
                    object: o.to_bytes().unwrap(),
                })
                .collect()
        }
        fn report_version(&self) -> u64 {
            self.inner.lock().unwrap().report_version()
        }
    }
}

#[test]
fn sync_round_trip_via_callback_transport() {
    use std::sync::Mutex;
    use sync_backend::AppTransport;
    use unissh_sync::InMemoryTransport;

    // IMPORTANT: both devices must be the SAME owner (shared keyset/Secret Key),
    // since genesis_owner and the VK wrappers are bound to the keyset. We model it thus: A
    // creates the account, B onboards via Path A with the same keyset blob (as in Task 8).
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path());
    let secret = core_a.create_account(Some("pw".to_string())).unwrap();
    let keyset_blob = std::fs::read(dir_a.path().join("keyset.bin")).unwrap();
    // Cloud vault bound to TENANT: only vaults bound to the synced server
    // are pushed (1:1 binding). A local vault would not go out.
    core_a
        .create_cloud_vault("Synced".to_string(), TENANT.to_string())
        .unwrap();

    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path());
    core_b
        .unlock_from_server_blob(keyset_blob, Some("pw".to_string()), secret)
        .unwrap();

    // the shared "server" behind the callback
    let backend = Arc::new(AppTransport {
        inner: Mutex::new(InMemoryTransport::new()),
    });

    // A push
    let rep_a = core_a
        .sync_now(backend.clone(), TENANT.to_string())
        .unwrap();
    assert!(rep_a.pushed >= 1, "A must push at least the vault record");

    // B pull → sees A's vault
    let rep_b = core_b
        .sync_now(backend.clone(), TENANT.to_string())
        .unwrap();
    assert!(rep_b.applied >= 1, "B must apply >=1 object: {rep_b:?}");
    let vaults_b = core_b.list_vaults().unwrap();
    assert!(vaults_b.iter().any(|v| v.name == "Synced"));

    // locked negative
    core_a.lock();
    assert!(matches!(
        core_a.sync_now(backend, TENANT.to_string()),
        Err(unissh_ffi::FfiError::Locked)
    ));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn new_ffi_methods_never_return_private_key_material() {
    use unissh_ffi::{OnboardInitiatorHandle, OnboardResponderHandle};
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    // Secret Key (Emergency Kit) — the only raw secret available to the test across
    // the boundary (the keyset secrets X25519/Ed25519 themselves are not handed out by
    // design, so the test cannot obtain their 32-byte values — that is exactly the
    // boundary guarantee). No return/sidecar/relay blob must carry the raw Secret Key.
    let secret_hex = core.create_account(Some("masterpw".to_string())).unwrap();
    let secret_raw = hex::decode(secret_hex.trim()).unwrap();
    // 128-bit Secret Key (SECRET_KEY_LEN=16). We scan exactly these raw bytes — this
    // strengthens the check beyond the ASCII marker 'OPENSSH PRIVATE KEY'.
    assert_eq!(secret_raw.len(), 16, "Secret Key — 16 bytes (128 bits)");

    let vid = core
        .create_cloud_vault("Sec".to_string(), TENANT.to_string())
        .unwrap();
    core.add_member(
        vid.clone(),
        "11".repeat(32),
        "22".repeat(32),
        FfiMemberRole::Editor,
    )
    .unwrap();

    // Returns of the new methods — public/opaque material.
    let aid = core.account_id().unwrap();
    let reg = core.build_registration().unwrap();
    let members = core.list_members(vid.clone()).unwrap();
    let fp = core.member_fingerprint("11".repeat(32)).unwrap();
    let sig = core
        .sign_server_challenge(
            "h".into(),
            aid.clone(),
            "d".into(),
            "k".into(),
            b"n".to_vec(),
            1,
        )
        .unwrap();

    // Path B: msg3 = sealed keyset (relay blob). Must be encrypted — neither an OpenSSH
    // private-key marker nor raw Secret Key bytes in plaintext.
    let code = b"424242".to_vec();
    let init = OnboardInitiatorHandle::start(code.clone());
    let msg1 = init.msg();
    let resp = OnboardResponderHandle::respond(code, msg1).unwrap();
    let msg2 = resp.msg();
    let msg3 = core
        .onboard_confirm_and_seal(init, msg2, secret_hex.clone())
        .unwrap();

    // The OpenSSH private-key marker appears in none of the returns (incl. msg3).
    let marker = b"OPENSSH PRIVATE KEY";
    for blob in [reg.as_slice(), sig.as_slice(), msg3.as_slice()] {
        assert!(!contains(blob, marker), "OpenSSH marker leaked");
        // And the raw 32-byte secret (Secret Key) — also nowhere in plaintext.
        assert!(
            !contains(blob, &secret_raw),
            "raw 32-byte secret leaked into a relay/return"
        );
    }
    // account_id/fingerprint — deterministic public strings (hex), not key bytes.
    assert!(hex::decode(&aid).is_ok());
    assert_eq!(fp.len(), 64);
    assert!(members
        .iter()
        .all(|m| hex::decode(&m.ed25519_pub_hex).is_ok()));

    // On disk (after the operations) — no plaintext keyset/SSH private key and no raw
    // Secret Key bytes.
    core.lock();
    let db = std::fs::read(dir.path().join("inst.db")).unwrap();
    let keyset = std::fs::read(dir.path().join("keyset.bin")).unwrap();
    assert!(!contains(&db, marker));
    assert!(!contains(&keyset, marker));
    assert!(
        !contains(&db, &secret_raw),
        "raw Secret Key in the on-disk DB"
    );
    assert!(
        !contains(&keyset, &secret_raw),
        "raw Secret Key in the on-disk keyset sidecar"
    );
}

#[test]
fn new_methods_require_unlock() {
    use unissh_ffi::FfiError;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("L".to_string(), TENANT.to_string())
        .unwrap();
    core.lock();

    assert!(matches!(
        core.create_cloud_vault("x".into(), TENANT.to_string()),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.add_member(
            vid.clone(),
            "11".repeat(32),
            "22".repeat(32),
            FfiMemberRole::Editor
        ),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.list_members(vid.clone()),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.confirm_member_pin("a".into(), "11".repeat(32)),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.rotate_vk(vid.clone(), vec![]),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.purge_vault(vid.clone()),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.verify_chain(vid.clone()),
        Err(FfiError::Locked)
    ));
    assert!(matches!(core.account_id(), Err(FfiError::Locked)));
    assert!(matches!(core.build_registration(), Err(FfiError::Locked)));
    assert!(matches!(
        core.get_cache_policy(vid.clone()),
        Err(FfiError::Locked)
    ));
    assert!(matches!(core.audit_query(0), Err(FfiError::Locked)));
    assert!(matches!(
        core.sign_server_challenge(
            "h".into(),
            "a".into(),
            "d".into(),
            "k".into(),
            b"n".to_vec(),
            1
        ),
        Err(FfiError::Locked)
    ));
}

#[test]
fn new_methods_reject_bad_input_without_panic() {
    use unissh_ffi::FfiError;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    // corrupt hex vault_id
    assert!(matches!(
        core.list_members("zz-not-hex".into()),
        Err(FfiError::Other { .. })
    ));
    // corrupt hex/length pubkey
    let vid = core
        .create_cloud_vault("B".into(), TENANT.to_string())
        .unwrap();
    assert!(matches!(
        core.add_member(
            vid.clone(),
            "short".into(),
            "22".repeat(32),
            FfiMemberRole::Editor
        ),
        Err(FfiError::Other { .. })
    ));
    // member_fingerprint with a corrupt key
    assert!(core.member_fingerprint("nope".into()).is_err());
    // rotate without membership (a vault without a manifest) → a typed error, not a panic
    assert!(core.rotate_vk(vid.clone(), vec![]).is_err());
    // corrupt hex author in audit_append
    assert!(matches!(
        core.audit_append(vid, b"e".to_vec(), b"s".to_vec(), "zz".into()),
        Err(FfiError::Other { .. })
    ));
}

#[test]
fn e2e_cloud_membership_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(Some("pw".to_string())).unwrap();

    // 1) cloud vault
    let vid = core
        .create_cloud_vault("Project X".to_string(), TENANT.to_string())
        .unwrap();

    // 2) add two members
    let alice_ed = "a1".repeat(32);
    let alice_x = "a2".repeat(32);
    let bob_ed = "b1".repeat(32);
    let bob_x = "b2".repeat(32);
    core.add_member(
        vid.clone(),
        alice_ed.clone(),
        alice_x.clone(),
        FfiMemberRole::Admin,
    )
    .unwrap();
    core.add_member(
        vid.clone(),
        bob_ed.clone(),
        bob_x.clone(),
        FfiMemberRole::Editor,
    )
    .unwrap();

    // 3) list: owner + alice + bob, fingerprints present
    let members = core.list_members(vid.clone()).unwrap();
    assert_eq!(members.len(), 3);
    assert!(members.iter().all(|m| m.fingerprint.len() == 64));

    // 4) verify_chain ok
    assert!(core.verify_chain(vid.clone()).unwrap().ok);

    // 5) rotation: keep only alice (Admin), revoke bob
    let new_epoch = core
        .rotate_vk(
            vid.clone(),
            vec![unissh_ffi::RemainingMember {
                ed25519_pub_hex: alice_ed.clone(),
                x25519_pub_hex: alice_x.clone(),
                role: FfiMemberRole::Admin,
            }],
        )
        .unwrap();
    assert!(new_epoch >= 2);
    assert!(core.verify_chain(vid.clone()).unwrap().ok);

    // bob revoked, alice remained, owner remained
    let after = core.list_members(vid.clone()).unwrap();
    assert!(after.iter().all(|m| m.ed25519_pub_hex != bob_ed));
    assert!(after.iter().any(|m| m.ed25519_pub_hex == alice_ed));

    // 6) purge → the vault is gone
    core.purge_vault(vid.clone()).unwrap();
    assert!(core
        .list_vaults()
        .unwrap()
        .iter()
        .all(|v| v.name != "Project X"));
    // verify_chain on a deleted vault → NotFound (via Vault::open)
    assert!(matches!(
        core.verify_chain(vid),
        Err(unissh_ffi::FfiError::NotFound)
    ));
}

#[test]
fn build_registration_request_matches_signature_and_payload_shape() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    let req = core.build_registration_request().unwrap();
    // payload = u16 len(account_id=16) || account_id(16) || x25519(32) || ed25519(32)
    assert_eq!(req.payload.len(), 2 + 16 + 32 + 32);
    assert_eq!(u16::from_be_bytes([req.payload[0], req.payload[1]]), 16);
    // Signature = the same blob the sig-only method returns (the same canonical
    // payload is signed) — a guarantee that payload and signature are consistent.
    let sig_only = core.build_registration().unwrap();
    assert_eq!(req.signature, sig_only);
    assert_eq!(req.signature.len(), 67); // header(3) + ed25519 sig(64)

    // on a locked core — Locked
    core.lock();
    assert!(matches!(
        core.build_registration_request(),
        Err(unissh_ffi::FfiError::Locked)
    ));
}

#[test]
fn sign_server_challenge_raw_matches_string_variant_and_accepts_non_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    // For UTF-8-safe values the raw variant must produce the same (deterministic
    // Ed25519) signature as the string one — it only drops the UTF-8 requirement on id.
    let s = core
        .sign_server_challenge(
            "h".to_string(),
            "a".to_string(),
            "d".to_string(),
            "k".to_string(),
            b"n".to_vec(),
            1,
        )
        .unwrap();
    let r = core
        .sign_server_challenge_raw(
            b"h".to_vec(),
            b"a".to_vec(),
            b"d".to_vec(),
            b"k".to_vec(),
            b"n".to_vec(),
            1,
        )
        .unwrap();
    assert_eq!(s, r);
    assert_eq!(r.len(), 67);

    // the raw variant accepts NON-UTF8 identifiers (the server's random 16 bytes).
    let non_utf8 = vec![0u8, 159, 146, 150]; // invalid UTF-8
    let sig = core
        .sign_server_challenge_raw(
            non_utf8.clone(),
            non_utf8.clone(),
            non_utf8.clone(),
            b"k".to_vec(),
            b"nonce".to_vec(),
            42,
        )
        .unwrap();
    assert_eq!(sig.len(), 67);
}

#[test]
fn vault_info_exposes_sync_target_and_tenant() {
    use unissh_ffi::FfiSyncTarget;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    core.create_vault("local-1".to_string(), "Local".to_string())
        .unwrap();
    let cloud_hex = core
        .create_cloud_vault("Cloud".to_string(), TENANT.to_string())
        .unwrap();

    let vaults = core.list_vaults().unwrap();
    let local = vaults.iter().find(|v| v.name == "Local").unwrap();
    let cloud = vaults.iter().find(|v| v.name == "Cloud").unwrap();
    assert_eq!(local.sync_target, FfiSyncTarget::Local);
    assert_eq!(cloud.sync_target, FfiSyncTarget::Cloud);
    assert_eq!(cloud.vault_id, cloud_hex);
    // 1:1 binding: the local vault is not bound; the cloud vault is bound to TENANT (the UI
    // shows the associated server).
    assert_eq!(local.sync_tenant, None);
    assert_eq!(cloud.sync_tenant, Some(TENANT.to_string()));
}

#[test]
fn create_cloud_vault_requires_active_server() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    // Empty tenant (no active server) → refusal with a clear error.
    assert!(matches!(
        core.create_cloud_vault("X".to_string(), String::new()),
        Err(unissh_ffi::FfiError::Other { .. })
    ));
}

#[test]
fn bind_unbound_cloud_vaults_binds_legacy_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    // Simulate legacy: a cloud vault "without a server" — create it with one tenant; then,
    // since an empty binding can't be produced directly via ffi, we test the normal path:
    // the vault is created under TENANT → binding to a DIFFERENT tenant changes nothing (already bound).
    core.create_cloud_vault("Legacy".to_string(), TENANT.to_string())
        .unwrap();
    let other = "b3RoZXItdGVuYW50"; // base64("other-tenant")
                                    // An already-bound vault is not re-bound → 0 affected.
    assert_eq!(
        core.bind_unbound_cloud_vaults(other.to_string()).unwrap(),
        0
    );
    let v = core
        .list_vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.name == "Legacy")
        .unwrap();
    assert_eq!(v.sync_tenant, Some(TENANT.to_string()));

    // An empty tenant is rejected.
    assert!(core.bind_unbound_cloud_vaults(String::new()).is_err());
}

#[test]
fn sync_push_skips_vault_bound_to_other_tenant() {
    use std::sync::Mutex;
    use sync_backend::AppTransport;
    use unissh_sync::InMemoryTransport;

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    // The vault is bound to TENANT.
    core.create_cloud_vault("Bound".to_string(), TENANT.to_string())
        .unwrap();

    // Sync with a DIFFERENT tenant: the vault is not pushed (bound to another server).
    let backend = Arc::new(AppTransport {
        inner: Mutex::new(InMemoryTransport::new()),
    });
    let other = "b3RoZXItdGVuYW50"; // base64("other-tenant")
    let rep = core.sync_now(backend, other.to_string()).unwrap();
    assert_eq!(
        rep.pushed, 0,
        "vault bound to TENANT must NOT push to other tenant"
    );
}

#[test]
fn cloud_vault_can_hold_items() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("Cloud".to_string(), TENANT.to_string())
        .unwrap();
    // Put a secret in the CLOUD vault (id is hex) and read it back.
    core.save_password(vid.clone(), "p1".to_string(), "secret".to_string())
        .unwrap();
    let got = core.get_password(vid.clone(), "p1".to_string()).unwrap();
    assert_eq!(got, "secret");
    let items = core.list_items(vid).unwrap();
    assert_eq!(items.len(), 1);
}

#[test]
fn cloud_vault_rename_reflects_in_list() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("Old".to_string(), TENANT.to_string())
        .unwrap();
    core.rename_vault(vid.clone(), "New".to_string()).unwrap();
    // list_vaults reads the name cache by the RAW id — the rename must show.
    let vaults = core.list_vaults().unwrap();
    let v = vaults.iter().find(|v| v.vault_id == vid).unwrap();
    assert_eq!(v.name, "New");
}
