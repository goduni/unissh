//! Trusting a vault a teammate shared (share-accept, A0): the inspection that
//! shows the user whose fingerprint to confirm, and the targeted pull that
//! brings the vault in once its owner is pinned.
#![expect(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use std::sync::{Arc, Mutex};

use unissh_ffi::{
    Core, FfiError, FfiMemberRole, FfiSyncMode, FfiSyncTransport, FfiVaultTrust, SyncDeltaItem,
};
use unissh_sync::{InMemoryTransport, SyncObject, SyncTransport};

/// base64 `tenant_id` the cloud vaults bind to.
const TENANT: &str = "dGVuYW50LXRlc3Q="; // base64("tenant-test")

/// A sync server every account of a test shares.
struct Server {
    inner: Mutex<InMemoryTransport>,
}

impl FfiSyncTransport for Server {
    fn push_objects(&self, objects: Vec<Vec<u8>>) -> Result<Vec<u64>, FfiError> {
        let objs: Vec<SyncObject> = objects
            .iter()
            .map(|b| SyncObject::from_bytes(b).unwrap())
            .collect();
        self.inner
            .lock()
            .unwrap()
            .push_objects(&objs)
            .map_err(|e| FfiError::Other { msg: e.to_string() })
    }
    fn delta_since(&self, cursor: u64) -> Vec<SyncDeltaItem> {
        self.inner
            .lock()
            .unwrap()
            .delta_since(cursor)
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

impl Server {
    /// What `GET /v1/sync/delta?vault=<id>` serves: that vault's objects, in
    /// the order the server received them.
    fn vault_objects(&self, vault_id_hex: &str) -> Vec<Vec<u8>> {
        let raw = hex::decode(vault_id_hex).unwrap();
        self.delta_since(0)
            .into_iter()
            .map(|item| item.object)
            .filter(|o| {
                SyncObject::from_bytes(o).is_ok_and(|o| o.vault_id() == Some(raw.as_slice()))
            })
            .collect()
    }
}

/// An account of its own, unlocked.
fn account(dir: &std::path::Path) -> Arc<Core> {
    let core = Core::new(
        dir.join("inst.db").to_str().unwrap().to_owned(),
        dir.join("keyset.bin").to_str().unwrap().to_owned(),
    );
    core.create_account(None).unwrap();
    core
}

/// The account's member keys (Ed25519, X25519) in hex, read off its
/// registration payload (`… || x25519(32) || ed25519(32)`).
fn member_keys(core: &Core) -> (String, String) {
    let payload = core.build_registration_request().unwrap().payload;
    let (_, keys) = payload.split_at(payload.len() - 64);
    let (x, ed) = keys.split_at(32);
    (hex::encode(ed), hex::encode(x))
}

/// A team: the owner's account with a cloud vault shared with `member` as
/// an Editor, holding one password, all of it on the server.
struct Team {
    server: Arc<Server>,
    owner_ed: String,
    vault_id: String,
}

fn share_with(owner: &Core, member: &Core) -> Team {
    let server = Arc::new(Server {
        inner: Mutex::new(InMemoryTransport::new()),
    });
    let vault_id = owner
        .create_cloud_vault("Team".to_owned(), TENANT.to_owned())
        .unwrap();
    let (member_ed, member_x) = member_keys(member);
    owner
        .add_member(vault_id.clone(), member_ed, member_x, FfiMemberRole::Editor)
        .unwrap();
    owner
        .save_password(vault_id.clone(), "db-pw".to_owned(), "s3cr3t".to_owned())
        .unwrap();
    owner
        .sync_now(server.clone(), TENANT.to_owned(), FfiSyncMode::Full)
        .unwrap();
    Team {
        server,
        owner_ed: member_keys(owner).0,
        vault_id,
    }
}

/// The member is shown the vault's creator — the author of its verified
/// genesis — with the fingerprint to compare, and its own role; nothing is
/// pinned or written by looking.
#[test]
fn inspection_names_the_owner_a_granted_member_confirms() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);

    let info = member
        .inspect_shared_vault(
            team.vault_id.clone(),
            team.server.vault_objects(&team.vault_id),
        )
        .unwrap();

    assert_eq!(info.owner_ed25519_hex, team.owner_ed);
    assert_eq!(
        info.fingerprint,
        member.member_fingerprint(team.owner_ed.clone()).unwrap()
    );
    assert_eq!(
        info.fingerprint,
        owner.own_fingerprint().unwrap(),
        "what the owner reads out from their own device"
    );
    assert_eq!(info.my_role, FfiMemberRole::Editor);
    assert_eq!(info.trust, FfiVaultTrust::NotPinned);
    assert!(
        member.list_vaults().unwrap().is_empty(),
        "inspecting writes nothing"
    );
}

/// A server that adds a genesis signed by another key next to the real one
/// is offering a second owner: the vault is not offered for trust at all.
#[test]
fn inspection_refuses_a_vault_the_server_gives_a_second_creator() {
    use unissh_crypto::KdfParams;
    use unissh_storage::MemberRole;
    use unissh_vault::{build_manifest, Member};

    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);
    let params = KdfParams {
        mem_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
        salt: vec![1_u8; 16],
    };
    let (_sk, _enc, impostor) = unissh_keychain::create_account(Some(b"pw"), params).unwrap();
    let impostor_ed = impostor.signing.verifying.to_bytes().to_vec();
    let forged = build_manifest(
        &impostor,
        &hex::decode(&team.vault_id).unwrap(),
        1,
        &[
            Member {
                ed25519_pub: impostor_ed,
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: hex::decode(member_keys(&member).0).unwrap(),
                role: MemberRole::Editor,
            },
        ],
    )
    .unwrap();
    let mut objects = team.server.vault_objects(&team.vault_id);
    objects.push(SyncObject::MembershipManifest(forged).to_bytes().unwrap());

    let err = member
        .inspect_shared_vault(team.vault_id, objects)
        .unwrap_err();

    assert!(err.to_string().contains("two different creators"), "{err}");
}

/// An account the vault was not shared with is refused: the chain verifies,
/// but no grant at the latest epoch opens with its key.
#[test]
fn inspection_refuses_a_vault_that_grants_this_account_nothing() {
    let dirs = [
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    ];
    let owner = account(dirs[0].path());
    let member = account(dirs[1].path());
    let outsider = account(dirs[2].path());
    let team = share_with(&owner, &member);

    let err = outsider
        .inspect_shared_vault(
            team.vault_id.clone(),
            team.server.vault_objects(&team.vault_id),
        )
        .unwrap_err();

    assert!(
        err.to_string().contains("grants this account nothing"),
        "{err}"
    );
}

/// A sync before the pin rejects the vault and moves the pull cursor past it,
/// so a sync after the pin does not bring it; the targeted pull does.
#[test]
fn a_rejected_shared_vault_arrives_by_targeted_pull_once_its_owner_is_pinned() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);
    let before = member
        .sync_now(team.server.clone(), TENANT.to_owned(), FfiSyncMode::Full)
        .unwrap();
    assert!(before.rejected > 0, "{before:?}");

    member
        .pin_vault_genesis_owner(team.vault_id.clone(), team.owner_ed.clone())
        .unwrap();
    member
        .sync_now(team.server.clone(), TENANT.to_owned(), FfiSyncMode::Full)
        .unwrap();
    assert!(
        member.list_vaults().unwrap().is_empty(),
        "the cursor already moved past the vault"
    );
    // One object per page, as a server pages a large vault.
    let objects = team.server.vault_objects(&team.vault_id);
    let report = member
        .pull_vault_paged(TENANT, |cursor| {
            let at = usize::try_from(cursor).unwrap();
            let next = (at + 1 < objects.len()).then_some(cursor + 1);
            (objects.get(at).cloned().into_iter().collect(), next)
        })
        .unwrap();

    assert_eq!(report.rejected, 0, "{report:?}");
    assert_eq!(
        member
            .get_password(team.vault_id, "db-pw".to_owned())
            .unwrap(),
        "s3cr3t"
    );
}
