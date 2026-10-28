//! Trusting a vault a teammate shared (share-accept, A0): the inspection that
//! shows the user whose fingerprint to confirm, and the targeted pull that
//! brings the vault in once its owner is pinned.
#![expect(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use std::sync::{Arc, Mutex};

use unissh_crypto::KdfParams;
use unissh_ffi::{
    grouped_fingerprint, Core, FfiError, FfiMemberRole, FfiSyncMode, FfiSyncTransport,
    FfiTrustOutcome, FfiVaultTrust, SharedVaultInfo, SyncDeltaItem,
};
use unissh_keychain::UnlockedKeyset;
use unissh_storage::{MemberRole, MembershipManifest};
use unissh_sync::{InMemoryTransport, SyncObject, SyncTransport};
use unissh_vault::{build_manifest, Member};

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

/// A keyset of an account the server could slip in as a vault's owner.
fn impostor() -> UnlockedKeyset {
    let params = KdfParams {
        mem_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
        salt: vec![1_u8; 16],
    };
    unissh_keychain::create_account(Some(b"pw"), params)
        .unwrap()
        .2
}

/// A manifest `signer` signs for the team's vault at `epoch`, naming itself
/// an Admin and `member` an Editor: a valid signature, no authority.
fn forged(signer: &UnlockedKeyset, team: &Team, member: &Core, epoch: u64) -> MembershipManifest {
    build_manifest(
        signer,
        &hex::decode(&team.vault_id).unwrap(),
        epoch,
        &[
            Member {
                ed25519_pub: signer.signing.verifying.to_bytes().to_vec(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: hex::decode(member_keys(member).0).unwrap(),
                role: MemberRole::Editor,
            },
        ],
    )
    .unwrap()
}

/// The team's vault objects with `extra` manifests added after them.
fn served_with(team: &Team, extra: Vec<MembershipManifest>) -> Vec<Vec<u8>> {
    let mut objects = team.server.vault_objects(&team.vault_id);
    objects.extend(
        extra
            .into_iter()
            .map(|m| SyncObject::MembershipManifest(m).to_bytes().unwrap()),
    );
    objects
}

/// What `member` sees of the team's vault as the server serves it.
fn inspected(member: &Core, team: &Team) -> SharedVaultInfo {
    member
        .inspect_shared_vault(
            team.vault_id.clone(),
            team.server.vault_objects(&team.vault_id),
        )
        .unwrap()
        .unwrap()
}

/// `member` trusts the team's vault owner by `fingerprint`.
fn trust(member: &Core, team: &Team, fingerprint: &str) -> FfiTrustOutcome {
    member
        .trust_shared_vault(
            team.vault_id.clone(),
            team.server.vault_objects(&team.vault_id),
            fingerprint.to_owned(),
        )
        .unwrap()
}

/// The member is shown the vault's creator — the author of its verified
/// genesis — with the fingerprint to compare, and its own role; nothing is
/// pinned or written by looking.
#[test]
fn inspection_names_the_owner_a_granted_member_confirms() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);

    let info = inspected(&member, &team);

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
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);
    let objects = served_with(&team, vec![forged(&impostor(), &team, &member, 1)]);

    let err = member
        .inspect_shared_vault(team.vault_id, objects)
        .unwrap_err();

    assert!(err.to_string().contains("two different creators"), "{err}");
}

/// A second genesis whose signature does not verify stands for no creator:
/// it neither refuses the vault nor changes whose it is.
#[test]
fn inspection_ignores_a_second_genesis_that_does_not_verify() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);
    let mut bogus = forged(&impostor(), &team, &member, 1);
    bogus.signature[0] ^= 0xff;
    let objects = served_with(&team, vec![bogus]);

    let info = member
        .inspect_shared_vault(team.vault_id.clone(), objects)
        .unwrap()
        .unwrap();

    assert_eq!(info.owner_ed25519_hex, team.owner_ed);
}

/// A later epoch signed by a key with no authority breaks the chain: the
/// vault is refused, not offered at the epoch before.
#[test]
fn inspection_refuses_a_chain_that_breaks_at_a_later_epoch() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);
    let next = inspected(&member, &team).epoch + 1;
    let objects = served_with(&team, vec![forged(&impostor(), &team, &member, next)]);

    let err = member
        .inspect_shared_vault(team.vault_id, objects)
        .unwrap_err();

    assert!(err.to_string().contains("does not verify"), "{err}");
}

/// An epoch missing between genesis and the latest one served is a gap.
#[test]
fn inspection_refuses_a_chain_with_a_gap() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);
    let beyond = inspected(&member, &team).epoch + 2;
    let objects = served_with(&team, vec![forged(&impostor(), &team, &member, beyond)]);

    let err = member
        .inspect_shared_vault(team.vault_id, objects)
        .unwrap_err();

    assert!(err.to_string().contains("gap"), "{err}");
}

/// A server that floods one epoch with manifests is refused rather than
/// walked: the kept set per epoch is capped.
#[test]
fn inspection_refuses_an_epoch_flooded_with_manifests() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);
    let signer = impostor();
    let flood = (0..9_u8)
        .map(|n| {
            let mut m = forged(&signer, &team, &member, 1);
            m.signature[0] = n;
            m
        })
        .collect();

    let err = member
        .inspect_shared_vault(team.vault_id.clone(), served_with(&team, flood))
        .unwrap_err();

    assert!(err.to_string().contains("too many"), "{err}");
}

/// A vault this account created needs no trust, through the one-piece
/// entry point as through the paged one.
#[test]
fn inspecting_an_own_vault_says_it_needs_no_trust() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);

    let own = owner
        .inspect_shared_vault(
            team.vault_id.clone(),
            team.server.vault_objects(&team.vault_id),
        )
        .unwrap();

    assert_eq!(own, None);
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

    let fingerprint = grouped_fingerprint(owner.own_fingerprint().unwrap()).to_uppercase();
    assert_eq!(
        trust(&member, &team, &fingerprint),
        FfiTrustOutcome::Trusted,
        "the owner's fingerprint, in any grouping or case"
    );
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
            Ok((objects.get(at).cloned().into_iter().collect(), next))
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

/// A fingerprint that is not the owner's pins nothing.
#[test]
fn a_wrong_fingerprint_trusts_nothing() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);
    let wrong = member.member_fingerprint(member_keys(&member).0).unwrap();

    assert_eq!(
        trust(&member, &team, &wrong),
        FfiTrustOutcome::FingerprintMismatch
    );
    assert_eq!(inspected(&member, &team).trust, FfiVaultTrust::NotPinned);
}

/// Once this device trusts an owner for a vault, a server that names a
/// different creator is reported as such and the pin stays as it was, even
/// for the fingerprint of the creator the server now names.
#[test]
fn a_vault_pinned_to_another_owner_is_refused() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);
    let earlier = impostor().signing.verifying.to_bytes();
    member
        .pin_vault_genesis_owner(team.vault_id.clone(), hex::encode(earlier))
        .unwrap();

    let outcome = trust(&member, &team, &owner.own_fingerprint().unwrap());

    assert_eq!(outcome, FfiTrustOutcome::PinnedToAnotherOwner);
    assert_eq!(
        inspected(&member, &team).trust,
        FfiVaultTrust::PinnedToAnotherOwner
    );
}

/// A page that cannot be read ends the targeted pull with an error saying
/// it was cut short, never with a report that looks complete.
#[test]
fn a_targeted_pull_cut_short_is_an_error() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (owner, member) = (account(dir_a.path()), account(dir_b.path()));
    let team = share_with(&owner, &member);
    trust(&member, &team, &owner.own_fingerprint().unwrap());
    let objects = team.server.vault_objects(&team.vault_id);

    let err = member
        .pull_vault_paged(TENANT, |cursor| {
            if cursor == 0 {
                Ok((objects.iter().take(1).cloned().collect(), Some(1)))
            } else {
                Err(FfiError::Other {
                    msg: "connection reset".to_owned(),
                })
            }
        })
        .unwrap_err();

    assert!(err.to_string().contains("cut short"), "{err}");
}

/// Locked, the account's fingerprint is still read, off the public half of
/// the keyset file: it is the same one as unlocked.
#[test]
fn the_own_fingerprint_reads_while_locked() {
    let dir = tempfile::tempdir().unwrap();
    let core = account(dir.path());
    let unlocked = core.own_fingerprint().unwrap();

    core.lock();

    assert_eq!(core.own_fingerprint().unwrap(), unlocked);
}
