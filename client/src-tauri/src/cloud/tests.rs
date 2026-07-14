//! Live end-to-end integration tests against a real `unissh-server` subprocess.
//!
//! Ignored by default (they need the server binary built + free TCP ports). Run:
//! ```text
//! cargo build -p unissh-server            # from the workspace root (../../)
//! cd client/src-tauri && cargo test cloud::tests -- --ignored --nocapture
//! ```
//! They exercise the real HTTP/crypto/sync chain the cloud client drives, on the
//! instance-scoped server (v2): claim (owner + first space) → auth → cloud vault →
//! one-link invite → a distinct account joins → owner grants it into the vault →
//! sync push/pull → a second (sibling) device reads the shared secret. Plus the
//! device-to-device PAKE onboarding path (Path B) and keyless escrow recovery (Path A).

use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use unissh_ffi::{Core, FfiMemberRole};

use crate::cloud::transport::HttpSyncTransport;
use crate::cloud::{client, identity};

/// The fixed setup code the spawned server boots with (`[setup] code`). Any stable
/// value works — the test sets it in the config and presents it verbatim on claim.
const SETUP_CODE: &str = "integration-test-setup-code";

struct ServerProc {
    child: Child,
    base_url: String,
    _dir: tempfile::TempDir,
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Path to the workspace-built server binary (sibling workspace `target/`).
fn server_binary() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/unissh-server")
}

/// The server crate dir — its CWD when running, so it can resolve the relative
/// `./migrations/sqlite` path.
fn server_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Spawn the server with an isolated SQLite DB + a fixed setup code (instance-scoped
/// v2 config: `[setup] code`, no bootstrap token / tenant). Returns `None` (skip) if
/// the binary hasn't been built.
fn spawn_server() -> Option<ServerProc> {
    let bin = server_binary();
    if !bin.exists() {
        eprintln!(
            "SKIP: server binary not found at {} — run `cargo build -p unissh-server` first",
            bin.display()
        );
        return None;
    }
    let dir = tempfile::tempdir().ok()?;
    let port = free_port();
    let metrics_port = free_port();
    let db_path = dir.path().join("unissh.db");
    let cfg_path = dir.path().join("config.toml");
    // v2 (instance-scoped) config. `[setup] code` is the single-winner claim
    // authorization — the first claimer becomes the instance owner. No `[bootstrap]`
    // token / tier / tenant exists anymore. `validate_signatures` is left at its
    // default (on): the client pushes genuinely core-signed objects, so server-side
    // signature validation is satisfied (unlike the server's own unit tests, which
    // push synthetic dummy-signed objects and disable it).
    let config = format!(
        "[server]\n\
         bind = \"127.0.0.1:{port}\"\n\
         tls_cert = \"\"\n\
         tls_key = \"\"\n\
         trust_proxy = true\n\n\
         [db]\n\
         backend = \"sqlite\"\n\
         url = \"{db}\"\n\n\
         [setup]\n\
         code = \"{code}\"\n\n\
         [obs]\n\
         metrics_bind = \"127.0.0.1:{metrics_port}\"\n\
         log_format = \"text\"\n",
        port = port,
        db = db_path.to_string_lossy(),
        code = SETUP_CODE,
        metrics_port = metrics_port,
    );
    {
        let mut f = std::fs::File::create(&cfg_path).ok()?;
        f.write_all(config.as_bytes()).ok()?;
    }
    let child = Command::new(&bin)
        .current_dir(server_dir())
        .arg("--config")
        .arg(&cfg_path)
        .spawn()
        .ok()?;

    let base_url = format!("http://127.0.0.1:{port}");
    // The binary IS present here, so a start failure is a real problem — fail loud
    // (the `proc` owns the child, so its Drop kills the server even on panic).
    let proc = ServerProc {
        child,
        base_url: base_url.clone(),
        _dir: dir,
    };
    assert!(
        wait_ready(&base_url),
        "unissh-server did not become ready on {base_url} (see its stderr above)"
    );
    Some(proc)
}

fn wait_ready(base_url: &str) -> bool {
    let http = client::http();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(r) = http.get(format!("{base_url}/readyz")).send() {
            if r.status().is_success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn new_core(dir: &std::path::Path, name: &str) -> Arc<Core> {
    Core::new(
        dir.join(format!("{name}.db")).to_string_lossy().to_string(),
        dir.join(format!("{name}.keyset.bin"))
            .to_string_lossy()
            .to_string(),
    )
}

/// Locate an account (by server id) in the owner's `/v1/accounts` listing and return
/// its `(ed25519_pub_hex, x25519_pub_hex)` — the hex public material that feeds
/// `add_member` / `pin_vault_genesis_owner`.
fn account_pubkeys(accounts: &[crate::dto::AccountInfo], account_id: &str) -> (String, String) {
    let a = accounts
        .iter()
        .find(|a| a.account_id == account_id)
        .unwrap_or_else(|| panic!("account {account_id} should appear in /v1/accounts"));
    (
        a.ed25519_pub_hex
            .clone()
            .expect("account has an ed25519 pubkey"),
        a.x25519_pub_hex
            .clone()
            .expect("account has an x25519 pubkey"),
    )
}

#[test]
#[ignore = "needs `cargo build -p unissh-server` + free TCP ports"]
fn live_e2e_claim_invite_join_and_two_device_sync() {
    let srv = match spawn_server() {
        Some(s) => s,
        None => return, // skipped (binary absent)
    };
    let base = &srv.base_url;
    let http = client::http();

    // ── Device A: claim the instance (owner + first space) + login ─────────────
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path(), "a");
    let secret_a = core_a.create_account(None).unwrap();

    let reg_a = core_a.build_registration_request().unwrap();
    let out_a = identity::claim(
        http,
        base,
        SETUP_CODE,
        reg_a,
        Some("Owner".into()),
        Some("owner".into()),
        Some("Shared".into()),
    )
    .expect("claim should succeed");
    assert!(!out_a.account_id.is_empty());
    assert!(!out_a.device_id.is_empty());
    // The claim seeds the owner's first space; the cloud vault binds to it.
    let space = out_a.space_id.clone();

    let session_a = identity::login(http, base, &core_a, &out_a.account_id, &out_a.device_id)
        .expect("A login should succeed");
    assert!(!session_a.access_token.is_empty());

    // ── Device A creates the cloud vault bound to the space ────────────────────
    let vid = core_a
        .create_cloud_vault("Shared".into(), space.clone())
        .unwrap();

    // ── Owner mints a one-link invite for the space (role = member) ────────────
    let invite = identity::invite(http, base, &session_a.access_token, &space, "member", None)
        .expect("owner mints an invite for its own space");
    assert!(!invite.token.is_empty(), "invite carries a one-shot token");

    // ── Device B: a DISTINCT account (its OWN keyset) joins via the invite ──────
    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path(), "b");
    let _secret_b = core_b.create_account(None).unwrap();
    let reg_b = core_b.build_registration_request().unwrap();
    let out_b = identity::join(
        http,
        base,
        &invite.token,
        reg_b,
        None, // binding_mac: the server accepts a join without it
        Some("Member".into()),
        Some("member".into()),
    )
    .expect("B joins via the invite");
    assert!(!out_b.account_id.is_empty());
    assert_ne!(
        out_b.account_id, out_a.account_id,
        "B is a distinct account, not a sibling device of A"
    );
    assert!(
        out_b.spaces.iter().any(|s| s == &space),
        "the join grants B membership of the shared space"
    );

    let session_b = identity::login(http, base, &core_b, &out_b.account_id, &out_b.device_id)
        .expect("B login should succeed");
    assert!(!session_b.access_token.is_empty());

    // ── Owner grants B into the cloud vault (a real signed manifest + grant at a
    //    new epoch, wrapping the vault key under B's real X25519 key) ───────────
    // A resolves both accounts' public keys from the owner-only directory (hex).
    let accounts =
        identity::list_accounts(http, base, &session_a.access_token).expect("owner lists accounts");
    let (a_ed_hex, _a_x_hex) = account_pubkeys(&accounts, &out_a.account_id);
    let (b_ed_hex, b_x_hex) = account_pubkeys(&accounts, &out_b.account_id);

    core_a
        .add_member(vid.clone(), b_ed_hex, b_x_hex, FfiMemberRole::Editor)
        .expect("owner adds B as a vault member");
    // Store the SECRET AFTER establishing membership, so the item is stamped at the
    // membership epoch B's grant unlocks (mirrors the vault crate's proven ordering).
    core_a
        .save_password(vid.clone(), "db-pw".into(), "s3cr3t".into())
        .expect("owner stores a secret in the cloud vault");

    // ── A pushes vault + membership manifest + B's grant + the item ────────────
    let transport_a: Arc<dyn unissh_ffi::FfiSyncTransport> = Arc::new(HttpSyncTransport::new(
        base.clone(),
        session_a.access_token.clone(),
    ));
    let report_a = core_a
        .sync_now(transport_a, space.clone())
        .expect("A sync_now should succeed");
    assert!(
        report_a.pushed >= 1,
        "A should push the vault + membership + item objects: {report_a:?}"
    );

    // ── B (the granted member) pulls the shared vault ──────────────────────────
    // B first pins A as the vault's genesis owner (the TOFU share-accept step), so the
    // untrusted-DB authority checks verify A's objects against the RIGHT anchor rather
    // than defaulting to B's own keyset (which would reject them).
    core_b
        .pin_vault_genesis_owner(vid.clone(), a_ed_hex)
        .expect("B pins A as the shared vault's genesis owner");
    let transport_b: Arc<dyn unissh_ffi::FfiSyncTransport> = Arc::new(HttpSyncTransport::new(
        base.clone(),
        session_b.access_token.clone(),
    ));
    let report_b = core_b
        .sync_now(transport_b, space.clone())
        .expect("B sync_now should succeed");
    // The membership grant makes B's server-side delta include the shared vault's
    // objects (server delta visibility is grant-scoped at the latest epoch), and B
    // accepts them after pinning A. This proves the full invite → join → grant →
    // cross-account visibility chain over the real server.
    assert!(
        report_b.applied >= 1,
        "B should receive & accept A's shared-vault objects after the grant: {report_b:?}"
    );
    // DECISIVE: B — a DISTINCT account, not a sibling device of A — decrypts the shared
    // secret through the ordinary FFI read surface using ITS OWN keyset. B's grant wraps
    // the VK under B's X25519 key, and `Vault::open` now takes the member path
    // (open_grant, anchored on the pinned genesis owner A) instead of the owner-only
    // wrap. This proves the full cross-account chain: invite → join → grant → member
    // decrypt over the real server.
    let member_pw = core_b
        .get_password(vid.clone(), "db-pw".into())
        .expect("B (distinct account) decrypts the shared secret via its own grant");
    assert_eq!(
        member_pw, "s3cr3t",
        "the member-decrypted secret must match byte-for-byte"
    );

    // Below: the owner read path via a sibling device (A2, sharing A's keyset) is kept
    // as a control that the owner-wrap path is unchanged.

    // ── Device A2 (a sibling of A, shared keyset): the decisive secret read ─────
    let device_a2 = identity::device_add(http, base, &session_a.access_token)
        .expect("devices/add should succeed");
    let keyset_blob = std::fs::read(dir_a.path().join("a.keyset.bin")).unwrap();
    let dir_a2 = tempfile::tempdir().unwrap();
    let core_a2 = new_core(dir_a2.path(), "a2");
    core_a2
        .unlock_from_server_blob(keyset_blob, None, secret_a)
        .expect("A2 unlocks from A's keyset blob (Path A shared keyset)");
    let session_a2 = identity::login(http, base, &core_a2, &out_a.account_id, &device_a2)
        .expect("A2 login with the shared keyset should succeed");

    let transport_a2: Arc<dyn unissh_ffi::FfiSyncTransport> = Arc::new(HttpSyncTransport::new(
        base.clone(),
        session_a2.access_token.clone(),
    ));
    let report_a2 = core_a2
        .sync_now(transport_a2, space.clone())
        .expect("A2 sync_now should succeed");
    assert!(
        report_a2.applied >= 1,
        "A2 should apply at least one object from A: {report_a2:?}"
    );
    let vaults_a2 = core_a2.list_vaults().unwrap();
    assert!(
        vaults_a2.iter().any(|v| v.name == "Shared"),
        "A2 sees the shared cloud vault after pull"
    );
    let pw = core_a2
        .get_password(vid.clone(), "db-pw".into())
        .expect("A2 reads the secret synced into the cloud vault");
    assert_eq!(pw, "s3cr3t", "the synced secret must match byte-for-byte");

    // ── Session lifecycle: refresh + logout round-trip (on B's session). ───────
    let refreshed =
        identity::refresh(http, base, &session_b.refresh_token).expect("refresh should succeed");
    assert!(!refreshed.access_token.is_empty());
    identity::logout(http, base, &refreshed.access_token).expect("logout should succeed");
}

/// Path B (device-to-device PAKE onboarding) end-to-end through the real server
/// relay, exercising the SHARED-account-key model (model A): device A seals its
/// own Secret Key into the transfer; device B reuses it. Asserts B opens, B's
/// on-disk keyset re-unlocks with A's Secret Key (proving the shared wrap), and
/// B authenticates to the server with the transferred keyset.
#[test]
#[ignore = "needs `cargo build -p unissh-server` + free TCP ports"]
fn live_e2e_path_b_pake_onboarding_shares_account_secret_key() {
    let srv = match spawn_server() {
        Some(s) => s,
        None => return, // skipped (binary absent)
    };
    let base = srv.base_url.clone();
    let http = client::http();

    // ── Device A: claim the instance + login (existing, authenticated device) ──
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path(), "a");
    let secret_a = core_a.create_account(Some("pw-a".into())).unwrap();
    let reg = core_a.build_registration_request().unwrap();
    let out_a = identity::claim(
        http,
        &base,
        SETUP_CODE,
        reg,
        Some("Alice".into()),
        Some("alice".into()),
        Some("Personal".into()),
    )
    .expect("claim should succeed");
    let session_a = identity::login(http, &base, &core_a, &out_a.account_id, &out_a.device_id)
        .expect("A login should succeed");

    // ── A initiates pairing: pre-create device B + open a relay channel ───────
    let device_b = identity::device_add(http, &base, &session_a.access_token).expect("device_add");
    let channel_id =
        identity::relay_open(http, &base, &session_a.access_token).expect("relay_open");
    // Shared OOB code (raw bytes — both sides key the PAKE off the same value).
    let oob = uuid::Uuid::new_v4().as_bytes().to_vec();

    // Initiator runs concurrently (it blocks polling the relay for msg2).
    let initiator = {
        let base = base.clone();
        let channel_id = channel_id.clone();
        let oob = oob.clone();
        let core_a = core_a.clone();
        let secret_a = secret_a.clone();
        std::thread::spawn(move || {
            crate::cloud::onboard::initiator_complete(
                &core_a,
                client::http(),
                &base,
                &channel_id,
                oob,
                secret_a,
            )
        })
    };

    // ── Device B (responder): no prior local state ────────────────────────────
    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path(), "b");
    crate::cloud::onboard::responder_join(
        &core_b,
        http,
        &base,
        &channel_id,
        oob,
        Some("pw-b".into()),
    )
    .expect("B responder_join should succeed");
    initiator
        .join()
        .unwrap()
        .expect("A initiator_complete should succeed");

    assert!(core_b.is_unlocked(), "B is unlocked right after join");

    // Model A, decisive: B's on-disk keyset is wrapped with the SHARED account
    // Secret Key. A fresh Core on B's files (≈ restart) unlocks with A's key — it
    // would FAIL if B had minted its own discarded key (the bug this flow fixes).
    let core_b2 = new_core(dir_b.path(), "b");
    core_b2
        .unlock(Some("pw-b".into()), secret_a.clone())
        .expect("B re-unlocks its persisted keyset with the SHARED Secret Key");
    assert!(core_b2.is_unlocked());

    // And B is a real device on the server: it authenticates with the keyset it
    // received over the PAKE channel.
    let session_b = identity::login(http, &base, &core_b, &out_a.account_id, &device_b)
        .expect("B login with the transferred keyset should succeed");
    assert!(!session_b.access_token.is_empty());
}

/// Path A keyless escrow recovery end-to-end: device A arms escrow sign-in for its
/// keyset (password + Secret Key), then a FRESH device C — holding only the handle,
/// password and Secret Key (an Emergency Kit), with no session and no device — re-
/// derives `K_auth`, fetches the escrowed keyset by handle, unlocks, authenticates,
/// and reads back the secret A stored in the cloud vault byte-for-byte.
#[test]
#[ignore = "needs `cargo build -p unissh-server` + free TCP ports"]
fn live_e2e_escrow_recovery() {
    let srv = match spawn_server() {
        Some(s) => s,
        None => return, // skipped (binary absent)
    };
    let base = &srv.base_url;
    let http = client::http();

    // ── Device A: claim (handle "alice") + login. A password-backed account, so
    //    escrow arms the password+SecretKey sign-in. ───────────────────────────
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path(), "a");
    let secret_a = core_a.create_account(Some("pw-a".into())).unwrap();
    let reg_a = core_a.build_registration_request().unwrap();
    let out_a = identity::claim(
        http,
        base,
        SETUP_CODE,
        reg_a,
        Some("Alice".into()),
        Some("alice".into()),
        Some("Shared".into()),
    )
    .expect("claim should succeed");
    let space = out_a.space_id.clone();
    let session_a = identity::login(http, base, &core_a, &out_a.account_id, &out_a.device_id)
        .expect("A login should succeed");

    // ── A creates a cloud vault + stores a secret + pushes ─────────────────────
    let vid = core_a
        .create_cloud_vault("Shared".into(), space.clone())
        .unwrap();
    // A synthetic member establishes the membership manifest (mirrors the unit tests);
    // A stays Admin and remains the vault's owner, so the owner read path is unaffected.
    core_a
        .add_member(
            vid.clone(),
            "11".repeat(32),
            "22".repeat(32),
            FfiMemberRole::Editor,
        )
        .unwrap();
    core_a
        .save_password(vid.clone(), "db-pw".into(), "s3cr3t".into())
        .expect("storing a secret in the cloud vault should work");
    let transport_a: Arc<dyn unissh_ffi::FfiSyncTransport> = Arc::new(HttpSyncTransport::new(
        base.clone(),
        session_a.access_token.clone(),
    ));
    let report_a = core_a
        .sync_now(transport_a, space.clone())
        .expect("A sync_now should succeed");
    assert!(
        report_a.pushed >= 1,
        "A should push the vault: {report_a:?}"
    );

    // ── A arms keyless escrow for its keyset: derive K_auth + params ONCE from the
    //    SAME (password, Secret Key) that wraps the blob, and PUT them together. ─
    let blob_a = std::fs::read(dir_a.path().join("a.keyset.bin")).unwrap();
    let creds = core_a
        .derive_escrow_credentials(Some("pw-a".into()), secret_a.clone())
        .expect("derive escrow credentials");
    let enroll = identity::EscrowEnroll {
        k_auth: creds.k_auth,
        argon_salt: creds.argon_salt,
        argon_mem_kib: creds.argon_mem_kib,
        argon_iterations: creds.argon_iterations,
        argon_parallelism: creds.argon_parallelism,
    };
    let generation =
        identity::keyset_put(http, base, &session_a.access_token, &blob_a, Some(&enroll))
            .expect("escrow-enrolling keyset PUT should succeed");
    assert!(generation >= 1, "the escrowed keyset has a generation");

    // ── Device C (fresh, no session, no device): keyless recovery by handle ────
    let dir_c = tempfile::tempdir().unwrap();
    let core_c = new_core(dir_c.path(), "c");

    // Re-derive K_auth with the SERVER-STORED params (enroll/fetch symmetry).
    let params = identity::escrow_params(http, base, "alice").expect("escrow params");
    let k_auth = core_c
        .derive_escrow_auth_with_params(
            Some("pw-a".into()),
            secret_a.clone(),
            params.argon_salt,
            params.argon_mem_kib,
            params.argon_iterations,
            params.argon_parallelism,
        )
        .expect("re-derive K_auth from the Emergency Kit");
    let recovered = identity::escrow_fetch(http, base, "alice", &k_auth).expect("escrow fetch");
    assert_eq!(
        recovered, blob_a,
        "the fetched keyset blob is exactly A's uploaded blob"
    );
    core_c
        .unlock_from_server_blob(recovered, Some("pw-a".into()), secret_a.clone())
        .expect("C unlocks from the escrowed keyset blob");

    // C now holds A's account keyset (shared). It authenticates as an existing device
    // of the account (the recovered keyset signs the challenge) and syncs.
    let session_c = identity::login(http, base, &core_c, &out_a.account_id, &out_a.device_id)
        .expect("C login with the recovered keyset should succeed");
    let transport_c: Arc<dyn unissh_ffi::FfiSyncTransport> = Arc::new(HttpSyncTransport::new(
        base.clone(),
        session_c.access_token.clone(),
    ));
    let report_c = core_c
        .sync_now(transport_c, space.clone())
        .expect("C sync_now should succeed");
    assert!(
        report_c.applied >= 1,
        "C should apply A's cloud-vault objects: {report_c:?}"
    );

    // Decisive: C reads back the secret A stored, byte-for-byte (owner read path).
    let vaults_c = core_c.list_vaults().unwrap();
    assert!(
        vaults_c.iter().any(|v| v.name == "Shared"),
        "C sees the shared cloud vault after recovery + pull"
    );
    let pw = core_c
        .get_password(vid.clone(), "db-pw".into())
        .expect("C reads the secret from the recovered vault");
    assert_eq!(
        pw, "s3cr3t",
        "the recovered secret must match byte-for-byte"
    );
}
