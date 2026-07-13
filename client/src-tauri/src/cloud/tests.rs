//! Live end-to-end integration tests against a real `unissh-server` subprocess.
//!
//! Ignored by default (they need the server binary built + free TCP ports). Run:
//! ```text
//! cargo build -p unissh-server            # from the workspace root (../../)
//! cd client/src-tauri && cargo test cloud::tests -- --ignored --nocapture
//! ```
//! They exercise the real HTTP/crypto/sync chain my cloud client drives:
//! bootstrap → auth → cloud vault → membership → sync push → second device
//! (shared keyset, Path A) → auth → sync pull → cross-device vault visibility.

use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use unissh_ffi::{Core, FfiMemberRole};

use crate::cloud::transport::HttpSyncTransport;
use crate::cloud::{client, identity};

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

/// Spawn the server with an isolated SQLite DB + bootstrap token. Returns `None`
/// (skip) if the binary hasn't been built.
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
    let config = format!(
        "[server]\n\
         bind = \"127.0.0.1:{port}\"\n\
         tls_cert = \"\"\n\
         tls_key = \"\"\n\
         trust_proxy = true\n\n\
         [db]\n\
         backend = \"sqlite\"\n\
         url = \"{db}\"\n\n\
         [bootstrap]\n\
         token = \"{token}\"\n\
         default_tier = \"personal\"\n\n\
         [obs]\n\
         metrics_bind = \"127.0.0.1:{metrics_port}\"\n\
         log_format = \"text\"\n",
        port = port,
        db = db_path.to_string_lossy(),
        token = SETUP_CODE,
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

#[test]
#[ignore = "needs `cargo build -p unissh-server` + free TCP ports"]
fn live_e2e_bootstrap_auth_cloud_vault_membership_and_two_device_sync() {
    let srv = match spawn_server() {
        Some(s) => s,
        None => return, // skipped (binary absent)
    };
    let base = &srv.base_url;
    let http = client::http();

    // ── Device A: claim the instance + login ───────────────────────────────
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path(), "a");
    let secret = core_a.create_account(None).unwrap();

    let reg = core_a.build_registration_request().unwrap();
    let out_a = identity::claim(
        http,
        base,
        SETUP_CODE,
        reg,
        Some("Alice".into()),
        Some("alice".into()),
        Some("personal".into()),
    )
    .expect("claim should succeed");
    assert!(!out_a.account_id.is_empty());
    assert!(!out_a.device_id.is_empty());
    // The claim's first space is the cloud-vault binding label.
    let space = out_a.space_id.clone();

    let session_a = identity::login(http, base, &core_a, &out_a.account_id, &out_a.device_id)
        .expect("login should succeed");
    assert!(!session_a.access_token.is_empty());

    // ── Cloud vault + a member (real signed manifest+grant objects) ────────
    let vid = core_a
        .create_cloud_vault("Shared".into(), space.clone())
        .unwrap();
    // Synthetic member public keys (public material; same shape the unit tests use).
    core_a
        .add_member(
            vid.clone(),
            "11".repeat(32),
            "22".repeat(32),
            FfiMemberRole::Editor,
        )
        .unwrap();
    // A real SECRET in the cloud vault — the whole point of a cloud vault.
    core_a
        .save_password(vid.clone(), "db-pw".into(), "s3cr3t".into())
        .expect("storing a secret in a cloud vault should work");

    // ── A pushes (vault + membership + item objects) ───────────────────────
    let transport_a: Arc<dyn unissh_ffi::FfiSyncTransport> = Arc::new(HttpSyncTransport::new(
        base.clone(),
        session_a.access_token.clone(),
    ));
    let report_a = core_a
        .sync_now(transport_a, space.clone())
        .expect("A sync_now should succeed");
    assert!(
        report_a.pushed >= 1,
        "A should push at least the vault record: {report_a:?}"
    );

    // ── Device B: add a sibling device, share the keyset (Path A), log in ──
    let device_b = identity::device_add(http, base, &session_a.access_token)
        .expect("devices/add should succeed");

    let keyset_blob = std::fs::read(dir_a.path().join("a.keyset.bin")).unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path(), "b");
    core_b
        .unlock_from_server_blob(keyset_blob, None, secret)
        .expect("B unlocks from A's keyset blob");

    let session_b = identity::login(http, base, &core_b, &out_a.account_id, &device_b)
        .expect("B login with shared keyset should succeed");
    assert!(!session_b.access_token.is_empty());

    // ── B pulls and sees A's cloud vault ───────────────────────────────────
    let transport_b: Arc<dyn unissh_ffi::FfiSyncTransport> = Arc::new(HttpSyncTransport::new(
        base.clone(),
        session_b.access_token.clone(),
    ));
    let report_b = core_b
        .sync_now(transport_b, space.clone())
        .expect("B sync_now should succeed");
    assert!(
        report_b.applied >= 1,
        "B should apply at least one object from A: {report_b:?}"
    );
    let vaults_b = core_b.list_vaults().unwrap();
    assert!(
        vaults_b.iter().any(|v| v.name == "Shared"),
        "B should see the shared cloud vault after pull"
    );
    // The decisive check: B reads the SECRET A stored in the cloud vault.
    let pw = core_b
        .get_password(vid.clone(), "db-pw".into())
        .expect("B should read the secret synced into the cloud vault");
    assert_eq!(pw, "s3cr3t", "the synced secret must match byte-for-byte");

    // Session lifecycle: refresh + logout round-trip.
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
        Some("personal".into()),
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
