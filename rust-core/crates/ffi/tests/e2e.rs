//! End-to-end local scenario through the FFI facade (core Definition of Done):
//! create a local vault → generate an SSH key → connect to a server
//! (including via ProxyJump) — without a server instance and without the UI.
//!
//! Plus a check of a hard constraint: the private key never leaks to disk in
//! plaintext and is never handed out.

use std::net::TcpStream as StdTcp;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use unissh_ffi::{AuthMethod, Core, JumpHost, MultiExecTarget};

fn agent_auth(vault_id: &str, key_item_id: &str) -> AuthMethod {
    AuthMethod::Agent {
        vault_id: vault_id.to_string(),
        key_item_id: key_item_id.to_string(),
    }
}

struct TestSshd {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn sftp_server_path() -> &'static str {
    for p in [
        "/usr/lib/openssh/sftp-server",
        "/usr/libexec/sftp-server",
        "/usr/libexec/openssh/sftp-server",
        "/usr/lib/ssh/sftp-server",
    ] {
        if std::path::Path::new(p).exists() {
            return p;
        }
    }
    "/usr/lib/openssh/sftp-server"
}

impl TestSshd {
    fn start(authorized_pubkey: &str) -> TestSshd {
        Self::start_on_port(authorized_pubkey, free_port())
    }

    fn start_on_port(authorized_pubkey: &str, port: u16) -> TestSshd {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        let hostkey = p.join("hostkey");
        assert!(Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-q", "-N", ""])
            .arg("-f")
            .arg(&hostkey)
            .status()
            .expect("ssh-keygen")
            .success());
        std::fs::write(p.join("authorized_keys"), format!("{authorized_pubkey}\n")).unwrap();
        let _ = std::fs::create_dir_all("/run/sshd");
        let cfg = p.join("sshd_config");
        std::fs::write(
            &cfg,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {hk}\nPidFile {pid}\n\
                 PasswordAuthentication no\nPubkeyAuthentication yes\n\
                 PermitRootLogin prohibit-password\nAuthorizedKeysFile {ak}\n\
                 AllowTcpForwarding yes\nUsePAM no\nStrictModes no\n\
                 Subsystem sftp {sftp}\nLogLevel ERROR\n",
                hk = hostkey.display(),
                pid = p.join("sshd.pid").display(),
                ak = p.join("authorized_keys").display(),
                sftp = sftp_server_path(),
            ),
        )
        .unwrap();
        let child = Command::new("/usr/sbin/sshd")
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&cfg)
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn sshd");
        let deadline = Instant::now() + Duration::from_secs(8);
        while StdTcp::connect(("127.0.0.1", port)).is_err() {
            if Instant::now() > deadline {
                panic!("sshd not ready");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        TestSshd {
            child,
            port,
            _dir: dir,
        }
    }

    /// Like [`Self::start`], but with `MaxSessions {max_sessions}` — the server
    /// will refuse to open more session channels (`AdministrativelyProhibited`).
    /// For testing SFTP channel-pool degradation against a restrictive server.
    fn start_with_max_sessions(authorized_pubkey: &str, max_sessions: u32) -> TestSshd {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        let hostkey = p.join("hostkey");
        assert!(Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-q", "-N", ""])
            .arg("-f")
            .arg(&hostkey)
            .status()
            .expect("ssh-keygen")
            .success());
        std::fs::write(p.join("authorized_keys"), format!("{authorized_pubkey}\n")).unwrap();
        let _ = std::fs::create_dir_all("/run/sshd");
        let port = free_port();
        let cfg = p.join("sshd_config");
        std::fs::write(
            &cfg,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {hk}\nPidFile {pid}\n\
                 PasswordAuthentication no\nPubkeyAuthentication yes\n\
                 PermitRootLogin prohibit-password\nAuthorizedKeysFile {ak}\n\
                 AllowTcpForwarding yes\nUsePAM no\nStrictModes no\nMaxSessions {ms}\n\
                 Subsystem sftp {sftp}\nLogLevel ERROR\n",
                hk = hostkey.display(),
                pid = p.join("sshd.pid").display(),
                ak = p.join("authorized_keys").display(),
                ms = max_sessions,
                sftp = sftp_server_path(),
            ),
        )
        .unwrap();
        let child = Command::new("/usr/sbin/sshd")
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&cfg)
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn sshd");
        let deadline = Instant::now() + Duration::from_secs(8);
        while StdTcp::connect(("127.0.0.1", port)).is_err() {
            if Instant::now() > deadline {
                panic!("sshd not ready");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        TestSshd {
            child,
            port,
            _dir: dir,
        }
    }
}

impl TestSshd {
    /// Brings up an sshd that trusts user certificates signed by `ca_pubkey`
    /// (via TrustedUserCAKeys) instead of authorized_keys.
    fn start_with_ca(ca_pubkey: &str) -> TestSshd {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        let hostkey = p.join("hostkey");
        assert!(Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-q", "-N", ""])
            .arg("-f")
            .arg(&hostkey)
            .status()
            .expect("ssh-keygen")
            .success());
        std::fs::write(p.join("ca.pub"), format!("{ca_pubkey}\n")).unwrap();
        let _ = std::fs::create_dir_all("/run/sshd");
        let port = free_port();
        let cfg = p.join("sshd_config");
        std::fs::write(
            &cfg,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {hk}\nPidFile {pid}\n\
                 PasswordAuthentication no\nPubkeyAuthentication yes\n\
                 PermitRootLogin prohibit-password\nTrustedUserCAKeys {ca}\n\
                 AllowTcpForwarding yes\nUsePAM no\nStrictModes no\nLogLevel ERROR\n",
                hk = hostkey.display(),
                pid = p.join("sshd.pid").display(),
                ca = p.join("ca.pub").display(),
            ),
        )
        .unwrap();
        let child = Command::new("/usr/sbin/sshd")
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&cfg)
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn sshd");
        let deadline = Instant::now() + Duration::from_secs(8);
        while StdTcp::connect(("127.0.0.1", port)).is_err() {
            if Instant::now() > deadline {
                panic!("sshd not ready");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        TestSshd {
            child,
            port,
            _dir: dir,
        }
    }
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn new_core(dir: &std::path::Path) -> std::sync::Arc<Core> {
    Core::new(
        dir.join("inst.db").to_str().unwrap().to_string(),
        dir.join("keyset.bin").to_str().unwrap().to_string(),
    )
}

#[test]
fn end_to_end_local_scenario() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());

    let secret = core.create_account(Some("master-pw".to_string())).unwrap();
    core.create_vault("default".to_string(), "Default".to_string())
        .unwrap();
    let pubkey = core
        .generate_ssh_key("default".to_string(), "id_ed25519".to_string())
        .unwrap();
    assert!(pubkey.starts_with("ssh-ed25519 "));

    let sshd = TestSshd::start(&pubkey);
    let res = core
        .ssh_exec(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("default", "id_ed25519"),
            "echo ffi-e2e".to_string(),
            vec![],
        )
        .unwrap();
    assert_eq!(res.stdout.trim(), "ffi-e2e");
    assert_eq!(res.exit_status, 0);

    // lock → unlock with the same password + Secret Key; data is preserved
    core.lock();
    assert!(!core.is_unlocked());
    core.unlock(Some("master-pw".to_string()), secret).unwrap();
    assert!(core.is_unlocked());
    assert_eq!(core.list_items("default".to_string()).unwrap().len(), 1);
}

#[test]
fn end_to_end_proxyjump() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();

    let jump = TestSshd::start(&pubkey);
    let target = TestSshd::start(&pubkey);

    let res = core
        .ssh_exec(
            "127.0.0.1".to_string(),
            target.port,
            "root".to_string(),
            agent_auth("v", "key"),
            "echo through-jump".to_string(),
            vec![JumpHost {
                host: "127.0.0.1".to_string(),
                port: jump.port,
                user: "root".to_string(),
                auth: agent_auth("v", "key"),
                hop_ref: None,
            }],
        )
        .unwrap();
    assert_eq!(res.stdout.trim(), "through-jump");
}

#[test]
fn private_key_never_stored_in_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(Some("pw".to_string())).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();

    // public is public
    assert!(pubkey.contains("ssh-ed25519"));

    // on disk (encrypted DB + keyset sidecar) there is no OpenSSH private-key marker
    let db = std::fs::read(dir.path().join("inst.db")).unwrap();
    let keyset = std::fs::read(dir.path().join("keyset.bin")).unwrap();
    let marker = b"OPENSSH PRIVATE KEY";
    assert!(!contains(&db, marker), "plaintext private key found in DB");
    assert!(
        !contains(&keyset, marker),
        "plaintext private key found in keyset sidecar"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn create_account_rejects_existing_instance() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    // again with the same Core — the instance already exists
    assert!(matches!(
        core.create_account(None),
        Err(unissh_ffi::FfiError::AlreadyExists)
    ));
    // and with a new Core over the same paths — also
    let core2 = new_core(dir.path());
    assert!(matches!(
        core2.create_account(None),
        Err(unissh_ffi::FfiError::AlreadyExists)
    ));
}

#[test]
fn multi_exec_on_several_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();

    let sshd1 = TestSshd::start(&pubkey);
    let sshd2 = TestSshd::start(&pubkey);

    let mk = |port: u16| MultiExecTarget {
        host: "127.0.0.1".to_string(),
        port,
        user: "root".to_string(),
        auth: agent_auth("v", "key"),
        jumps: vec![],
    };
    let results = core
        .ssh_exec_multi(
            vec![mk(sshd1.port), mk(sshd2.port)],
            "echo multi-ok".to_string(),
            0,
            0,
        )
        .unwrap();
    assert_eq!(results.len(), 2);
    for r in &results {
        assert!(r.error.is_none(), "unexpected error: {:?}", r.error);
        assert_eq!(r.stdout.trim(), "multi-ok");
        assert_eq!(r.exit_status, 0);
        assert!(!r.timed_out);
    }
}

#[test]
fn certificate_auth() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let user_pub = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();

    // CA + signing the user's public key with a certificate (principal root)
    let work = tempfile::tempdir().unwrap();
    let ca = work.path().join("ca");
    assert!(Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-q", "-N", ""])
        .arg("-f")
        .arg(&ca)
        .status()
        .unwrap()
        .success());
    let ca_pub = std::fs::read_to_string(work.path().join("ca.pub")).unwrap();

    let user_pub_path = work.path().join("user.pub");
    std::fs::write(&user_pub_path, format!("{user_pub}\n")).unwrap();
    assert!(Command::new("ssh-keygen")
        .arg("-s")
        .arg(&ca)
        .args(["-I", "unissh-test", "-n", "root", "-V", "+1h"])
        .arg(&user_pub_path)
        .status()
        .unwrap()
        .success());
    let cert = std::fs::read_to_string(work.path().join("user-cert.pub")).unwrap();

    // import the certificate into the core
    core.import_ssh_certificate("v".to_string(), "key".to_string(), cert)
        .unwrap();

    // in the listing the key is flagged as having a certificate
    let items = core.list_items("v".to_string()).unwrap();
    let key_item = items.iter().find(|i| i.item_id == "key").unwrap();
    assert!(
        key_item.has_certificate,
        "key should report has_certificate"
    );

    // sshd trusts the CA → authentication via certificate
    let sshd = TestSshd::start_with_ca(&ca_pub);
    let res = core
        .ssh_exec(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            "echo cert-ok".to_string(),
            vec![],
        )
        .unwrap();
    assert_eq!(res.stdout.trim(), "cert-ok");
    assert_eq!(res.exit_status, 0);
}

#[test]
fn import_pkcs1_rsa_key_and_auth() {
    // User scenario through FFI: a classic PKCS#1 (`-----BEGIN RSA
    // PRIVATE KEY-----`) is imported into the vault and works for authentication
    // (import normalizes it to OpenSSH; the connection uses rsa-sha2-512).
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    let pubkey = core
        .import_ssh_key(
            "v".to_string(),
            "rsa".to_string(),
            RSA_PKCS1.to_string(),
            None,
        )
        .unwrap();
    assert!(
        pubkey.starts_with("ssh-rsa "),
        "expected rsa pub, got {pubkey}"
    );

    // the key is stored in the vault as a separate item
    let items = core.list_items("v".to_string()).unwrap();
    assert!(items.iter().any(|i| i.item_id == "rsa"), "key item stored");

    // full connect to a real sshd with the imported PKCS#1 key
    let sshd = TestSshd::start(&pubkey);
    let res = core
        .ssh_exec(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "rsa"),
            "echo ffi-pkcs1".to_string(),
            vec![],
        )
        .unwrap();
    assert_eq!(res.stdout.trim(), "ffi-pkcs1");
    assert_eq!(res.exit_status, 0);
}

/// Classic RSA-2048 in PKCS#1 (one-off test key).
const RSA_PKCS1: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Nz6qk+yFoEL3gBixnDidk4jLEIvDk25O5yTpEMmmIHa/o8x
MVd1pYkXbh2IZwy/SrTyUqWDvAif5Monzuti7kT/0/VMldm4X/JNhfr6K+p5Y+oJ
61cHMNzW+PVe/SFCdqYeFZaa4v0feSKfc3pdTawrVyopGQ9Onj/W2QS5OGdwFblq
zqzaJKZWA9qvFy90qmTpliSxxr7mY5C/RMwqiXt9+4DtPeJBRK9BNZ8AkMGbwgP8
/WW6yqYDd1L62AxLA+uNymQWf6t9nWaSf03mREe1zVXS/HFIVeSPBDej80gULfJt
3ftjQNTem6PxSqAOdHWBS2PCtrRVClMSnLcvPwIDAQABAoIBAACnSj+Uc33n3dZO
K1ZHm5DUJS90pSyp/x0hfYUlkosmqEmbamshAeAtGAK4eVCvUc+c+qcEsAeW3Wn3
dUlhHaI4QpH7rXIkGm+rjoBxGQ8XQlWW7ojSob2zA/KxvsrQVmXBNTRpnE/47T88
EGbjnbE2VJgxgdyNu/4X5yKQZ2jnYaONCPPozU9/P94oXj+huOl8LQQ3P+dukcMu
13X/Bdbo7FjmHL0Fci7Ii33PZm350lcfeIuOIYltglZNSTUPrJy9FIrQ8H8BY6yM
GKrI6UMbMWSopJdwEi99pCoPGr7O7frz9Ly7Cpl1axj9WfsA/G6MZMjnFLAyvYKv
43AdHPECgYEA9+pbS3o9LwMok/cqPHzrYnK1Vn0BHH10HqeXpuwJE4lsps2Fo2LH
Xz1Wi9+/JY1jObnadWMkkAvx1ZUsp4FkcLOr/HDZOYF+uaEw+gKRVpOlWCLICjlm
GjeP5X72aoHUJ8PNBvjqAVp8ylKBFE9ukLzZsVb4FBPS+bMu63pJ8YsCgYEA16yb
cUO9N2uzlQMAUckIDyoUnHptRdcHapXDneZd/SnKzcU/hD/S/RcVqQB1YANpZyeM
/bNzSfkWcxVkaWC7Z2maHn/DXm3ZhFT15I5ELAbdq37e+vUbdvWGcBuCzmtwFdIl
yeqx6BzHoUWaVuPAZ5Z5VJQoTH1OhHuQFJUxx50CgYEAlLu/JdsiVdAZShwg9MUl
Gp0i+c5pGkSRo8p8CyLUlyn9S11F7a3XWuYbxDLqJIdcnkdILuDaEKl53t9uONhB
//NrHTo+uGdeNdPk5DkiJMTTj7reNHQXM2deJxsyjtdxBqJLoQE4srMs5tz0n9C/
zoneOKyqjLEQA8piPdfSAN0CgYASvq3D6l9HsdSp3tjoQtCwgLfJ4dodd9LtMJcP
4jXJCxjVSY97rxBnbtozFhcdgS5oCMf4ROCATWXmGrXfcsjW9BaxD+mrC2EcX0X/
112VdgNOJHi81xDMBgrpM3rq9euH+fvO0NcllVrEaYhAhQrz9eAVucrG2x035oVf
RJhPAQKBgQCcjnPyuFuq3zIIAVSA1ryvtFW5n95eij/AABeBhKjcsKKC9TyPy145
5mXOxoXcTAT4qbLxLc34BVjC49DoquOVble2OBVWWNng+x+AKyJXVaih7o+mTt6Y
otqRUgfM3Hf3sdwr66X6ltp1sQlzggaVlhH3pBsCWTPQ6nBzWEgiPA==
-----END RSA PRIVATE KEY-----";

struct CollectObserver {
    buf: std::sync::Mutex<Vec<u8>>,
    closed: std::sync::atomic::AtomicBool,
}

impl unissh_ffi::SessionObserver for CollectObserver {
    fn on_data(&self, data: Vec<u8>) {
        self.buf.lock().unwrap().extend_from_slice(&data);
    }
    fn on_close(&self, _exit_status: i32) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn interactive_pty_session() {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();

    let sshd = TestSshd::start(&pubkey);

    let observer = Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    let session = core
        .open_session(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            "xterm".to_string(),
            80,
            24,
            observer.clone(),
            None,
            false,
        )
        .unwrap();

    // enter a command into the interactive shell
    session.write(b"echo pty-works\n".to_vec()).unwrap();

    // wait for output to appear in the observer (up to ~3s)
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if contains(&observer.buf.lock().unwrap(), b"pty-works") {
            break;
        }
        if Instant::now() > deadline {
            panic!(
                "no expected output; got: {:?}",
                String::from_utf8_lossy(&observer.buf.lock().unwrap())
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    session.close().unwrap();
}

#[test]
fn vault_and_item_management() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "Old Name".to_string())
        .unwrap();
    core.generate_ssh_key("v".to_string(), "k".to_string())
        .unwrap();

    // rename
    core.rename_vault("v".to_string(), "New Name".to_string())
        .unwrap();
    let vaults = core.list_vaults().unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].name, "New Name");

    // delete item
    assert_eq!(core.list_items("v".to_string()).unwrap().len(), 1);
    core.delete_item("v".to_string(), "k".to_string()).unwrap();
    assert!(core.list_items("v".to_string()).unwrap().is_empty());

    // delete vault
    core.delete_vault("v".to_string()).unwrap();
    assert!(core.list_vaults().unwrap().is_empty());
}

#[test]
fn known_hosts_list_and_forget() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    // the connection pins the host key (TOFU)
    core.ssh_exec(
        "127.0.0.1".to_string(),
        sshd.port,
        "root".to_string(),
        agent_auth("v", "key"),
        "true".to_string(),
        vec![],
    )
    .unwrap();

    let hosts = core.list_known_hosts().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host, "127.0.0.1");
    assert_eq!(hosts[0].port, sshd.port);
    assert!(hosts[0].key.starts_with("ssh-"));

    assert!(core
        .forget_host("127.0.0.1".to_string(), sshd.port)
        .unwrap());
    assert!(core.list_known_hosts().unwrap().is_empty());
    // repeated forget — the record is already gone
    assert!(!core
        .forget_host("127.0.0.1".to_string(), sshd.port)
        .unwrap());
}

#[test]
fn password_auth_path_wired() {
    // sshd accepts keys only → the password is guaranteed to fail, but the
    // password-authentication path reaches the server and returns a clean error.
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let res = core.ssh_exec(
        "127.0.0.1".to_string(),
        sshd.port,
        "root".to_string(),
        AuthMethod::Password {
            password: "wrong".to_string(),
        },
        "true".to_string(),
        vec![],
    );
    assert!(res.is_err());
}

#[test]
fn host_key_mismatch_detected() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();

    // first sshd → pin its host key (TOFU)
    let sshd1 = TestSshd::start(&pubkey);
    let port = sshd1.port;
    core.ssh_exec(
        "127.0.0.1".to_string(),
        port,
        "root".to_string(),
        agent_auth("v", "key"),
        "true".to_string(),
        vec![],
    )
    .unwrap();

    // bring up a DIFFERENT sshd (different host key) on the SAME port
    drop(sshd1);
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _sshd2 = TestSshd::start_on_port(&pubkey, port);

    let err = core
        .ssh_exec(
            "127.0.0.1".to_string(),
            port,
            "root".to_string(),
            agent_auth("v", "key"),
            "true".to_string(),
            vec![],
        )
        .unwrap_err();
    assert!(
        matches!(err, unissh_ffi::FfiError::HostKeyMismatch { .. }),
        "expected HostKeyMismatch, got: {err:?}"
    );
}

#[test]
fn change_password_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    let secret = core.create_account(Some("old-pw".to_string())).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    // change the password
    core.change_password(
        Some("old-pw".to_string()),
        Some("new-pw".to_string()),
        secret.clone(),
    )
    .unwrap();

    // the old password no longer unlocks, the new one does
    core.lock();
    assert!(matches!(
        core.unlock(Some("old-pw".to_string()), secret.clone()),
        Err(unissh_ffi::FfiError::InvalidCredentials)
    ));
    core.unlock(Some("new-pw".to_string()), secret.clone())
        .unwrap();
    assert_eq!(core.list_vaults().unwrap().len(), 1);

    // wrong old credentials don't "brick" the account (error, no overwrite)
    assert!(core
        .change_password(
            Some("wrong".to_string()),
            Some("x".to_string()),
            secret.clone()
        )
        .is_err());
    // still unlocks with the current password
    core.lock();
    core.unlock(Some("new-pw".to_string()), secret).unwrap();
    assert!(core.is_unlocked());
}

#[test]
fn get_public_key_and_item_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let generated = core
        .generate_ssh_key("v".to_string(), "id".to_string())
        .unwrap();

    // the public key matches the one returned at generation; a fingerprint is present
    let pk = core
        .get_public_key("v".to_string(), "id".to_string())
        .unwrap();
    assert_eq!(pk.openssh.trim(), generated.trim());
    assert!(pk.fingerprint.starts_with("SHA256:"));

    // metadata: timestamps are set, no certificate
    let items = core.list_items("v".to_string()).unwrap();
    let it = items.iter().find(|i| i.item_id == "id").unwrap();
    assert!(it.created_at > 0 && it.updated_at > 0);
    assert!(!it.has_certificate);

    // get_public_key on a missing item → NotFound
    assert!(matches!(
        core.get_public_key("v".to_string(), "nope".to_string()),
        Err(unissh_ffi::FfiError::NotFound)
    ));
}

#[test]
fn rename_item_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "old".to_string())
        .unwrap();
    let before = core
        .get_public_key("v".to_string(), "old".to_string())
        .unwrap();

    core.rename_item("v".to_string(), "old".to_string(), "new".to_string())
        .unwrap();

    // the old one is gone, the new one carries the same key
    assert!(matches!(
        core.get_public_key("v".to_string(), "old".to_string()),
        Err(unissh_ffi::FfiError::NotFound)
    ));
    let after = core
        .get_public_key("v".to_string(), "new".to_string())
        .unwrap();
    assert_eq!(before.openssh, after.openssh);

    // the renamed key can be used to connect
    let sshd = TestSshd::start(&pubkey);
    let res = core
        .ssh_exec(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "new"),
            "echo renamed-ok".to_string(),
            vec![],
        )
        .unwrap();
    assert_eq!(res.stdout.trim(), "renamed-ok");
}

#[test]
fn trust_host_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();

    let sshd1 = TestSshd::start(&pubkey);
    let port = sshd1.port;
    core.ssh_exec(
        "127.0.0.1".to_string(),
        port,
        "root".to_string(),
        agent_auth("v", "key"),
        "true".to_string(),
        vec![],
    )
    .unwrap();

    // a different host key on the same port → mismatch with a fingerprint
    drop(sshd1);
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _sshd2 = TestSshd::start_on_port(&pubkey, port);
    let presented = match core.ssh_exec(
        "127.0.0.1".to_string(),
        port,
        "root".to_string(),
        agent_auth("v", "key"),
        "true".to_string(),
        vec![],
    ) {
        Err(unissh_ffi::FfiError::HostKeyMismatch { fingerprint, .. }) => {
            assert!(fingerprint.starts_with("SHA256:"));
            fingerprint
        }
        other => panic!("expected HostKeyMismatch, got {other:?}"),
    };

    // trusting with the "wrong" fingerprint is not allowed
    assert!(matches!(
        core.trust_host("127.0.0.1".to_string(), port, "SHA256:bogus".to_string()),
        Err(unissh_ffi::FfiError::HostKeyMismatch { .. })
    ));

    // trust the new key with the confirmed fingerprint → everything works afterward
    let fp = core
        .trust_host("127.0.0.1".to_string(), port, presented)
        .unwrap();
    assert!(fp.starts_with("SHA256:"));
    let res = core
        .ssh_exec(
            "127.0.0.1".to_string(),
            port,
            "root".to_string(),
            agent_auth("v", "key"),
            "echo trusted".to_string(),
            vec![],
        )
        .unwrap();
    assert_eq!(res.stdout.trim(), "trusted");
}

#[test]
fn local_forward_e2e() {
    use std::io::{Read, Write};
    // echo server in a separate thread
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in echo.incoming() {
            let mut s = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            std::thread::spawn(move || {
                let mut buf = [0u8; 256];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]);
                }
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let tunnel = core
        .open_local_forward(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            "127.0.0.1:0".to_string(),
            "127.0.0.1".to_string(),
            echo_port,
        )
        .unwrap();
    let bind = tunnel.bind_address();
    assert!(bind.starts_with("127.0.0.1:"));

    // connect through the tunnel → land on the echo server
    let mut conn = std::net::TcpStream::connect(&bind).unwrap();
    conn.write_all(b"ping-through-tunnel").unwrap();
    let mut got = [0u8; 64];
    let n = conn.read(&mut got).unwrap();
    assert_eq!(&got[..n], b"ping-through-tunnel");

    tunnel.close();
}

#[test]
fn sftp_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let sftp = core
        .open_sftp(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            1,
        )
        .unwrap();

    let base = format!("/tmp/unissh-ffi-sftp-{}", sshd.port);
    let _ = sftp.remove(format!("{base}/f.bin"));
    let _ = sftp.rmdir(base.clone());
    sftp.mkdir(base.clone()).unwrap();

    let data = b"ffi sftp payload".repeat(1000);
    sftp.write_file(format!("{base}/f.bin"), data.clone())
        .unwrap();
    assert_eq!(sftp.read_file(format!("{base}/f.bin")).unwrap(), data);

    let st = sftp.stat(format!("{base}/f.bin")).unwrap();
    assert_eq!(st.size, data.len() as u64);
    assert!(!st.is_dir);

    let entries = sftp.list_dir(base.clone()).unwrap();
    assert!(entries.iter().any(|e| e.filename == "f.bin" && !e.is_dir));

    sftp.rename(format!("{base}/f.bin"), format!("{base}/g.bin"))
        .unwrap();
    assert!(sftp.read_file(format!("{base}/f.bin")).is_err());
    sftp.remove(format!("{base}/g.bin")).unwrap();
    sftp.rmdir(base).unwrap();
}

#[test]
fn connection_profiles_crud_and_import() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    let prof = unissh_ffi::ConnectionProfile {
        profile_id: "prod-web".to_string(),
        uid: String::new(),
        username_template: None,
        label: "Prod Web".to_string(),
        host: "10.0.0.5".to_string(),
        port: 22,
        user: "deploy".to_string(),
        auth: unissh_ffi::ProfileAuth::Key {
            key_item_id: "id_ed25519".to_string(),
        },
        jumps: vec![JumpHost {
            host: "bastion".to_string(),
            port: 22,
            user: "admin".to_string(),
            auth: agent_auth("v", "id_ed25519"),
            hop_ref: None,
        }],
        tags: vec![],
        startup_snippet_ids: vec![],
        record_sessions: false,
        agent_forward: false,
    };
    core.save_connection("v".to_string(), prof).unwrap();

    let list = core.list_connections("v".to_string()).unwrap();
    assert_eq!(list.len(), 1);
    let got = core
        .get_connection("v".to_string(), "prod-web".to_string())
        .unwrap();
    assert_eq!(got.host, "10.0.0.5");
    assert_eq!(got.user, "deploy");
    assert!(matches!(
        &got.auth,
        unissh_ffi::ProfileAuth::Key { key_item_id } if key_item_id == "id_ed25519"
    ));
    assert_eq!(got.jumps.len(), 1);
    assert_eq!(got.jumps[0].host, "bastion");

    // profiles don't show up in the regular listing as "keys" — it's a separate type
    // (list_items returns them with item_type=3); verify that management works
    core.delete_connection("v".to_string(), "prod-web".to_string())
        .unwrap();
    assert!(core.list_connections("v".to_string()).unwrap().is_empty());

    // import ssh-config
    let cfg = "Host web prod\n  HostName 192.168.1.10\n  User deploy\n  Port 2222\n\
               Host bastion\n  HostName gw.example.com\n  ProxyJump jumpuser@jump.example.com:2200\n";
    let created = core
        .import_ssh_config("v".to_string(), cfg.to_string())
        .unwrap();
    assert_eq!(created, vec!["web", "prod", "bastion"]);
    let bastion = core
        .get_connection("v".to_string(), "bastion".to_string())
        .unwrap();
    assert_eq!(bastion.host, "gw.example.com");
    assert_eq!(bastion.jumps.len(), 1);
    assert_eq!(bastion.jumps[0].host, "jump.example.com");
    assert_eq!(bastion.jumps[0].port, 2200);
    assert_eq!(bastion.jumps[0].user, "jumpuser");
}

#[test]
fn cross_type_clobber_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "id".to_string())
        .unwrap();

    // a connection profile with the id of an existing key must NOT overwrite the key
    let prof = unissh_ffi::ConnectionProfile {
        profile_id: "id".to_string(),
        uid: String::new(),
        username_template: None,
        label: "x".to_string(),
        host: "h".to_string(),
        port: 22,
        user: "u".to_string(),
        auth: unissh_ffi::ProfileAuth::PromptPassword,
        jumps: vec![],
        tags: vec![],
        startup_snippet_ids: vec![],
        record_sessions: false,
        agent_forward: false,
    };
    assert!(matches!(
        core.save_connection("v".to_string(), prof),
        Err(unissh_ffi::FfiError::AlreadyExists)
    ));
    // the key is intact and readable
    assert!(core
        .get_public_key("v".to_string(), "id".to_string())
        .is_ok());

    // and vice versa: generating a key over a profile is rejected
    let prof2 = unissh_ffi::ConnectionProfile {
        profile_id: "conn".to_string(),
        uid: String::new(),
        username_template: None,
        label: "x".to_string(),
        host: "h".to_string(),
        port: 22,
        user: "u".to_string(),
        auth: unissh_ffi::ProfileAuth::PromptPassword,
        jumps: vec![],
        tags: vec![],
        startup_snippet_ids: vec![],
        record_sessions: false,
        agent_forward: false,
    };
    core.save_connection("v".to_string(), prof2).unwrap();
    assert!(matches!(
        core.generate_ssh_key("v".to_string(), "conn".to_string()),
        Err(unissh_ffi::FfiError::AlreadyExists)
    ));

    // import_ssh_config with an alias = a key id skips it (does not overwrite)
    let created = core
        .import_ssh_config("v".to_string(), "Host id\n  HostName x\n".to_string())
        .unwrap();
    assert!(created.is_empty(), "colliding alias must be skipped");
    assert!(core
        .get_public_key("v".to_string(), "id".to_string())
        .is_ok());
}

#[test]
fn import_ssh_config_ipv6_proxyjump() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let cfg = "Host h\n  HostName 2001:db8::5\n  ProxyJump j@[2001:db8::1]:2200\n";
    core.import_ssh_config("v".to_string(), cfg.to_string())
        .unwrap();
    let p = core
        .get_connection("v".to_string(), "h".to_string())
        .unwrap();
    assert_eq!(p.host, "2001:db8::5");
    assert_eq!(p.jumps.len(), 1);
    assert_eq!(p.jumps[0].host, "2001:db8::1");
    assert_eq!(p.jumps[0].port, 2200);
    assert_eq!(p.jumps[0].user, "j");
}

// --- server passwords in the vault ---

/// In-process SSH server (russh) that accepts the password `password` and can exec
/// (echo the command + code 0). Hermetic replacement for sshd: a system sshd cannot
/// have a user password set without touching /etc/shadow.
mod pwserver {
    use std::sync::Arc;

    use russh::server::{self, Auth as ServerAuth, Msg, Session};
    use russh::{Channel, ChannelId};

    struct PwHandler {
        password: String,
    }

    impl server::Handler for PwHandler {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            password: &str,
        ) -> Result<ServerAuth, russh::Error> {
            if password == self.password {
                Ok(ServerAuth::Accept)
            } else {
                Ok(ServerAuth::reject())
            }
        }

        // russh 0.62 replaced the `-> Result<bool>` "did you accept?" convention with an
        // explicit handle: the channel is opened by calling `accept()`, and returning
        // without doing so leaves the client waiting rather than refusing.
        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), russh::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), russh::Error> {
            session.channel_success(channel)?;
            session.data(channel, data.to_vec())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    /// Brings up the server on a separate tokio runtime; returns (runtime, port).
    /// The runtime must be kept alive while the test runs.
    pub fn start(password: &str) -> (tokio::runtime::Runtime, u16) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let password = password.to_string();
        let port = rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();

            // host key: we can't generate Ed25519 through the core's ssh-agent crate
            // (no dependency here) — reuse ssh-keygen already used in the tests? No:
            // russh accepts OpenSSH PEM. Generate a temporary key with ssh-keygen.
            let dir = tempfile::tempdir().unwrap();
            let keypath = dir.path().join("hostkey");
            let st = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-q", "-N", ""])
                .arg("-f")
                .arg(&keypath)
                .status()
                .expect("ssh-keygen");
            assert!(st.success());
            let pem = std::fs::read_to_string(&keypath).unwrap();
            let host_key = russh::keys::PrivateKey::from_openssh(&pem).unwrap();

            let config = Arc::new(server::Config {
                keys: vec![host_key],
                auth_rejection_time: std::time::Duration::from_millis(10),
                ..Default::default()
            });

            tokio::spawn(async move {
                let _dir = dir; // keep the tempdir alive
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let config = config.clone();
                    let handler = PwHandler {
                        password: password.clone(),
                    };
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, stream, handler).await {
                            let _ = session.await;
                        }
                    });
                }
            });
            port
        });
        (rt, port)
    }
}

#[test]
fn password_items_crud() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    core.save_password("v".to_string(), "srv1".to_string(), "s3cret!".to_string())
        .unwrap();

    // reveal returns what was stored
    assert_eq!(
        core.get_password("v".to_string(), "srv1".to_string())
            .unwrap(),
        "s3cret!"
    );

    // in the items listing — type "password" (4), the version grows on update
    let items = core.list_items("v".to_string()).unwrap();
    let it = items.iter().find(|i| i.item_id == "srv1").unwrap();
    assert_eq!(it.item_type, 4);
    let v1 = it.version;

    core.save_password("v".to_string(), "srv1".to_string(), "newpass".to_string())
        .unwrap();
    assert_eq!(
        core.get_password("v".to_string(), "srv1".to_string())
            .unwrap(),
        "newpass"
    );
    let items = core.list_items("v".to_string()).unwrap();
    let it = items.iter().find(|i| i.item_id == "srv1").unwrap();
    assert!(it.version > v1, "version must grow monotonically");

    // deletion (tombstone) → NotFound
    core.delete_item("v".to_string(), "srv1".to_string())
        .unwrap();
    assert!(matches!(
        core.get_password("v".to_string(), "srv1".to_string()),
        Err(unissh_ffi::FfiError::NotFound)
    ));
}

#[test]
fn get_password_refuses_non_password_items() {
    // Critical: the reveal path must not expose a private key or any other item.
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();

    let err = core
        .get_password("v".to_string(), "key".to_string())
        .unwrap_err();
    assert!(
        !matches!(err, unissh_ffi::FfiError::NotFound),
        "expected a type error, not NotFound"
    );
    // and vice versa: a password does not masquerade as a key
    core.save_password("v".to_string(), "pw".to_string(), "x".to_string())
        .unwrap();
    assert!(core
        .get_public_key("v".to_string(), "pw".to_string())
        .is_err());
}

#[test]
fn cross_type_clobber_password_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "id".to_string())
        .unwrap();

    // a password with the id of an existing key must NOT overwrite the key
    assert!(matches!(
        core.save_password("v".to_string(), "id".to_string(), "x".to_string()),
        Err(unissh_ffi::FfiError::AlreadyExists)
    ));
    assert!(core
        .get_public_key("v".to_string(), "id".to_string())
        .is_ok());
}

#[test]
fn connect_with_vault_password() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.save_password("v".to_string(), "srv".to_string(), "hunter2!".to_string())
        .unwrap();

    let (_rt, port) = pwserver::start("hunter2!");

    let res = core
        .ssh_exec(
            "127.0.0.1".to_string(),
            port,
            "root".to_string(),
            AuthMethod::VaultPassword {
                vault_id: "v".to_string(),
                password_item_id: "srv".to_string(),
            },
            "echo vault-pw".to_string(),
            vec![],
        )
        .unwrap();
    assert_eq!(res.exit_status, 0);
    assert_eq!(res.stdout.trim(), "echo vault-pw"); // the test server echoes the command

    // a bad reference → NotFound even before connecting
    assert!(matches!(
        core.ssh_exec(
            "127.0.0.1".to_string(),
            port,
            "root".to_string(),
            AuthMethod::VaultPassword {
                vault_id: "v".to_string(),
                password_item_id: "nope".to_string(),
            },
            "true".to_string(),
            vec![],
        ),
        Err(unissh_ffi::FfiError::NotFound)
    ));

    // a deleted (tombstone) password is also not acceptable
    core.delete_item("v".to_string(), "srv".to_string())
        .unwrap();
    assert!(matches!(
        core.ssh_exec(
            "127.0.0.1".to_string(),
            port,
            "root".to_string(),
            AuthMethod::VaultPassword {
                vault_id: "v".to_string(),
                password_item_id: "srv".to_string(),
            },
            "true".to_string(),
            vec![],
        ),
        Err(unissh_ffi::FfiError::NotFound)
    ));
}

#[test]
fn profile_with_vault_password_and_inline_jump_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    // a profile referencing a password + a jump using a password from the vault
    let prof = unissh_ffi::ConnectionProfile {
        profile_id: "pw-host".to_string(),
        uid: String::new(),
        username_template: None,
        label: "PW Host".to_string(),
        host: "10.0.0.7".to_string(),
        port: 22,
        user: "root".to_string(),
        auth: unissh_ffi::ProfileAuth::VaultPassword {
            password_item_id: "srv-pw".to_string(),
        },
        jumps: vec![JumpHost {
            host: "bastion".to_string(),
            port: 22,
            user: "jump".to_string(),
            auth: AuthMethod::VaultPassword {
                vault_id: "v".to_string(),
                password_item_id: "bastion-pw".to_string(),
            },
            hop_ref: None,
        }],
        tags: vec![],
        startup_snippet_ids: vec![],
        record_sessions: false,
        agent_forward: false,
    };
    core.save_connection("v".to_string(), prof).unwrap();

    let got = core
        .get_connection("v".to_string(), "pw-host".to_string())
        .unwrap();
    assert!(matches!(
        &got.auth,
        unissh_ffi::ProfileAuth::VaultPassword { password_item_id } if password_item_id == "srv-pw"
    ));
    assert!(matches!(
        &got.jumps[0].auth,
        AuthMethod::VaultPassword { password_item_id, .. } if password_item_id == "bastion-pw"
    ));

    // inline password in the profile's jump host — rejected (secret not written to JSON)
    let bad = unissh_ffi::ConnectionProfile {
        profile_id: "bad".to_string(),
        uid: String::new(),
        username_template: None,
        label: "x".to_string(),
        host: "h".to_string(),
        port: 22,
        user: "u".to_string(),
        auth: unissh_ffi::ProfileAuth::PromptPassword,
        jumps: vec![JumpHost {
            host: "j".to_string(),
            port: 22,
            user: "u".to_string(),
            auth: AuthMethod::Password {
                password: "inline-secret".to_string(),
            },
            hop_ref: None,
        }],
        tags: vec![],
        startup_snippet_ids: vec![],
        record_sessions: false,
        agent_forward: false,
    };
    assert!(core.save_connection("v".to_string(), bad).is_err());
    assert!(matches!(
        core.get_connection("v".to_string(), "bad".to_string()),
        Err(unissh_ffi::FfiError::NotFound)
    ));
}

#[test]
fn password_never_stored_in_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(Some("masterpw".to_string())).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    let secret = "uniqu3-p4ssw0rd-m4rker";
    core.save_password("v".to_string(), "srv".to_string(), secret.to_string())
        .unwrap();
    core.lock();

    let db = std::fs::read(dir.path().join("inst.db")).unwrap();
    let keyset = std::fs::read(dir.path().join("keyset.bin")).unwrap();
    assert!(
        !contains(&db, secret.as_bytes()),
        "plaintext password found in DB"
    );
    assert!(
        !contains(&keyset, secret.as_bytes()),
        "plaintext password found in keyset sidecar"
    );
}

// --- fleet-hardening: concurrency limit, timeout, timing ---

/// Configurable in-process SSH server for fleet tests: password auth + exec,
/// exec behavior is configurable (instant/with sleep/hang), plus a shared counter
/// of concurrent execs for testing the concurrency limit.
mod fleetserver {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use russh::server::{self, Auth as ServerAuth, Msg, Session};
    use russh::{Channel, ChannelId};

    #[derive(Clone, Copy)]
    pub enum Mode {
        /// Sleep N ms on the server side, then echo + exit 0.
        Sleep(u64),
        /// channel_success, but never reply (hung host).
        Hang,
    }

    /// Counters of concurrent execs (for testing the concurrency ceiling).
    #[derive(Default)]
    pub struct Counters {
        current: AtomicUsize,
        peak: AtomicUsize,
    }
    impl Counters {
        pub fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }
    }

    struct H {
        password: String,
        mode: Mode,
        counters: Arc<Counters>,
    }

    impl server::Handler for H {
        type Error = russh::Error;

        async fn auth_password(&mut self, _u: &str, p: &str) -> Result<ServerAuth, russh::Error> {
            if p == self.password {
                Ok(ServerAuth::Accept)
            } else {
                Ok(ServerAuth::reject())
            }
        }

        // See the note on the other test server: 0.62 accepts via the handle, not by
        // returning true.
        async fn channel_open_session(
            &mut self,
            _c: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _s: &mut Session,
        ) -> Result<(), russh::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), russh::Error> {
            session.channel_success(channel)?;
            let cur = self.counters.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.counters.peak.fetch_max(cur, Ordering::SeqCst);
            match self.mode {
                Mode::Sleep(ms) => tokio::time::sleep(Duration::from_millis(ms)).await,
                Mode::Hang => {
                    self.counters.current.fetch_sub(1, Ordering::SeqCst);
                    return Ok(()); // channel is open, no reply — the client must time out on its own
                }
            }
            self.counters.current.fetch_sub(1, Ordering::SeqCst);
            session.data(channel, data.to_vec())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    pub fn start(
        password: &str,
        mode: Mode,
        counters: Arc<Counters>,
    ) -> (tokio::runtime::Runtime, u16) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let password = password.to_string();
        let port = rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let dir = tempfile::tempdir().unwrap();
            let keypath = dir.path().join("hostkey");
            let st = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-q", "-N", ""])
                .arg("-f")
                .arg(&keypath)
                .status()
                .expect("ssh-keygen");
            assert!(st.success());
            let pem = std::fs::read_to_string(&keypath).unwrap();
            let host_key = russh::keys::PrivateKey::from_openssh(&pem).unwrap();
            let config = Arc::new(server::Config {
                keys: vec![host_key],
                auth_rejection_time: Duration::from_millis(10),
                ..Default::default()
            });
            tokio::spawn(async move {
                let _dir = dir;
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let config = config.clone();
                    let handler = H {
                        password: password.clone(),
                        mode,
                        counters: counters.clone(),
                    };
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, stream, handler).await {
                            let _ = session.await;
                        }
                    });
                }
            });
            port
        });
        (rt, port)
    }
}

fn pw_target(port: u16) -> MultiExecTarget {
    MultiExecTarget {
        host: "127.0.0.1".to_string(),
        port,
        user: "root".to_string(),
        auth: AuthMethod::VaultPassword {
            vault_id: "v".to_string(),
            password_item_id: "pw".to_string(),
        },
        jumps: vec![],
    }
}

fn core_with_pw(dir: &std::path::Path, password: &str) -> std::sync::Arc<Core> {
    let core = new_core(dir);
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.save_password("v".to_string(), "pw".to_string(), password.to_string())
        .unwrap();
    core
}

#[test]
fn multi_exec_timeout_marks_timed_out() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let core = core_with_pw(dir.path(), "pw");
    let (_rt, port) = fleetserver::start(
        "pw",
        fleetserver::Mode::Hang,
        Arc::new(fleetserver::Counters::default()),
    );

    // exec hangs on the server; a per-host timeout=1s must flag the result and return control.
    let results = core
        .ssh_exec_multi(vec![pw_target(port)], "echo hi".to_string(), 0, 1)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].timed_out, "expected timed_out=true");
    assert!(results[0].error.is_some());
    assert_eq!(results[0].exit_status, -1);
}

#[test]
fn multi_exec_concurrency_is_capped() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let core = core_with_pw(dir.path(), "pw");
    let counters = Arc::new(fleetserver::Counters::default());
    let (_rt, port) = fleetserver::start("pw", fleetserver::Mode::Sleep(200), counters.clone());

    // 5 targets on the same port, limit 2 → no more than 2 run concurrently.
    let targets: Vec<_> = (0..5).map(|_| pw_target(port)).collect();
    let results = core
        .ssh_exec_multi(targets, "echo hi".to_string(), 2, 0)
        .unwrap();
    assert_eq!(results.len(), 5);
    for r in &results {
        assert!(r.error.is_none(), "unexpected error: {:?}", r.error);
        assert!(
            r.duration_ms >= 150,
            "sleep(200) → duration should be ~200ms, got {}",
            r.duration_ms
        );
    }
    assert!(
        counters.peak() <= 2,
        "peak concurrent execs {} exceeded the limit of 2",
        counters.peak()
    );
}

// --- secure-notes (item_type=6) ---

#[test]
fn secure_notes_crud() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    let note = "IPMI: 10.0.0.9 admin / recovery codes:\n111-222\n333-444";
    core.save_note("v".to_string(), "host-notes".to_string(), note.to_string())
        .unwrap();
    assert_eq!(
        core.get_note("v".to_string(), "host-notes".to_string())
            .unwrap(),
        note
    );

    // type 6, the version grows on update
    let items = core.list_items("v".to_string()).unwrap();
    let it = items.iter().find(|i| i.item_id == "host-notes").unwrap();
    assert_eq!(it.item_type, 6);
    let v1 = it.version;
    core.save_note(
        "v".to_string(),
        "host-notes".to_string(),
        "updated".to_string(),
    )
    .unwrap();
    let items = core.list_items("v".to_string()).unwrap();
    assert!(
        items
            .iter()
            .find(|i| i.item_id == "host-notes")
            .unwrap()
            .version
            > v1
    );

    // deletion → NotFound
    core.delete_item("v".to_string(), "host-notes".to_string())
        .unwrap();
    assert!(matches!(
        core.get_note("v".to_string(), "host-notes".to_string()),
        Err(unissh_ffi::FfiError::NotFound)
    ));
}

#[test]
fn get_note_is_type_gated() {
    // a note and a password don't substitute for each other; a key can't be pulled via get_note.
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    core.save_password("v".to_string(), "pw".to_string(), "secret".to_string())
        .unwrap();
    core.save_note("v".to_string(), "note".to_string(), "hello".to_string())
        .unwrap();

    // get_note on a key/password → not NotFound, but a type error
    let e = core
        .get_note("v".to_string(), "key".to_string())
        .unwrap_err();
    assert!(!matches!(e, unissh_ffi::FfiError::NotFound));
    let e = core
        .get_note("v".to_string(), "pw".to_string())
        .unwrap_err();
    assert!(!matches!(e, unissh_ffi::FfiError::NotFound));
    // get_password on a note → error
    assert!(core
        .get_password("v".to_string(), "note".to_string())
        .is_err());
}

#[test]
fn note_never_stored_in_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(Some("masterpw".to_string())).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let marker = "uniqu3-n0te-m4rker";
    core.save_note("v".to_string(), "n".to_string(), marker.to_string())
        .unwrap();
    core.lock();
    let db = std::fs::read(dir.path().join("inst.db")).unwrap();
    assert!(
        !contains(&db, marker.as_bytes()),
        "plaintext note found in DB"
    );
}

// --- profile tags: target selection + exec by tags ---

fn save_profile(core: &Core, id: &str, host: &str, port: u16, key_item: &str, tags: &[&str]) {
    core.save_connection(
        "v".to_string(),
        unissh_ffi::ConnectionProfile {
            profile_id: id.to_string(),
            uid: String::new(),
            username_template: None,
            label: id.to_string(),
            host: host.to_string(),
            port,
            user: "root".to_string(),
            auth: unissh_ffi::ProfileAuth::Key {
                key_item_id: key_item.to_string(),
            },
            jumps: vec![],
            tags: tags.iter().map(|s| s.to_string()).collect(),
            startup_snippet_ids: vec![],
            record_sessions: false,
            agent_forward: false,
        },
    )
    .unwrap();
}

#[test]
fn select_targets_by_tags_filters() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    save_profile(&core, "web1", "10.0.0.1", 22, "key", &["prod", "web"]);
    save_profile(&core, "web2", "10.0.0.2", 22, "key", &["staging", "web"]);
    save_profile(&core, "db1", "10.0.0.3", 22, "key", &["prod", "db"]);

    // any: tag=web → web1, web2
    let any_web = core
        .select_targets_by_tags("v".to_string(), vec!["web".to_string()], false)
        .unwrap();
    let mut hosts: Vec<_> = any_web.iter().map(|t| t.host.clone()).collect();
    hosts.sort();
    assert_eq!(hosts, vec!["10.0.0.1", "10.0.0.2"]);

    // all: prod+web → only web1
    let all = core
        .select_targets_by_tags(
            "v".to_string(),
            vec!["prod".to_string(), "web".to_string()],
            true,
        )
        .unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].host, "10.0.0.1");

    // empty query → nothing
    assert!(core
        .select_targets_by_tags("v".to_string(), vec![], false)
        .unwrap()
        .is_empty());
}

/// #12 (B4.3): select_targets_by_tags EXCLUDES PromptPassword hosts — there is no
/// pre-known password, so they don't go into the fan-out. Regression on a gap that
/// B4.3 closed but the test didn't cover (all prior profiles were key-auth).
#[test]
fn select_targets_by_tags_excludes_prompt_password() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    save_profile(&core, "web1", "10.0.0.1", 22, "key", &["web"]);
    // PromptPassword host with the same tag — must be filtered out.
    core.save_connection(
        "v".to_string(),
        unissh_ffi::ConnectionProfile {
            profile_id: "ask1".to_string(),
            uid: String::new(),
            username_template: None,
            label: "ask1".to_string(),
            host: "10.0.0.9".to_string(),
            port: 22,
            user: "root".to_string(),
            auth: unissh_ffi::ProfileAuth::PromptPassword,
            jumps: vec![],
            tags: vec!["web".to_string()],
            startup_snippet_ids: vec![],
            record_sessions: false,
            agent_forward: false,
        },
    )
    .unwrap();

    let sel = core
        .select_targets_by_tags("v".to_string(), vec!["web".to_string()], false)
        .unwrap();
    let hosts: Vec<_> = sel.iter().map(|t| t.host.clone()).collect();
    assert_eq!(
        hosts,
        vec!["10.0.0.1"],
        "PromptPassword host excluded from tag fan-out (#12)"
    );
}

#[test]
fn ssh_exec_by_tags_runs_on_matching() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);
    save_profile(&core, "h1", "127.0.0.1", sshd.port, "key", &["prod"]);
    save_profile(&core, "h2", "127.0.0.1", sshd.port, "key", &["staging"]);

    let results = core
        .ssh_exec_by_tags(
            "v".to_string(),
            vec!["prod".to_string()],
            false,
            "echo tagged".to_string(),
            0,
            0,
        )
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].error.is_none(), "err: {:?}", results[0].error);
    assert_eq!(results[0].stdout.trim(), "tagged");
}

// --- host groups (nested) ---

fn group(id: &str, members: &[&str], parent: Option<&str>) -> unissh_ffi::ServerGroup {
    unissh_ffi::ServerGroup {
        group_id: id.to_string(),
        label: id.to_string(),
        member_ids: members.iter().map(|s| s.to_string()).collect(),
        parent_id: parent.map(|s| s.to_string()),
    }
}

#[test]
fn host_group_crud_and_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    core.save_group("v".to_string(), group("prod", &["web1", "web2"], None))
        .unwrap();
    let g = core.get_group("v".to_string(), "prod".to_string()).unwrap();
    assert_eq!(g.label, "prod");
    assert_eq!(g.member_ids, vec!["web1", "web2"]);
    assert!(g.parent_id.is_none());

    // type 5, the version grows
    let items = core.list_items("v".to_string()).unwrap();
    let it = items.iter().find(|i| i.item_id == "prod").unwrap();
    assert_eq!(it.item_type, 5);
    let v1 = it.version;
    core.save_group("v".to_string(), group("prod", &["web1"], Some("all")))
        .unwrap();
    let items = core.list_items("v".to_string()).unwrap();
    assert!(items.iter().find(|i| i.item_id == "prod").unwrap().version > v1);
    let g = core.get_group("v".to_string(), "prod".to_string()).unwrap();
    assert_eq!(g.parent_id.as_deref(), Some("all"));

    assert_eq!(core.list_groups("v".to_string()).unwrap().len(), 1);

    // tombstone → NotFound, list doesn't see it
    core.delete_group("v".to_string(), "prod".to_string())
        .unwrap();
    assert!(matches!(
        core.get_group("v".to_string(), "prod".to_string()),
        Err(unissh_ffi::FfiError::NotFound)
    ));
    assert!(core.list_groups("v".to_string()).unwrap().is_empty());
}

#[test]
fn group_validation_and_clobber() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "id".to_string())
        .unwrap();

    // self-membership / self-parenting / empty id → error
    assert!(core
        .save_group("v".to_string(), group("g", &["g"], None))
        .is_err());
    assert!(core
        .save_group("v".to_string(), group("g", &[], Some("g")))
        .is_err());
    assert!(core
        .save_group("v".to_string(), group("", &[], None))
        .is_err());

    // cross-type clobber: a group with the id of an existing key → AlreadyExists, key intact
    assert!(matches!(
        core.save_group("v".to_string(), group("id", &[], None)),
        Err(unissh_ffi::FfiError::AlreadyExists)
    ));
    assert!(core
        .get_public_key("v".to_string(), "id".to_string())
        .is_ok());
}

#[test]
fn group_serde_forward_compat() {
    // a group without parent_id/color (minimal JSON) is read
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.save_group("v".to_string(), group("g", &["a", "b"], None))
        .unwrap();
    let g = core.get_group("v".to_string(), "g".to_string()).unwrap();
    assert!(g.parent_id.is_none());
    assert_eq!(g.member_ids, vec!["a", "b"]);
}

#[test]
fn ssh_exec_group_runs_nested() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);
    save_profile(&core, "p1", "127.0.0.1", sshd.port, "key", &[]);
    save_profile(&core, "p2", "127.0.0.1", sshd.port, "key", &[]);

    // A → [p1, B]; B → [p2]  (nesting)
    core.save_group("v".to_string(), group("B", &["p2"], None))
        .unwrap();
    core.save_group("v".to_string(), group("A", &["p1", "B"], None))
        .unwrap();

    let results = core
        .ssh_exec_group(
            "v".to_string(),
            "A".to_string(),
            "echo grp".to_string(),
            0,
            0,
        )
        .unwrap();
    assert_eq!(results.len(), 2, "a nested group should yield 2 hosts");
    for r in &results {
        assert!(r.error.is_none(), "err: {:?}", r.error);
        assert_eq!(r.stdout.trim(), "grp");
    }
}

#[test]
fn ssh_exec_group_empty_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.save_group("v".to_string(), group("empty", &[], None))
        .unwrap();
    let results = core
        .ssh_exec_group(
            "v".to_string(),
            "empty".to_string(),
            "echo x".to_string(),
            0,
            0,
        )
        .unwrap();
    assert!(results.is_empty());
}

#[test]
fn dry_run_group_reports_statuses() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    // ok profile (key), prompt profile (PromptPassword), and a dangling reference
    save_profile(&core, "ok1", "10.0.0.1", 22, "key", &[]);
    core.save_connection(
        "v".to_string(),
        unissh_ffi::ConnectionProfile {
            profile_id: "prompt1".to_string(),
            uid: String::new(),
            username_template: None,
            label: "p".to_string(),
            host: "10.0.0.2".to_string(),
            port: 22,
            user: "root".to_string(),
            auth: unissh_ffi::ProfileAuth::PromptPassword,
            jumps: vec![],
            tags: vec![],
            startup_snippet_ids: vec![],
            record_sessions: false,
            agent_forward: false,
        },
    )
    .unwrap();
    core.save_group(
        "v".to_string(),
        group("g", &["ok1", "prompt1", "ghost"], None),
    )
    .unwrap();

    let plans = core
        .dry_run_group("v".to_string(), "g".to_string())
        .unwrap();
    let status = |id: &str| plans.iter().find(|p| p.member_id == id).map(|p| p.status);
    assert_eq!(status("ok1"), Some(unissh_ffi::ResolveStatus::Ok));
    assert_eq!(
        status("prompt1"),
        Some(unissh_ffi::ResolveStatus::PromptPassword)
    );
    assert_eq!(status("ghost"), Some(unissh_ffi::ResolveStatus::Dangling));
    // ok1 resolved to a real host
    assert_eq!(
        plans.iter().find(|p| p.member_id == "ok1").unwrap().host,
        "10.0.0.1"
    );
}

#[test]
fn ssh_exec_group_marks_dangling_and_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);
    save_profile(&core, "p1", "127.0.0.1", sshd.port, "key", &[]);

    // cycle A→B→A + a dangling member; p1 is valid and must run once
    core.save_group("v".to_string(), group("A", &["p1", "B", "ghost"], None))
        .unwrap();
    core.save_group("v".to_string(), group("B", &["A"], None))
        .unwrap();

    let results = core
        .ssh_exec_group(
            "v".to_string(),
            "A".to_string(),
            "echo ok".to_string(),
            0,
            0,
        )
        .unwrap();
    // exactly one success (p1), plus error markers for ghost and the cycle
    let ok: Vec<_> = results.iter().filter(|r| r.error.is_none()).collect();
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].stdout.trim(), "ok");
    assert!(results
        .iter()
        .any(|r| r.host == "ghost" && r.error.is_some()));
    // and the cycle marker (member-group B already visited → the reference to A is flagged as an error)
    assert!(
        results
            .iter()
            .any(|r| r.error.as_deref().is_some_and(|e| e.contains("cycle"))),
        "expected a cycle error marker; got: {:?}",
        results
            .iter()
            .map(|r| (&r.host, &r.error))
            .collect::<Vec<_>>()
    );
}

// --- terminal-resize hardening ---

#[test]
fn resize_changes_terminal_size() {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let observer = Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    let session = core
        .open_session(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            "xterm".to_string(),
            80,
            24,
            observer.clone(),
            None,
            false,
        )
        .unwrap();

    // resize → window_change; verify the actual PTY size via stty size
    session.resize(120, 40).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    session.write(b"stty size\n".to_vec()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        // stty size prints "rows cols" → "40 120" (axes not swapped)
        if contains(&observer.buf.lock().unwrap(), b"40 120") {
            break;
        }
        if Instant::now() > deadline {
            panic!(
                "PTY size not updated; got: {:?}",
                String::from_utf8_lossy(&observer.buf.lock().unwrap())
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // zero size is rejected at the FFI boundary (garbage doesn't reach the server)
    assert!(session.resize(0, 40).is_err());
    assert!(session.resize(120, 0).is_err());

    session.close().unwrap();
}

#[test]
fn open_session_rejects_zero_size() {
    // Real sshd: without validation, open_session(cols=0) would connect SUCCESSFULLY.
    // So is_err() catches the size validation specifically, not a connection failure.
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);
    let observer = std::sync::Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    let r = core.open_session(
        "127.0.0.1".to_string(),
        sshd.port,
        "root".to_string(),
        agent_auth("v", "key"),
        vec![],
        "xterm".to_string(),
        0,
        24,
        observer,
        None,
        false,
    );
    assert!(r.is_err(), "zero width must be rejected by validation");
}

// --- vault integrity audit (verify_chain) ---

#[test]
fn verify_vault_integrity_ok() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    core.save_password("v".to_string(), "pw".to_string(), "s".to_string())
        .unwrap();
    core.save_note("v".to_string(), "n".to_string(), "note".to_string())
        .unwrap();
    core.delete_item("v".to_string(), "n".to_string()).unwrap(); // tombstone

    let report = core.verify_vault_integrity("v".to_string()).unwrap();
    assert!(report.ok, "issues: {:?}", report.issues);
    assert!(report.issues.is_empty());
    // vault + key + pw + n(tombstone) = 4
    assert!(report.checked >= 4);
}

// --- exporting ~/.ssh/config from the vault ---

#[test]
fn export_ssh_config_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let cfg = "Host web\n  HostName 192.168.1.10\n  User deploy\n  Port 2222\n\
               Host gw\n  HostName gw.example.com\n  ProxyJump jumpuser@jump.example.com:2200\n";
    core.import_ssh_config("v".to_string(), cfg.to_string())
        .unwrap();

    let exported = core.export_ssh_config("v".to_string()).unwrap();
    assert!(exported.contains("Host web"));
    assert!(exported.contains("HostName 192.168.1.10"));
    assert!(exported.contains("Port 2222"));
    assert!(exported.contains("ProxyJump jumpuser@jump.example.com:2200"));

    // round-trip: importing the export into a fresh vault yields the same profiles
    core.create_vault("v2".to_string(), "V2".to_string())
        .unwrap();
    core.import_ssh_config("v2".to_string(), exported).unwrap();
    let web = core
        .get_connection("v2".to_string(), "web".to_string())
        .unwrap();
    assert_eq!(web.host, "192.168.1.10");
    assert_eq!(web.port, 2222);
    assert_eq!(web.user, "deploy");
    let gw = core
        .get_connection("v2".to_string(), "gw".to_string())
        .unwrap();
    assert_eq!(gw.jumps.len(), 1);
    assert_eq!(gw.jumps[0].host, "jump.example.com");
    assert_eq!(gw.jumps[0].port, 2200);
    assert_eq!(gw.jumps[0].user, "jumpuser");
}

// --- importing ~/.ssh/known_hosts ---

#[test]
fn import_known_hosts_pins_and_skips_hashed() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    // a real ed25519 public key
    let pubkey = core
        .generate_ssh_key("v".to_string(), "k".to_string())
        .unwrap();

    let text = format!(
        "# comment line\nexample.com {pubkey}\n[10.0.0.1]:2222 {pubkey}\n\
         |1|aGFzaA==|c2FsdA== {pubkey}\ngarbage-no-key\n"
    );
    let report = core.import_known_hosts(text).unwrap();
    assert_eq!(report.imported, 2, "example.com + [10.0.0.1]:2222");
    assert_eq!(report.skipped_hashed, 1);
    assert!(report.skipped_invalid >= 1);

    let hosts = core.list_known_hosts().unwrap();
    assert!(hosts
        .iter()
        .any(|h| h.host == "example.com" && h.port == 22));
    assert!(hosts.iter().any(|h| h.host == "10.0.0.1" && h.port == 2222));

    // repeated import is idempotent (UPSERT) — the number of known hosts doesn't grow
    let before = core.list_known_hosts().unwrap().len();
    core.import_known_hosts(format!("example.com {pubkey}\n"))
        .unwrap();
    assert_eq!(core.list_known_hosts().unwrap().len(), before);
}

// --- DB consistency check ---

#[test]
fn check_consistency_ok() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "k".to_string())
        .unwrap();
    let report = core.check_consistency().unwrap();
    assert!(report.ok, "issues: {:?}", report.issues);
    assert!(report.integrity_ok);
    assert!(report.issues.is_empty());
}

// --- fleet push: distributing a file to many hosts via SFTP ---

fn key_target(port: u16) -> MultiExecTarget {
    MultiExecTarget {
        host: "127.0.0.1".to_string(),
        port,
        user: "root".to_string(),
        auth: agent_auth("v", "key"),
        jumps: vec![],
    }
}

#[test]
fn sftp_put_multi_distributes_file() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let path = dir.path().join("pushed.bin");
    let data = b"fleet-payload-123".to_vec();
    let results = core
        .sftp_put_multi(
            vec![key_target(sshd.port)],
            path.to_str().unwrap().to_string(),
            data.clone(),
            false,
            0,
            0,
        )
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].error.is_none(), "err: {:?}", results[0].error);
    assert_eq!(std::fs::read(&path).unwrap(), data);
}

#[test]
fn sftp_put_multi_makes_parent_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let path = dir.path().join("nested").join("file.bin");
    let data = b"in-subdir".to_vec();
    // first time: creates the parent
    let r1 = core
        .sftp_put_multi(
            vec![key_target(sshd.port)],
            path.to_str().unwrap().to_string(),
            data.clone(),
            true,
            0,
            0,
        )
        .unwrap();
    assert!(r1[0].error.is_none(), "err: {:?}", r1[0].error);
    assert_eq!(std::fs::read(&path).unwrap(), data);

    // second time: the parent already exists, the mkdir error is swallowed
    let r2 = core
        .sftp_put_multi(
            vec![key_target(sshd.port)],
            path.to_str().unwrap().to_string(),
            b"again".to_vec(),
            true,
            0,
            0,
        )
        .unwrap();
    assert!(r2[0].error.is_none(), "err: {:?}", r2[0].error);
}

// --- broadcast session (cluster-ssh): one input → many PTYs ---

struct BcastObserver {
    bufs: std::sync::Mutex<std::collections::HashMap<u32, Vec<u8>>>,
}
impl unissh_ffi::BroadcastObserver for BcastObserver {
    fn on_data(&self, host_index: u32, data: Vec<u8>) {
        self.bufs
            .lock()
            .unwrap()
            .entry(host_index)
            .or_default()
            .extend_from_slice(&data);
    }
    fn on_close(&self, _host_index: u32, _exit_status: i32) {}
}

#[test]
fn broadcast_fans_out_input() {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let obs = Arc::new(BcastObserver {
        bufs: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    let session = core
        .open_broadcast(
            vec![key_target(sshd.port), key_target(sshd.port)],
            "xterm".to_string(),
            80,
            24,
            obs.clone(),
        )
        .unwrap();
    let st = session.statuses();
    assert_eq!(st.len(), 2);
    assert!(st.iter().all(|s| s.connected), "statuses: {:?}", st);

    // a single write_all goes to both hosts
    session.write_all(b"echo bcast-hi\n".to_vec()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let bufs = obs.bufs.lock().unwrap();
        let both = (0..2).all(|i| {
            bufs.get(&i)
                .map(|b| contains(b, b"bcast-hi"))
                .unwrap_or(false)
        });
        drop(bufs);
        if both {
            break;
        }
        if Instant::now() > deadline {
            panic!(
                "broadcast output not received on both hosts: {:?}",
                obs.bufs.lock().unwrap().keys().collect::<Vec<_>>()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    session.close();
}

// --- streaming exec (separate stdout/stderr + return code) ---

struct StreamObs {
    out: std::sync::Mutex<Vec<u8>>,
    err: std::sync::Mutex<Vec<u8>>,
    exit: std::sync::Mutex<Option<i32>>,
}
impl unissh_ffi::ExecObserver for StreamObs {
    fn on_stdout(&self, data: Vec<u8>) {
        self.out.lock().unwrap().extend_from_slice(&data);
    }
    fn on_stderr(&self, data: Vec<u8>) {
        self.err.lock().unwrap().extend_from_slice(&data);
    }
    fn on_exit(&self, exit_status: i32) {
        *self.exit.lock().unwrap() = Some(exit_status);
    }
}

#[test]
fn ssh_exec_stream_streams_and_reports_exit() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let obs = Arc::new(StreamObs {
        out: std::sync::Mutex::new(Vec::new()),
        err: std::sync::Mutex::new(Vec::new()),
        exit: std::sync::Mutex::new(None),
    });
    let handle = core
        .ssh_exec_stream(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            "echo to-out; echo to-err 1>&2; exit 3".to_string(),
            vec![],
            obs.clone(),
        )
        .unwrap();

    assert!(
        handle.wait_exit(4000).unwrap(),
        "command should have exited"
    );
    assert!(contains(&obs.out.lock().unwrap(), b"to-out"));
    assert!(contains(&obs.err.lock().unwrap(), b"to-err"));
    assert_eq!(*obs.exit.lock().unwrap(), Some(3));
    handle.close().unwrap();
}

// --- resumable SFTP with progress and cancellation ---

#[derive(Default)]
struct ProgObs {
    last: std::sync::Mutex<(u64, u64)>,
}
impl unissh_ffi::SftpProgressObserver for ProgObs {
    fn on_progress(&self, transferred: u64, total: u64) {
        *self.last.lock().unwrap() = (transferred, total);
    }
}

#[test]
fn sftp_upload_download_resume_and_cancel() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);
    let sftp = core
        .open_sftp(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            4,
        )
        .unwrap();

    // source ~100KB (several 32KB chunks)
    let content: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let src = dir.path().join("src.bin");
    std::fs::write(&src, &content).unwrap();
    let remote = dir.path().join("remote.bin");

    // upload with progress
    let prog = Arc::new(ProgObs::default());
    let done = sftp
        .sftp_upload(
            src.to_str().unwrap().to_string(),
            remote.to_str().unwrap().to_string(),
            0,
            Some(prog.clone()),
            None,
        )
        .unwrap();
    assert!(done, "upload should complete");
    assert_eq!(std::fs::read(&remote).unwrap(), content);
    assert_eq!(prog.last.lock().unwrap().0, content.len() as u64);

    // download in full
    let dl = dir.path().join("dl.bin");
    let done = sftp
        .sftp_download(
            remote.to_str().unwrap().to_string(),
            dl.to_str().unwrap().to_string(),
            0,
            None, // known_size: the core will stat by itself
            None,
            None,
        )
        .unwrap();
    assert!(done);
    assert_eq!(std::fs::read(&dl).unwrap(), content);

    // resume download: pre-fill the first 40000 bytes, fetch the rest
    let resume = dir.path().join("resume.bin");
    std::fs::write(&resume, &content[..40_000]).unwrap();
    let done = sftp
        .sftp_download(
            remote.to_str().unwrap().to_string(),
            resume.to_str().unwrap().to_string(),
            40_000,
            Some(content.len() as u64), // known_size: skip the stat (directory resume)
            None,
            None,
        )
        .unwrap();
    assert!(done);
    assert_eq!(std::fs::read(&resume).unwrap(), content);

    // cancellation: the token is cancelled up front → does not complete
    let token = unissh_ffi::CancelToken::new();
    token.cancel();
    let cancelled = dir.path().join("cancelled.bin");
    let done = sftp
        .sftp_download(
            remote.to_str().unwrap().to_string(),
            cancelled.to_str().unwrap().to_string(),
            0,
            None, // known_size
            None,
            Some(token),
        )
        .unwrap();
    assert!(!done, "cancelled download must not report completion");
}

// --- auto-reconnect of an interactive session ---

#[test]
fn reconnecting_session_reconnects_and_works() {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let observer = Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    let session = core
        .open_reconnecting_session(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            "xterm".to_string(),
            80,
            24,
            2,
            10,
            observer.clone(),
            false,
        )
        .unwrap();
    assert!(session.is_connected());

    // an explicit reconnect recreates a working PTY session (new TOFU, re-resolved creds)
    session.reconnect().unwrap();
    session.write(b"echo recon-OK\n".to_vec()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if contains(&observer.buf.lock().unwrap(), b"recon-OK") {
            break;
        }
        if Instant::now() > deadline {
            panic!("no output after reconnect");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    session.close();
}

#[test]
fn reconnecting_session_fails_after_retries() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let observer = std::sync::Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    // nobody listens on this port → the connect exhausts its attempts and returns an error
    let dead = free_port();
    let r = core.open_reconnecting_session(
        "127.0.0.1".to_string(),
        dead,
        "root".to_string(),
        agent_auth("v", "key"),
        vec![],
        "xterm".to_string(),
        80,
        24,
        2,
        10,
        observer,
        false,
    );
    assert!(r.is_err());
}

// --- importing PuTTY sessions (.reg) ---

#[test]
fn import_putty_sessions_creates_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    // the session name "prod web" is url-encoded as prod%20web; port dword (0x16=22, 0x935=2357)
    let reg = "Windows Registry Editor Version 5.00\r\n\r\n\
        [HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\prod%20web]\r\n\
        \"HostName\"=\"10.0.0.5\"\r\n\
        \"PortNumber\"=dword:00000935\r\n\
        \"UserName\"=\"deploy\"\r\n\
        \"Protocol\"=\"ssh\"\r\n\r\n\
        [HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\telnetbox]\r\n\
        \"HostName\"=\"10.0.0.9\"\r\n\
        \"Protocol\"=\"telnet\"\r\n";
    let report = core
        .import_putty_sessions("v".to_string(), reg.to_string())
        .unwrap();
    // the ssh session is created, telnet is skipped
    assert_eq!(report.created_ids, vec!["prod web"]);
    assert_eq!(report.skipped, 1);

    let p = core
        .get_connection("v".to_string(), "prod web".to_string())
        .unwrap();
    assert_eq!(p.host, "10.0.0.5");
    assert_eq!(p.port, 2357);
    assert_eq!(p.user, "deploy");
}

// --- secret version history through FFI ---

#[test]
fn password_version_history_reveal_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.save_password("v".to_string(), "pw".to_string(), "p1".to_string())
        .unwrap();
    core.save_password("v".to_string(), "pw".to_string(), "p2".to_string())
        .unwrap();
    core.save_password("v".to_string(), "pw".to_string(), "p3".to_string())
        .unwrap();

    let mut versions = core
        .list_item_versions("v".to_string(), "pw".to_string())
        .unwrap();
    versions.sort();
    assert_eq!(versions, vec![1, 2, 3]);

    assert_eq!(
        core.get_password_version("v".to_string(), "pw".to_string(), 1)
            .unwrap(),
        "p1"
    );
    assert_eq!(
        core.get_password_version("v".to_string(), "pw".to_string(), 2)
            .unwrap(),
        "p2"
    );
    assert_eq!(
        core.get_password("v".to_string(), "pw".to_string())
            .unwrap(),
        "p3"
    );

    // type-gate: a key's version can't be pulled via the password reveal
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    assert!(core
        .get_password_version("v".to_string(), "key".to_string(), 1)
        .is_err());

    // deletion clears the history
    core.delete_item("v".to_string(), "pw".to_string()).unwrap();
    assert!(core
        .list_item_versions("v".to_string(), "pw".to_string())
        .unwrap()
        .is_empty());
}

// --- encrypted vault backup/export ---

#[test]
fn vault_backup_export_import_round_trip() {
    // instance A
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path());
    core_a.create_account(None).unwrap();
    core_a
        .create_vault("v".to_string(), "V".to_string())
        .unwrap();
    let pub_a = core_a
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    core_a
        .save_password("v".to_string(), "pw".to_string(), "secret-pw".to_string())
        .unwrap();
    core_a
        .save_note(
            "v".to_string(),
            "note".to_string(),
            "secret-note".to_string(),
        )
        .unwrap();

    let backup = core_a
        .export_vault("v".to_string(), "backup-pass".to_string())
        .unwrap();
    assert!(!backup.is_empty());

    // instance B (fresh) — restore into vault "restored"
    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path());
    core_b.create_account(None).unwrap();
    core_b
        .import_vault(
            backup.clone(),
            "backup-pass".to_string(),
            "restored".to_string(),
        )
        .unwrap();

    // secrets restored
    assert_eq!(
        core_b
            .get_password("restored".to_string(), "pw".to_string())
            .unwrap(),
        "secret-pw"
    );
    assert_eq!(
        core_b
            .get_note("restored".to_string(), "note".to_string())
            .unwrap(),
        "secret-note"
    );
    // the private key is restored (the public key matches the original)
    assert_eq!(
        core_b
            .get_public_key("restored".to_string(), "key".to_string())
            .unwrap()
            .openssh,
        pub_a
    );

    // wrong passphrase → error
    assert!(core_b
        .import_vault(backup.clone(), "wrong-pass".to_string(), "x".to_string())
        .is_err());

    // corrupted backup → error
    let mut tampered = backup.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0x01;
    assert!(core_b
        .import_vault(tampered, "backup-pass".to_string(), "y".to_string())
        .is_err());

    // A restore carries the ORIGINAL vault's name with it — the name is a record
    // inside the bundle, not a property of the id it is restored under. So a
    // restore beside its own source produces two entries with identical names and
    // nothing to tell them apart, which is what "Restore as" is for. Renaming
    // afterwards is the whole of that feature, so it is checked here: the name
    // cache is keyed by the RAW vault id, and an id that resolves differently
    // would leave list_vaults reading the old name back.
    let named = core_b
        .list_vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.vault_id == "restored")
        .expect("the restored vault is listed");
    assert_eq!(named.name, "V", "the backup carries the source's name");

    core_b
        .rename_vault("restored".to_string(), "RETEST-restored".to_string())
        .unwrap();
    let renamed = core_b
        .list_vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.vault_id == "restored")
        .expect("still listed after the rename");
    assert_eq!(
        renamed.name, "RETEST-restored",
        "the restored vault has to answer to the name it was restored as"
    );
}

// --- review regressions ---

#[test]
fn sftp_download_rejects_offset_beyond_size() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);
    let sftp = core
        .open_sftp(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            4,
        )
        .unwrap();

    let src = dir.path().join("src.bin");
    std::fs::write(&src, b"abc").unwrap();
    let remote = dir.path().join("remote.bin");
    sftp.sftp_upload(
        src.to_str().unwrap().to_string(),
        remote.to_str().unwrap().to_string(),
        0,
        None,
        None,
    )
    .unwrap();

    // offset past the end of remote (3 bytes) → error, not a "success" with a corrupt file
    let dl = dir.path().join("dl.bin");
    assert!(sftp
        .sftp_download(
            remote.to_str().unwrap().to_string(),
            dl.to_str().unwrap().to_string(),
            999,
            None, // known_size
            None,
            None
        )
        .is_err());
}

// Channel pool: more concurrent transfers than channels (8 > K=4), across different
// threads. Verifies concurrent channel lease/return under saturation (4 wait for
// release), absence of deadlock, and correctness of each file's contents.
#[test]
fn sftp_pool_parallel_downloads() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);
    let sftp = core
        .open_sftp(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            4, // K=4 channels, but there are 8 files below
        )
        .unwrap();

    // 8 files with distinguishable contents; upload sequentially.
    let n = 8usize;
    let remotes: Vec<(String, Vec<u8>)> = (0..n)
        .map(|i| {
            let content: Vec<u8> = (0..50_000u32)
                .map(|b| ((b as usize + i) % 251) as u8)
                .collect();
            let src = dir.path().join(format!("src{i}.bin"));
            std::fs::write(&src, &content).unwrap();
            let remote = dir.path().join(format!("remote{i}.bin"));
            sftp.sftp_upload(
                src.to_str().unwrap().to_string(),
                remote.to_str().unwrap().to_string(),
                0,
                None,
                None,
            )
            .unwrap();
            (remote.to_str().unwrap().to_string(), content)
        })
        .collect();

    // Download them all in parallel — one thread per file; leases > channels.
    let sftp = Arc::new(sftp);
    let handles: Vec<_> = remotes
        .into_iter()
        .enumerate()
        .map(|(i, (remote, content))| {
            let sftp = sftp.clone();
            let dl = dir.path().join(format!("dl{i}.bin"));
            std::thread::spawn(move || {
                let ok = sftp
                    .sftp_download(
                        remote,
                        dl.to_str().unwrap().to_string(),
                        0,
                        Some(content.len() as u64),
                        None,
                        None,
                    )
                    .unwrap();
                assert!(ok, "parallel download {i} should complete");
                assert_eq!(std::fs::read(&dl).unwrap(), content, "file {i} content");
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

// Regression: a server with `MaxSessions 1` refuses the second channel
// (`AdministrativelyProhibited`). A pool requested at K=4 must SHRINK to 1 and
// reuse the single channel rather than dropping transfers. Previously a parallel
// upload would fail with a channel-open error.
#[test]
fn sftp_pool_degrades_on_max_sessions() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start_with_max_sessions(&pubkey, 1);
    let sftp = core
        .open_sftp(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            4, // request 4, but the server will allow only 1
        )
        .unwrap();

    let n = 6usize;
    let remotes: Vec<(String, Vec<u8>)> = (0..n)
        .map(|i| {
            let content: Vec<u8> = (0..30_000u32)
                .map(|b| ((b as usize + i) % 251) as u8)
                .collect();
            let src = dir.path().join(format!("src{i}.bin"));
            std::fs::write(&src, &content).unwrap();
            let remote = dir.path().join(format!("remote{i}.bin"));
            sftp.sftp_upload(
                src.to_str().unwrap().to_string(),
                remote.to_str().unwrap().to_string(),
                0,
                None,
                None,
            )
            .unwrap();
            (remote.to_str().unwrap().to_string(), content)
        })
        .collect();

    // Parallel downloads: the pool will reject extra channels and reuse one.
    let sftp = Arc::new(sftp);
    let handles: Vec<_> = remotes
        .into_iter()
        .enumerate()
        .map(|(i, (remote, content))| {
            let sftp = sftp.clone();
            let dl = dir.path().join(format!("dl{i}.bin"));
            std::thread::spawn(move || {
                let ok = sftp
                    .sftp_download(
                        remote,
                        dl.to_str().unwrap().to_string(),
                        0,
                        Some(content.len() as u64),
                        None,
                        None,
                    )
                    .unwrap();
                assert!(ok, "download {i} should complete despite MaxSessions=1");
                assert_eq!(std::fs::read(&dl).unwrap(), content, "file {i} content");
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn import_vault_rejects_used_vault_id() {
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path());
    core_a.create_account(None).unwrap();
    core_a
        .create_vault("v".to_string(), "V".to_string())
        .unwrap();
    core_a
        .save_password("v".to_string(), "pw".to_string(), "s".to_string())
        .unwrap();
    let backup = core_a
        .export_vault("v".to_string(), "pass".to_string())
        .unwrap();

    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path());
    core_b.create_account(None).unwrap();
    core_b
        .import_vault(backup.clone(), "pass".to_string(), "restored".to_string())
        .unwrap();
    // delete it — the id stays occupied by a tombstone
    core_b.delete_vault("restored".to_string()).unwrap();
    // re-importing into the same id → a clear error, not corruption
    assert!(matches!(
        core_b.import_vault(backup, "pass".to_string(), "restored".to_string()),
        Err(unissh_ffi::FfiError::AlreadyExists)
    ));
}

#[test]
fn backup_tampered_kdf_params_fail() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.save_password("v".to_string(), "pw".to_string(), "s".to_string())
        .unwrap();
    let backup = core
        .export_vault("v".to_string(), "pass".to_string())
        .unwrap();

    // a byte inside kdf_blob (after magic(4)+version(1)+len(4)) — now covered by AAD
    let mut tampered = backup.clone();
    tampered[12] ^= 0x01;
    let dir2 = tempfile::tempdir().unwrap();
    let core2 = new_core(dir2.path());
    core2.create_account(None).unwrap();
    assert!(core2
        .import_vault(tampered, "pass".to_string(), "x".to_string())
        .is_err());
}

#[test]
fn import_putty_skips_existing_profile() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    save_profile(&core, "web", "10.0.0.1", 22, "key", &[]);

    let reg = "[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\web]\r\n\
        \"HostName\"=\"10.0.0.99\"\r\n\"Protocol\"=\"ssh\"\r\n";
    let report = core
        .import_putty_sessions("v".to_string(), reg.to_string())
        .unwrap();
    assert!(report.created_ids.is_empty());
    assert_eq!(report.skipped, 1);
    // the existing profile is NOT overwritten
    assert_eq!(
        core.get_connection("v".to_string(), "web".to_string())
            .unwrap()
            .host,
        "10.0.0.1"
    );
}

#[test]
fn reconnecting_session_auto_reconnects_on_write() {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);
    let observer = Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    let session = core
        .open_reconnecting_session(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            "xterm".to_string(),
            80,
            24,
            2,
            10,
            observer.clone(),
            false,
        )
        .unwrap();
    // tear down the current session; the next write must reconnect on its own
    session.close();
    assert!(!session.is_connected());
    session.write(b"echo auto-reconnect-OK\n".to_vec()).unwrap();
    assert!(session.is_connected());

    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if contains(&observer.buf.lock().unwrap(), b"auto-reconnect-OK") {
            break;
        }
        if Instant::now() > deadline {
            panic!("write() did not auto-reconnect");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    session.close();
}

/// Secret-boundary contract (see module-doc `unissh-ffi`): enumerates the ONLY
/// methods allowed to return secret material outward, and checks their
/// type-gating. Tripwire: added a new secret-returning method — update both this
/// test and the module-doc. The device's private keyset is returned by no method.
#[test]
fn secret_returning_surface() {
    // Deliberately secret-returning methods (exhaustive list):
    const SECRET_RETURNING: &[&str] = &[
        "get_password",   // user secret (password manager reveal)
        "get_note",       // user secret (note reveal)
        "export_ssh_key", // by-design: user owns & may export their private key
        "export_vault",   // passphrase-encrypted backup
        // Snippet command text. Listed here rather than quietly omitted: a saved
        // command routinely carries hostnames, ticket ids and the odd token, so
        // it is user content of the same kind as a note. It is NOT type-gated
        // like get_note, because a snippet library is chosen from by reading the
        // commands — gating the only thing that makes the list usable would be
        // theatre, not a control.
        "list_snippets",
    ];
    assert_eq!(
        SECRET_RETURNING.len(),
        5,
        "update the test when the surface changes"
    );

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.save_password("v".to_string(), "pw".to_string(), "s3cret".to_string())
        .unwrap();
    core.save_note("v".to_string(), "nt".to_string(), "a note".to_string())
        .unwrap();
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();

    // get_password: reveal only for a password item, otherwise refuse (type-gate).
    assert_eq!(
        core.get_password("v".to_string(), "pw".to_string())
            .unwrap(),
        "s3cret"
    );
    assert!(core
        .get_password("v".to_string(), "nt".to_string())
        .is_err());
    assert!(core
        .get_password("v".to_string(), "key".to_string())
        .is_err());

    // get_note: reveal only for a note item.
    assert_eq!(
        core.get_note("v".to_string(), "nt".to_string()).unwrap(),
        "a note"
    );
    assert!(core.get_note("v".to_string(), "pw".to_string()).is_err());

    // export_ssh_key: the private key — by-design, but only for an SSH-key item.
    let priv_key = core
        .export_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    assert!(
        priv_key.contains("PRIVATE KEY"),
        "expected an OpenSSH private key"
    );
    assert!(core
        .export_ssh_key("v".to_string(), "pw".to_string())
        .is_err());

    // export_vault: a non-empty encrypted backup.
    let backup = core
        .export_vault("v".to_string(), "backup-pass".to_string())
        .unwrap();
    assert!(!backup.is_empty());
}

/// Snippets: the round-trip, the guards, and that a delete leaves a tombstone
/// rather than a gap another device will refill on the next sync.
#[test]
fn snippet_crud_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    core.save_snippet(
        "v".to_string(),
        unissh_ffi::Snippet {
            snippet_id: "tail-log".to_string(),
            label: "Tail the app log".to_string(),
            command: "sudo journalctl -fu app".to_string(),
            tags: vec!["ops".to_string()],
        },
    )
    .unwrap();
    core.save_snippet(
        "v".to_string(),
        unissh_ffi::Snippet {
            snippet_id: "motd".to_string(),
            label: "A greeting".to_string(),
            command: "echo hi".to_string(),
            tags: vec![],
        },
    )
    .unwrap();

    let list = core.list_snippets("v".to_string()).unwrap();
    assert_eq!(list.len(), 2);
    // Sorted by label, so the library does not reshuffle between reads.
    assert_eq!(list[0].label, "A greeting");
    assert_eq!(list[1].command, "sudo journalctl -fu app");
    assert_eq!(list[1].tags, vec!["ops".to_string()]);

    // Empty id and empty command are refused rather than stored as junk.
    assert!(core
        .save_snippet(
            "v".to_string(),
            unissh_ffi::Snippet {
                snippet_id: String::new(),
                label: "x".to_string(),
                command: "echo".to_string(),
                tags: vec![],
            },
        )
        .is_err());
    assert!(core
        .save_snippet(
            "v".to_string(),
            unissh_ffi::Snippet {
                snippet_id: "blank".to_string(),
                label: "x".to_string(),
                command: String::new(),
                tags: vec![],
            },
        )
        .is_err());

    core.delete_snippet("v".to_string(), "motd".to_string())
        .unwrap();
    let after = core.list_snippets("v".to_string()).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].snippet_id, "tail-log");
}

/// A snippet id must not be usable to overwrite an item of another type — the
/// same cross-type guard the other item kinds get.
#[test]
fn snippet_cannot_overwrite_another_item_type() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.save_password(
        "v".to_string(),
        "shared-id".to_string(),
        "s3cret".to_string(),
    )
    .unwrap();

    let clash = core.save_snippet(
        "v".to_string(),
        unissh_ffi::Snippet {
            snippet_id: "shared-id".to_string(),
            label: "sneaky".to_string(),
            command: "echo pwned".to_string(),
            tags: vec![],
        },
    );
    assert!(
        clash.is_err(),
        "a snippet must not clobber a stored password"
    );
    // And the password is still intact.
    assert_eq!(
        core.get_password("v".to_string(), "shared-id".to_string())
            .unwrap(),
        "s3cret"
    );
}

/// Startup snippets live on the profile, not as a global flag on the snippet:
/// "run on connect" has to say *where*, and a global one would run on every
/// host. Checks the round-trip and that clearing the list really clears it.
#[test]
fn profile_carries_its_startup_snippets() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    let mut p = unissh_ffi::ConnectionProfile {
        profile_id: "web1".to_string(),
        uid: String::new(),
        label: "web1".to_string(),
        host: "10.0.0.1".to_string(),
        port: 22,
        user: "deploy".to_string(),
        auth: unissh_ffi::ProfileAuth::PromptPassword,
        username_template: None,
        jumps: vec![],
        tags: vec![],
        startup_snippet_ids: vec!["tmux-attach".to_string(), "cd-app".to_string()],
        record_sessions: false,
        agent_forward: false,
    };
    core.save_connection("v".to_string(), p.clone()).unwrap();

    let read = core
        .list_connections("v".to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.profile_id == "web1")
        .expect("saved profile");
    assert_eq!(
        read.startup_snippet_ids,
        vec!["tmux-attach".to_string(), "cd-app".to_string()],
        "order matters — these are typed in sequence"
    );

    p.uid = read.uid.clone();
    p.startup_snippet_ids.clear();
    core.save_connection("v".to_string(), p).unwrap();
    let cleared = core
        .list_connections("v".to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.profile_id == "web1")
        .unwrap();
    assert!(cleared.startup_snippet_ids.is_empty());
}

/// Session recording against a real sshd: the capture happens, it lands in the
/// vault when the session ends, and it is a valid asciicast v2 document.
#[test]
fn session_recording_captures_and_persists() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let observer = std::sync::Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    let session = core
        .open_session(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            "xterm".to_string(),
            80,
            24,
            observer.clone(),
            Some(unissh_ffi::RecordingRequest {
                vault_id: "v".to_string(),
                recording_id: "rec-1".to_string(),
                label: "test host".to_string(),
            }),
            false,
        )
        .unwrap();

    // Nothing is written while the session is live — the document lands when it ends.
    assert!(
        core.list_recordings("v".to_string()).unwrap().is_empty(),
        "a recording must not appear before the session it records has finished"
    );

    session.write(b"echo recorded-marker\n".to_vec()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if contains(&observer.buf.lock().unwrap(), b"recorded-marker") {
            break;
        }
        assert!(Instant::now() <= deadline, "no output from the shell");
        std::thread::sleep(Duration::from_millis(50));
    }
    session.close().unwrap();

    // on_close is delivered from the reader task, so give it a moment to land.
    let deadline = Instant::now() + Duration::from_secs(5);
    let meta = loop {
        let list = core.list_recordings("v".to_string()).unwrap();
        if let Some(m) = list.into_iter().next() {
            break m;
        }
        assert!(
            Instant::now() <= deadline,
            "the recording was never written"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    assert_eq!(meta.recording_id, "rec-1");
    assert_eq!(meta.host, "127.0.0.1");
    assert_eq!(meta.user, "root");
    assert!(
        !meta.truncated,
        "a short session must not be marked truncated"
    );
    assert!(meta.size_bytes > 0);

    let cast = core
        .get_recording("v".to_string(), "rec-1".to_string())
        .unwrap();
    let mut lines = cast.lines();
    // The header is a JSON object naming the format version and the geometry.
    let header: serde_json::Value = serde_json::from_str(lines.next().expect("header")).unwrap();
    assert_eq!(header["version"], 2);
    assert_eq!(header["width"], 80);
    assert_eq!(header["height"], 24);
    // Every following line is an [time, "o", data] event, and the output we
    // provoked has to be in there somewhere.
    let mut saw_marker = false;
    for line in lines {
        let ev: serde_json::Value = serde_json::from_str(line).expect("event is valid JSON");
        assert_eq!(ev[1], "o");
        assert!(ev[0].as_f64().is_some(), "event carries a timestamp");
        if ev[2]
            .as_str()
            .is_some_and(|s| s.contains("recorded-marker"))
        {
            saw_marker = true;
        }
    }
    assert!(
        saw_marker,
        "the recording is missing the output it recorded"
    );

    core.delete_recording("v".to_string(), "rec-1".to_string())
        .unwrap();
    assert!(core.list_recordings("v".to_string()).unwrap().is_empty());
}

/// Closing the TAB, not the shell: the handle is closed and dropped at once.
///
/// This is what the desktop app does — `session_close` takes the session out of
/// its registry and drops the last reference the moment `close()` returns — and
/// it is the case the test above misses, because there the handle stays alive
/// afterwards and the reader survives long enough to see the peer's close. With
/// the reader aborted on Drop, the recording of a session ended this way was
/// thrown away in silence, while the identical session ended with `exit` was
/// kept.
#[test]
fn a_recording_survives_the_session_being_dropped_on_close() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let observer = std::sync::Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    let session = core
        .open_session(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            "xterm".to_string(),
            80,
            24,
            observer.clone(),
            Some(unissh_ffi::RecordingRequest {
                vault_id: "v".to_string(),
                recording_id: "rec-tab".to_string(),
                label: "test host".to_string(),
            }),
            false,
        )
        .unwrap();

    session.write(b"echo closed-by-tab\n".to_vec()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if contains(&observer.buf.lock().unwrap(), b"closed-by-tab") {
            break;
        }
        assert!(Instant::now() <= deadline, "no output from the shell");
        std::thread::sleep(Duration::from_millis(50));
    }

    // The app's exact sequence: close, then release the last reference at once.
    session.close().unwrap();
    drop(session);

    let deadline = Instant::now() + Duration::from_secs(5);
    let meta = loop {
        let list = core.list_recordings("v".to_string()).unwrap();
        if let Some(m) = list.into_iter().next() {
            break m;
        }
        assert!(
            Instant::now() <= deadline,
            "the recording was thrown away when the session handle was dropped"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(meta.recording_id, "rec-tab");
    assert!(meta.size_bytes > 0);

    let cast = core
        .get_recording("v".to_string(), "rec-tab".to_string())
        .unwrap();
    assert!(
        cast.contains("closed-by-tab"),
        "the recording is missing the output it recorded"
    );
}

/// A session opened without a recording request leaves nothing behind.
#[test]
fn no_recording_request_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);
    let observer = std::sync::Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    let session = core
        .open_session(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            "xterm".to_string(),
            80,
            24,
            observer,
            None,
            false,
        )
        .unwrap();
    session.write(b"echo nope\n".to_vec()).unwrap();
    std::thread::sleep(Duration::from_millis(400));
    session.close().unwrap();
    std::thread::sleep(Duration::from_millis(400));
    assert!(core.list_recordings("v".to_string()).unwrap().is_empty());
}

/// A profile can carry a system-agent identity, and it survives a round-trip.
///
/// The public key is stored in the clear inside the (encrypted) profile because
/// it is a handle, not a secret — the same status as a key item id.
#[test]
fn profile_round_trips_a_system_agent_identity() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    let pub_line = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QHNzaC5jb20AAAA token";
    core.save_connection(
        "v".to_string(),
        unissh_ffi::ConnectionProfile {
            profile_id: "gw".to_string(),
            uid: String::new(),
            label: "gw".to_string(),
            host: "gw.example.com".to_string(),
            port: 22,
            user: "me".to_string(),
            auth: unissh_ffi::ProfileAuth::SystemAgent {
                public_key: pub_line.to_string(),
            },
            username_template: None,
            jumps: vec![],
            tags: vec![],
            startup_snippet_ids: vec![],
            record_sessions: false,
            agent_forward: false,
        },
    )
    .unwrap();

    let read = core
        .list_connections("v".to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.profile_id == "gw")
        .expect("saved profile");
    match read.auth {
        unissh_ffi::ProfileAuth::SystemAgent { public_key } => {
            assert_eq!(public_key, pub_line)
        }
        _ => panic!("expected ProfileAuth::SystemAgent"),
    }
}

/// With no agent reachable, a system-agent connect fails with a message that
/// says the agent is the problem — not a generic authentication failure that
/// would send the user to check their key.
#[test]
fn system_agent_without_an_agent_reports_the_agent() {
    let _env = AGENT_ENV.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    // Point SSH_AUTH_SOCK at nothing so the lookup fails deterministically
    // rather than depending on whatever the test machine happens to run.
    let missing = dir.path().join("no-such-agent.sock");
    // SAFETY: single-threaded test setup; no other thread reads the environment
    // between the set and the call below.
    unsafe { std::env::set_var("SSH_AUTH_SOCK", &missing) };

    let err = core.system_agent_keys().expect_err("no agent is listening");
    let msg = err.to_string();
    assert!(
        msg.contains("agent"),
        "the error must name the agent, got: {msg}"
    );
}

/// The recording write must not run inside a tokio task.
///
/// That was the deadlock in d500e0e: on_close fires on a channel-reader task,
/// and writing to the vault needs the core lock that a concurrent connect holds
/// across its block_on. The fix moved the write to its own thread; a
/// debug_assert in RecordingSaver::save keeps it there, so a real recorded
/// session is what proves it — if the write ever drifts back onto the runtime,
/// this test panics.
#[test]
fn a_recording_is_written_off_the_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);
    let observer = std::sync::Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    let session = core
        .open_session(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            "xterm".to_string(),
            80,
            24,
            observer,
            Some(unissh_ffi::RecordingRequest {
                vault_id: "v".to_string(),
                recording_id: "rec-thread".to_string(),
                label: "t".to_string(),
            }),
            false,
        )
        .unwrap();
    session.write(b"echo x\n".to_vec()).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    session.close().unwrap();

    // The assertion fires inside the writing thread, so the recording simply
    // never lands if it tripped. Waiting for it is the check.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !core.list_recordings("v".to_string()).unwrap().is_empty() {
            break;
        }
        assert!(
            Instant::now() <= deadline,
            "the recording never landed — the write thread may have tripped its assertion"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The core lock must be free while a connection is being established.
///
/// This is the property the whole KnownHosts/KeySource split exists for. Before,
/// the lock was held across the entire handshake, so every other call queued
/// behind it — and a callback needing the same lock from a runtime thread
/// deadlocked outright.
///
/// The test drives a real handshake against a real sshd and, from another
/// thread, hammers a method that needs the lock. If the lock were still held
/// across the network phase those calls would stall until the connect finished;
/// here they have to keep completing while it runs.
#[test]
fn the_core_lock_is_free_during_a_handshake() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let pubkey = core
        .generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    let sshd = TestSshd::start(&pubkey);

    let stop = std::sync::Arc::new(AtomicBool::new(false));
    // The longest a call had to wait for the lock. This, not a simple count, is
    // the measurement that matters: if the lock were held across the handshake
    // there would be exactly one gap the length of the whole connect.
    let worst_wait_us = std::sync::Arc::new(AtomicUsize::new(0));
    let prober = std::thread::spawn({
        let core = core.clone();
        let stop = stop.clone();
        let worst = worst_wait_us.clone();
        move || {
            while !stop.load(Ordering::Relaxed) {
                let t = Instant::now();
                core.list_vaults().unwrap();
                let waited = t.elapsed().as_micros() as usize;
                worst.fetch_max(waited, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    });

    let observer = std::sync::Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    // A quiet baseline first: on a loaded CI box the scheduler alone can stall a
    // thread for milliseconds, and comparing against a fixed number would make
    // this test flake. The question is whether the connect makes waiting
    // *dramatically* worse than it already is.
    std::thread::sleep(Duration::from_millis(120));
    let baseline = Duration::from_micros(worst_wait_us.swap(0, Ordering::Relaxed) as u64);

    let connect_started = Instant::now();
    let session = core
        .open_session(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            agent_auth("v", "key"),
            vec![],
            "xterm".to_string(),
            80,
            24,
            observer,
            None,
            false,
        )
        .unwrap();
    let connect_took = connect_started.elapsed();

    stop.store(true, Ordering::Relaxed);
    prober.join().unwrap();
    session.close().unwrap();

    let worst = Duration::from_micros(worst_wait_us.load(Ordering::Relaxed) as u64);
    // Holding the lock across the handshake produces one wait the length of the
    // whole connect, so the threshold is expressed relative to that rather than
    // as an absolute number: a fraction of the connect fails loudly for a held
    // lock while leaving room for the scheduler noise a loaded CI box adds. The
    // idle baseline is the floor, for the case where the connect is so fast that
    // a fraction of it is smaller than ordinary jitter.
    let allowed = std::cmp::max(connect_took / 3, baseline * 4 + Duration::from_millis(10));
    assert!(
        worst < allowed,
        "a core call waited {worst:?} during a {connect_took:?} handshake (idle baseline \
         {baseline:?}) — the lock looks held across the network phase"
    );
}

/// Serializes the tests that set `SSH_AUTH_SOCK`.
///
/// The environment is process-wide, so two of these running at once would point
/// each other at the wrong agent — one expects a live socket, another expects a
/// dead one. That is a flake waiting for a busy CI box, not a theoretical race.
static AGENT_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A real `ssh-agent`, spawned and torn down by the test.
///
/// The system-agent path had no live coverage: the unit test only proved the
/// error when no agent is listening. This runs the actual protocol against the
/// actual OpenSSH agent, which is the only way to know the wire format, the
/// identity matching and the signature all line up.
struct TestAgent {
    sock: std::path::PathBuf,
    pid: String,
    _dir: tempfile::TempDir,
}

impl TestAgent {
    /// Starts an agent and loads `private_key_pem` into it. Returns `None` when
    /// the tools are missing, so the test skips rather than fails on a machine
    /// without OpenSSH.
    fn start(private_key_pem: &str) -> Option<TestAgent> {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let out = Command::new("ssh-agent")
            .args(["-a"])
            .arg(&sock)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        // ssh-agent prints `SSH_AGENT_PID=1234; export ...`
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let pid = stdout
            .split("SSH_AGENT_PID=")
            .nth(1)?
            .split(';')
            .next()?
            .trim()
            .to_string();

        let key_path = dir.path().join("id");
        std::fs::write(&key_path, private_key_pem).unwrap();
        // ssh-add refuses a world-readable key.
        std::fs::set_permissions(
            &key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let added = Command::new("ssh-add")
            .arg(&key_path)
            .env("SSH_AUTH_SOCK", &sock)
            .env("DISPLAY", "")
            .env("SSH_ASKPASS", "/bin/false")
            .output()
            .ok()?;
        if !added.status.success() {
            let _ = Command::new("kill").arg(&pid).status();
            return None;
        }
        Some(TestAgent {
            sock,
            pid,
            _dir: dir,
        })
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        let _ = Command::new("kill").arg(&self.pid).status();
    }
}

/// End to end through a real OpenSSH agent: the agent holds the key, the core
/// only names it, and the signature is produced by the agent.
///
/// This is the path a FIDO token, a PKCS#11 card, a Secure Enclave key or
/// 1Password would take, so it is the one that has to be exercised for real.
#[test]
fn system_agent_authenticates_end_to_end() {
    let _env = AGENT_ENV.lock().unwrap_or_else(|e| e.into_inner());
    // A key the agent will hold and sshd will trust. Generated with ssh-keygen so
    // the whole chain is the real formats.
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("live");
    if Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-q", "-N", ""])
        .arg("-f")
        .arg(&key_path)
        .status()
        .map(|s| !s.success())
        .unwrap_or(true)
    {
        eprintln!("ssh-keygen unavailable — skipping");
        return;
    }
    let private = std::fs::read_to_string(&key_path).unwrap();
    let public = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();

    let Some(agent) = TestAgent::start(&private) else {
        eprintln!("ssh-agent/ssh-add unavailable — skipping");
        return;
    };
    // SAFETY: single-threaded test setup, before any core call reads it.
    unsafe { std::env::set_var("SSH_AUTH_SOCK", &agent.sock) };

    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    // The picker's data source must see the key the agent actually holds.
    let listed = core.system_agent_keys().unwrap();
    assert!(
        listed.iter().any(|k| public.contains(&k.public_key)
            || k.public_key.split_whitespace().nth(1) == public.split_whitespace().nth(1)),
        "the agent's key is missing from system_agent_keys: {listed:?}"
    );
    let chosen = listed
        .iter()
        .find(|k| k.algorithm.contains("ed25519"))
        .expect("the ed25519 key we just added");

    let sshd = TestSshd::start(&public);
    let observer = std::sync::Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });

    // No key in our own vault or agent — the OS agent is the only thing that can
    // produce this signature.
    let session = core
        .open_session(
            "127.0.0.1".to_string(),
            sshd.port,
            "root".to_string(),
            unissh_ffi::AuthMethod::SystemAgent {
                public_key: chosen.public_key.clone(),
            },
            vec![],
            "xterm".to_string(),
            80,
            24,
            observer.clone(),
            None,
            false,
        )
        .expect("the agent must be able to authenticate this session");

    session.write(b"echo agent-auth-works\n".to_vec()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if contains(&observer.buf.lock().unwrap(), b"agent-auth-works") {
            break;
        }
        assert!(
            Instant::now() <= deadline,
            "no shell output; got {:?}",
            String::from_utf8_lossy(&observer.buf.lock().unwrap())
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    session.close().unwrap();
}

/// And the negative: a key the agent does not hold must fail with the dedicated
/// error, not a generic authentication failure that sends the user to check
/// their key instead of plugging in their token.
#[test]
fn system_agent_missing_key_is_named() {
    let _env = AGENT_ENV.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("held");
    if Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-q", "-N", ""])
        .arg("-f")
        .arg(&key_path)
        .status()
        .map(|s| !s.success())
        .unwrap_or(true)
    {
        return;
    }
    let held = std::fs::read_to_string(&key_path).unwrap();
    let Some(agent) = TestAgent::start(&held) else {
        return;
    };
    unsafe { std::env::set_var("SSH_AUTH_SOCK", &agent.sock) };

    // A different key, never added to the agent.
    let other = dir.path().join("other");
    assert!(
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-q", "-N", ""])
            .arg("-f")
            .arg(&other)
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "ssh-keygen must produce the second key"
    );
    let other_pub = std::fs::read_to_string(other.with_extension("pub")).unwrap();

    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    let sshd = TestSshd::start(&other_pub);
    let observer = std::sync::Arc::new(CollectObserver {
        buf: std::sync::Mutex::new(Vec::new()),
        closed: std::sync::atomic::AtomicBool::new(false),
    });
    // `SshSession` is not Debug (it holds a live connection), so unwrap the
    // Result by hand rather than through expect_err.
    let outcome = core.open_session(
        "127.0.0.1".to_string(),
        sshd.port,
        "root".to_string(),
        unissh_ffi::AuthMethod::SystemAgent {
            public_key: other_pub.clone(),
        },
        vec![],
        "xterm".to_string(),
        80,
        24,
        observer,
        None,
        false,
    );
    let msg = match outcome {
        Ok(_) => panic!("the agent does not hold this key; the connect must fail"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("ssh-add") || msg.contains("does not hold"),
        "the error must say the agent lacks the key, got: {msg}"
    );
}

// ── local terminal ─────────────────────────────────────────────
//
// The point of these is the wiring, not the pty (that is `unissh-local-pty`'s
// own test suite): that a local session reaches the same observer, the same
// recorder and the same vault as an SSH one, and is described honestly when it
// lands there. unix-only, like the crate's tests, because CI runs the workspace
// suite on ubuntu and a Windows-named test nobody runs would be worse than an
// admitted gap.

#[cfg(unix)]
#[test]
fn local_session_streams_output_and_exit_code() {
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    struct Obs {
        buf: std::sync::Mutex<Vec<u8>>,
        exit: AtomicI32,
    }
    impl unissh_ffi::SessionObserver for Obs {
        fn on_data(&self, data: Vec<u8>) {
            self.buf.lock().unwrap().extend_from_slice(&data);
        }
        fn on_close(&self, exit_status: i32) {
            self.exit.store(exit_status, Ordering::SeqCst);
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    let obs = Arc::new(Obs {
        buf: std::sync::Mutex::new(Vec::new()),
        exit: AtomicI32::new(i32::MIN),
    });
    let session = core
        .open_local_session(
            unissh_ffi::LocalSpec {
                program: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), "echo local-marker; exit 3".to_string()],
                cwd: None,
            },
            80,
            24,
            obs.clone(),
            None,
        )
        .expect("a local session must open on a desktop platform");

    let deadline = Instant::now() + Duration::from_secs(10);
    while obs.exit.load(Ordering::SeqCst) == i32::MIN {
        assert!(Instant::now() <= deadline, "the shell never closed");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        contains(&obs.buf.lock().unwrap(), b"local-marker"),
        "the shell's output never reached the observer"
    );
    // Never negative: the UI reads a negative code as "the link dropped, offer
    // to reconnect", and a local shell has no link to drop.
    assert_eq!(obs.exit.load(Ordering::SeqCst), 3);
    session.close();
}

#[cfg(unix)]
#[test]
fn local_session_records_into_the_vault() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    struct Obs(AtomicBool);
    impl unissh_ffi::SessionObserver for Obs {
        fn on_data(&self, _data: Vec<u8>) {}
        fn on_close(&self, _exit_status: i32) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    let obs = Arc::new(Obs(AtomicBool::new(false)));
    let session = core
        .open_local_session(
            unissh_ffi::LocalSpec {
                program: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), "echo recorded-locally".to_string()],
                cwd: None,
            },
            80,
            24,
            obs.clone(),
            Some(unissh_ffi::RecordingRequest {
                vault_id: "v".to_string(),
                recording_id: "rec-local".to_string(),
                label: "sh".to_string(),
            }),
        )
        .expect("a local session must open on a desktop platform");

    let deadline = Instant::now() + Duration::from_secs(10);
    let meta = loop {
        if let Some(m) = core
            .list_recordings("v".to_string())
            .unwrap()
            .into_iter()
            .next()
        {
            break m;
        }
        assert!(
            Instant::now() <= deadline,
            "the local recording was never written"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    assert_eq!(meta.recording_id, "rec-local");
    assert_eq!(meta.label, "sh");
    // What a local session ran against, said plainly — and what lets
    // ViewRecordings list it with no special case at all.
    assert_eq!(meta.host, "localhost");
    assert_eq!(meta.user, unissh_local_pty::os_username());
    assert!(!meta.truncated);

    let body = core
        .get_recording("v".to_string(), "rec-local".to_string())
        .unwrap();
    assert!(
        body.contains("recorded-locally"),
        "the recording is missing the output it was made of"
    );
    assert!(
        body.lines()
            .next()
            .unwrap_or_default()
            .contains("\"version\":2"),
        "a local recording must be the same asciicast v2 document as any other, got: {}",
        body.lines().next().unwrap_or_default()
    );
    session.close();
}

#[cfg(unix)]
#[test]
fn local_session_rejects_a_zero_terminal_size() {
    use std::sync::Arc;

    struct Obs;
    impl unissh_ffi::SessionObserver for Obs {
        fn on_data(&self, _data: Vec<u8>) {}
        fn on_close(&self, _exit_status: i32) {}
    }

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    // `LocalSession` is not Debug (nor is `SshSession`), so unwrap the error by
    // hand rather than through expect_err.
    let err = match core.open_local_session(
        unissh_ffi::LocalSpec {
            program: "/bin/sh".to_string(),
            args: vec![],
            cwd: None,
        },
        0,
        24,
        Arc::new(Obs),
        None,
    ) {
        Ok(_) => panic!("a 0-column terminal is not a terminal"),
        Err(e) => e,
    };
    assert!(format!("{err}").contains("non-zero"), "got: {err}");
}

#[test]
fn local_shell_default_is_usable_as_given() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    let info = core.local_shell_default();
    // The Settings placeholder shows this, and an empty shell field falls back
    // to it — so "" here would mean a pane that cannot open and a placeholder
    // that says nothing.
    assert!(!info.program.is_empty(), "no default shell was resolved");
    assert!(!info.user.is_empty());
    assert!(!info.hostname.is_empty());
}

#[test]
fn local_shell_split_args_parses_like_a_shell() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    assert_eq!(
        core.local_shell_split_args("-c \"echo hi\"".to_string()),
        Some(vec!["-c".to_string(), "echo hi".to_string()])
    );
    // An unbalanced quote is a mistake to surface, not to guess at.
    assert_eq!(core.local_shell_split_args("\"oops".to_string()), None);
}

#[cfg(unix)]
#[test]
fn a_local_recording_survives_the_auto_lock_that_kills_it() {
    // The scenario the synchronous close exists for. Auto-lock drops every live
    // session and *then* locks the vault (`commands.rs::lock`), so a session's
    // recording has to be written in the window between those two steps. If it
    // is not, the user loses the recording of the session auto-lock ended —
    // which is exactly the session they are most likely to want back.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    struct Obs {
        seen: std::sync::Mutex<Vec<u8>>,
        closed: AtomicBool,
    }
    impl unissh_ffi::SessionObserver for Obs {
        fn on_data(&self, data: Vec<u8>) {
            self.seen.lock().unwrap().extend_from_slice(&data);
        }
        fn on_close(&self, _exit_status: i32) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    let secret = core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    let obs = Arc::new(Obs {
        seen: std::sync::Mutex::new(Vec::new()),
        closed: AtomicBool::new(false),
    });
    let session = core
        .open_local_session(
            unissh_ffi::LocalSpec {
                program: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "echo before-the-lock; sleep 120".to_string(),
                ],
                cwd: None,
            },
            80,
            24,
            obs.clone(),
            Some(unissh_ffi::RecordingRequest {
                vault_id: "v".to_string(),
                recording_id: "rec-locked".to_string(),
                label: "sh".to_string(),
            }),
        )
        .expect("a local session must open on a desktop platform");

    // Wait until the shell has actually produced output, so there is a recording
    // worth losing.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !contains(&obs.seen.lock().unwrap(), b"before-the-lock") {
        assert!(Instant::now() <= deadline, "the shell never started");
        std::thread::sleep(Duration::from_millis(20));
    }

    // Exactly what auto-lock does, in the same order and with nothing in between.
    drop(session);
    core.lock();

    core.unlock(None, secret).unwrap();
    let list = core.list_recordings("v".to_string()).unwrap();
    assert_eq!(
        list.len(),
        1,
        "the recording was lost to the lock that followed the close"
    );
    let body = core
        .get_recording("v".to_string(), "rec-locked".to_string())
        .unwrap();
    assert!(
        body.contains("before-the-lock"),
        "the recording exists but is missing what the session printed"
    );
}
