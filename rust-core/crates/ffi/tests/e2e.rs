//! Сквозной локальный сценарий через FFI-фасад (Definition of Done ядра):
//! создать local-волт → сгенерить SSH-ключ → подключиться к серверу
//! (в т.ч. через ProxyJump) — без сервера-инстанса и без UI.
//!
//! Плюс проверка жёсткого ограничения: приватный ключ не утекает на диск в
//! открытом виде и не отдаётся наружу.

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

    /// Как [`Self::start`], но с `MaxSessions {max_sessions}` — сервер отклонит
    /// открытие большего числа session-каналов (`AdministrativelyProhibited`).
    /// Для проверки деградации пула SFTP-каналов на рестриктивном сервере.
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
    /// Поднимает sshd, доверяющий user-сертификатам, подписанным `ca_pubkey`
    /// (через TrustedUserCAKeys), вместо authorized_keys.
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

    // lock → unlock тем же паролем + Secret Key; данные сохраняются
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

    // публичный — это публичный
    assert!(pubkey.contains("ssh-ed25519"));

    // на диске (зашифрованная БД + сайдкар keyset) нет маркера OpenSSH-приватника
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
    // повторно тем же Core — инстанс уже существует
    assert!(matches!(
        core.create_account(None),
        Err(unissh_ffi::FfiError::AlreadyExists)
    ));
    // и новым Core по тем же путям — тоже
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

    // CA + подпись пользовательского публичного ключа сертификатом (принципал root)
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

    // импортируем сертификат в ядро
    core.import_ssh_certificate("v".to_string(), "key".to_string(), cert)
        .unwrap();

    // в листинге ключ помечен как имеющий сертификат
    let items = core.list_items("v".to_string()).unwrap();
    let key_item = items.iter().find(|i| i.item_id == "key").unwrap();
    assert!(
        key_item.has_certificate,
        "key should report has_certificate"
    );

    // sshd доверяет CA → аутентификация по сертификату
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
    // Сценарий пользователя через FFI: классический PKCS#1 (`-----BEGIN RSA
    // PRIVATE KEY-----`) импортируется в волт и работает для аутентификации
    // (импорт нормализует его в OpenSSH; коннект идёт rsa-sha2-512).
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

    // ключ сохранён в волте отдельным item-ом
    let items = core.list_items("v".to_string()).unwrap();
    assert!(items.iter().any(|i| i.item_id == "rsa"), "key item stored");

    // полный коннект к настоящему sshd импортированным PKCS#1-ключом
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

/// Классический RSA-2048 в PKCS#1 (одноразовый тестовый ключ).
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
        )
        .unwrap();

    // вводим команду в интерактивный shell
    session.write(b"echo pty-works\n".to_vec()).unwrap();

    // ждём появления вывода в observer (до ~3с)
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

    // коннект закрепляет host key (TOFU)
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
    // повторный forget — записи уже нет
    assert!(!core
        .forget_host("127.0.0.1".to_string(), sshd.port)
        .unwrap());
}

#[test]
fn password_auth_path_wired() {
    // sshd принимает только ключи → пароль гарантированно не пройдёт, но путь
    // password-аутентификации доходит до сервера и чисто возвращает ошибку.
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

    // первый sshd → закрепляем его host key (TOFU)
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

    // поднимаем ДРУГОЙ sshd (другой host key) на ТОМ ЖЕ порту
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

    // меняем пароль
    core.change_password(
        Some("old-pw".to_string()),
        Some("new-pw".to_string()),
        secret.clone(),
    )
    .unwrap();

    // старый пароль больше не открывает, новый — открывает
    core.lock();
    assert!(matches!(
        core.unlock(Some("old-pw".to_string()), secret.clone()),
        Err(unissh_ffi::FfiError::InvalidCredentials)
    ));
    core.unlock(Some("new-pw".to_string()), secret.clone())
        .unwrap();
    assert_eq!(core.list_vaults().unwrap().len(), 1);

    // неверные старые креды не «кирпичат» (ошибка, без перезаписи)
    assert!(core
        .change_password(
            Some("wrong".to_string()),
            Some("x".to_string()),
            secret.clone()
        )
        .is_err());
    // всё ещё открывается актуальным паролем
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

    // публичный ключ совпадает с выданным при генерации; есть отпечаток
    let pk = core
        .get_public_key("v".to_string(), "id".to_string())
        .unwrap();
    assert_eq!(pk.openssh.trim(), generated.trim());
    assert!(pk.fingerprint.starts_with("SHA256:"));

    // метаданные: временные метки проставлены, сертификата нет
    let items = core.list_items("v".to_string()).unwrap();
    let it = items.iter().find(|i| i.item_id == "id").unwrap();
    assert!(it.created_at > 0 && it.updated_at > 0);
    assert!(!it.has_certificate);

    // get_public_key на отсутствующем → NotFound
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

    // старого нет, новый несёт тот же ключ
    assert!(matches!(
        core.get_public_key("v".to_string(), "old".to_string()),
        Err(unissh_ffi::FfiError::NotFound)
    ));
    let after = core
        .get_public_key("v".to_string(), "new".to_string())
        .unwrap();
    assert_eq!(before.openssh, after.openssh);

    // переименованным ключом можно подключиться
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

    // другой host key на том же порту → mismatch с отпечатком
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

    // доверять «не тем» отпечатком нельзя
    assert!(matches!(
        core.trust_host("127.0.0.1".to_string(), port, "SHA256:bogus".to_string()),
        Err(unissh_ffi::FfiError::HostKeyMismatch { .. })
    ));

    // доверяем новому ключу с подтверждённым отпечатком → дальше всё работает
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
    // эхо-сервер в отдельном потоке
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

    // соединяемся через туннель → попадаем на эхо-сервер
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

    // профили не появляются в обычном списке как «ключи» — это отдельный тип
    // (list_items вернёт их с item_type=3); проверим, что управление работает
    core.delete_connection("v".to_string(), "prod-web".to_string())
        .unwrap();
    assert!(core.list_connections("v".to_string()).unwrap().is_empty());

    // импорт ssh-config
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

    // профиль соединения с id существующего ключа НЕ должен затереть ключ
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
    };
    assert!(matches!(
        core.save_connection("v".to_string(), prof),
        Err(unissh_ffi::FfiError::AlreadyExists)
    ));
    // ключ цел и читается
    assert!(core
        .get_public_key("v".to_string(), "id".to_string())
        .is_ok());

    // и наоборот: генерация ключа поверх профиля отклоняется
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
    };
    core.save_connection("v".to_string(), prof2).unwrap();
    assert!(matches!(
        core.generate_ssh_key("v".to_string(), "conn".to_string()),
        Err(unissh_ffi::FfiError::AlreadyExists)
    ));

    // import_ssh_config с алиасом = id ключа пропускает его (не затирает)
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

// --- пароли серверов в волте ---

/// In-process SSH-сервер (russh), принимающий пароль `password` и умеющий exec
/// (эхо команды + код 0). Hermetic-замена sshd: системному sshd нельзя задать
/// пароль пользователя, не трогая /etc/shadow.
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

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            _session: &mut Session,
        ) -> Result<bool, russh::Error> {
            Ok(true)
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

    /// Поднимает сервер на отдельном tokio-runtime; возвращает (runtime, port).
    /// Runtime нужно держать живым, пока идёт тест.
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

            // host key: генерим Ed25519 через ssh-agent крейт ядра нельзя (нет
            // зависимости тут) — берём ssh-keygen уже использующийся в тестах? Нет:
            // russh принимает OpenSSH PEM. Сгенерим временный ключ ssh-keygen-ом.
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
                let _dir = dir; // держим tempdir живым
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

    // reveal возвращает то, что положили
    assert_eq!(
        core.get_password("v".to_string(), "srv1".to_string())
            .unwrap(),
        "s3cret!"
    );

    // в списке items — тип «пароль» (4), версия растёт при обновлении
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
    assert!(it.version > v1, "версия должна монотонно расти");

    // удаление (tombstone) → NotFound
    core.delete_item("v".to_string(), "srv1".to_string())
        .unwrap();
    assert!(matches!(
        core.get_password("v".to_string(), "srv1".to_string()),
        Err(unissh_ffi::FfiError::NotFound)
    ));
}

#[test]
fn get_password_refuses_non_password_items() {
    // Критично: через reveal-путь нельзя вытащить приватный ключ или иной item.
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
        "ожидалась ошибка типа, не NotFound"
    );
    // и наоборот: пароль не притворяется ключом
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

    // пароль с id существующего ключа НЕ должен затереть ключ
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
    assert_eq!(res.stdout.trim(), "echo vault-pw"); // тест-сервер эхает команду

    // неверная ссылка → NotFound ещё до коннекта
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

    // удалённый (tombstone) пароль тоже не годится
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

    // профиль со ссылкой на пароль + jump по паролю из волта
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

    // inline-пароль в jump-хосте профиля — отказ (секрет не пишется в JSON)
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

// --- fleet-hardening: лимит конкуренции, таймаут, тайминг ---

/// Конфигурируемый in-process SSH-сервер для fleet-тестов: парольный auth + exec,
/// поведение exec настраивается (мгновенно/со сном/зависание), плюс общий счётчик
/// одновременных exec для проверки лимита конкуренции.
mod fleetserver {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use russh::server::{self, Auth as ServerAuth, Msg, Session};
    use russh::{Channel, ChannelId};

    #[derive(Clone, Copy)]
    pub enum Mode {
        /// Поспать N мс на стороне сервера, затем echo + exit 0.
        Sleep(u64),
        /// channel_success, но никогда не отвечать (завис хост).
        Hang,
    }

    /// Счётчики одновременных exec (для проверки потолка конкуренции).
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

        async fn channel_open_session(
            &mut self,
            _c: Channel<Msg>,
            _s: &mut Session,
        ) -> Result<bool, russh::Error> {
            Ok(true)
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
                    return Ok(()); // канал открыт, ответа нет — клиент должен сам отвалиться по таймауту
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

    // exec зависает на сервере; per-host timeout=1с должен пометить результат и вернуть управление.
    let results = core
        .ssh_exec_multi(vec![pw_target(port)], "echo hi".to_string(), 0, 1)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].timed_out, "ожидался timed_out=true");
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

    // 5 целей на тот же порт, лимит 2 → одновременно выполняется не больше 2.
    let targets: Vec<_> = (0..5).map(|_| pw_target(port)).collect();
    let results = core
        .ssh_exec_multi(targets, "echo hi".to_string(), 2, 0)
        .unwrap();
    assert_eq!(results.len(), 5);
    for r in &results {
        assert!(r.error.is_none(), "unexpected error: {:?}", r.error);
        assert!(
            r.duration_ms >= 150,
            "sleep(200) → duration должна быть ~200мс, got {}",
            r.duration_ms
        );
    }
    assert!(
        counters.peak() <= 2,
        "пик одновременных exec {} превысил лимит 2",
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

    // тип 6, версия растёт при обновлении
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

    // удаление → NotFound
    core.delete_item("v".to_string(), "host-notes".to_string())
        .unwrap();
    assert!(matches!(
        core.get_note("v".to_string(), "host-notes".to_string()),
        Err(unissh_ffi::FfiError::NotFound)
    ));
}

#[test]
fn get_note_is_type_gated() {
    // заметка и пароль не подменяют друг друга; ключ через get_note не достать.
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

    // get_note на ключе/пароле → не NotFound, а ошибка типа
    let e = core
        .get_note("v".to_string(), "key".to_string())
        .unwrap_err();
    assert!(!matches!(e, unissh_ffi::FfiError::NotFound));
    let e = core
        .get_note("v".to_string(), "pw".to_string())
        .unwrap_err();
    assert!(!matches!(e, unissh_ffi::FfiError::NotFound));
    // get_password на заметке → ошибка
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

// --- теги профилей: выборка целей + exec по тегам ---

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

    // all: prod+web → только web1
    let all = core
        .select_targets_by_tags(
            "v".to_string(),
            vec!["prod".to_string(), "web".to_string()],
            true,
        )
        .unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].host, "10.0.0.1");

    // пустой запрос → ничего
    assert!(core
        .select_targets_by_tags("v".to_string(), vec![], false)
        .unwrap()
        .is_empty());
}

/// #12 (B4.3): select_targets_by_tags ИСКЛЮЧАЕТ PromptPassword-хосты — нет
/// заранее известного пароля, в fan-out они не идут. Регрессия на дыру, которую
/// закрывал B4.3, но которую не покрывал тест (все прежние профили были key-auth).
#[test]
fn select_targets_by_tags_excludes_prompt_password() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    save_profile(&core, "web1", "10.0.0.1", 22, "key", &["web"]);
    // PromptPassword-хост с тем же тегом — должен быть отфильтрован.
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
        "PromptPassword-хост исключён из tag-fan-out (#12)"
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

// --- группы хостов (вложенные) ---

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

    // тип 5, версия растёт
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

    // tombstone → NotFound, list не видит
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

    // само-членство / само-родительство / пустой id → ошибка
    assert!(core
        .save_group("v".to_string(), group("g", &["g"], None))
        .is_err());
    assert!(core
        .save_group("v".to_string(), group("g", &[], Some("g")))
        .is_err());
    assert!(core
        .save_group("v".to_string(), group("", &[], None))
        .is_err());

    // кросс-тип клоббер: группа с id существующего ключа → AlreadyExists, ключ цел
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
    // группа без parent_id/color (минимальный JSON) читается
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

    // A → [p1, B]; B → [p2]  (вложенность)
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
    assert_eq!(results.len(), 2, "вложенная группа должна дать 2 хоста");
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
    // ok-профиль (ключ), prompt-профиль (PromptPassword), и висячая ссылка
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
    // ok1 зарезолвился с реальным хостом
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

    // цикл A→B→A + висячий член; p1 валиден и должен выполниться один раз
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
    // ровно один успешный (p1), плюс error-маркеры для ghost и цикла
    let ok: Vec<_> = results.iter().filter(|r| r.error.is_none()).collect();
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].stdout.trim(), "ok");
    assert!(results
        .iter()
        .any(|r| r.host == "ghost" && r.error.is_some()));
    // и маркер цикла (член-группа B уже посещена → ссылка на A помечена ошибкой)
    assert!(
        results
            .iter()
            .any(|r| r.error.as_deref().is_some_and(|e| e.contains("cycle"))),
        "ожидался error-маркер цикла; got: {:?}",
        results
            .iter()
            .map(|r| (&r.host, &r.error))
            .collect::<Vec<_>>()
    );
}

// --- hardening ресайза терминала ---

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
        )
        .unwrap();

    // ресайз → window_change; проверяем фактический размер PTY через stty size
    session.resize(120, 40).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    session.write(b"stty size\n".to_vec()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        // stty size печатает "rows cols" → "40 120" (оси не перепутаны)
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

    // нулевой размер отвергается на FFI-границе (мусор не уходит на сервер)
    assert!(session.resize(0, 40).is_err());
    assert!(session.resize(120, 0).is_err());

    session.close().unwrap();
}

#[test]
fn open_session_rejects_zero_size() {
    // Реальный sshd: без валидации open_session(cols=0) бы УСПЕШНО подключился.
    // Значит is_err() ловит именно валидацию размера, а не отказ коннекта.
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
    );
    assert!(r.is_err(), "нулевая ширина должна отвергаться валидацией");
}

// --- аудит целостности волта (verify_chain) ---

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

// --- экспорт ~/.ssh/config из волта ---

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

    // round-trip: импорт экспортированного в свежий волт даёт те же профили
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

// --- импорт ~/.ssh/known_hosts ---

#[test]
fn import_known_hosts_pins_and_skips_hashed() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();
    // настоящий ed25519-публичный ключ
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

    // повторный импорт идемпотентен (UPSERT) — число известных хостов не растёт
    let before = core.list_known_hosts().unwrap().len();
    core.import_known_hosts(format!("example.com {pubkey}\n"))
        .unwrap();
    assert_eq!(core.list_known_hosts().unwrap().len(), before);
}

// --- проверка консистентности БД ---

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

// --- fleet push: раскладка файла на много хостов через SFTP ---

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
    // первый раз: создаёт родителя
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

    // второй раз: родитель уже есть, mkdir-ошибка проглатывается
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

// --- broadcast-сессия (cluster-ssh): один ввод → много PTY ---

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

    // один write_all уходит на оба хоста
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

// --- streaming exec (раздельные stdout/stderr + код возврата) ---

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

// --- возобновляемый SFTP с прогрессом и отменой ---

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

    // источник ~100КБ (несколько чанков по 32КБ)
    let content: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let src = dir.path().join("src.bin");
    std::fs::write(&src, &content).unwrap();
    let remote = dir.path().join("remote.bin");

    // upload с прогрессом
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

    // download целиком
    let dl = dir.path().join("dl.bin");
    let done = sftp
        .sftp_download(
            remote.to_str().unwrap().to_string(),
            dl.to_str().unwrap().to_string(),
            0,
            None, // known_size: ядро сделает stat само
            None,
            None,
        )
        .unwrap();
    assert!(done);
    assert_eq!(std::fs::read(&dl).unwrap(), content);

    // resume download: предзаполнить первые 40000 байт, докачать остаток
    let resume = dir.path().join("resume.bin");
    std::fs::write(&resume, &content[..40_000]).unwrap();
    let done = sftp
        .sftp_download(
            remote.to_str().unwrap().to_string(),
            resume.to_str().unwrap().to_string(),
            40_000,
            Some(content.len() as u64), // known_size: пропустить stat (докачка папки)
            None,
            None,
        )
        .unwrap();
    assert!(done);
    assert_eq!(std::fs::read(&resume).unwrap(), content);

    // отмена: токен отменён заранее → не завершается
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

// --- авто-reconnect интерактивной сессии ---

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
        )
        .unwrap();
    assert!(session.is_connected());

    // явный реконнект пересоздаёт рабочую PTY-сессию (новый TOFU, реролв кред)
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
    // на этот порт никто не слушает → коннект исчерпает попытки и вернёт ошибку
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
    );
    assert!(r.is_err());
}

// --- импорт PuTTY-сессий (.reg) ---

#[test]
fn import_putty_sessions_creates_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("v".to_string(), "V".to_string()).unwrap();

    // имя сессии "prod web" url-кодируется как prod%20web; порт dword (0x16=22, 0x935=2357)
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
    // ssh-сессия создана, telnet — пропущена
    assert_eq!(report.created_ids, vec!["prod web"]);
    assert_eq!(report.skipped, 1);

    let p = core
        .get_connection("v".to_string(), "prod web".to_string())
        .unwrap();
    assert_eq!(p.host, "10.0.0.5");
    assert_eq!(p.port, 2357);
    assert_eq!(p.user, "deploy");
}

// --- история версий секретов через FFI ---

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

    // type-gate: версия ключа через reveal пароля не достаётся
    core.generate_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    assert!(core
        .get_password_version("v".to_string(), "key".to_string(), 1)
        .is_err());

    // удаление чистит историю
    core.delete_item("v".to_string(), "pw".to_string()).unwrap();
    assert!(core
        .list_item_versions("v".to_string(), "pw".to_string())
        .unwrap()
        .is_empty());
}

// --- зашифрованный бэкап/экспорт волта ---

#[test]
fn vault_backup_export_import_round_trip() {
    // инстанс A
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

    // инстанс B (свежий) — восстановление в волт "restored"
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

    // секреты восстановлены
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
    // приватный ключ восстановлен (публичный ключ совпадает с исходным)
    assert_eq!(
        core_b
            .get_public_key("restored".to_string(), "key".to_string())
            .unwrap()
            .openssh,
        pub_a
    );

    // неверная passphrase → ошибка
    assert!(core_b
        .import_vault(backup.clone(), "wrong-pass".to_string(), "x".to_string())
        .is_err());

    // порча бэкапа → ошибка
    let mut tampered = backup.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0x01;
    assert!(core_b
        .import_vault(tampered, "backup-pass".to_string(), "y".to_string())
        .is_err());
}

// --- регрессии по ревью ---

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

    // offset за концом remote (3 байта) → ошибка, не «успех» с битым файлом
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

// Пул каналов: больше одновременных передач, чем каналов (8 > K=4), в разных
// потоках. Проверяет конкурентную аренду/возврат канала под насыщением (4 ждут
// освобождения), отсутствие дедлока и корректность содержимого каждого файла.
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
            4, // K=4 каналов, а файлов ниже — 8
        )
        .unwrap();

    // 8 файлов с различимым содержимым; заливаем последовательно.
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

    // Скачиваем все параллельно — по потоку на файл; leases > каналов.
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

// Регрессия: сервер с `MaxSessions 1` отклоняет второй канал
// (`AdministrativelyProhibited`). Пул, запрошенный на K=4, должен УЖАТЬСЯ до 1 и
// переиспользовать единственный канал, а не ронять передачи. Раньше параллельная
// выгрузка падала бы с ошибкой открытия канала.
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
            4, // запрашиваем 4, но сервер разрешит только 1
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

    // Параллельные скачивания: пул отклонит доп. каналы и переиспользует один.
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
    // удаляем — id остаётся занятым tombstone'ом
    core_b.delete_vault("restored".to_string()).unwrap();
    // повторный импорт в тот же id → ясная ошибка, не порча
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

    // байт внутри kdf_blob (после magic(4)+version(1)+len(4)) — теперь покрыт AAD
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
    // существующий профиль НЕ перезаписан
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
        )
        .unwrap();
    // рвём текущую сессию; следующий write должен сам переподключиться
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

/// Контракт границы секретов (см. module-doc `unissh-ffi`): перечисляет ЕДИНСТВЕННЫЕ
/// методы, которым позволено возвращать секретный материал наружу, и проверяет их
/// type-gating. Tripwire: добавил новый secret-возвращающий метод — обнови и этот
/// тест, и module-doc. Приватный keyset устройства не отдаётся ни одним методом.
#[test]
fn secret_returning_surface() {
    // Намеренно секрето-возвращающие методы (исчерпывающий список):
    const SECRET_RETURNING: &[&str] = &[
        "get_password",   // user secret (password manager reveal)
        "get_note",       // user secret (note reveal)
        "export_ssh_key", // by-design: user owns & may export their private key
        "export_vault",   // passphrase-encrypted backup
    ];
    assert_eq!(
        SECRET_RETURNING.len(),
        4,
        "обнови тест при изменении surface"
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

    // get_password: reveal только для password-item, иначе отказ (type-gate).
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

    // get_note: reveal только для note-item.
    assert_eq!(
        core.get_note("v".to_string(), "nt".to_string()).unwrap(),
        "a note"
    );
    assert!(core.get_note("v".to_string(), "pw".to_string()).is_err());

    // export_ssh_key: приватный ключ — by-design, но только для SSH-key item.
    let priv_key = core
        .export_ssh_key("v".to_string(), "key".to_string())
        .unwrap();
    assert!(
        priv_key.contains("PRIVATE KEY"),
        "ожидался OpenSSH-приватник"
    );
    assert!(core
        .export_ssh_key("v".to_string(), "pw".to_string())
        .is_err());

    // export_vault: непустой зашифрованный бэкап.
    let backup = core
        .export_vault("v".to_string(), "backup-pass".to_string())
        .unwrap();
    assert!(!backup.is_empty());
}
