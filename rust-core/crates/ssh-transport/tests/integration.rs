//! Integration tests against a real local `sshd`:
//! connect + authentication with a key from the agent + exec, TOFU pinning,
//! ProxyJump chain, local forward.
//!
//! Require `/usr/sbin/sshd` and `ssh-keygen` (run as root in an isolated
//! environment). If sshd is unavailable, the tests fail at harness startup.

use std::net::TcpStream as StdTcp;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use unissh_ssh_agent::ssh_key::Algorithm;
use unissh_ssh_agent::{
    generate_ed25519_openssh, generate_openssh, normalize_private_key_to_openssh, InMemoryAgent,
};
use unissh_ssh_transport::{trust_host_key, Auth, ConnectOptions, SshClient};
use unissh_storage::Storage;

/// An sshd instance brought up for the duration of the test.
struct TestSshd {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

/// Path to `sftp-server` (for the `Subsystem sftp` directive). Take the first existing one.
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl TestSshd {
    fn start(authorized_pubkey: &str) -> TestSshd {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();

        let hostkey = p.join("hostkey");
        let st = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-q", "-N", ""])
            .arg("-f")
            .arg(&hostkey)
            .status()
            .expect("ssh-keygen");
        assert!(st.success(), "ssh-keygen failed");

        let authkeys = p.join("authorized_keys");
        std::fs::write(&authkeys, format!("{authorized_pubkey}\n")).unwrap();

        // privileged privsep directory of sshd
        let _ = std::fs::create_dir_all("/run/sshd");

        let port = free_port();
        let cfg = p.join("sshd_config");
        let cfg_text = format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {hk}\n\
             PidFile {pid}\n\
             PasswordAuthentication no\n\
             PubkeyAuthentication yes\n\
             PermitRootLogin prohibit-password\n\
             AuthorizedKeysFile {ak}\n\
             AllowTcpForwarding yes\n\
             UsePAM no\n\
             StrictModes no\n\
             Subsystem sftp {sftp}\n\
             LogLevel ERROR\n",
            hk = hostkey.display(),
            pid = p.join("sshd.pid").display(),
            ak = authkeys.display(),
            sftp = sftp_server_path(),
        );
        std::fs::write(&cfg, &cfg_text).unwrap();

        let child = Command::new("/usr/sbin/sshd")
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&cfg)
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn sshd");

        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if StdTcp::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            if Instant::now() > deadline {
                panic!("sshd did not become ready on port {port}");
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

fn agent_with_key(priv_pem: &str) -> InMemoryAgent {
    let mut agent = InMemoryAgent::new();
    agent
        .add_from_openssh(b"k".to_vec(), priv_pem.as_bytes())
        .unwrap();
    agent
}

#[tokio::test]
async fn connect_exec_and_tofu_pinning() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[5u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );

    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let out = client.exec("echo hello-unissh").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello-unissh");
    assert_eq!(out.exit_status, Some(0));

    // TOFU: the host key is pinned in storage
    assert!(storage
        .get_known_host("127.0.0.1", sshd.port)
        .unwrap()
        .is_some());

    // a repeat connect is verified against the pinned key — success
    let client2 = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    assert_eq!(client2.exec("true").await.unwrap().exit_status, Some(0));
    let _ = client.disconnect().await;
}

#[tokio::test]
async fn wrong_user_auth_fails() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[7u8; 32]).unwrap();

    // this user's key is not in another user's authorized_keys;
    // we use a nonexistent user → authentication will not pass
    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "nosuchuser",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    assert!(SshClient::connect(&opts, &agent, &storage).await.is_err());
}

#[tokio::test]
async fn proxy_jump_chain() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let jump = TestSshd::start(&pub_ssh);
    let target = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[6u8; 32]).unwrap();

    let jump_opts = ConnectOptions::new(
        "127.0.0.1",
        jump.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let target_opts = ConnectOptions::new(
        "127.0.0.1",
        target.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );

    let client = SshClient::connect_through(&[jump_opts], &target_opts, &agent, &storage)
        .await
        .unwrap();
    let out = client.exec("echo via-proxyjump").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "via-proxyjump");
}

#[tokio::test]
async fn local_forward_pipes_data() {
    // echo server inside the test process
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match echo.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[8u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();

    // forward: local port → (through sshd) → echo server
    let guard = client
        .local_forward("127.0.0.1:0", "127.0.0.1", echo_port)
        .await
        .unwrap();
    let local = guard.local_addr();

    let mut conn = tokio::net::TcpStream::connect(local).await.unwrap();
    conn.write_all(b"ping-through-tunnel").await.unwrap();
    let mut buf = vec![0u8; b"ping-through-tunnel".len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping-through-tunnel");
}

/// Brings up a simple TCP echo server inside the test process, returns the port.
async fn spawn_echo() -> u16 {
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn dynamic_socks5_forward() {
    let echo_port = spawn_echo().await;
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[10u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let guard = client.dynamic_forward("127.0.0.1:0").await.unwrap();

    // SOCKS5 client: connect to the dynamic forward and request CONNECT to echo
    let mut conn = tokio::net::TcpStream::connect(guard.local_addr())
        .await
        .unwrap();
    // greeting: ver=5, 1 method, method 0 (no-auth)
    conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = [0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x00]);
    // request: CONNECT 127.0.0.1:echo_port (ATYP=1 IPv4)
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    conn.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x05);
    assert_eq!(resp[1], 0x00); // success

    // now the stream flows through to echo
    conn.write_all(b"socks-echo").await.unwrap();
    let mut buf = vec![0u8; b"socks-echo".len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"socks-echo");
}

#[tokio::test]
async fn remote_forward_delivers_to_local() {
    let echo_port = spawn_echo().await;
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[11u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();

    // the server listens on 127.0.0.1:assigned and delivers connections to the local echo
    let assigned = client
        .remote_forward("127.0.0.1", 0, "127.0.0.1", echo_port)
        .await
        .unwrap();
    assert!(assigned > 0);

    // connect to the port on the sshd side (localhost) → should reach echo
    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", assigned))
        .await
        .unwrap();
    conn.write_all(b"remote-fwd").await.unwrap();
    let mut buf = vec![0u8; b"remote-fwd".len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"remote-fwd");
}

#[tokio::test]
async fn ecdsa_key_auth() {
    use unissh_ssh_agent::generate_openssh;
    use unissh_ssh_agent::ssh_key::{Algorithm, EcdsaCurve};

    // ECDSA P-256 key: check that a signature via the agent Signer is accepted by sshd
    let (priv_pem, pub_ssh) = generate_openssh(Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    })
    .unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[12u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let out = client.exec("echo ecdsa-ok").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ecdsa-ok");
}

#[tokio::test]
async fn sftp_roundtrip_write_read_list_stat_rename_remove() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[21u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let mut sftp = client.open_sftp().await.unwrap();

    // working directory
    let base = format!("/tmp/unissh-sftp-{}", sshd.port);
    let _ = sftp.rmdir(&format!("{base}/sub")).await;
    let _ = sftp.remove(&format!("{base}/a.txt")).await;
    let _ = sftp.remove(&format!("{base}/b.txt")).await;
    let _ = sftp.rmdir(&base).await;
    sftp.mkdir(&base).await.unwrap();

    // write + read
    let payload = b"hello sftp \x00\x01\x02 world".repeat(5000); // > 1 chunk
    let fa = format!("{base}/a.txt");
    sftp.write_file(&fa, &payload).await.unwrap();
    let back = sftp.read_file(&fa).await.unwrap();
    assert_eq!(back, payload);

    // stat
    let st = sftp.stat(&fa).await.unwrap();
    assert_eq!(st.size, payload.len() as u64);
    assert!(!st.is_dir);

    // subdirectory + listing
    sftp.mkdir(&format!("{base}/sub")).await.unwrap();
    let entries = sftp.list_dir(&base).await.unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.filename.as_str()).collect();
    assert!(names.contains(&"a.txt"));
    let sub = entries.iter().find(|e| e.filename == "sub").unwrap();
    assert!(sub.is_dir);

    // realpath
    let rp = sftp.realpath(&base).await.unwrap();
    assert!(rp.ends_with(&base) || rp.contains("unissh-sftp"));

    // rename + remove
    let fb = format!("{base}/b.txt");
    sftp.rename(&fa, &fb).await.unwrap();
    assert!(sftp.read_file(&fa).await.is_err());
    assert_eq!(sftp.read_file(&fb).await.unwrap(), payload);
    sftp.remove(&fb).await.unwrap();

    // error on a missing file
    assert!(sftp.read_file(&fa).await.is_err());

    // cleanup
    let _ = sftp.rmdir(&format!("{base}/sub")).await;
    let _ = sftp.rmdir(&base).await;
}

#[tokio::test]
async fn sftp_remove_tree_deletes_recursively() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[22u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let mut sftp = client.open_sftp().await.unwrap();

    let base = format!("/tmp/unissh-sftp-tree-{}", sshd.port);
    let _ = sftp.remove_tree(&base).await; // clean start

    // tree: base/{f1.txt, sub/{f2.txt, deep/f3.txt}}
    sftp.mkdir(&base).await.unwrap();
    sftp.write_file(&format!("{base}/f1.txt"), b"a")
        .await
        .unwrap();
    sftp.mkdir(&format!("{base}/sub")).await.unwrap();
    sftp.write_file(&format!("{base}/sub/f2.txt"), b"b")
        .await
        .unwrap();
    sftp.mkdir(&format!("{base}/sub/deep")).await.unwrap();
    sftp.write_file(&format!("{base}/sub/deep/f3.txt"), b"c")
        .await
        .unwrap();

    // A direct rmdir on a non-empty directory must fail (SSH_FX_FAILURE / status 4)
    // — exactly what was complained about. remove_tree must survive this.
    assert!(
        sftp.rmdir(&base).await.is_err(),
        "rmdir on a non-empty dir must fail"
    );

    // Recursive removal wipes the whole tree.
    sftp.remove_tree(&base).await.unwrap();

    // The directory is gone: listing and stat of a nested file fail.
    assert!(
        sftp.list_dir(&base).await.is_err(),
        "base dir must be gone after remove_tree"
    );
    assert!(sftp.stat(&format!("{base}/sub/deep/f3.txt")).await.is_err());
}

#[tokio::test]
async fn trust_host_key_repins_after_mismatch() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[31u8; 32]).unwrap();

    // Pin a KNOWINGLY WRONG key → simulate a mismatch.
    storage
        .put_known_host("127.0.0.1", sshd.port, b"ssh-ed25519 AAAAbogus wrong")
        .unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let presented = match SshClient::connect(&opts, &agent, &storage).await {
        Ok(_) => panic!("expected HostKeyMismatch"),
        Err(unissh_ssh_transport::TransportError::HostKeyMismatch { fingerprint, .. }) => {
            assert!(fingerprint.starts_with("SHA256:"), "fp: {fingerprint}");
            fingerprint
        }
        Err(other) => panic!("expected HostKeyMismatch, got {other:?}"),
    };

    // Trusting with the "wrong" fingerprint is not allowed — rejected (protection against MITM in the trust window).
    assert!(matches!(
        trust_host_key("127.0.0.1", sshd.port, &storage, "SHA256:bogus").await,
        Err(unissh_ssh_transport::TransportError::FingerprintMismatch { .. })
    ));

    // Trust the NEW key with a confirmed fingerprint → re-pinning.
    let fp = trust_host_key("127.0.0.1", sshd.port, &storage, &presented)
        .await
        .unwrap();
    assert_eq!(fp, presented);

    // Now an ordinary connect passes.
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let out = client.exec("echo trusted").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "trusted");
}

// === RSA (rsa-sha2-512) authentication against a real sshd ===

#[tokio::test]
async fn rsa_pubkey_auth_end_to_end() {
    // An RSA key from the agent must authenticate (rsa-sha2-512, RFC 8332).
    let (priv_pem, pub_ssh) = generate_openssh(Algorithm::Rsa { hash: None }).unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[6u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );

    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let out = client.exec("echo rsa-ok").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "rsa-ok");
    assert_eq!(out.exit_status, Some(0));
    let _ = client.disconnect().await;
}

#[tokio::test]
async fn imported_pkcs1_rsa_key_authenticates() {
    // The full user-scenario path: a classic `BEGIN RSA PRIVATE KEY`
    // (PKCS#1) → import normalization → agent → connect to a real sshd.
    let normalized = normalize_private_key_to_openssh(RSA_PKCS1).unwrap();
    let sshd = TestSshd::start(RSA_PUB);
    let agent = agent_with_key(&normalized);
    let storage = Storage::open_in_memory(&[7u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );

    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let out = client.exec("echo pkcs1-ok").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "pkcs1-ok");
    let _ = client.disconnect().await;
}

/// A classic RSA-2048 in PKCS#1 (`BEGIN RSA PRIVATE KEY`) and its OpenSSH public key.
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

const RSA_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQ3PqqT7IWgQveAGLGcOJ2TiMsQi8OTbk7nJOkQyaYgdr+jzExV3WliRduHYhnDL9KtPJSpYO8CJ/kyifO62LuRP/T9UyV2bhf8k2F+vor6nlj6gnrVwcw3Nb49V79IUJ2ph4Vlpri/R95Ip9zel1NrCtXKikZD06eP9bZBLk4Z3AVuWrOrNokplYD2q8XL3SqZOmWJLHGvuZjkL9EzCqJe337gO094kFEr0E1nwCQwZvCA/z9ZbrKpgN3UvrYDEsD643KZBZ/q32dZpJ/TeZER7XNVdL8cUhV5I8EN6PzSBQt8m3d+2NA1N6bo/FKoA50dYFLY8K2tFUKUxKcty8/";
