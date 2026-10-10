//! Integration tests against a real local `sshd`:
//! connect + authentication with a key from the agent + exec, TOFU pinning,
//! ProxyJump chain, local forward.
//!
//! Require `/usr/sbin/sshd` and `ssh-keygen` (run as root in an isolated
//! environment). If sshd is unavailable, the tests fail at harness startup.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::missing_assert_message,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use std::net::TcpStream as StdTcp;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use unissh_ssh_agent::ssh_key::Algorithm;
use unissh_ssh_agent::{
    generate_ed25519_openssh, generate_openssh, normalize_private_key_to_openssh, InMemoryAgent,
};
use unissh_ssh_transport::{
    trust_host_key, Auth, ConnectOptions, ProxyKind, ProxyOptions, SshClient,
};
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
    fn start(authorized_pubkey: &str) -> Self {
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
        if std::fs::create_dir_all("/run/sshd").is_err() {
            // sshd names the missing privsep directory itself if this mattered.
        }

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

        let started = Instant::now();
        loop {
            if StdTcp::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            if started.elapsed() > Duration::from_secs(8) {
                panic!("sshd did not become ready on port {port}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Self {
            child,
            port,
            _dir: dir,
        }
    }
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        // Best effort: a child that already exited cannot be killed again.
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
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
async fn automation_requires_a_pin_and_reuses_one_authenticated_connection() {
    let (private, public) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&public);
    let agent = agent_with_key(&private);
    let storage = Storage::open_in_memory(&[0x51; 32]).unwrap();
    let mut opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    opts.require_pinned = true;
    assert!(matches!(
        SshClient::connect(&opts, &agent, &storage).await,
        Err(unissh_ssh_transport::TransportError::HostUntrusted)
    ));
    assert!(storage
        .get_known_host("127.0.0.1", sshd.port)
        .unwrap()
        .is_none());
    // Ordinary interactive TOFU is unchanged; automation can use that trusted pin.
    opts.require_pinned = false;
    SshClient::connect(&opts, &agent, &storage)
        .await
        .unwrap()
        .disconnect()
        .await
        .unwrap();
    opts.require_pinned = true;
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let first = client
        .exec("export UNISSH_MCP_TEST=changed; cd /tmp; printf '%s' \"$SSH_CONNECTION\"")
        .await
        .unwrap();
    let second = client
        .exec("test -z \"$UNISSH_MCP_TEST\" && printf '%s' \"$SSH_CONNECTION\"")
        .await
        .unwrap();
    assert!(!first.stdout.is_empty());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(second.exit_status, Some(0));
    client.disconnect().await.unwrap();
    let one = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let one_id = one
        .exec("printf '%s' \"$SSH_CONNECTION\"")
        .await
        .unwrap()
        .stdout;
    one.disconnect().await.unwrap();
    let two = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let two_id = two
        .exec("printf '%s' \"$SSH_CONNECTION\"")
        .await
        .unwrap()
        .stdout;
    two.disconnect().await.unwrap();
    assert_ne!(one_id, two_id);
}

#[tokio::test]
async fn automation_rejects_unknown_bastion_before_target_authentication() {
    let (private, public) = generate_ed25519_openssh().unwrap();
    let bastion = TestSshd::start(&public);
    let target = TestSshd::start(&public);
    let agent = agent_with_key(&private);
    let storage = Storage::open_in_memory(&[0x52; 32]).unwrap();
    let mut hop = ConnectOptions::new(
        "127.0.0.1",
        bastion.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let mut dest = ConnectOptions::new(
        "127.0.0.1",
        target.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    hop.require_pinned = true;
    dest.require_pinned = true;
    assert!(matches!(
        SshClient::connect_through(&[hop], &dest, &agent, &storage).await,
        Err(unissh_ssh_transport::TransportError::HostUntrusted)
    ));
    assert!(storage.list_known_hosts().unwrap().is_empty());
}

#[tokio::test]
async fn connect_exec_and_tofu_pinning() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[5_u8; 32]).unwrap();

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
    let _disconnected = client.disconnect().await;
}

#[tokio::test]
async fn wrong_user_auth_fails() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[7_u8; 32]).unwrap();

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
    let storage = Storage::open_in_memory(&[6_u8; 32]).unwrap();

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
    let echo_port = spawn_echo().await;

    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[8_u8; 32]).unwrap();

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
    let mut buf = vec![0_u8; b"ping-through-tunnel".len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping-through-tunnel");
}

/// Brings up a simple TCP echo server inside the test process, returns the port.
async fn spawn_echo() -> u16 {
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = echo.accept().await {
            tokio::spawn(echo_connection(s));
        }
    });
    port
}

/// Echoes everything read from `s` back until EOF or an I/O error.
async fn echo_connection(mut s: tokio::net::TcpStream) {
    let mut buf = vec![0_u8; 1024];
    while let Ok(n @ 1..) = s.read(&mut buf).await {
        if s.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
}

#[tokio::test]
async fn dynamic_socks5_forward() {
    let echo_port = spawn_echo().await;
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[10_u8; 32]).unwrap();

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
    let mut reply = [0_u8; 2];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x00]);
    // request: CONNECT 127.0.0.1:echo_port (ATYP=1 IPv4)
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    conn.write_all(&req).await.unwrap();
    let mut resp = [0_u8; 10];
    conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x05);
    assert_eq!(resp[1], 0x00); // success

    // now the stream flows through to echo
    conn.write_all(b"socks-echo").await.unwrap();
    let mut buf = vec![0_u8; b"socks-echo".len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"socks-echo");
}

#[tokio::test]
async fn remote_forward_delivers_to_local() {
    let echo_port = spawn_echo().await;
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[11_u8; 32]).unwrap();

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
    let mut buf = vec![0_u8; b"remote-fwd".len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"remote-fwd");
}

/// The same forward asked for on a WILDCARD bind, which is what the tunnel
/// dialog suggests ("0.0.0.0:9000"). The server is free to report a different
/// address in the forwarded-tcpip open than the one it was asked to bind, and
/// the delivery table is keyed by that address — so this is the case where a
/// listener appears on the far side and every connection to it dies.
#[tokio::test]
async fn remote_forward_on_a_wildcard_bind_delivers() {
    let echo_port = spawn_echo().await;
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[13_u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();

    let assigned = client
        .remote_forward("0.0.0.0", 0, "127.0.0.1", echo_port)
        .await
        .unwrap();
    assert!(assigned > 0);

    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", assigned))
        .await
        .unwrap();
    conn.write_all(b"wildcard-fwd").await.unwrap();
    let mut buf = vec![0_u8; b"wildcard-fwd".len()];
    conn.read_exact(&mut buf)
        .await
        .expect("the forwarded connection delivered nothing");
    assert_eq!(&buf, b"wildcard-fwd");
}

/// A free port BELOW the range the kernel hands out for `bind(0)`.
///
/// The first cut of this took a port by binding `:0` and letting go — the usual
/// trick, and the wrong one here. The workspace suite runs in parallel and every
/// `TestSshd` takes its port the same way, so this test could hand the SSH server
/// a port another test's sshd was about to bind. That test then failed to listen
/// and its client got ConnectionRefused, a thousand lines from the cause. It
/// passed CI three times before it fired.
///
/// Picking below `ip_local_port_range` leaves that pool entirely: nothing in the
/// suite binds a fixed port, so the only racer would be another copy of this
/// function, and there is one caller.
fn port_below_the_ephemeral_range() -> u16 {
    let lo: u16 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(32768);
    // Probe downward: bindable now is the best answer available, and nothing else
    // here competes for this range. Floored at 1024 so a host configured with a
    // low ephemeral range can never send this into the privileged ports, where a
    // "free" port means a real service is simply not running yet.
    let hi = lo.saturating_sub(1);
    let floor = hi.saturating_sub(2000).max(1024);
    for candidate in (floor..=hi).rev() {
        if std::net::TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
            return candidate;
        }
    }
    panic!("no free port in {floor}..={hi} (ephemeral range starts at {lo})");
}

/// A remote forward on an EXPLICIT port — what anyone actually asks for, and the
/// case the two tests above miss by requesting port 0.
///
/// RFC 4254 carries a port in the reply only for a port-0 request, so for a
/// specific port russh reports 0. Registering delivery under that 0 left every
/// forwarded channel unmatched: the server bound the port, and refused every
/// connection that arrived on it.
#[tokio::test]
async fn remote_forward_on_an_explicit_port_delivers() {
    let echo_port = spawn_echo().await;
    let wanted = port_below_the_ephemeral_range();

    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[14_u8; 32]).unwrap();

    let opts = ConnectOptions::new(
        "127.0.0.1",
        sshd.port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    );
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();

    let assigned = client
        .remote_forward("127.0.0.1", wanted, "127.0.0.1", echo_port)
        .await
        .unwrap();
    assert_eq!(
        assigned, wanted,
        "a specific port was asked for, so that is the port in use — reporting 0 \
         here is what put the delivery table under the wrong key"
    );

    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", wanted))
        .await
        .unwrap();
    conn.write_all(b"explicit-port").await.unwrap();
    let mut buf = vec![0_u8; b"explicit-port".len()];
    conn.read_exact(&mut buf)
        .await
        .expect("the forwarded connection delivered nothing");
    assert_eq!(&buf, b"explicit-port");
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
    let storage = Storage::open_in_memory(&[12_u8; 32]).unwrap();

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
    let storage = Storage::open_in_memory(&[21_u8; 32]).unwrap();

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
    let _cleanup = sftp.rmdir(&format!("{base}/sub")).await;
    let _cleanup = sftp.remove(&format!("{base}/a.txt")).await;
    let _cleanup = sftp.remove(&format!("{base}/b.txt")).await;
    let _cleanup = sftp.rmdir(&base).await;
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
    assert!(entries.iter().any(|e| e.filename == "a.txt"));
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
    let _cleanup = sftp.rmdir(&format!("{base}/sub")).await;
    let _cleanup = sftp.rmdir(&base).await;
}

#[tokio::test]
async fn sftp_create_new_refuses_an_existing_path() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[23_u8; 32]).unwrap();

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

    let base = format!("/tmp/unissh-sftp-excl-{}", sshd.port);
    let _cleanup = sftp.remove(&format!("{base}/f.txt")).await;
    let _cleanup = sftp.rmdir(&base).await;
    sftp.mkdir(&base).await.unwrap();
    let f = format!("{base}/f.txt");

    // creates an empty file
    sftp.create_new(&f).await.unwrap();
    assert_eq!(sftp.stat(&f).await.unwrap().size, 0);

    // the whole point: a second create fails instead of truncating, and the
    // contents written in between survive it
    let payload = b"do not lose me".to_vec();
    sftp.write_file(&f, &payload).await.unwrap();
    assert!(sftp.create_new(&f).await.is_err());
    assert_eq!(sftp.read_file(&f).await.unwrap(), payload);

    // a directory occupies the name just as a file does
    let d = format!("{base}/sub");
    sftp.mkdir(&d).await.unwrap();
    assert!(sftp.create_new(&d).await.is_err());

    // cleanup
    let _cleanup = sftp.remove(&f).await;
    let _cleanup = sftp.rmdir(&d).await;
    let _cleanup = sftp.rmdir(&base).await;
}

#[tokio::test]
async fn sftp_remove_tree_deletes_recursively() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[22_u8; 32]).unwrap();

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
    let _cleanup = sftp.remove_tree(&base).await; // clean start

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
    let storage = Storage::open_in_memory(&[31_u8; 32]).unwrap();

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
    let storage = Storage::open_in_memory(&[6_u8; 32]).unwrap();

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
    let _disconnected = client.disconnect().await;
}

#[tokio::test]
async fn imported_pkcs1_rsa_key_authenticates() {
    // The full user-scenario path: a classic `BEGIN RSA PRIVATE KEY`
    // (PKCS#1) → import normalization → agent → connect to a real sshd.
    let normalized = normalize_private_key_to_openssh(RSA_PKCS1).unwrap();
    let sshd = TestSshd::start(RSA_PUB);
    let agent = agent_with_key(&normalized);
    let storage = Storage::open_in_memory(&[7_u8; 32]).unwrap();

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
    let _disconnected = client.disconnect().await;
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

// ---------------------------------------------------------------------------
// Outbound proxy (http/socks4/socks5): fake in-process proxies in front of a
// real sshd, exercising the client side of each handshake.
// ---------------------------------------------------------------------------

fn key_opts(port: u16) -> ConnectOptions {
    ConnectOptions::new(
        "127.0.0.1",
        port,
        "root",
        Auth::Agent {
            key_id: b"k".to_vec(),
        },
    )
}

fn proxy_opts(kind: ProxyKind, port: u16) -> ProxyOptions {
    ProxyOptions {
        kind,
        host: "127.0.0.1".into(),
        port,
        username: None,
        password: None,
    }
}

async fn relay(mut inbound: tokio::net::TcpStream, dest: (String, u16)) {
    let mut outbound = tokio::net::TcpStream::connect(dest).await.unwrap();
    if tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .is_err()
    {
        // Either side hanging up just ends this relayed connection.
    }
}

/// A SOCKS5 proxy: optionally demands RFC 1929 credentials, refuses when
/// `refuse` is set, otherwise tunnels to the requested destination.
fn fake_socks5(creds: Option<(&'static str, &'static str)>, refuse: bool) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = [0_u8; 2];
                s.read_exact(&mut head).await.unwrap();
                assert_eq!(head[0], 5);
                let mut methods = vec![0_u8; head[1] as usize];
                s.read_exact(&mut methods).await.unwrap();
                if let Some((user, pass)) = creds {
                    assert!(methods.contains(&0x02), "client must offer user/pass");
                    s.write_all(&[5, 0x02]).await.unwrap();
                    let mut ver_ulen = [0_u8; 2];
                    s.read_exact(&mut ver_ulen).await.unwrap();
                    let mut u = vec![0_u8; ver_ulen[1] as usize];
                    s.read_exact(&mut u).await.unwrap();
                    let mut plen = [0_u8; 1];
                    s.read_exact(&mut plen).await.unwrap();
                    let mut p = vec![0_u8; plen[0] as usize];
                    s.read_exact(&mut p).await.unwrap();
                    if u != user.as_bytes() || p != pass.as_bytes() {
                        s.write_all(&[1, 1]).await.unwrap();
                        return;
                    }
                    s.write_all(&[1, 0]).await.unwrap();
                } else {
                    assert!(methods.contains(&0x00));
                    s.write_all(&[5, 0x00]).await.unwrap();
                }
                let mut req = [0_u8; 4];
                s.read_exact(&mut req).await.unwrap();
                assert_eq!(&req[..3], &[5, 1, 0]);
                let host = match req[3] {
                    0x01 => {
                        let mut a = [0_u8; 4];
                        s.read_exact(&mut a).await.unwrap();
                        format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
                    }
                    0x03 => {
                        let mut len = [0_u8; 1];
                        s.read_exact(&mut len).await.unwrap();
                        let mut dn = vec![0_u8; len[0] as usize];
                        s.read_exact(&mut dn).await.unwrap();
                        String::from_utf8(dn).unwrap()
                    }
                    other => panic!("unexpected atyp {other}"),
                };
                let mut port = [0_u8; 2];
                s.read_exact(&mut port).await.unwrap();
                let port = u16::from_be_bytes(port);
                if refuse {
                    s.write_all(&[5, 0x05, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    return;
                }
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                relay(s, (host, port)).await;
            });
        }
    });
    port
}

/// Reads a NUL-terminated SOCKS4 field (userid or 4a hostname), without the NUL.
async fn read_until_nul(s: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut field = Vec::new();
    loop {
        let mut b = [0_u8; 1];
        s.read_exact(&mut b).await.unwrap();
        if b[0] == 0 {
            return field;
        }
        field.push(b[0]);
    }
}

/// A SOCKS4/4a proxy that records nothing and tunnels; asserts the userid.
fn fake_socks4(expect_userid: &'static str) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = [0_u8; 8];
                s.read_exact(&mut head).await.unwrap();
                assert_eq!(head[0], 4);
                assert_eq!(head[1], 1);
                let port = u16::from_be_bytes([head[2], head[3]]);
                let ip = [head[4], head[5], head[6], head[7]];
                let userid = read_until_nul(&mut s).await;
                assert_eq!(userid, expect_userid.as_bytes());
                let host = if ip[..3] == [0, 0, 0] && ip[3] != 0 {
                    // SOCKS4a: hostname follows.
                    String::from_utf8(read_until_nul(&mut s).await).unwrap()
                } else {
                    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                };
                s.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await.unwrap();
                relay(s, (host, port)).await;
            });
        }
    });
    port
}

/// An HTTP CONNECT proxy; when `require_basic` is set the exact
/// `Proxy-Authorization` header must be present, otherwise it answers 407.
fn fake_http_proxy(require_basic: Option<&'static str>) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut req = Vec::new();
                while !req.ends_with(b"\r\n\r\n") {
                    let mut b = [0_u8; 1];
                    s.read_exact(&mut b).await.unwrap();
                    req.push(b[0]);
                }
                let text = String::from_utf8(req).unwrap();
                let first = text.lines().next().unwrap();
                assert!(first.starts_with("CONNECT "), "got: {first}");
                let authority = first.split_whitespace().nth(1).unwrap();
                if let Some(basic) = require_basic {
                    let header = format!("Proxy-Authorization: Basic {basic}");
                    if !text.lines().any(|l| l == header) {
                        s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                            .await
                            .unwrap();
                        return;
                    }
                }
                let (host, port) = authority.rsplit_once(':').unwrap();
                let port: u16 = port.parse().unwrap();
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                relay(s, (host.to_owned(), port)).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn connect_via_socks5_proxy() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[8_u8; 32]).unwrap();
    let proxy_port = fake_socks5(None, false);

    let opts = key_opts(sshd.port).with_proxy(proxy_opts(ProxyKind::Socks5, proxy_port));
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let out = client.exec("echo via-socks5").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "via-socks5");
    // TOFU pins against the DESTINATION host:port, not the proxy.
    assert!(storage
        .get_known_host("127.0.0.1", sshd.port)
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn connect_via_socks5_proxy_with_auth() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[9_u8; 32]).unwrap();
    let proxy_port = fake_socks5(Some(("joe", "sekret")), false);

    let mut proxy = proxy_opts(ProxyKind::Socks5, proxy_port);
    proxy.username = Some("joe".into());
    proxy.password = Some(zeroize::Zeroizing::new("sekret".into()));
    let opts = key_opts(sshd.port).with_proxy(proxy);
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    assert_eq!(client.exec("true").await.unwrap().exit_status, Some(0));

    // Wrong password → a proxy error, not an SSH one.
    let mut bad = proxy_opts(ProxyKind::Socks5, proxy_port);
    bad.username = Some("joe".into());
    bad.password = Some(zeroize::Zeroizing::new("wrong".into()));
    let Err(err) = SshClient::connect(&key_opts(sshd.port).with_proxy(bad), &agent, &storage).await
    else {
        panic!("connect with wrong proxy password unexpectedly succeeded");
    };
    assert!(err.to_string().contains("proxy"), "unexpected error: {err}");
}

#[tokio::test]
async fn connect_via_socks5_proxy_password_only() {
    // A password with no username still means "authenticate" (RFC 1929 allows
    // a zero-length field) — it must not be silently dropped.
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[15_u8; 32]).unwrap();
    let proxy_port = fake_socks5(Some(("", "sekret")), false);

    let mut proxy = proxy_opts(ProxyKind::Socks5, proxy_port);
    proxy.password = Some(zeroize::Zeroizing::new("sekret".into()));
    let client = SshClient::connect(&key_opts(sshd.port).with_proxy(proxy), &agent, &storage)
        .await
        .unwrap();
    assert_eq!(client.exec("true").await.unwrap().exit_status, Some(0));
}

#[tokio::test]
async fn connect_via_socks4_proxy() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[10_u8; 32]).unwrap();
    let proxy_port = fake_socks4("ident-user");

    let mut proxy = proxy_opts(ProxyKind::Socks4, proxy_port);
    proxy.username = Some("ident-user".into());
    let opts = key_opts(sshd.port).with_proxy(proxy);
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let out = client.exec("echo via-socks4").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "via-socks4");
}

#[tokio::test]
async fn connect_via_http_proxy() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[11_u8; 32]).unwrap();
    let proxy_port = fake_http_proxy(None);

    let opts = key_opts(sshd.port).with_proxy(proxy_opts(ProxyKind::Http, proxy_port));
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    let out = client.exec("echo via-http").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "via-http");
}

#[tokio::test]
async fn connect_via_http_proxy_with_basic_auth() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[12_u8; 32]).unwrap();
    // base64("aladdin:opensesame")
    let proxy_port = fake_http_proxy(Some("YWxhZGRpbjpvcGVuc2VzYW1l"));

    let mut proxy = proxy_opts(ProxyKind::Http, proxy_port);
    proxy.username = Some("aladdin".into());
    proxy.password = Some(zeroize::Zeroizing::new("opensesame".into()));
    let client = SshClient::connect(&key_opts(sshd.port).with_proxy(proxy), &agent, &storage)
        .await
        .unwrap();
    assert_eq!(client.exec("true").await.unwrap().exit_status, Some(0));

    // No credentials → 407 → a proxy error naming authentication.
    let Err(err) = SshClient::connect(
        &key_opts(sshd.port).with_proxy(proxy_opts(ProxyKind::Http, proxy_port)),
        &agent,
        &storage,
    )
    .await
    else {
        panic!("connect without proxy credentials unexpectedly succeeded");
    };
    assert!(
        err.to_string().contains("authentication"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn socks5_refusal_is_a_proxy_error() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[13_u8; 32]).unwrap();
    let proxy_port = fake_socks5(None, true);

    let Err(err) = SshClient::connect(
        &key_opts(sshd.port).with_proxy(proxy_opts(ProxyKind::Socks5, proxy_port)),
        &agent,
        &storage,
    )
    .await
    else {
        panic!("connect through a refusing proxy unexpectedly succeeded");
    };
    let text = err.to_string();
    assert!(
        text.contains("proxy") && text.contains("refused"),
        "unexpected error: {text}"
    );
}

#[tokio::test]
async fn socks5_minimal_refusal_is_reported_as_a_refusal() {
    // Some proxies answer a refusal with a truncated body (ATYP=0, no bound
    // address). Reading the address before the reply code turned that into a
    // bogus "bad address type" or an io error — the refusal must survive.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = [0_u8; 2];
                s.read_exact(&mut head).await.unwrap();
                let mut methods = vec![0_u8; head[1] as usize];
                s.read_exact(&mut methods).await.unwrap();
                s.write_all(&[5, 0]).await.unwrap();
                let mut req = [0_u8; 4];
                s.read_exact(&mut req).await.unwrap();
                let mut rest = if req[3] == 3 {
                    let mut len = [0_u8; 1];
                    s.read_exact(&mut len).await.unwrap();
                    vec![0_u8; len[0] as usize + 2]
                } else {
                    vec![0_u8; 6]
                };
                if s.read_exact(&mut rest).await.is_err() {
                    // The client may hang up early; the refusal is sent regardless.
                }
                // Refusal with no bound address at all, then hang up.
                s.write_all(&[5, 0x05, 0x00, 0x00]).await.unwrap();
            });
        }
    });

    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[16_u8; 32]).unwrap();
    let Err(err) = SshClient::connect(
        &key_opts(sshd.port).with_proxy(proxy_opts(ProxyKind::Socks5, proxy_port)),
        &agent,
        &storage,
    )
    .await
    else {
        panic!("a refused connection unexpectedly succeeded");
    };
    let text = err.to_string();
    assert!(
        text.contains("refused") && text.contains("connection refused"),
        "a truncated refusal must still name the reply code: {text}"
    );
}

#[tokio::test]
async fn unreachable_proxy_names_the_proxy() {
    // A dead proxy used to surface as a bare io error indistinguishable from
    // one on the destination host, sending the reader to the wrong machine.
    let dead = free_port();
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[17_u8; 32]).unwrap();
    let Err(err) = SshClient::connect(
        &key_opts(sshd.port).with_proxy(proxy_opts(ProxyKind::Socks5, dead)),
        &agent,
        &storage,
    )
    .await
    else {
        panic!("connect through a dead proxy unexpectedly succeeded");
    };
    let text = err.to_string();
    assert!(
        text.contains("proxy") && text.contains(&dead.to_string()),
        "the error must name the proxy and its port: {text}"
    );
}

#[tokio::test]
async fn proxy_then_jump_chain() {
    // proxy → bastion → target: the proxy wraps only the first TCP hop.
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let jump = TestSshd::start(&pub_ssh);
    let target = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[14_u8; 32]).unwrap();
    let proxy_port = fake_socks5(None, false);

    let jump_opts = key_opts(jump.port).with_proxy(proxy_opts(ProxyKind::Socks5, proxy_port));
    let target_opts = key_opts(target.port);
    let client = SshClient::connect_through(&[jump_opts], &target_opts, &agent, &storage)
        .await
        .unwrap();
    let out = client.exec("echo proxy-then-jump").await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "proxy-then-jump"
    );
}

#[tokio::test]
async fn sftp_preserves_relative_absolute_dangling_and_cyclic_links() {
    let (priv_pem, pub_ssh) = generate_ed25519_openssh().unwrap();
    let sshd = TestSshd::start(&pub_ssh);
    let agent = agent_with_key(&priv_pem);
    let storage = Storage::open_in_memory(&[21_u8; 32]).unwrap();

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

    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().to_str().unwrap();
    sftp.mkdir(&format!("{base}/lib")).await.unwrap();
    sftp.write_file(
        &format!("{base}/lib/data"),
        b"payload larger than link name",
    )
    .await
    .unwrap();
    for (name, target) in [
        ("lib64", "lib".to_owned()),
        ("python", "lib/data".to_owned()),
        ("absolute", format!("{base}/lib/data")),
        ("broken", "../missing-target".to_owned()),
        ("loop", "loop".to_owned()),
    ] {
        let path = format!("{base}/{name}");
        sftp.symlink(&target, &path).await.unwrap();
        assert_eq!(sftp.readlink(&path).await.unwrap(), target);
        let md = sftp.lstat(&path).await.unwrap();
        assert_eq!(md.mode & 0o170000, 0o120000);
        assert!(!md.is_dir);
        assert_eq!(md.size, target.len() as u64);
        let entries = sftp.list_dir(base).await.unwrap();
        let entry = entries.iter().find(|e| e.filename == name).unwrap();
        assert_eq!(entry.mode & 0o170000, 0o120000);
        // Creating a link never replaces an occupied path.
        assert!(sftp.symlink("different", &path).await.is_err());
        assert_eq!(sftp.readlink(&path).await.unwrap(), target);
    }
    assert!(sftp.stat(&format!("{base}/lib64")).await.unwrap().is_dir);
    assert!(sftp.stat(&format!("{base}/broken")).await.is_err());
    assert_eq!(sftp.stat(&format!("{base}/python")).await.unwrap().size, 29);
    sftp.remove(&format!("{base}/lib64")).await.unwrap();
    sftp.remove(&format!("{base}/python")).await.unwrap();
    assert_eq!(
        sftp.read_file(&format!("{base}/lib/data")).await.unwrap(),
        b"payload larger than link name"
    );
}
