//! Password authentication and the fallback to keyboard-interactive — against an
//! in-process russh server (hermetic: sshd without PAM cannot do kbd-interactive,
//! and the password of a system user must not be changed in tests).

use std::sync::Arc;

use russh::server::{self, Auth as ServerAuth, Response};
use russh::{MethodKind, MethodSet};
use zeroize::Zeroizing;

use unissh_ssh_agent::{generate_ed25519_openssh, InMemoryAgent};
use unissh_ssh_transport::{Auth, ConnectOptions, SshClient, TransportError};
use unissh_storage::Storage;

const PASSWORD: &str = "correct horse battery staple";

/// The keyboard-interactive mode of the test server.
#[derive(Clone, Copy, PartialEq)]
enum Kbd {
    /// The method is not offered.
    Off,
    /// `prompts` prompts in a single InfoRequest; all answers must equal the password.
    Prompts(usize),
    /// Endless InfoRequests (a malicious server).
    Endless,
}

struct PwServer {
    allow_password: bool,
    kbd: Kbd,
}

impl server::Handler for PwServer {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        _user: &str,
        password: &str,
    ) -> Result<ServerAuth, russh::Error> {
        if self.allow_password && password == PASSWORD {
            return Ok(ServerAuth::Accept);
        }
        Ok(ServerAuth::reject())
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<ServerAuth, russh::Error> {
        let prompts = |n: usize| ServerAuth::Partial {
            name: "".into(),
            instructions: "".into(),
            prompts: (0..n)
                .map(|i| (format!("Password {i}: ").into(), false))
                .collect::<Vec<_>>()
                .into(),
        };
        match self.kbd {
            Kbd::Off => Ok(ServerAuth::reject()),
            Kbd::Endless => Ok(prompts(1)),
            Kbd::Prompts(n) => match response {
                None => Ok(prompts(n)),
                Some(resp) => {
                    let answers: Vec<_> = resp.collect();
                    if answers.len() == n
                        && answers.iter().all(|a| a.as_ref() == PASSWORD.as_bytes())
                    {
                        Ok(ServerAuth::Accept)
                    } else {
                        Ok(ServerAuth::reject())
                    }
                }
            },
        }
    }
}

/// Brings up an in-process SSH server; returns the port. The server lives as long
/// as the test runtime does (handler tasks outlive completion — that is fine).
async fn start_server(allow_password: bool, kbd: Kbd) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (priv_pem, _) = generate_ed25519_openssh().unwrap();
    let host_key = russh::keys::PrivateKey::from_openssh(&priv_pem).unwrap();

    let mut methods = MethodSet::empty();
    if allow_password {
        methods.push(MethodKind::Password);
    }
    if kbd != Kbd::Off {
        methods.push(MethodKind::KeyboardInteractive);
    }
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        // Shorten the constant rejection time — otherwise every negative test waits 1s.
        auth_rejection_time: std::time::Duration::from_millis(10),
        methods,
        ..Default::default()
    });

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let config = config.clone();
            let handler = PwServer {
                allow_password,
                kbd,
            };
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream::<_, _>(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    port
}

fn password_opts(port: u16, password: &str) -> ConnectOptions {
    ConnectOptions::new(
        "127.0.0.1",
        port,
        "root",
        Auth::Password {
            password: Zeroizing::new(password.to_owned()),
        },
    )
}

async fn try_connect(port: u16, password: &str) -> Result<SshClient, TransportError> {
    let agent = InMemoryAgent::new();
    let storage = Storage::open_in_memory(&[9_u8; 32]).unwrap();
    SshClient::connect(&password_opts(port, password), &agent, &storage).await
}

#[tokio::test]
async fn password_auth_success() {
    let port = start_server(true, Kbd::Off).await;
    let client = try_connect(port, PASSWORD).await.unwrap();
    let _ = client.disconnect().await;
}

#[tokio::test]
async fn wrong_password_fails() {
    let port = start_server(true, Kbd::Off).await;
    assert!(matches!(
        try_connect(port, "wrong").await,
        Err(TransportError::AuthFailed)
    ));
}

#[tokio::test]
async fn keyboard_interactive_only_server_falls_back() {
    // The server does not accept the "password" method — only keyboard-interactive.
    let port = start_server(false, Kbd::Prompts(1)).await;
    let client = try_connect(port, PASSWORD).await.unwrap();
    let _ = client.disconnect().await;
}

#[tokio::test]
async fn keyboard_interactive_multiple_prompts() {
    let port = start_server(false, Kbd::Prompts(3)).await;
    let client = try_connect(port, PASSWORD).await.unwrap();
    let _ = client.disconnect().await;
}

#[tokio::test]
async fn keyboard_interactive_wrong_password_fails() {
    let port = start_server(false, Kbd::Prompts(1)).await;
    assert!(matches!(
        try_connect(port, "wrong").await,
        Err(TransportError::AuthFailed)
    ));
}

#[tokio::test]
async fn endless_info_requests_are_bounded() {
    // A malicious server sends InfoRequests endlessly: the client must stop
    // at the round limit with an error, rather than hang/spin forever.
    let port = start_server(false, Kbd::Endless).await;
    assert!(try_connect(port, PASSWORD).await.is_err());
}
