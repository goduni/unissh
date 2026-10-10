//! Cancellation during channel confirmation and SFTP negotiation must close the
//! abandoned channel without disconnecting other users of the SSH transport.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_assert_message,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use std::sync::Arc;
use std::time::Duration;

use russh::server::{self, Auth as ServerAuth};
use russh::{Channel, ChannelId};
use tokio::sync::Notify;
use unissh_ssh_agent::{generate_ed25519_openssh, InMemoryAgent};
use unissh_ssh_transport::{Auth, ConnectOptions, SshClient};
use unissh_storage::Storage;
use zeroize::Zeroizing;

struct DelayedSftp {
    confirm_gate: Option<Arc<Notify>>,
    stall_version: bool,
    started: Arc<Notify>,
    closed: Arc<Notify>,
}

impl server::Handler for DelayedSftp {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<ServerAuth, Self::Error> {
        Ok(ServerAuth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if let Some(gate) = self.confirm_gate.take() {
            self.started.notify_one();
            gate.notified().await;
        }
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        _: ChannelId,
        name: &str,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        assert_eq!(name, "sftp");
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.stall_version {
            self.stall_version = false;
            self.started.notify_one();
        } else {
            // SFTP v3 VERSION reply to the client's INIT.
            session.data(channel, vec![0, 0, 0, 5, 2, 0, 0, 0, 3])?;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _: ChannelId,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.closed.notify_one();
        Ok(())
    }
}

async fn cancel_open(delay_confirmation: bool) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (key, _) = generate_ed25519_openssh().unwrap();
    let config = Arc::new(server::Config {
        keys: vec![russh::keys::PrivateKey::from_openssh(&key).unwrap()],
        ..Default::default()
    });
    let started = Arc::new(Notify::new());
    let closed = Arc::new(Notify::new());
    let gate = Arc::new(Notify::new());
    let handler = DelayedSftp {
        confirm_gate: delay_confirmation.then(|| gate.clone()),
        stall_version: !delay_confirmation,
        started: started.clone(),
        closed: closed.clone(),
    };
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let session = server::run_stream(config, stream, handler).await.unwrap();
        if session.await.is_err() {
            // How the client ended the session is not under test.
        }
    });
    let opts = ConnectOptions::new(
        "127.0.0.1",
        port,
        "test",
        Auth::Password {
            password: Zeroizing::new("test".into()),
        },
    );
    let agent = InMemoryAgent::new();
    let storage = Storage::open_in_memory(&[9; 32]).unwrap();
    let client = SshClient::connect(&opts, &agent, &storage).await.unwrap();
    {
        let open = client.open_sftp();
        tokio::pin!(open);
        tokio::select! {
            _ = started.notified() => {},
            _ = &mut open => panic!("the server has not finished opening SFTP"),
        }
        // Drop the pending open, just as a cancelled FFI wait does.
    }
    gate.notify_one();
    tokio::time::timeout(Duration::from_secs(2), closed.notified())
        .await
        .expect("the abandoned channel must be closed after a late server reply");
    // Cancellation must preserve the shared connection for subsequent opens.
    let next = client.open_sftp().await.unwrap();
    drop(next);
    client.disconnect().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn cancellation_closes_late_channel_confirmation() {
    tokio::time::timeout(Duration::from_secs(10), cancel_open(true))
        .await
        .unwrap();
}

#[tokio::test]
async fn cancellation_closes_silent_sftp_negotiation() {
    tokio::time::timeout(Duration::from_secs(10), cancel_open(false))
        .await
        .unwrap();
}
