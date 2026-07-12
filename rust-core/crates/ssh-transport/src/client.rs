//! SSH client: connect, authentication (agent/password), host key TOFU/pinning,
//! exec, ProxyJump chains, forwards (local/remote/dynamic).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use russh::client::{
    AuthResult, Config, Handle, Handler, KeyboardInteractiveAuthResponse, Msg, Session,
};
use russh::keys::agent::AgentIdentity;
use russh::keys::{HashAlg, PublicKey};
use russh::MethodKind;
use russh::{Channel, ChannelMsg, Signer};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use zeroize::Zeroizing;

use unissh_ssh_agent::InMemoryAgent;
use unissh_storage::Storage;

use crate::error::TransportError;

/// A hard deadline on the session establishment phase (TCP+KEX+host-key+authentication).
/// Protects the FFI thread from blocking forever on a hung/malicious server
/// (the SFTP per-packet timeout only covers an already-established session).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The authentication method.
#[derive(Clone)]
pub enum Auth {
    /// With a key from the embedded agent (by the key's id in the agent).
    Agent {
        /// Key id in the agent.
        key_id: Vec<u8>,
    },
    /// With a password (zeroized on Drop).
    Password {
        /// Password.
        password: Zeroizing<String>,
    },
}

impl core::fmt::Debug for Auth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Auth::Agent { key_id } => f.debug_struct("Agent").field("key_id", key_id).finish(),
            // Do not print the password.
            Auth::Password { .. } => f
                .debug_struct("Password")
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}

/// Parameters for connecting to a single host.
#[derive(Clone, Debug)]
pub struct ConnectOptions {
    /// Host (name or IP).
    pub host: String,
    /// Port.
    pub port: u16,
    /// User name.
    pub user: String,
    /// Authentication.
    pub auth: Auth,
}

impl ConnectOptions {
    /// Constructor.
    pub fn new(host: impl Into<String>, port: u16, user: impl Into<String>, auth: Auth) -> Self {
        Self {
            host: host.into(),
            port,
            user: user.into(),
            auth,
        }
    }
}

/// The result of running a command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// stdout.
    pub stdout: Vec<u8>,
    /// stderr.
    pub stderr: Vec<u8>,
    /// Exit status (if the server sent one).
    pub exit_status: Option<u32>,
}

type RemoteForwards = Arc<Mutex<HashMap<(String, u32), (String, u16)>>>;

/// russh handler: host key check (TOFU/pinning) and delivery of remote forwards.
struct ClientHandler {
    expected_host_key: Option<Vec<u8>>,
    observed_host_key: Arc<Mutex<Option<Vec<u8>>>>,
    remote_forwards: RemoteForwards,
}

impl Handler for ClientHandler {
    type Error = TransportError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, TransportError> {
        let bytes = server_public_key
            .to_openssh()
            .map_err(|e| TransportError::KeyEncoding(e.to_string()))?
            .into_bytes();
        *self.observed_host_key.lock().expect("mutex") = Some(bytes.clone());
        Ok(match &self.expected_host_key {
            // Pinning: the key must match the pinned one (constant-time comparison).
            Some(pinned) => bool::from(pinned.as_slice().ct_eq(bytes.as_slice())),
            // TOFU: first connection — accept, the caller will pin the key.
            None => true,
        })
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<(), TransportError> {
        let target = self
            .remote_forwards
            .lock()
            .expect("mutex")
            .get(&(connected_address.to_string(), connected_port))
            .cloned();
        if let Some((host, port)) = target {
            tokio::spawn(async move {
                if let Ok(mut tcp) = TcpStream::connect((host.as_str(), port)).await {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                }
            });
        }
        Ok(())
    }
}

/// An active SSH client (one established connection, possibly through a chain).
pub struct SshClient {
    handle: Arc<Handle<ClientHandler>>,
    /// Intermediate jump hosts — kept alive (their tunnels are needed by the connection).
    _hops: Vec<Arc<Handle<ClientHandler>>>,
    remote_forwards: RemoteForwards,
}

impl SshClient {
    /// Direct connection to a host with authentication and host key TOFU pinning.
    pub async fn connect(
        opts: &ConnectOptions,
        agent: &InMemoryAgent,
        storage: &Storage,
    ) -> Result<Self, TransportError> {
        log::info!("ssh connect {}@{}:{}", opts.user, opts.host, opts.port);
        let remote_forwards: RemoteForwards = Arc::new(Mutex::new(HashMap::new()));
        let mut handle = establish_tcp(opts, storage, remote_forwards.clone()).await?;
        authenticate(&mut handle, opts, agent).await?;
        Ok(SshClient {
            handle: Arc::new(handle),
            _hops: Vec::new(),
            remote_forwards,
        })
    }

    /// Connection through a chain of jump hosts (ProxyJump). `chain` — the jumps in
    /// order, `target` — the final host. An empty chain = a direct connect.
    pub async fn connect_through(
        chain: &[ConnectOptions],
        target: &ConnectOptions,
        agent: &InMemoryAgent,
        storage: &Storage,
    ) -> Result<Self, TransportError> {
        if chain.is_empty() {
            return Self::connect(target, agent, storage).await;
        }

        log::info!(
            "ssh connect {}@{}:{} via {} jump(s)",
            target.user,
            target.host,
            target.port,
            chain.len()
        );
        let remote_forwards: RemoteForwards = Arc::new(Mutex::new(HashMap::new()));
        let mut handles: Vec<Handle<ClientHandler>> = Vec::new();

        // The first jump — over TCP.
        let mut first =
            establish_tcp(&chain[0], storage, Arc::new(Mutex::new(HashMap::new()))).await?;
        authenticate(&mut first, &chain[0], agent).await?;
        handles.push(first);

        // The remaining jumps and the final host — tunneled through the previous one.
        let rest: Vec<&ConnectOptions> = chain[1..].iter().chain(std::iter::once(target)).collect();
        for (idx, hop) in rest.iter().enumerate() {
            let is_target = idx == rest.len() - 1;
            let stream = {
                let via = handles.last().expect("at least one hop");
                via.channel_open_direct_tcpip(
                    hop.host.clone(),
                    hop.port as u32,
                    "127.0.0.1".to_string(),
                    0,
                )
                .await?
                .into_stream()
            };
            let rf = if is_target {
                remote_forwards.clone()
            } else {
                Arc::new(Mutex::new(HashMap::new()))
            };
            let mut next = establish_stream(stream, hop, storage, rf).await?;
            authenticate(&mut next, hop, agent).await?;
            handles.push(next);
        }

        let target_handle = handles.pop().expect("target handle");
        Ok(SshClient {
            handle: Arc::new(target_handle),
            _hops: handles.into_iter().map(Arc::new).collect(),
            remote_forwards,
        })
    }

    /// Runs a command, collects stdout/stderr/exit status.
    pub async fn exec(&self, command: &str) -> Result<CommandOutput, TransportError> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                _ => {}
            }
        }
        Ok(CommandOutput {
            stdout,
            stderr,
            exit_status,
        })
    }

    /// Streaming exec (without PTY): stdout/stderr are streamed into `sink`
    /// separately by a background task, the exit status via `on_exit`. Returns an
    /// [`ExecHandle`] for (optional) stdin and closing. The connection must stay alive
    /// while the handle is open (keep `SshClient` alive).
    pub async fn exec_stream(
        &self,
        command: &str,
        sink: Arc<dyn ExecSink>,
    ) -> Result<ExecHandle, TransportError> {
        let channel = self.handle.channel_open_session().await?;
        // want_reply=true: the server refusing to run the command → Err here (rather than
        // a "success" with empty output), so only data/exit arrive in the reader.
        channel.exec(true, command).await?;
        let (mut read, write) = channel.split();
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exited2 = exited.clone();
        let reader = tokio::spawn(async move {
            let mut exit = None;
            while let Some(msg) = read.wait().await {
                match msg {
                    ChannelMsg::Data { data } => sink.on_stdout(data.to_vec()),
                    ChannelMsg::ExtendedData { data, .. } => sink.on_stderr(data.to_vec()),
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    // The command was killed by a signal or the channel dropped → exit stays None,
                    // the consumer will see code -1 (rather than a false success).
                    _ => {}
                }
            }
            sink.on_exit(exit);
            // set exited AFTER on_exit → wait_exit()==true guarantees delivery.
            exited2.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        Ok(ExecHandle {
            write,
            reader,
            exited,
        })
    }

    /// Local forward: listens on `bind_addr`, tunnels each connection to
    /// `target_host:target_port` from the server side (direct-tcpip).
    ///
    /// SECURITY: `bind_addr` is controlled by the caller. Binding to a non-loopback
    /// address (`0.0.0.0`/a LAN address) makes the tunnel reachable by the whole local
    /// network (analogous to OpenSSH `GatewayPorts`) — the UI/FFI MUST use loopback
    /// (`127.0.0.1`/`::1`) by default and expose it outward only on an explicit user
    /// choice. Unlike [`Self::dynamic_forward`] (an open SOCKS without authentication,
    /// where loopback is forced), here the forward goes to a fixed `target`, so
    /// non-loopback is allowed as a conscious choice.
    pub async fn local_forward(
        &self,
        bind_addr: &str,
        target_host: &str,
        target_port: u16,
    ) -> Result<ForwardGuard, TransportError> {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let handle = self.handle.clone();
        let target_host = target_host.to_string();

        let task = tokio::spawn(async move {
            while let Ok((mut socket, _peer)) = listener.accept().await {
                let handle = handle.clone();
                let target_host = target_host.clone();
                tokio::spawn(async move {
                    if let Ok(channel) = handle
                        .channel_open_direct_tcpip(
                            target_host,
                            target_port as u32,
                            "127.0.0.1".to_string(),
                            0,
                        )
                        .await
                    {
                        let mut stream = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
                    }
                });
            }
        });
        Ok(ForwardGuard { local_addr, task })
    }

    /// Dynamic forward (SOCKS5 CONNECT, without authentication): listens on
    /// `bind_addr`, and on a client request opens direct-tcpip to the requested address.
    ///
    /// SECURITY: SOCKS5 without authentication — `bind_addr` MUST be
    /// loopback (`127.0.0.1`/`::1`). Binding to `0.0.0.0` would open the proxy to the
    /// whole network. Controlling the address is up to the caller.
    pub async fn dynamic_forward(&self, bind_addr: &str) -> Result<ForwardGuard, TransportError> {
        // SECURITY: we force loopback at the library level (not only in the docs) —
        // an open SOCKS5 without authentication must not be exposed to the network.
        require_loopback(bind_addr)?;
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let handle = self.handle.clone();

        let task = tokio::spawn(async move {
            while let Ok((mut socket, _peer)) = listener.accept().await {
                let handle = handle.clone();
                tokio::spawn(async move {
                    let (host, port) = match socks5_handshake(&mut socket).await {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    if let Ok(channel) = handle
                        .channel_open_direct_tcpip(host, port as u32, "127.0.0.1".to_string(), 0)
                        .await
                    {
                        let mut stream = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
                    }
                });
            }
        });
        Ok(ForwardGuard { local_addr, task })
    }

    /// Remote forward: asks the server to listen on `remote_bind:remote_port` and
    /// deliver incoming connections to the local `local_host:local_port`.
    pub async fn remote_forward(
        &self,
        remote_bind: &str,
        remote_port: u16,
        local_host: &str,
        local_port: u16,
    ) -> Result<u16, TransportError> {
        // First ask the server to listen (port 0 → the server assigns one), then
        // register delivery by the ACTUALLY assigned port: that is the one the
        // server will indicate as connected_port in forwarded-tcpip.
        let assigned = self
            .handle
            .tcpip_forward(remote_bind.to_string(), remote_port as u32)
            .await? as u16;
        self.remote_forwards.lock().expect("mutex").insert(
            (remote_bind.to_string(), assigned as u32),
            (local_host.to_string(), local_port),
        );
        Ok(assigned)
    }

    /// Terminates the connection.
    pub async fn disconnect(&self) -> Result<(), TransportError> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await?;
        Ok(())
    }

    /// Opens an interactive shell session with a PTY. The output (PTY stdout/stderr)
    /// is streamed into `sink` by a background task; input/resize/close via the
    /// returned [`ShellHandle`]. The connection must stay alive while the session is
    /// open (keep `SshClient` alive at the caller).
    pub async fn open_shell(
        &self,
        term: &str,
        cols: u32,
        rows: u32,
        sink: Arc<dyn OutputSink>,
    ) -> Result<ShellHandle, TransportError> {
        let channel = self.handle.channel_open_session().await?;
        channel
            .request_pty(false, term, cols, rows, 0, 0, &[])
            .await?;
        channel.request_shell(false).await?;
        let (mut read, write) = channel.split();

        let reader = tokio::spawn(async move {
            let mut exit = None;
            while let Some(msg) = read.wait().await {
                match msg {
                    ChannelMsg::Data { data } => sink.on_data(data.to_vec()),
                    ChannelMsg::ExtendedData { data, .. } => sink.on_data(data.to_vec()),
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    // A shell killed by a signal carries no numeric status; report a
                    // non-negative code (shell convention 128 + signal) so the UI sees
                    // a real shell termination, not a transport drop to auto-reconnect.
                    ChannelMsg::ExitSignal { .. } => exit = exit.or(Some(128)),
                    _ => {}
                }
            }
            sink.on_close(exit);
        });
        Ok(ShellHandle { write, reader })
    }

    /// Opens an SFTP session (the `sftp` subsystem) over the connection. The connection
    /// must stay alive while the session is open (keep `SshClient` alive).
    pub async fn open_sftp(&self) -> Result<SftpSession, TransportError> {
        let channel = self.handle.channel_open_session().await?;
        channel.request_subsystem(false, "sftp").await?;
        crate::sftp::Sftp::start(channel.into_stream()).await
    }
}

/// An SFTP session over the client SSH channel (a concrete russh stream type).
pub type SftpSession = crate::sftp::Sftp<russh::ChannelStream<Msg>>;

/// A receiver of interactive-session output (implemented by the consumer, e.g. FFI).
pub trait OutputSink: Send + Sync {
    /// Data from the session (PTY output).
    fn on_data(&self, data: Vec<u8>);
    /// The session is closed; the exit status, if received.
    fn on_close(&self, exit_status: Option<u32>);
}

/// A receiver of streaming exec: separate stdout/stderr + exit status. Unlike
/// [`OutputSink`] (a PTY deliberately merges the streams), here they are separated.
pub trait ExecSink: Send + Sync {
    /// stdout data.
    fn on_stdout(&self, data: Vec<u8>);
    /// stderr data.
    fn on_stderr(&self, data: Vec<u8>);
    /// The command finished; the exit status, if received.
    fn on_exit(&self, exit_status: Option<u32>);
}

/// Control of streaming exec: stdin (optional), closing, polling for completion.
/// Stops the background reading on Drop.
pub struct ExecHandle {
    write: russh::ChannelWriteHalf<Msg>,
    reader: tokio::task::JoinHandle<()>,
    exited: Arc<std::sync::atomic::AtomicBool>,
}

impl ExecHandle {
    /// Whether the command has finished (whether `on_exit` was delivered).
    pub fn has_exited(&self) -> bool {
        self.exited.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Writes to the command's stdin.
    pub async fn write_stdin(&self, data: &[u8]) -> Result<(), TransportError> {
        self.write.data_bytes(data.to_vec()).await?;
        Ok(())
    }

    /// Closes the channel (EOF stdin + close).
    pub async fn close(&self) -> Result<(), TransportError> {
        let _ = self.write.eof().await;
        self.write.close().await?;
        Ok(())
    }
}

impl Drop for ExecHandle {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Control of an interactive session: input, window resize, closing. Stops the
/// background reading on Drop.
pub struct ShellHandle {
    write: russh::ChannelWriteHalf<Msg>,
    reader: tokio::task::JoinHandle<()>,
}

impl ShellHandle {
    /// Sends input (keystrokes) into the session.
    pub async fn write(&self, data: &[u8]) -> Result<(), TransportError> {
        self.write.data_bytes(data.to_vec()).await?;
        Ok(())
    }

    /// Changes the terminal window size.
    pub async fn resize(&self, cols: u32, rows: u32) -> Result<(), TransportError> {
        self.write.window_change(cols, rows, 0, 0).await?;
        Ok(())
    }

    /// Closes the session.
    pub async fn close(&self) -> Result<(), TransportError> {
        let _ = self.write.eof().await;
        self.write.close().await?;
        Ok(())
    }
}

impl Drop for ShellHandle {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// A handle for a local/dynamic forward. Stops accepting on Drop.
pub struct ForwardGuard {
    local_addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl ForwardGuard {
    /// The address the forward is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for ForwardGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// --- internal ---

/// Keepalive interval (seconds) for all new SSH connections; `0` — disabled.
/// Global, since this is a user setting shared across sessions, tunnels and the
/// broadcast; read when establishing each new connection.
/// Defaults to 15 s (keeps idle sessions alive and detects a dead peer).
static KEEPALIVE_SECS: AtomicU64 = AtomicU64::new(15);

/// Set the keepalive interval (seconds) for subsequent connections; `0` —
/// disable keepalive. Does not affect already-established connections.
pub fn set_keepalive_secs(secs: u64) {
    KEEPALIVE_SECS.store(secs, Ordering::Relaxed);
}

fn client_config() -> Arc<Config> {
    let secs = KEEPALIVE_SECS.load(Ordering::Relaxed);
    Arc::new(Config {
        // Keepalive detects a dead peer on long sessions/tunnels, while
        // NOT killing live-but-idle sessions (we leave inactivity_timeout as
        // None — otherwise an idle interactive shell/tunnel would be torn down).
        // The interval is configured by the user; 0 → keepalive off.
        keepalive_interval: (secs > 0).then(|| Duration::from_secs(secs)),
        keepalive_max: 3,
        nodelay: true,
        // Per-channel SSH flow-control window. The russh default (2 MiB) throttles
        // the SFTP pipeline on "fat, long" channels: the window must fit
        // WINDOW*CHUNK bytes in flight (see sftp.rs). Memory is per-channel; with a pool of
        // several channels this multiplies, so we keep a moderate 8 MiB.
        // We do NOT touch maximum_packet_size: russh requires ≤ 65535 (otherwise the error
        // "Maximum packet size should not be larger than a TCP packet"), while CHUNK
        // (128 KiB) is the SFTP application-level chunk size; russh splits it into
        // SSH packets itself, so a large chunk does not require a large max_packet.
        window_size: 8 * 1024 * 1024,
        ..Config::default()
    })
}

async fn establish_tcp(
    opts: &ConnectOptions,
    storage: &Storage,
    remote_forwards: RemoteForwards,
) -> Result<Handle<ClientHandler>, TransportError> {
    let expected = storage.get_known_host(&opts.host, opts.port)?;
    let observed = Arc::new(Mutex::new(None));
    let handler = ClientHandler {
        expected_host_key: expected.clone(),
        observed_host_key: observed.clone(),
        remote_forwards,
    };
    let connected = timeout(
        HANDSHAKE_TIMEOUT,
        russh::client::connect(client_config(), (opts.host.as_str(), opts.port), handler),
    )
    .await
    .map_err(|_| TransportError::HandshakeTimeout)?;
    match connected {
        Ok(handle) => {
            pin_tofu(storage, &opts.host, opts.port, &expected, &observed)?;
            Ok(handle)
        }
        Err(e) => Err(classify_connect_error(
            e, &opts.host, opts.port, &expected, &observed,
        )),
    }
}

async fn establish_stream<R>(
    stream: R,
    opts: &ConnectOptions,
    storage: &Storage,
    remote_forwards: RemoteForwards,
) -> Result<Handle<ClientHandler>, TransportError>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let expected = storage.get_known_host(&opts.host, opts.port)?;
    let observed = Arc::new(Mutex::new(None));
    let handler = ClientHandler {
        expected_host_key: expected.clone(),
        observed_host_key: observed.clone(),
        remote_forwards,
    };
    let connected = timeout(
        HANDSHAKE_TIMEOUT,
        russh::client::connect_stream(client_config(), stream, handler),
    )
    .await
    .map_err(|_| TransportError::HandshakeTimeout)?;
    match connected {
        Ok(handle) => {
            pin_tofu(storage, &opts.host, opts.port, &expected, &observed)?;
            Ok(handle)
        }
        Err(e) => Err(classify_connect_error(
            e, &opts.host, opts.port, &expected, &observed,
        )),
    }
}

fn pin_tofu(
    storage: &Storage,
    host: &str,
    port: u16,
    expected: &Option<Vec<u8>>,
    observed: &Arc<Mutex<Option<Vec<u8>>>>,
) -> Result<(), TransportError> {
    if expected.is_none() {
        if let Some(key) = observed.lock().expect("mutex").clone() {
            storage.put_known_host(host, port, &key)?;
        }
    }
    Ok(())
}

fn classify_connect_error(
    e: TransportError,
    host: &str,
    port: u16,
    expected: &Option<Vec<u8>>,
    observed: &Arc<Mutex<Option<Vec<u8>>>>,
) -> TransportError {
    // If a key was pinned and the observed one differs — this is a mismatch (MITM).
    if let Some(pinned) = expected {
        if let Some(obs) = observed.lock().expect("mutex").clone() {
            if !bool::from(obs.as_slice().ct_eq(pinned.as_slice())) {
                return TransportError::HostKeyMismatch {
                    host: host.to_string(),
                    port,
                    fingerprint: fingerprint_openssh(&obs),
                };
            }
        }
    }
    e
}

/// Checks that the bind address is loopback (for the dynamic SOCKS5 forward). Requires
/// an IP literal `ip:port`; hostnames and non-loopback addresses are rejected.
pub(crate) fn require_loopback(bind_addr: &str) -> Result<(), TransportError> {
    match bind_addr.parse::<SocketAddr>() {
        Ok(sa) if sa.ip().is_loopback() => Ok(()),
        _ => Err(TransportError::NonLoopbackBind(bind_addr.to_string())),
    }
}

/// The SHA256 fingerprint of a host key from its OpenSSH representation (for showing in the UI).
/// For an unparseable key — `"unknown"` (not critical: it is an informational string).
/// Canonicalizes the public host key with the **same** `russh` as pinning does
/// ([`ClientHandler::check_server_key`] stores `server_public_key.to_openssh()`),
/// so that a key imported from `~/.ssh/known_hosts` matches byte-for-byte the one
/// pinned during a live connect. The input is a `keytype base64` token (without the
/// host name and comment). Returns the canonical OpenSSH form in bytes.
pub fn canonical_host_key(key_openssh: &str) -> Result<Vec<u8>, TransportError> {
    let pk = PublicKey::from_openssh(key_openssh.trim())
        .map_err(|e| TransportError::KeyEncoding(e.to_string()))?;
    Ok(pk
        .to_openssh()
        .map_err(|e| TransportError::KeyEncoding(e.to_string()))?
        .into_bytes())
}

/// The OpenSSH SHA256 fingerprint (`SHA256:…`) of a public key in OpenSSH text
/// form, or `"unknown"` if it can't be parsed. This is the exact format the
/// `HostKeyMismatch` error emits for the presented key, so a stored key run through
/// this is directly comparable against it.
pub fn fingerprint_openssh(openssh: &[u8]) -> String {
    let s = String::from_utf8_lossy(openssh);
    match PublicKey::from_openssh(s.trim()) {
        Ok(pk) => pk.fingerprint(HashAlg::Sha256).to_string(),
        Err(_) => "unknown".to_string(),
    }
}

/// Connects (transport handshake only, without authentication), learns the server's
/// host key and **re-pins** it (overwrite) — the "trust the new key" UX
/// after [`TransportError::HostKeyMismatch`]. Returns the SHA256 fingerprint of the
/// pinned key.
///
/// `expected_fingerprint` — the fingerprint confirmed by the user in the
/// warning (`HostKeyMismatch.fingerprint`). The freshly obtained key is
/// verified against it (constant-time) before pinning: if an active MITM swaps the
/// key between the warning and the consent, no pinning happens
/// ([`TransportError::FingerprintMismatch`]).
///
/// Direct connection only (no ProxyJump). For hosts reachable only through a
/// jump, use `forget_host` + an ordinary reconnect (a repeat TOFU).
pub async fn trust_host_key(
    host: &str,
    port: u16,
    storage: &Storage,
    expected_fingerprint: &str,
) -> Result<String, TransportError> {
    let observed = Arc::new(Mutex::new(None));
    let handler = ClientHandler {
        // None → accept the presented key (as on the first TOFU).
        expected_host_key: None,
        observed_host_key: observed.clone(),
        remote_forwards: Arc::new(Mutex::new(HashMap::new())),
    };
    let handle = timeout(
        HANDSHAKE_TIMEOUT,
        russh::client::connect(client_config(), (host, port), handler),
    )
    .await
    .map_err(|_| TransportError::HandshakeTimeout)??;
    let key = observed
        .lock()
        .expect("mutex")
        .clone()
        .ok_or_else(|| TransportError::KeyEncoding("no host key observed".into()))?;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;

    // Verify the actually presented key against the confirmed fingerprint
    // (constant-time) — pin only on a match.
    let got = fingerprint_openssh(&key);
    if !bool::from(got.as_bytes().ct_eq(expected_fingerprint.as_bytes())) {
        return Err(TransportError::FingerprintMismatch {
            expected: expected_fingerprint.to_string(),
            got,
        });
    }
    // put_known_host does an UPSERT → re-pinning (overwrite).
    storage.put_known_host(host, port, &key)?;
    Ok(got)
}

async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    opts: &ConnectOptions,
    agent: &InMemoryAgent,
) -> Result<(), TransportError> {
    // The whole authentication phase is under a hard deadline (a malicious/hung
    // server must not hang the call forever).
    let result = timeout(HANDSHAKE_TIMEOUT, async {
        Ok::<AuthResult, TransportError>(match &opts.auth {
            Auth::Agent { key_id } => {
                // The private key does NOT leave the agent: the agent itself signs via
                // russh::auth::Signer. Out of the agent — only the public key /
                // certificate (bridged into russh::keys via the stable OpenSSH format,
                // since ssh-agent is on ssh-key 0.6 and russh is on 0.7).
                let public06 = agent
                    .public_key(key_id)
                    .ok_or_else(|| TransportError::KeyEncoding("key not in agent".into()))?;
                let public_openssh = public06
                    .to_openssh()
                    .map_err(|e| TransportError::KeyEncoding(e.to_string()))?;
                let russh_public = PublicKey::from_openssh(&public_openssh)
                    .map_err(|e| TransportError::KeyEncoding(e.to_string()))?;

                // RSA is signed with rsa-sha2-512 (as ssh-key does); everything else — without a hash.
                let hash_alg = if russh_public.algorithm().is_rsa() {
                    Some(HashAlg::Sha512)
                } else {
                    None
                };

                let mut signer = AgentSigner {
                    agent,
                    key_id: key_id.clone(),
                };

                // If a certificate is attached to the key — cert-based authentication
                // (also via Signer, the key does not leave the agent).
                match agent.certificate(key_id) {
                    Some(cert06) => {
                        let cert_openssh = cert06
                            .to_openssh()
                            .map_err(|e| TransportError::KeyEncoding(e.to_string()))?;
                        let russh_cert = russh::keys::Certificate::from_openssh(&cert_openssh)
                            .map_err(|e| TransportError::KeyEncoding(e.to_string()))?;
                        handle
                            .authenticate_certificate_with(
                                opts.user.clone(),
                                russh_cert,
                                hash_alg,
                                &mut signer,
                            )
                            .await?
                    }
                    None => {
                        handle
                            .authenticate_publickey_with(
                                opts.user.clone(),
                                russh_public,
                                hash_alg,
                                &mut signer,
                            )
                            .await?
                    }
                }
            }
            Auth::Password { password } => {
                // Residual risk: russh::authenticate_password (and kbd-respond)
                // take a String by value and do not zeroize it — a copy of the password
                // lives in russh memory until the allocator reuses it. This can be
                // eliminated only by patching russh; our side (Auth::Password) keeps
                // the password in Zeroizing.
                let first = handle
                    .authenticate_password(opts.user.clone(), password.as_str().to_string())
                    .await?;
                match first {
                    // The server did not accept the "password" method but offers
                    // keyboard-interactive (a typical sshd with PAM) — try it,
                    // answering with the same password (like OpenSSH).
                    AuthResult::Failure {
                        ref remaining_methods,
                        ..
                    } if remaining_methods.contains(&MethodKind::KeyboardInteractive) => {
                        keyboard_interactive_with_password(handle, &opts.user, password).await?
                    }
                    other => other,
                }
            }
        })
    })
    .await
    .map_err(|_| TransportError::HandshakeTimeout)??;
    match result {
        AuthResult::Success => {
            log::debug!("ssh auth ok for user {}", opts.user);
            Ok(())
        }
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => {
            // Surface the context russh otherwise drops on the floor: which methods
            // the server still offers (and whether a partial step succeeded) is the
            // single most useful thing when diagnosing an auth failure. Method kinds
            // and the username are connection metadata, not secrets.
            log::warn!(
                "ssh auth failed for user {}: partial_success={}, server still offers {:?}",
                opts.user,
                partial_success,
                remaining_methods,
            );
            Err(TransportError::AuthFailed)
        }
    }
}

/// Maximum number of InfoRequest rounds in keyboard-interactive: a malicious/broken
/// server must not keep the client in an endless loop of prompts.
const MAX_KBD_INTERACTIVE_ROUNDS: usize = 8;

/// keyboard-interactive that answers each prompt with the password. Used as a
/// fallback for `Auth::Password`; interactive scenarios (OTP etc.) are a separate
/// task (prompts are not forwarded to the UI).
async fn keyboard_interactive_with_password(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    password: &Zeroizing<String>,
) -> Result<AuthResult, TransportError> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(user.to_string(), None::<String>)
        .await?;
    for _ in 0..MAX_KBD_INTERACTIVE_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(AuthResult::Success),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Ok(AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                })
            }
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                // Answer with the password only on NON-echo prompts (hidden-input
                // fields — password/passphrase). echo=true is a visible field (login,
                // hint); the password must not be sent there — answer with an empty string.
                let answers = prompts
                    .iter()
                    .map(|p| {
                        if p.echo {
                            String::new()
                        } else {
                            password.as_str().to_string()
                        }
                    })
                    .collect();
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Err(TransportError::AuthFailed)
}

/// A signer on top of the embedded agent: implements `russh::auth::Signer` without
/// exporting the private key. The agent signs the authentication data, and the
/// result is wrapped in the SSH signature format.
struct AgentSigner<'a> {
    agent: &'a InMemoryAgent,
    key_id: Vec<u8>,
}

impl Signer for AgentSigner<'_> {
    type Error = TransportError;

    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, TransportError> {
        // The agent signs the whole authentication buffer (session_id || request).
        let sig = self.agent.sign(&self.key_id, &to_sign)?;
        let name = sig.algorithm.as_bytes();
        let raw = &sig.signature;

        // russh expects: to_sign ++ string( string(alg) || string(sig) ).
        let inner_len = 4 + name.len() + 4 + raw.len();
        let mut out = to_sign;
        out.extend_from_slice(&(inner_len as u32).to_be_bytes());
        out.extend_from_slice(&(name.len() as u32).to_be_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        out.extend_from_slice(raw);
        Ok(out)
    }
}

/// Minimal SOCKS5 CONNECT (without authentication). Returns the target host:port.
async fn socks5_handshake<S>(socket: &mut S) -> Result<(String, u16), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Greeting: VER NMETHODS METHODS...
    let mut head = [0u8; 2];
    socket.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(TransportError::Socks);
    }
    let n = head[1] as usize;
    if n == 0 {
        return Err(TransportError::Socks);
    }
    let mut methods = vec![0u8; n];
    socket.read_exact(&mut methods).await?;
    // We support only method 0 (without authentication); otherwise 0xFF and disconnect.
    if !methods.contains(&0x00) {
        let _ = socket.write_all(&[0x05, 0xff]).await;
        return Err(TransportError::Socks);
    }
    socket.write_all(&[0x05, 0x00]).await?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = [0u8; 4];
    socket.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        // we support only CONNECT
        socket
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(TransportError::Socks);
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            socket.read_exact(&mut a).await?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            if len[0] == 0 {
                return Err(TransportError::Socks);
            }
            let mut dn = vec![0u8; len[0] as usize];
            socket.read_exact(&mut dn).await?;
            String::from_utf8(dn).map_err(|_| TransportError::Socks)?
        }
        0x04 => {
            let mut a = [0u8; 16];
            socket.read_exact(&mut a).await?;
            let segments: Vec<String> = a
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            segments.join(":")
        }
        _ => return Err(TransportError::Socks),
    };
    let mut port = [0u8; 2];
    socket.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    // Success: BND.ADDR/PORT = 0.
    socket
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::require_loopback;
    use crate::error::TransportError;

    #[test]
    fn loopback_accepted() {
        assert!(require_loopback("127.0.0.1:0").is_ok());
        assert!(require_loopback("127.0.0.1:1080").is_ok());
        assert!(require_loopback("[::1]:1080").is_ok());
    }

    #[test]
    fn non_loopback_rejected() {
        for bad in [
            "0.0.0.0:1080",
            "192.168.1.5:1080",
            "[::]:1080",
            "example.com:1080",
            "garbage",
        ] {
            assert!(
                matches!(
                    require_loopback(bad),
                    Err(TransportError::NonLoopbackBind(_))
                ),
                "should reject {bad}"
            );
        }
    }
}
