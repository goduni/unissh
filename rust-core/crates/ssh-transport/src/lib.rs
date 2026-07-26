//! # unissh-ssh-transport
//!
//! UniSSH SSH transport on [`russh`] (spec 10.4). Builds on `ssh-agent`
//! (key-based authentication) and `storage` (host key TOFU/pinning).
//!
//! ## Features
//! - Connection and authentication **with a key from the embedded agent** or a password.
//! - **ProxyJump and chains** of jump hosts ([`SshClient::connect_through`]).
//! - Forwards: **local** ([`SshClient::local_forward`]), **dynamic SOCKS5**
//!   ([`SshClient::dynamic_forward`]), **remote** ([`SshClient::remote_forward`]).
//! - **Host key TOFU + pinning**: on the first connect the key is pinned in
//!   `storage.known_hosts`; on subsequent ones it is verified, a mismatch →
//!   [`TransportError::HostKeyMismatch`] (with the fingerprint of the presented key).
//!   Consciously "trust the new key" — [`trust_host_key`].
//! - **SFTP** (v3) on top of the `sftp` subsystem ([`SshClient::open_sftp`], [`Sftp`]):
//!   listing, file read/write, stat, mkdir/rmdir, remove, rename, realpath.
//! - Import of `~/.ssh/config` ([`SshConfig`]).
//!
//! ## Security
//! - **Agent forwarding is DISABLED by default** (spec 10.2): the handler does not
//!   enable agent-forward; ProxyJump is used instead (the key is not handed to the bastion).
//! - **The private key never leaves the agent.** Authentication goes through
//!   `russh::auth::Signer` on top of the embedded agent: the agent signs the
//!   authentication data, and only the public key is handed out of the agent.
//!
//! ## Interactive authentication
//! `keyboard-interactive` is answered from the stored password only where that
//! is unambiguous: the first round, every field hidden-input — the shape a PAM
//! sshd uses when it wants nothing but the password. Anything else (a one-time
//! code, a push confirmation, a forced password change) is handed to an
//! [`AuthPrompter`] attached via [`ConnectOptions::with_prompter`]. Without one,
//! such a login fails with [`TransportError::InteractiveAuthUnsupported`] rather
//! than sending a wrong answer.
//!
//! ## Out of scope (⏳ LATER)
//! The relay/bastion service and CA are not implemented (spec 11).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod config;
mod error;
mod sftp;

pub use client::system_agent_keys;
pub use client::{
    algorithm_policy, canonical_host_key, fingerprint_openssh, set_algorithm_policy,
    set_keepalive_secs, trust_host_key, AlgorithmPolicy, Auth, AuthPrompter, CommandOutput,
    ConnectOptions, ExecHandle, ExecSink, ForwardGuard, OutputSink, PromptField, SftpSession,
    ShellHandle, SshClient, SystemAgentKey,
};
pub use config::{HostSettings, SkipReason, SkippedDirective, SshConfig};
pub use error::TransportError;
pub use sftp::{DirEntry, FileStat, Sftp, SftpCancel, SftpProgress, TransferOutcome};
