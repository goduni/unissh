//! Managed application state.
//!
//! The core hands out `Arc<SshSession>` / `Arc<SshTunnel>` / `Arc<SftpFfi>` and
//! then forgets them — if we drop the `Arc`, the session/tunnel closes. So the
//! wrapper owns the lifecycle: every long-lived object is kept here, keyed by a
//! generated id the frontend uses for follow-up calls.

use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::Arc;
use unissh_ffi::{
    BroadcastSession, CancelToken, Core, ExecHandleFfi, FfiError, LocalSession,
    ReconnectingSession, SftpFfi, SshSession, SshTunnel,
};

use crate::cloud::CloudState;

/// A live interactive PTY — a plain SSH session, an auto-reconnecting one, or a
/// shell on this machine. `Clone` is cheap (clones the inner `Arc`) and lets
/// commands lift the handle out of the `DashMap` so the shard lock isn't held
/// across a blocking core call.
///
/// One enum, one id space: `session_write` / `session_resize` / `session_close`
/// serve all three, which is what lets the whole terminal UI — snippets, splits,
/// the command palette — work on a local pane without knowing it is one.
#[derive(Clone)]
pub enum LiveSession {
    Plain(Arc<SshSession>),
    Reconnecting(Arc<ReconnectingSession>),
    Local(Arc<LocalSession>),
}

impl LiveSession {
    pub fn write(&self, data: Vec<u8>) -> Result<(), FfiError> {
        match self {
            LiveSession::Plain(s) => s.write(data),
            LiveSession::Reconnecting(s) => s.write(data),
            LiveSession::Local(s) => s.write(data),
        }
    }
    pub fn resize(&self, cols: u32, rows: u32) -> Result<(), FfiError> {
        match self {
            LiveSession::Plain(s) => s.resize(cols, rows),
            LiveSession::Reconnecting(s) => s.resize(cols, rows),
            LiveSession::Local(s) => s.resize(cols, rows),
        }
    }
    pub fn close(&self) {
        match self {
            LiveSession::Plain(s) => {
                let _ = s.close();
            }
            LiveSession::Reconnecting(s) => s.close(),
            LiveSession::Local(s) => s.close(),
        }
    }
}

pub struct AppState {
    pub core: Arc<Core>,
    pub db_path: PathBuf,
    pub keyset_path: PathBuf,
    pub sessions: DashMap<String, LiveSession>,
    pub tunnels: DashMap<String, Arc<SshTunnel>>,
    pub sftp: DashMap<String, Arc<SftpFfi>>,
    pub broadcasts: DashMap<String, Arc<BroadcastSession>>,
    pub exec_handles: DashMap<String, Arc<ExecHandleFfi>>,
    pub cancels: DashMap<String, Arc<CancelToken>>,
    /// Optional cloud-server link (config sidecar + in-memory session). The cloud
    /// integration is additive: a local-only instance simply leaves this unlinked.
    ///
    /// Behind an Arc so the HTTP layer can hold a handle to it: a call that comes
    /// back "access token expired" rotates the token and retries itself, and the
    /// only thing that knows how to rotate is this.
    pub cloud: Arc<CloudState>,
}

impl AppState {
    pub fn new(core: Arc<Core>, db_path: PathBuf, keyset_path: PathBuf) -> Self {
        // The cloud config sidecar lives next to the instance DB/keyset.
        let cloud_path = db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("cloud.json");
        AppState {
            core,
            db_path,
            keyset_path,
            sessions: DashMap::new(),
            tunnels: DashMap::new(),
            sftp: DashMap::new(),
            broadcasts: DashMap::new(),
            exec_handles: DashMap::new(),
            cancels: DashMap::new(),
            cloud: Arc::new(CloudState::new(cloud_path)),
        }
    }

    /// Both instance files present → a complete instance that can be unlocked.
    /// (AND, not OR: a half-written instance is reported via `instance_partial`.)
    pub fn instance_exists(&self) -> bool {
        self.db_path.exists() && self.keyset_path.exists()
    }

    /// Exactly one of the two files present → a half-written / corrupt instance.
    /// It can neither be unlocked (the core reads the keyset first and needs the
    /// DB too) nor (re)created (`create_account`'s OR-guard refuses), so the only
    /// recovery is a reset. The UI routes this to a dedicated "repair" overlay.
    pub fn instance_partial(&self) -> bool {
        self.db_path.exists() != self.keyset_path.exists()
    }
}

/// A fresh opaque id for a long-lived object handle.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
