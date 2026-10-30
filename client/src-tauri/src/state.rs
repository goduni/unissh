//! Managed application state.
//!
//! The core hands out `Arc<SshSession>` / `Arc<SshTunnel>` / `Arc<SftpFfi>` and
//! then forgets them — if we drop the `Arc`, the session/tunnel closes. So the
//! wrapper owns the lifecycle: every long-lived object is kept here, keyed by a
//! generated id the frontend uses for follow-up calls.

use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::Arc;
use unissh_ffi::key_rotation_plan::{RotationDriver, RotationPlan};
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
            Self::Plain(s) => s.write(data),
            Self::Reconnecting(s) => s.write(data),
            Self::Local(s) => s.write(data),
        }
    }
    pub fn resize(&self, cols: u32, rows: u32) -> Result<(), FfiError> {
        match self {
            Self::Plain(s) => s.resize(cols, rows),
            Self::Reconnecting(s) => s.resize(cols, rows),
            Self::Local(s) => s.resize(cols, rows),
        }
    }
    pub fn close(&self) {
        match self {
            Self::Plain(s) => {
                // Closing is the end state the caller wants either way; a
                // transport error here (peer already gone) has no one to inform.
                if let Err(e) = s.close() {
                    log::debug!("session close reported: {e}");
                }
            }
            Self::Reconnecting(s) => s.close(),
            Self::Local(s) => s.close(),
        }
    }
}

/// A guided key rotation the rotation dialog has open: the plan it shows,
/// frozen when the dialog opened, and once started the run that moves the
/// machines over. `Clone` is cheap (two `Arc`s).
#[derive(Clone)]
pub struct KeyRotationSlot {
    pub plan: Arc<RotationPlan>,
    pub driver: Option<Arc<RotationDriver>>,
}

pub struct AppState {
    pub core: Arc<Core>,
    pub db_path: PathBuf,
    pub keyset_path: PathBuf,
    pub sessions: DashMap<String, LiveSession>,
    pub tunnels: DashMap<String, Arc<SshTunnel>>,
    pub sftp_epoch: std::sync::Mutex<u64>,
    pub sftp: DashMap<String, Arc<SftpFfi>>,
    pub broadcasts: DashMap<String, Arc<BroadcastSession>>,
    pub exec_handles: DashMap<String, Arc<ExecHandleFfi>>,
    pub cancels: DashMap<String, Arc<CancelToken>>,
    /// Open guided key rotations, by the handle `key_rotation_plan` returned.
    pub key_rotations: DashMap<String, KeyRotationSlot>,
    /// Optional cloud-server link (config sidecar + in-memory session). The cloud
    /// integration is additive: a local-only instance simply leaves this unlinked.
    ///
    /// Behind an Arc so the HTTP layer can hold a handle to it: a call that comes
    /// back "access token expired" rotates the token and retries itself, and the
    /// only thing that knows how to rotate is this.
    pub cloud: Arc<CloudState>,
    /// Which biometric unlock attempt may still open the vault: a prompt
    /// answered after the user moved on (typed the password, locked again)
    /// must not unlock. Behind an Arc for the blocking closures that use it.
    pub unlock_attempts: Arc<crate::biometric::UnlockAttempts>,
}

impl AppState {
    pub fn new(core: Arc<Core>, db_path: PathBuf, keyset_path: PathBuf) -> Self {
        // The cloud config sidecar lives next to the instance DB/keyset.
        let cloud_path = db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("cloud.json");
        Self {
            core,
            db_path,
            keyset_path,
            sessions: DashMap::new(),
            tunnels: DashMap::new(),
            sftp_epoch: std::sync::Mutex::new(0),
            sftp: DashMap::new(),
            broadcasts: DashMap::new(),
            exec_handles: DashMap::new(),
            cancels: DashMap::new(),
            key_rotations: DashMap::new(),
            cloud: Arc::new(CloudState::new(cloud_path)),
            unlock_attempts: Arc::default(),
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
