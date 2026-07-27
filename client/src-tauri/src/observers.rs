//! Bridges from the core's observer callbacks to the frontend.
//!
//! Most of these are push-only and fire on the core's background runtime
//! threads, so they must stay non-blocking — they just forward the bytes/events
//! into the channel bound to the originating `invoke` call. The frontend feeds
//! the bytes straight into xterm.js (PTY) or its exec/broadcast/transfer views.
//!
//! [`AppPrompter`] is the exception: interactive authentication needs an answer
//! back, so it emits an app-wide event and blocks until the dialog replies.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter};
use unissh_ffi::{
    AgentApprover, AgentSignRequest, AuthPromptRequest, AuthPrompter, BroadcastObserver,
    ExecObserver, SessionObserver, SftpProgressObserver,
};

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TermEvent {
    Data { bytes: Vec<u8> },
    Close { exit: i32 },
}

pub struct ChannelSessionObserver {
    pub chan: Channel<TermEvent>,
}
impl SessionObserver for ChannelSessionObserver {
    fn on_data(&self, data: Vec<u8>) {
        let _ = self.chan.send(TermEvent::Data { bytes: data });
    }
    fn on_close(&self, exit_status: i32) {
        let _ = self.chan.send(TermEvent::Close { exit: exit_status });
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ExecEvent {
    Stdout { bytes: Vec<u8> },
    Stderr { bytes: Vec<u8> },
    Exit { exit: i32 },
}

pub struct ChannelExecObserver {
    pub chan: Channel<ExecEvent>,
}
impl ExecObserver for ChannelExecObserver {
    fn on_stdout(&self, data: Vec<u8>) {
        let _ = self.chan.send(ExecEvent::Stdout { bytes: data });
    }
    fn on_stderr(&self, data: Vec<u8>) {
        let _ = self.chan.send(ExecEvent::Stderr { bytes: data });
    }
    fn on_exit(&self, exit_status: i32) {
        let _ = self.chan.send(ExecEvent::Exit { exit: exit_status });
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BroadcastEvent {
    Data { index: u32, bytes: Vec<u8> },
    Close { index: u32, exit: i32 },
}

pub struct ChannelBroadcastObserver {
    pub chan: Channel<BroadcastEvent>,
}
impl BroadcastObserver for ChannelBroadcastObserver {
    fn on_data(&self, host_index: u32, data: Vec<u8>) {
        let _ = self.chan.send(BroadcastEvent::Data {
            index: host_index,
            bytes: data,
        });
    }
    fn on_close(&self, host_index: u32, exit_status: i32) {
        let _ = self.chan.send(BroadcastEvent::Close {
            index: host_index,
            exit: exit_status,
        });
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub transferred: u64,
    pub total: u64,
}

pub struct ChannelSftpProgress {
    pub chan: Channel<ProgressEvent>,
}
impl SftpProgressObserver for ChannelSftpProgress {
    fn on_progress(&self, transferred: u64, total: u64) {
        let _ = self.chan.send(ProgressEvent { transferred, total });
    }
}

/// Interactive authentication: a request the core cannot answer by itself.
///
/// Unlike everything else in this file, this one is not push-only — it needs an
/// answer back. It also cannot ride a `Channel` bound to an `invoke`, because a
/// prompt can surface during a reconnect or a fleet run that no live invoke owns.
/// So it goes out as an app-wide event and comes back through the
/// `submit_auth_prompt` command, matched by `id`.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPromptEvent {
    pub id: u64,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub name: String,
    pub instruction: String,
    pub prompts: Vec<AuthPromptFieldDto>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPromptFieldDto {
    pub prompt: String,
    /// The server saying whether the answer may be shown on screen. The dialog
    /// must mask the field when this is false — it marks one-time codes and
    /// passwords.
    pub echo: bool,
}

/// Bridges the core's blocking prompt call to the frontend dialog.
pub struct AppPrompter {
    app: AppHandle,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, SyncSender<Option<Vec<String>>>>>,
}

impl AppPrompter {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            next_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Called by the `submit_auth_prompt` command. `answers: None` is Cancel.
    /// Unknown ids are ignored: a prompt that already timed out is gone, and a
    /// late answer must not resurrect it.
    pub fn answer(&self, id: u64, answers: Option<Vec<String>>) {
        let tx = self.pending.lock().expect("prompt map").remove(&id);
        if let Some(tx) = tx {
            let _ = tx.send(answers);
        }
    }
}

impl AuthPrompter for AppPrompter {
    fn prompt(&self, request: AuthPromptRequest) -> Option<Vec<String>> {
        let id = self.next_id.fetch_add(1, AtomicOrdering::Relaxed);
        // Capacity 1, not a rendezvous: `answer` runs on a Tauri command thread
        // and should hand the answer over and return, not block until the core
        // thread happens to be back at recv.
        let (tx, rx) = sync_channel(1);
        self.pending.lock().expect("prompt map").insert(id, tx);

        let event = AuthPromptEvent {
            id,
            host: request.host,
            port: request.port,
            user: request.user,
            name: request.name,
            instruction: request.instruction,
            prompts: request
                .prompts
                .into_iter()
                .map(|p| AuthPromptFieldDto {
                    prompt: p.prompt,
                    echo: p.echo,
                })
                .collect(),
        };

        if self.app.emit("auth-prompt", event).is_err() {
            // No window to ask (the app is shutting down, or the webview died).
            // Abort rather than hold the connection open against a UI that will
            // never answer.
            self.pending.lock().expect("prompt map").remove(&id);
            return None;
        }

        // Bounded so a dialog the user walks away from cannot pin a core lock
        // forever. Kept just under the core's own interactive budget so the
        // timeout that fires is this one, with the connection torn down
        // deliberately rather than by an opaque handshake deadline.
        let answers = rx.recv_timeout(Duration::from_secs(290)).ok().flatten();
        self.pending.lock().expect("prompt map").remove(&id);
        answers
    }
}

/// A forwarded agent asking whether to sign.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentApprovalEvent {
    pub id: u64,
    pub host: String,
    /// `user@service` when the payload is an SSH login; empty otherwise. This is
    /// what turns the prompt from "something wants a signature" into "this would
    /// log in as X".
    pub target: String,
}

/// Bridges the core's blocking approval call to a dialog.
///
/// Same shape as [`AppPrompter`], and for the same reason: the core is blocked
/// on a worker thread waiting for an answer that only a person can give.
pub struct AppApprover {
    app: AppHandle,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, SyncSender<bool>>>,
}

impl AppApprover {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            next_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn answer(&self, id: u64, approved: bool) {
        let tx = self.pending.lock().expect("approval map").remove(&id);
        if let Some(tx) = tx {
            let _ = tx.send(approved);
        }
    }
}

impl AgentApprover for AppApprover {
    fn approve(&self, request: AgentSignRequest) -> bool {
        let id = self.next_id.fetch_add(1, AtomicOrdering::Relaxed);
        let (tx, rx) = sync_channel(1);
        self.pending.lock().expect("approval map").insert(id, tx);

        let event = AgentApprovalEvent {
            id,
            host: request.host,
            target: request.target,
        };
        if self.app.emit("agent-approval", event).is_err() {
            self.pending.lock().expect("approval map").remove(&id);
            return false;
        }

        // Refusing on timeout, not granting. An unanswered prompt means nobody
        // was watching, and that is exactly when a signature should not happen.
        let approved = rx.recv_timeout(Duration::from_secs(60)).unwrap_or(false);
        self.pending.lock().expect("approval map").remove(&id);
        approved
    }
}
