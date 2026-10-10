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
#[cfg(desktop)]
use tauri::{Manager, UserAttentionType};
use unissh_ffi::{
    AgentApprover, AgentSignOrigin, AgentSignRequest, AuthPromptRequest, AuthPrompter,
    BroadcastObserver, ExecObserver, SessionObserver, SftpProgressObserver,
};

/// Push one event into the channel of the originating `invoke`. A failed send
/// means the webview side is gone (window closed, page reloaded); the core
/// session ends through its own close path, so the event is simply dropped.
fn push<T: tauri::ipc::IpcResponse>(chan: &Channel<T>, event: T) {
    if let Err(e) = chan.send(event) {
        log::trace!("observer: event dropped, the webview channel is gone: {e}");
    }
}

/// Lock a prompt/approval map from a core callback, which cannot return an
/// error. The maps hold only reply senders keyed by id; a poisoned one is still
/// a valid map, and every prompt it holds ends by answer, cancel or timeout.
fn lock_map<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Tell the window about a prompt that ended without an answer. If the event
/// cannot be delivered the window is gone, and so is the dialog it would close.
fn emit_cancelled(app: &AppHandle, event: &str, id: u64) {
    if let Err(e) = app.emit(event, id) {
        log::debug!("observer: {event} for prompt {id} not delivered: {e}");
    }
}

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
        push(&self.chan, TermEvent::Data { bytes: data });
    }
    fn on_close(&self, exit_status: i32) {
        push(&self.chan, TermEvent::Close { exit: exit_status });
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
        push(&self.chan, ExecEvent::Stdout { bytes: data });
    }
    fn on_stderr(&self, data: Vec<u8>) {
        push(&self.chan, ExecEvent::Stderr { bytes: data });
    }
    fn on_exit(&self, exit_status: i32) {
        push(&self.chan, ExecEvent::Exit { exit: exit_status });
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
        push(
            &self.chan,
            BroadcastEvent::Data {
                index: host_index,
                bytes: data,
            },
        );
    }
    fn on_close(&self, host_index: u32, exit_status: i32) {
        push(
            &self.chan,
            BroadcastEvent::Close {
                index: host_index,
                exit: exit_status,
            },
        );
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
    last: Mutex<Option<std::time::Instant>>,
}
impl ChannelSftpProgress {
    pub const fn new(chan: Channel<ProgressEvent>) -> Self {
        Self {
            chan,
            last: Mutex::new(None),
        }
    }
}
impl SftpProgressObserver for ChannelSftpProgress {
    fn on_progress(&self, transferred: u64, total: u64) {
        {
            // A throttle timestamp only; a poisoned lock just resets the throttle.
            let mut last = self
                .last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if transferred != total
                && last.is_some_and(|t| t.elapsed() < Duration::from_millis(100))
            {
                return;
            }
            *last = Some(std::time::Instant::now());
        }
        push(&self.chan, ProgressEvent { transferred, total });
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
        let tx = lock_map(&self.pending).remove(&id);
        // The payload holds the user's answers: never log it, only the fact.
        if tx.is_some_and(|tx| tx.send(answers).is_err()) {
            log::debug!("auth prompt {id}: answered after the waiter gave up");
        }
    }
}

impl AppPrompter {
    pub fn prompt_until(
        &self,
        request: AuthPromptRequest,
        cancelled: impl Fn() -> bool,
        deadline: std::time::Instant,
    ) -> Option<Vec<String>> {
        let id = self.next_id.fetch_add(1, AtomicOrdering::Relaxed);
        // Capacity 1, not a rendezvous: `answer` runs on a Tauri command thread
        // and should hand the answer over and return, not block until the core
        // thread happens to be back at recv.
        let (tx, rx) = sync_channel(1);
        lock_map(&self.pending).insert(id, tx);

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
            lock_map(&self.pending).remove(&id);
            return None;
        }

        // Bounded so a dialog the user walks away from cannot pin a core lock
        // forever. Kept just under the core's own interactive budget so the
        // timeout that fires is this one, with the connection torn down
        // deliberately rather than by an opaque handshake deadline.
        let mut answered = false;
        let answers = loop {
            if cancelled() || std::time::Instant::now() >= deadline {
                break None;
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(answer) => {
                    answered = true;
                    break answer;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => break None,
            }
        };
        lock_map(&self.pending).remove(&id);
        if !answered {
            emit_cancelled(&self.app, "auth-prompt-cancelled", id);
        }
        answers
    }
}

impl AuthPrompter for AppPrompter {
    fn prompt(&self, request: AuthPromptRequest) -> Option<Vec<String>> {
        self.prompt_until(
            request,
            || false,
            std::time::Instant::now() + Duration::from_secs(290),
        )
    }
}

/// A forwarded agent, or the system agent, asking whether to sign.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentApprovalEvent {
    pub id: u64,
    /// `"forwarded"` or `"system"`.
    pub origin: &'static str,
    /// Forwarded: the session's host. Empty for the system agent.
    pub host: String,
    /// System agent: the key asked for and its vault. Empty for a forwarded
    /// agent.
    pub key: String,
    pub vault: String,
    /// System agent: the calling process, as the OS reported it. Advisory.
    pub pid: Option<u32>,
    pub executable: Option<String>,
    /// The user an SSH login payload would log in as; empty otherwise. The
    /// payload never names the server.
    pub user: String,
    /// `user@service` when the payload is an SSH login; empty otherwise. This is
    /// what turns the prompt from "something wants a signature" into "this would
    /// log in as X".
    pub target: String,
}

/// One prompt waiting for a person.
struct PendingApproval {
    answer: SyncSender<bool>,
    /// From the system agent, so withdrawn when its listener stops.
    system: bool,
}

/// Bridges the core's blocking approval call to a dialog.
///
/// Same shape as [`AppPrompter`], and for the same reason: the core is blocked
/// on a worker thread waiting for an answer that only a person can give. Every
/// way a prompt ends without an answer — timeout, a client that hung up, the
/// system agent stopping — refuses and tells the window to drop it
/// (`agent-approval-cancelled`, carrying the id, like `auth-prompt-cancelled`).
pub struct AppApprover {
    app: AppHandle,
    /// One lock for both, so a `cancel` never slips between the early-cancel
    /// check and the registration of the same id.
    state: Mutex<ApprovalState>,
}

#[derive(Default)]
struct ApprovalState {
    pending: HashMap<u64, PendingApproval>,
    /// Cancellations that arrived before their `approve` registered the id.
    cancelled_early: std::collections::HashSet<u64>,
}

impl AppApprover {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            state: Mutex::new(ApprovalState::default()),
        }
    }

    pub fn answer(&self, id: u64, approved: bool) {
        let pending = lock_map(&self.state).pending.remove(&id);
        if pending.is_some_and(|p| p.answer.send(approved).is_err()) {
            log::debug!("agent approval {id}: answered after the waiter gave up");
        }
    }

    /// Refuses `id` if it is still waiting, and tells the window to drop it.
    /// Returns whether it was waiting.
    fn withdraw(&self, id: u64) -> bool {
        let pending = lock_map(&self.state).pending.remove(&id);
        self.refuse(id, pending)
    }

    /// Refuses a prompt already taken out of the map, if there was one.
    fn refuse(&self, id: u64, pending: Option<PendingApproval>) -> bool {
        let Some(pending) = pending else {
            return false;
        };
        // The waiter may already have timed out; refusing is then a no-op.
        if pending.answer.send(false).is_err() {
            log::debug!("agent approval {id}: refused after the waiter gave up");
        }
        emit_cancelled(&self.app, "agent-approval-cancelled", id);
        true
    }

    /// Withdraws every system-agent prompt: its listener stopped (vault or
    /// screen lock, sleep, exit), so no answer could reach the caller anyway.
    pub fn cancel_system(&self) {
        let ids: Vec<u64> = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .iter()
            .filter(|(_, p)| p.system)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.withdraw(id);
        }
    }
}

impl AgentApprover for AppApprover {
    fn approve(&self, request: AgentSignRequest) -> bool {
        let id = request.id;
        let (origin, pid, executable) = match request.origin {
            AgentSignOrigin::Forwarded => ("forwarded", None, None),
            AgentSignOrigin::SystemAgent { pid, executable } => ("system", pid, executable),
        };
        let system = origin == "system";
        let (tx, rx) = sync_channel(1);
        {
            let mut state = lock_map(&self.state);
            if state.cancelled_early.remove(&id) {
                return false;
            }
            state
                .pending
                .insert(id, PendingApproval { answer: tx, system });
        }

        let event = AgentApprovalEvent {
            id,
            origin,
            host: request.host,
            key: request.key,
            vault: request.vault,
            pid,
            executable,
            user: request.user,
            target: request.target,
        };
        if self.app.emit("agent-approval", event).is_err() {
            lock_map(&self.state).pending.remove(&id);
            return false;
        }
        // The system agent's caller types in another terminal, so UniSSH may
        // sit behind other windows. Flag the waiting prompt (dock bounce,
        // taskbar flash) without taking focus: a keystroke meant for that
        // terminal must never land on Approve.
        #[cfg(desktop)]
        if system {
            if let Some(window) = self.app.get_webview_window("main") {
                // Cosmetic: the dialog is already up in the window either way.
                if let Err(e) =
                    window.request_user_attention(Some(UserAttentionType::Informational))
                {
                    log::debug!("agent approval {id}: attention request failed: {e}");
                }
            }
        }

        // Refusing on timeout, not granting. An unanswered prompt means nobody
        // was watching, and that is exactly when a signature should not happen.
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(approved) => approved,
            Err(_) => {
                self.withdraw(id);
                false
            }
        }
    }

    fn cancel(&self, id: u64) {
        let pending = {
            let mut state = lock_map(&self.state);
            let pending = state.pending.remove(&id);
            if pending.is_none() {
                // Not registered yet (or already over). Remember it so a late
                // `approve` refuses without showing anything; an id that is
                // over never comes back, so this only holds the rare early ones.
                if state.cancelled_early.len() >= 64 {
                    // Only ever ids that lost a race; never let them pile up.
                    state.cancelled_early.clear();
                }
                state.cancelled_early.insert(id);
            }
            pending
        };
        self.refuse(id, pending);
    }
}
