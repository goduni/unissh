//! Native authorization broker. HTTP callers cannot grant access or approve commands.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    any::Any,
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use unissh_mcp::{
    contract::{RunCommand, ToolError, ToolRequest},
    Backend, BackendResult, IntegrationId,
};
use zeroize::Zeroizing;

#[cfg(feature = "core")]
pub mod core;

pub type Result<T> = std::result::Result<T, ToolError>;
pub type Cancel = Arc<AtomicBool>;
fn cancelled(c: &Cancel) -> bool {
    c.load(Ordering::SeqCst)
}
fn cancel(c: &Cancel) {
    c.store(true, Ordering::SeqCst);
}
fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Clone, Serialize)]
pub struct TargetInfo {
    pub vault_id: String,
    pub profile_id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub user: String,
}

#[derive(Clone)]
pub struct Target {
    pub info: TargetInfo,
    pub revision: [u64; 2],
    pub payload: Arc<dyn Any + Send + Sync>,
}

pub trait Output: Send + Sync {
    fn data(&self, stderr: bool, bytes: Vec<u8>);
    fn exited(&self, code: Option<u32>);
}
pub trait Command: Send + Sync {
    fn close(&self);
}
pub trait Connection: Send + Sync {
    fn exec(
        &self,
        command: &str,
        sink: Arc<dyn Output>,
        cancel: Cancel,
        deadline: Instant,
    ) -> Result<Arc<dyn Command>>;
    fn valid(&self) -> bool;
    fn close(&self);
}
pub trait Executor: Send + Sync + 'static {
    fn revision(&self) -> Result<[u64; 2]>;
    fn resolve(&self, vault: &str, profile: &str) -> Result<Target>;
    fn connect(
        &self,
        target: &Target,
        cancel: Cancel,
        deadline: Option<Instant>,
        attribution: &str,
    ) -> Result<Arc<dyn Connection>>;
}

struct LiveConnection {
    inner: Arc<dyn Connection>,
    _slot: OwnedSemaphorePermit,
    _owner_slot: OwnedSemaphorePermit,
}
struct Grant {
    slots: Arc<Semaphore>,
    epoch: String,
    label: String,
    revision: [u64; 2],
    until: Option<Instant>,
    targets: BTreeMap<String, Target>,
}
struct Session {
    owner: String,
    epoch: String,
    target: String,
    request_key: String,
    state: &'static str,
    error: Option<ToolError>,
    cancel: Cancel,
    connection: Option<Arc<LiveConnection>>,
    idle: Instant,
    expires_at: Option<u64>,
}
struct Chunk {
    stderr: bool,
    data: Vec<u8>,
}
struct Run {
    id: String,
    owner: String,
    epoch: String,
    target: String,
    session: Option<String>,
    key: String,
    command: Zeroizing<String>,
    timeout_ms: u32,
    state: &'static str,
    error: Option<ToolError>,
    cancel: Cancel,
    approval_until: Instant,
    finished_at: Option<Instant>,
    started_at: Option<Instant>,
    exit_code: Option<u32>,
    chunks: Vec<Chunk>,
    bytes: usize,
    truncated: bool,
}
#[derive(Default)]
struct State {
    grants: BTreeMap<String, Grant>,
    sessions: BTreeMap<String, Session>,
    runs: BTreeMap<String, Run>,
    retained_bytes: usize,
}

/// Limits are deliberately shared by persistent and one-shot paths.
const OUTPUT_PER_RUN: usize = 1024 * 1024;
const OUTPUT_TOTAL: usize = 8 * 1024 * 1024;
const PAGE_BYTES: usize = 64 * 1024;
const RECORDS_PER_GRANT: usize = 128;
const RECORDS_TOTAL: usize = 256;
const GRANTS_TOTAL: usize = 32;

pub struct Broker {
    weak: Weak<Self>,
    executor: Arc<dyn Executor>,
    state: Mutex<State>,
    slots: Arc<Semaphore>,
    admission: RwLock<()>,
    revocation_epoch: AtomicU64,
}

impl Broker {
    pub fn new(executor: Arc<dyn Executor>) -> Arc<Self> {
        let broker = Arc::new_cyclic(|weak| Self {
            weak: weak.clone(),
            executor,
            state: Mutex::new(State::default()),
            slots: Arc::new(Semaphore::new(8)),
            admission: RwLock::new(()),
            revocation_epoch: AtomicU64::new(0),
        });
        let weak = Arc::downgrade(&broker);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(100));
            let Some(broker) = weak.upgrade() else {
                break;
            };
            broker.sweep();
        });
        broker
    }

    /// A timed-out transport can leave a blocking native prompt behind. Signal
    /// its cancellation before publishing a failed session/run or releasing slots.
    fn connect(
        &self,
        target: &Target,
        stop: Cancel,
        deadline: Option<Instant>,
        attribution: &str,
    ) -> Result<Arc<dyn Connection>> {
        let result = self
            .executor
            .connect(target, stop.clone(), deadline, attribution);
        if result.is_err() {
            cancel(&stop);
        }
        result
    }

    /// Native picker revision, not an authorization credential. A later lock,
    /// revoke or target mutation invalidates an already displayed grant form.
    pub fn grant_ticket(&self) -> Result<String> {
        let generation = self.revocation_epoch.load(Ordering::SeqCst);
        let revision = self.executor.revision()?;
        serde_json::to_string(&(generation, revision)).map_err(|_| ToolError::GrantExpired)
    }

    /// Trusted native API only. Granting again replaces, rather than widens, a grant.
    pub fn grant(
        &self,
        owner: &str,
        label: String,
        targets: Vec<(String, String)>,
        seconds: impl Into<Option<u32>>,
    ) -> Result<()> {
        let ticket = self.grant_ticket()?;
        self.grant_with_ticket(owner, label, targets, seconds, &ticket)
    }

    pub fn grant_with_ticket(
        &self,
        owner: &str,
        label: String,
        targets: Vec<(String, String)>,
        seconds: impl Into<Option<u32>>,
        ticket: &str,
    ) -> Result<()> {
        let seconds = seconds.into();
        if owner.is_empty()
            || targets.is_empty()
            || targets.len() > 64
            || seconds.is_some_and(|seconds| !(1..=1800).contains(&seconds))
        {
            return Err(ToolError::TargetUnavailable);
        }
        let (generation, revision): (u64, [u64; 2]) =
            serde_json::from_str(ticket).map_err(|_| ToolError::GrantExpired)?;
        if self.revocation_epoch.load(Ordering::SeqCst) != generation
            || self.executor.revision()? != revision
        {
            return Err(ToolError::GrantExpired);
        }
        let mut resolved = BTreeMap::new();
        for (vault, profile) in targets {
            let target = self.executor.resolve(&vault, &profile)?;
            if target.revision != revision {
                return Err(ToolError::GrantExpired);
            }
            resolved.insert(id(), target);
        }
        if self.executor.revision()? != revision {
            return Err(ToolError::GrantExpired);
        }
        let _admission = self.admission.write().unwrap_or_else(|e| e.into_inner());
        if self.revocation_epoch.load(Ordering::SeqCst) != generation {
            return Err(ToolError::GrantExpired);
        }
        {
            let state = lock(&self.state);
            if state.grants.len() >= GRANTS_TOTAL && !state.grants.contains_key(owner) {
                return Err(ToolError::Busy);
            }
        }
        self.revoke_inner(Some(owner));
        lock(&self.state).grants.insert(
            owner.into(),
            Grant {
                slots: Arc::new(Semaphore::new(4)),
                epoch: id(),
                label,
                revision,
                until: seconds.map(|seconds| Instant::now() + Duration::from_secs(seconds.into())),
                targets: resolved,
            },
        );
        log::info!("MCP grant issued: integration={owner}, ttl_seconds={seconds:?}");
        Ok(())
    }

    /// Revoke admission and output first. Cleanup is dispatched without the state lock.
    pub fn revoke(&self, owner: Option<&str>) {
        let _admission = self.admission.write().unwrap_or_else(|e| e.into_inner());
        self.revocation_epoch.fetch_add(1, Ordering::SeqCst);
        self.revoke_inner(owner);
    }

    fn revoke_inner(&self, owner: Option<&str>) {
        let mut state = lock(&self.state);
        let matches = |s: &str| owner.is_none_or(|o| o == s);
        let revoked = state.grants.keys().filter(|o| matches(o)).count();
        state.grants.retain(|o, _| !matches(o));
        if revoked > 0 {
            log::info!("MCP access revoked: grant_count={revoked}");
        }
        let mut close = Vec::new();
        state.sessions.retain(|_, s| {
            if !matches(&s.owner) {
                return true;
            }
            cancel(&s.cancel);
            if let Some(c) = s.connection.take() {
                close.push(c);
            }
            false
        });
        state.runs.retain(|_, r| {
            if matches(&r.owner) {
                cancel(&r.cancel);
                false
            } else {
                true
            }
        });
        state.retained_bytes = state.runs.values().map(|r| r.bytes).sum();
        drop(state);
        for connection in close {
            std::thread::spawn(move || connection.inner.close());
        }
    }

    fn sweep(&self) {
        let revision = self.executor.revision().ok();
        let now = Instant::now();
        let expired: Vec<_> = lock(&self.state)
            .grants
            .iter()
            .filter(|(_, g)| {
                g.until.is_some_and(|until| now >= until) || Some(g.revision) != revision
            })
            .map(|(o, _)| o.clone())
            .collect();
        for owner in expired {
            self.revoke(Some(&owner));
        }
        // Never call Core while holding the broker state: exec callbacks acquire
        // this mutex while Core serializes dispatch with vault mutation.
        let connections: Vec<_> = lock(&self.state)
            .sessions
            .iter()
            .filter_map(|(id, s)| s.connection.clone().map(|c| (id.clone(), c)))
            .collect();
        let invalid: Vec<_> = connections
            .into_iter()
            .filter(|(_, c)| !c.inner.valid())
            .collect();
        let mut state = lock(&self.state);
        for run in state.runs.values_mut() {
            if run.state == "awaiting_approval" && now >= run.approval_until {
                finish(run, "denied", Some(ToolError::ApprovalExpired));
            }
            if run
                .finished_at
                .is_some_and(|t| now.duration_since(t) >= Duration::from_secs(600))
                && !run.chunks.is_empty()
            {
                run.chunks.clear();
                run.bytes = 0;
                run.error = Some(ToolError::OutputExpired);
            }
        }
        let active: Vec<_> = state
            .runs
            .values()
            .filter(|r| r.finished_at.is_none())
            .filter_map(|r| r.session.clone())
            .collect();
        let mut close = Vec::new();
        for (sid, session) in &mut state.sessions {
            if session.state == "ready"
                && !active.contains(sid)
                && now.duration_since(session.idle) >= Duration::from_secs(300)
            {
                cancel(&session.cancel);
                session.state = "closed";
                if let Some(c) = session.connection.take() {
                    close.push(c);
                }
            }
            if invalid.iter().any(|(id, c)| {
                id == sid
                    && session
                        .connection
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, c))
            }) {
                cancel(&session.cancel);
                session.state = "closed";
                session.error = Some(ToolError::ConnectionLost);
                if let Some(c) = session.connection.take() {
                    close.push(c);
                }
            }
        }
        state.retained_bytes = state.runs.values().map(|r| r.bytes).sum();
        drop(state);
        for connection in close {
            std::thread::spawn(move || connection.inner.close());
        }
    }

    fn request(self: &Arc<Self>, owner: String, request: ToolRequest) -> Result<Value> {
        self.sweep();
        // Authentication alone never unlocks Core or creates a grant.
        let revision = self.executor.revision()?;
        let _admission = if matches!(
            &request,
            ToolRequest::CloseSession(_) | ToolRequest::CancelCommand(_)
        ) {
            Some(self.admission.write().unwrap_or_else(|e| e.into_inner()))
        } else {
            None
        };
        let mut state = lock(&self.state);
        let grant = state.grants.get(&owner).ok_or(ToolError::GrantRequired)?;
        if grant.revision != revision || grant.until.is_some_and(|until| Instant::now() >= until) {
            return Err(ToolError::GrantExpired);
        }
        let epoch = grant.epoch.clone();
        match request {
            ToolRequest::ListTargets(r) => {
                if r.cursor.is_some() {
                    return Err(ToolError::TargetUnavailable);
                }
                Ok(
                    json!({"targets":grant.targets.iter().map(|(id,t)| json!({"target_id":id,"alias":t.info.label,"available":true})).collect::<Vec<_>>()}),
                )
            }
            ToolRequest::ListSessions(r) => {
                if r.cursor.is_some() {
                    return Err(ToolError::SessionClosed);
                }
                Ok(
                    json!({"sessions":state.sessions.iter().filter(|(_,s)|s.owner==owner).map(|(id,s)|session_json(id,s)).collect::<Vec<_>>()}),
                )
            }
            ToolRequest::OpenSession(r) => {
                if let Some((sid, s)) = state.sessions.iter().find(|(_, s)| {
                    s.owner == owner && s.epoch == epoch && s.request_key == r.request_key
                }) {
                    return if s.target == r.target_id {
                        Ok(session_json(sid, s))
                    } else {
                        Err(ToolError::RequestConflict)
                    };
                }
                if state.sessions.values().filter(|s| s.owner == owner).count() >= 32 {
                    return Err(ToolError::Busy);
                }
                if state
                    .sessions
                    .values()
                    .filter(|s| s.owner == owner && matches!(s.state, "connecting" | "ready"))
                    .count()
                    >= 4
                {
                    return Err(ToolError::Busy);
                }
                let target = grant
                    .targets
                    .get(&r.target_id)
                    .cloned()
                    .ok_or(ToolError::TargetUnavailable)?;
                let deadline = grant.until;
                let attribution = grant.label.clone();
                let owner_slot = grant
                    .slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| ToolError::Busy)?;
                let permit = self
                    .slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| ToolError::Busy)?;
                let sid = id();
                let stop = Arc::new(AtomicBool::new(false));
                state.sessions.insert(
                    sid.clone(),
                    Session {
                        owner: owner.clone(),
                        epoch,
                        target: r.target_id,
                        request_key: r.request_key,
                        state: "connecting",
                        error: None,
                        cancel: stop.clone(),
                        connection: None,
                        idle: Instant::now(),
                        expires_at: deadline.map(|deadline| {
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                                + deadline.saturating_duration_since(Instant::now()).as_secs()
                        }),
                    },
                );
                let result = session_json(&sid, &state.sessions[&sid]);
                let broker = self.clone();
                std::thread::spawn(move || {
                    let connection = broker.connect(&target, stop.clone(), deadline, &attribution);
                    let mut state = lock(&broker.state);
                    if let Some(s) = state
                        .sessions
                        .get_mut(&sid)
                        .filter(|s| s.state == "connecting")
                    {
                        match connection {
                            Ok(c) if !cancelled(&s.cancel) => {
                                s.connection = Some(Arc::new(LiveConnection {
                                    inner: c,
                                    _slot: permit,
                                    _owner_slot: owner_slot,
                                }));
                                s.state = "ready";
                                s.idle = Instant::now();
                            }
                            Ok(c) => {
                                s.state = "closed";
                                s.error = Some(ToolError::GrantExpired);
                                drop(state);
                                c.close();
                            }
                            Err(e) => {
                                s.state = "closed";
                                s.error = Some(e);
                            }
                        }
                    } else if let Ok(c) = connection {
                        drop(state);
                        c.close();
                    }
                });
                Ok(result)
            }
            ToolRequest::CloseSession(r) => {
                let session = state
                    .sessions
                    .get_mut(&r.session_id)
                    .filter(|s| s.owner == owner)
                    .ok_or(ToolError::SessionClosed)?;
                cancel(&session.cancel);
                session.state = "closed";
                let connection = session.connection.take();
                let result = session_json(&r.session_id, session);
                // Use the requested ID, not a run's own identifier.
                for run in state
                    .runs
                    .values_mut()
                    .filter(|run| run.owner == owner && run.session.as_ref() == Some(&r.session_id))
                {
                    cancel(&run.cancel);
                    if run.state == "awaiting_approval" {
                        finish(run, "cancelled", None);
                    }
                }
                drop(state);
                if let Some(c) = connection {
                    std::thread::spawn(move || c.inner.close());
                }
                Ok(result)
            }
            ToolRequest::RunCommand(r) => {
                let (session, target_id, command, key, timeout_ms) = match r {
                    RunCommand::Existing(r) => {
                        let s = state
                            .sessions
                            .get(&r.session_id)
                            .filter(|s| s.owner == owner)
                            .ok_or(ToolError::SessionClosed)?;
                        (
                            Some(r.session_id),
                            s.target.clone(),
                            r.command,
                            r.request_key,
                            r.timeout_ms.unwrap_or(120_000),
                        )
                    }
                    RunCommand::OneShot(r) => (
                        None,
                        r.target_id,
                        r.command,
                        r.request_key,
                        r.timeout_ms.unwrap_or(120_000),
                    ),
                };
                if let Some((rid, r)) = state
                    .runs
                    .iter()
                    .find(|(_, r)| r.owner == owner && r.epoch == epoch && r.key == key)
                {
                    return if r.session == session
                        && r.target == target_id
                        && *r.command == command
                        && r.timeout_ms == timeout_ms
                    {
                        Ok(run_json(rid, r))
                    } else {
                        Err(ToolError::RequestConflict)
                    };
                }
                if state.runs.len() >= RECORDS_TOTAL
                    || state.runs.values().filter(|r| r.owner == owner).count() >= RECORDS_PER_GRANT
                {
                    return Err(ToolError::Busy);
                }
                if !grant.targets.contains_key(&target_id) {
                    return Err(ToolError::TargetUnavailable);
                }
                if let Some(sid) = &session {
                    if state.sessions[sid].state != "ready" {
                        return Err(ToolError::SessionNotReady);
                    }
                    if state
                        .runs
                        .values()
                        .any(|r| r.session.as_ref() == Some(sid) && r.finished_at.is_none())
                    {
                        return Err(ToolError::Busy);
                    }
                }
                if state
                    .runs
                    .values()
                    .filter(|r| r.owner == owner && r.finished_at.is_none())
                    .count()
                    >= 8
                {
                    return Err(ToolError::Busy);
                }
                let rid = id();
                state.runs.insert(
                    rid.clone(),
                    Run {
                        id: rid.clone(),
                        owner,
                        epoch,
                        target: target_id,
                        session,
                        key,
                        command: Zeroizing::new(command),
                        timeout_ms,
                        state: "awaiting_approval",
                        error: None,
                        cancel: Arc::new(AtomicBool::new(false)),
                        approval_until: Instant::now() + Duration::from_secs(120),
                        finished_at: None,
                        started_at: None,
                        exit_code: None,
                        chunks: Vec::new(),
                        bytes: 0,
                        truncated: false,
                    },
                );
                Ok(run_json(&rid, &state.runs[&rid]))
            }
            ToolRequest::GetCommand(r) => {
                let run = state
                    .runs
                    .get(&r.run_id)
                    .filter(|r| r.owner == owner)
                    .ok_or(ToolError::OutcomeUnknown)?;
                if run.error == Some(ToolError::OutputExpired) {
                    return Err(ToolError::OutputExpired);
                }
                let cursor = r
                    .output_cursor
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<usize>()
                    .map_err(|_| ToolError::OutputExpired)?;
                if cursor > run.chunks.len() {
                    return Err(ToolError::OutputExpired);
                }
                let mut bytes = 0;
                let mut next = cursor;
                let mut chunks = Vec::new();
                for chunk in run.chunks.iter().skip(cursor) {
                    if bytes + chunk.data.len() > PAGE_BYTES {
                        break;
                    }
                    chunks.push(json!({"cursor":next.to_string(),"stream":if chunk.stderr {"stderr"} else {"stdout"},"encoding":"base64","data":STANDARD.encode(&chunk.data)}));
                    bytes += chunk.data.len();
                    next += 1;
                }
                let mut result = run_json(&r.run_id, run);
                result["chunks"] = json!(chunks);
                result["next_cursor"] = json!(next.to_string());
                result["truncated"] = json!(run.truncated);
                result["exit_code"] = json!(run.exit_code);
                Ok(result)
            }
            ToolRequest::CancelCommand(r) => {
                let run = state
                    .runs
                    .get_mut(&r.run_id)
                    .filter(|r| r.owner == owner)
                    .ok_or(ToolError::OutcomeUnknown)?;
                if run.finished_at.is_none() {
                    cancel(&run.cancel);
                    if run.state == "awaiting_approval" {
                        finish(run, "cancelled", None);
                    } else {
                        run.state = "cancelling";
                    }
                }
                Ok(run_json(&r.run_id, run))
            }
        }
    }

    /// Native UI sees exact immutable command and resolved destination; MCP never approves.
    pub fn close_session(self: &Arc<Self>, id: &str) -> Result<Value> {
        let owner = lock(&self.state)
            .sessions
            .get(id)
            .map(|s| s.owner.clone())
            .ok_or(ToolError::SessionClosed)?;
        self.request(
            owner,
            ToolRequest::CloseSession(unissh_mcp::contract::CloseSession {
                session_id: id.into(),
            }),
        )
    }

    pub fn cancel_command(self: &Arc<Self>, id: &str) -> Result<Value> {
        let owner = lock(&self.state)
            .runs
            .get(id)
            .map(|r| r.owner.clone())
            .ok_or(ToolError::OutcomeUnknown)?;
        self.request(
            owner,
            ToolRequest::CancelCommand(unissh_mcp::contract::CancelCommand { run_id: id.into() }),
        )
    }

    pub fn review(&self) -> Value {
        self.sweep();
        let state = lock(&self.state);
        json!({
            "grants":state.grants.iter().map(|(owner,g)|json!({"integration_id":owner,"label":g.label,"remaining_seconds":g.until.map(|until| until.saturating_duration_since(Instant::now()).as_secs()),"targets":g.targets.values().map(|t|&t.info).collect::<Vec<_>>()})).collect::<Vec<_>>(),
            "sessions":state.sessions.iter().map(|(id,s)|{let mut v=session_json(id,s);v["integration_id"]=json!(s.owner);v["target"]=state.grants.get(&s.owner).and_then(|g|g.targets.get(&s.target)).map(|t|json!(&t.info)).unwrap_or(Value::Null);v["idle_seconds"]=json!(Duration::from_secs(300).saturating_sub(s.idle.elapsed()).as_secs());v}).collect::<Vec<_>>(),
            "runs":state.runs.iter().map(|(id,r)|{
                let mut v=run_json(id,r);v["integration_id"]=json!(r.owner);
                v["target"]=state.grants.get(&r.owner).and_then(|g|g.targets.get(&r.target)).map(|t|json!(&t.info)).unwrap_or(Value::Null);
                if r.state=="awaiting_approval" {
                    v["command"]=json!(&*r.command);v["timeout_ms"]=json!(r.timeout_ms);v["approval_remaining_seconds"]=json!(r.approval_until.saturating_duration_since(Instant::now()).as_secs());
                    v["target"]=state.grants.get(&r.owner).and_then(|g|g.targets.get(&r.target)).map(|t|json!(&t.info)).unwrap_or(Value::Null);
                } v
            }).collect::<Vec<_>>()
        })
    }

    pub fn approve(self: &Arc<Self>, run_id: &str, allowed: bool) -> Result<()> {
        self.sweep();
        let mut state = lock(&self.state);
        let run = state.runs.get(run_id).ok_or(ToolError::ApprovalExpired)?;
        if run.state != "awaiting_approval"
            || cancelled(&run.cancel)
            || Instant::now() >= run.approval_until
        {
            return Err(ToolError::ApprovalExpired);
        }
        if !allowed {
            finish(
                state.runs.get_mut(run_id).unwrap(),
                "denied",
                Some(ToolError::ApprovalDenied),
            );
            return Ok(());
        }
        let grant = state
            .grants
            .get(&run.owner)
            .filter(|g| g.epoch == run.epoch && g.until.is_none_or(|until| Instant::now() < until))
            .ok_or(ToolError::GrantExpired)?;
        let target = grant
            .targets
            .get(&run.target)
            .cloned()
            .ok_or(ToolError::TargetUnavailable)?;
        let runtime_deadline = Instant::now() + Duration::from_millis(run.timeout_ms.into());
        let deadline = grant
            .until
            .map_or(runtime_deadline, |until| until.min(runtime_deadline));
        let attribution = grant.label.clone();
        let (connection, slot) = if let Some(sid) = &run.session {
            let s = state
                .sessions
                .get(sid)
                .filter(|s| s.state == "ready" && !cancelled(&s.cancel))
                .ok_or(ToolError::SessionClosed)?;
            (
                Some(s.connection.clone().ok_or(ToolError::SessionNotReady)?),
                None,
            )
        } else {
            (
                None,
                Some((
                    self.slots
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| ToolError::Busy)?,
                    grant
                        .slots
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| ToolError::Busy)?,
                )),
            )
        };
        log::info!(
            "MCP approval accepted: integration_id={}, target_id={}, run_id={run_id}",
            run.owner,
            run.target
        );
        let stop = run.cancel.clone();
        let command = run.command.clone();
        let rid = run_id.to_string();
        let run = state.runs.get_mut(run_id).unwrap();
        run.state = if connection.is_none() {
            "connecting"
        } else {
            "running"
        };
        run.started_at = Some(Instant::now());
        let broker = self.clone();
        std::thread::spawn(move || {
            let implicit = connection.is_none();
            let connection = match connection {
                Some(c) => Ok(c),
                None => broker
                    .connect(&target, stop.clone(), Some(deadline), &attribution)
                    .map(|c| {
                        let (slot, owner_slot) = slot.expect("implicit slots");
                        Arc::new(LiveConnection {
                            inner: c,
                            _slot: slot,
                            _owner_slot: owner_slot,
                        })
                    }),
            };
            let result = (|| -> Result<()> {
                let c = connection.as_ref().map_err(|e| *e)?;
                // Revocation's cancel flag precedes cleanup. Core adds a final gate
                // under its state lock, including target revision and connection lease.
                if cancelled(&stop) || Instant::now() >= deadline {
                    return Err(ToolError::GrantExpired);
                }
                let admission = broker.admission.read().unwrap_or_else(|e| e.into_inner());
                if cancelled(&stop) || Instant::now() >= deadline {
                    return Err(ToolError::GrantExpired);
                }
                if let Some(run) = lock(&broker.state).runs.get_mut(&rid) {
                    run.state = "running";
                }
                let handle = c.inner.exec(
                    &command,
                    Arc::new(RunSink {
                        broker: Arc::downgrade(&broker),
                        run: rid.clone(),
                    }),
                    stop.clone(),
                    deadline,
                )?;
                drop(admission);
                loop {
                    if cancelled(&stop) || Instant::now() >= deadline || !c.inner.valid() {
                        handle.close();
                        return Err(ToolError::OutcomeUnknown);
                    }
                    if lock(&broker.state)
                        .runs
                        .get(&rid)
                        .is_none_or(|r| r.finished_at.is_some())
                    {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(())
            })();
            if implicit {
                if let Ok(c) = &connection {
                    c.inner.close();
                }
            }
            let mut state = lock(&broker.state);
            if let Some(run) = state.runs.get_mut(&rid) {
                if run.finished_at.is_none() {
                    finish(
                        run,
                        if cancelled(&stop) && (connection.is_ok() || run.state == "cancelling") {
                            "cancelled"
                        } else {
                            "failed"
                        },
                        result.err().or(Some(ToolError::OutcomeUnknown)),
                    );
                }
                if let Some(sid) = run.session.clone() {
                    if let Some(s) = state.sessions.get_mut(&sid) {
                        s.idle = Instant::now();
                    }
                }
            }
        });
        Ok(())
    }
}

impl Backend for Broker {
    fn call(&self, integration: IntegrationId, request: ToolRequest) -> BackendResult<'_> {
        let broker = self.weak.upgrade();
        Box::pin(async move {
            let broker = broker.ok_or(ToolError::GrantExpired)?;
            let poll = match &request {
                ToolRequest::GetCommand(r) => Some(r.clone()),
                _ => None,
            };
            let call_broker = broker.clone();
            let owner = integration.0;
            let call_owner = owner.clone();
            let first =
                tokio::task::spawn_blocking(move || call_broker.request(call_owner, request))
                    .await
                    .map_err(|_| ToolError::OutcomeUnknown)??;
            let Some(poll) = poll.filter(|r| r.wait_ms.unwrap_or(0) > 0) else {
                return Ok(first);
            };
            if first["chunks"].as_array().is_some_and(|c| !c.is_empty())
                || matches!(
                    first["state"].as_str(),
                    Some("completed" | "failed" | "cancelled" | "denied")
                )
            {
                return Ok(first);
            }
            let until = tokio::time::Instant::now()
                + Duration::from_millis(poll.wait_ms.unwrap_or(0).into());
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let b = broker.clone();
                let o = owner.clone();
                let p = poll.clone();
                let result =
                    tokio::task::spawn_blocking(move || b.request(o, ToolRequest::GetCommand(p)))
                        .await
                        .map_err(|_| ToolError::OutcomeUnknown)??;
                if result != first || tokio::time::Instant::now() >= until {
                    return Ok(result);
                }
            }
        })
    }
}

fn finish(run: &mut Run, state: &'static str, error: Option<ToolError>) {
    log::info!(
        "MCP run finished: run_id={}, outcome={}, retained_bytes={}, truncated={}",
        run.id,
        state,
        run.bytes,
        run.truncated
    );
    run.state = state;
    run.error = error;
    run.finished_at = Some(Instant::now());
}
fn session_json(id: &str, s: &Session) -> Value {
    json!({"session_id":id,"target_id":s.target,"state":s.state,"error":s.error,"expires_at":s.expires_at})
}
fn run_json(id: &str, r: &Run) -> Value {
    json!({"run_id":id,"session_id":r.session,"target_id":r.target,"state":r.state,"error":r.error})
}

struct RunSink {
    broker: Weak<Broker>,
    run: String,
}
impl Output for RunSink {
    fn data(&self, stderr: bool, bytes: Vec<u8>) {
        let Some(b) = self.broker.upgrade() else {
            return;
        };
        let mut state = lock(&b.state);
        if !state.runs.get(&self.run).is_some_and(|r| {
            state.grants.get(&r.owner).is_some_and(|g| {
                g.epoch == r.epoch && g.until.is_none_or(|until| Instant::now() < until)
            })
        }) {
            return;
        }
        let remaining = OUTPUT_TOTAL.saturating_sub(state.retained_bytes);
        let Some(run) = state
            .runs
            .get_mut(&self.run)
            .filter(|r| !cancelled(&r.cancel) && r.finished_at.is_none())
        else {
            return;
        };
        let kept = bytes
            .len()
            .min(remaining)
            .min(OUTPUT_PER_RUN.saturating_sub(run.bytes));
        let mut saved = 0;
        for chunk in bytes[..kept].chunks(16 * 1024) {
            if run.chunks.len() >= 4096 {
                break;
            }
            run.chunks.push(Chunk {
                stderr,
                data: chunk.to_vec(),
            });
            saved += chunk.len();
        }
        run.bytes += saved;
        run.truncated |= saved < bytes.len();
        state.retained_bytes += saved;
    }
    fn exited(&self, code: Option<u32>) {
        let Some(b) = self.broker.upgrade() else {
            return;
        };
        let mut state = lock(&b.state);
        if let Some(r) = state
            .runs
            .get_mut(&self.run)
            .filter(|r| !cancelled(&r.cancel) && r.finished_at.is_none())
        {
            r.exit_code = code;
            finish(
                r,
                if code.is_some() {
                    "completed"
                } else {
                    "failed"
                },
                if code.is_some() {
                    None
                } else {
                    Some(ToolError::OutcomeUnknown)
                },
            );
        }
    }
}

#[cfg(test)]
mod deadlines {
    use super::*;
    struct ExecutorFixture;
    impl Executor for ExecutorFixture {
        fn revision(&self) -> Result<[u64; 2]> {
            Ok([1, 0])
        }
        fn resolve(&self, v: &str, p: &str) -> Result<Target> {
            Ok(Target {
                info: TargetInfo {
                    vault_id: v.into(),
                    profile_id: p.into(),
                    label: "fixture".into(),
                    host: "localhost".into(),
                    port: 22,
                    user: "fixture".into(),
                },
                revision: [1, 0],
                payload: Arc::new(()),
            })
        }
        fn connect(
            &self,
            _: &Target,
            _: Cancel,
            _: Option<Instant>,
            _: &str,
        ) -> Result<Arc<dyn Connection>> {
            Err(ToolError::TargetUnavailable)
        }
    }
    fn pending() -> (Arc<Broker>, String) {
        let b = Broker::new(Arc::new(ExecutorFixture));
        b.grant("a", "a".into(), vec![("v".into(), "p".into())], 30)
            .unwrap();
        let target = lock(&b.state).grants["a"]
            .targets
            .keys()
            .next()
            .unwrap()
            .clone();
        let request = unissh_mcp::contract::parse(
            "run_command",
            json!({"session_id":null,"target_id":target,"command":"true","request_key":"k"})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
        let run = b.request("a".into(), request).unwrap()["run_id"]
            .as_str()
            .unwrap()
            .to_string();
        (b, run)
    }
    #[test]
    fn native_approval_deadline_cannot_be_extended_by_polling() {
        let (b, rid) = pending();
        lock(&b.state).runs.get_mut(&rid).unwrap().approval_until =
            Instant::now() - Duration::from_secs(1);
        assert_eq!(b.approve(&rid, true), Err(ToolError::ApprovalExpired));
        assert_eq!(b.review()["runs"][0]["state"], "denied");
    }
    #[test]
    fn output_expiry_is_explicit_and_late_callbacks_cannot_repopulate_it() {
        let (b, rid) = pending();
        let sink = RunSink {
            broker: Arc::downgrade(&b),
            run: rid.clone(),
        };
        sink.data(false, vec![1, 2, 3]);
        {
            let mut state = lock(&b.state);
            let run = state.runs.get_mut(&rid).unwrap();
            finish(run, "completed", None);
            run.finished_at = Some(Instant::now() - Duration::from_secs(601));
        }
        b.sweep();
        sink.data(false, vec![4, 5, 6]);
        let request = ToolRequest::GetCommand(unissh_mcp::contract::GetCommand {
            run_id: rid,
            output_cursor: None,
            wait_ms: None,
        });
        assert_eq!(
            b.request("a".into(), request),
            Err(ToolError::OutputExpired)
        );
        assert_eq!(lock(&b.state).retained_bytes, 0);
    }
    #[test]
    fn expired_lease_drops_output_before_housekeeping_runs() {
        let (b, rid) = pending();
        lock(&b.state).grants.get_mut("a").unwrap().until =
            Some(Instant::now() - Duration::from_secs(1));
        RunSink {
            broker: Arc::downgrade(&b),
            run: rid.clone(),
        }
        .data(false, vec![1, 2, 3]);
        assert_eq!(lock(&b.state).retained_bytes, 0);
        assert_eq!(b.approve(&rid, true), Err(ToolError::ApprovalExpired));
        assert!(b.review()["grants"].as_array().unwrap().is_empty());
    }
}
