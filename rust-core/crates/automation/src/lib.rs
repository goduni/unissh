//! Native authorization broker. HTTP callers cannot grant access or approve commands.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
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

mod access;
#[cfg(feature = "core")]
pub mod core;
mod output;
pub use access::SavedAccess;
mod working_directory;

/// Result of a broker operation; errors are the fixed MCP wire errors.
pub type Result<T> = std::result::Result<T, ToolError>;
/// Shared cancellation flag: set once, observed by every party of a session or run.
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
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
/// What indexing a missing key of a JSON value yields, without the panicking `Index`.
static NULL: Value = Value::Null;
/// Reads `key` of a JSON object, or `null` when the key or the object is absent.
fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&NULL)
}
/// Sets `key` on a JSON object; the broker only calls it on objects it built itself.
fn set_field(value: &mut Value, key: &str, field: Value) {
    if let Value::Object(fields) = value {
        fields.insert(key.to_owned(), field);
    }
}
/// Milliseconds of `elapsed` for JSON, saturating instead of truncating.
fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}
/// The snake_case wire code of an error (`ToolError` serializes to a plain string).
fn error_code(error: ToolError) -> String {
    serde_json::to_value(error)
        .ok()
        .and_then(|code| code.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Display and audit description of a granted target; never contains credentials.
#[derive(Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    /// Vault holding the host profile.
    pub vault_id: String,
    /// Host profile id inside the vault.
    pub profile_id: String,
    /// Vault display name.
    pub vault: String,
    /// Group names the profile belongs to.
    pub groups: Vec<String>,
    /// Profile tags.
    pub tags: Vec<String>,
    /// Profile display label.
    pub label: String,
    /// Destination host name or address.
    pub host: String,
    /// Destination SSH port.
    pub port: u16,
    /// Remote user name.
    pub user: String,
}

/// A resolved target: its description, the vault revision it was resolved at, and
/// the executor's opaque connection payload.
#[derive(Clone)]
pub struct Target {
    /// What the native UI and the audit log show.
    pub info: TargetInfo,
    /// Vault revision at resolution; a later mutation invalidates the grant.
    pub revision: [u64; 2],
    /// Executor-specific connection data, opaque to the broker.
    pub payload: Arc<dyn Any + Send + Sync>,
}

/// Receiver of a running command's output.
pub trait Output: Send + Sync {
    /// Delivers a chunk of stdout (`stderr == false`) or stderr output.
    fn data(&self, stderr: bool, bytes: Vec<u8>);
    /// Reports the command's exit; `None` when the remote side sent no status.
    fn exited(&self, code: Option<u32>);
}
/// Handle of a started remote command.
pub trait Command: Send + Sync {
    /// Closes the command's channel.
    fn close(&self);
}
/// A live SSH connection owned by the broker.
pub trait Connection: Send + Sync {
    /// Starts `command` with optional stdin, streaming output to `sink`; errors when
    /// the channel cannot be opened or the run is cancelled or past `deadline`.
    fn exec(
        &self,
        command: &str,
        stdin: Option<&str>,
        sink: Arc<dyn Output>,
        cancel: Cancel,
        deadline: Instant,
    ) -> Result<Arc<dyn Command>>;
    /// Whether the connection is still usable.
    fn valid(&self) -> bool;
    /// Closes the connection.
    fn close(&self);
}
/// A native recording remains independent of output retention and HTTP polling.
pub trait Recording: Send + Sync {
    /// Appends a chunk of stdout or stderr output.
    fn data(&self, stderr: bool, bytes: &[u8]);
    /// Records the command's exit status.
    fn exited(&self, code: Option<u32>);
    /// Seals the recording with the run's final outcome.
    fn finish(&self, outcome: &str);
    /// Summary of the recording for the native review UI.
    fn review(&self) -> Value;
}
/// The native side of the broker: vault access, persistence and SSH execution.
pub trait Executor: Send + Sync + 'static {
    /// Loads the saved consents; errors when the store cannot be read.
    fn load_access(&self) -> Result<Vec<SavedAccess>> {
        Ok(Vec::new())
    }
    /// Persists the saved consents; errors when the store cannot be written.
    fn save_access(&self, _access: &[SavedAccess]) -> Result<()> {
        Ok(())
    }
    /// Identity of the unlocked account that saved consents are bound to; errors when locked.
    fn access_fingerprint(&self) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
    /// Starts a native recording of a run, or `None` when recording is off; errors
    /// when a required recording cannot be created.
    #[expect(
        clippy::too_many_arguments,
        reason = "one parameter per audited run attribute; a params struct would duplicate Run"
    )]
    fn record(
        &self,
        _target: &Target,
        _run_id: &str,
        _application: &str,
        _command: &str,
        _cwd: Option<&str>,
        _stdin: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Result<Option<Arc<dyn Recording>>> {
        Ok(None)
    }
    /// Current vault revision; errors when the vault is locked.
    fn revision(&self) -> Result<[u64; 2]>;
    /// Resolves a host profile to a target; errors when it is missing or locked.
    fn resolve(&self, vault: &str, profile: &str) -> Result<Target>;
    /// Opens an SSH connection to `target`; errors on authentication, host-key or
    /// transport failure, cancellation or an elapsed deadline.
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
/// How commands under a grant are approved.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Every command waits for the user's confirmation in the native UI.
    #[default]
    Manual,
    /// The user trusts the application: commands start without confirmation.
    Trusted,
}

struct Grant {
    max_timeout_ms: u32,
    approval_mode: ApprovalMode,
    slots: Arc<Semaphore>,
    epoch: String,
    label: String,
    revision: [u64; 2],
    until: Option<Instant>,
    targets: BTreeMap<String, Target>,
}
struct Session {
    created_unix_ms: u64,
    connected_at: Option<Instant>,
    connected_unix_ms: Option<u64>,
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
struct Run {
    created_unix_ms: u64,
    started_unix_ms: Option<u64>,
    id: String,
    owner: String,
    epoch: String,
    target: String,
    session: Option<String>,
    key: String,
    command: Zeroizing<String>,
    stdin: Option<Zeroizing<String>>,
    env: Environment,
    cwd: Option<Zeroizing<String>>,
    timeout_ms: u32,
    state: &'static str,
    error: Option<ToolError>,
    cancel: Cancel,
    approval_until: Instant,
    finished_at: Option<Instant>,
    started_at: Option<Instant>,
    exit_code: Option<u32>,
    recording: Option<Arc<dyn Recording>>,
    output: output::OutputBuffer,
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

/// The native authorization broker: owns grants, SSH sessions and command runs.
pub struct Broker {
    weak: Weak<Self>,
    executor: Arc<dyn Executor>,
    state: Mutex<State>,
    slots: Arc<Semaphore>,
    admission: RwLock<()>,
    revocation_epoch: AtomicU64,
    suspended: AtomicBool,
    access_revision: Mutex<Option<[u64; 2]>>,
}

impl Broker {
    /// Creates a broker over `executor` and starts its background expiry sweep.
    pub fn new(executor: Arc<dyn Executor>) -> Arc<Self> {
        let broker = Arc::new_cyclic(|weak| Self {
            weak: weak.clone(),
            executor,
            state: Mutex::new(State::default()),
            slots: Arc::new(Semaphore::new(8)),
            admission: RwLock::new(()),
            revocation_epoch: AtomicU64::new(0),
            suspended: AtomicBool::new(false),
            access_revision: Mutex::new(None),
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
    #[expect(
        clippy::map_err_ignore,
        reason = "ToolError is the fixed MCP wire error set and carries no source by design"
    )]
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

    /// Grants with manual approval against a previously issued ticket; errors when the
    /// ticket is stale or the targets cannot be resolved.
    pub fn grant_with_ticket(
        &self,
        owner: &str,
        label: String,
        targets: Vec<(String, String)>,
        seconds: impl Into<Option<u32>>,
        ticket: &str,
    ) -> Result<()> {
        self.grant_with_policy(
            owner,
            label,
            targets,
            seconds.into(),
            ticket,
            ApprovalMode::Manual,
        )
    }

    /// Only the trusted native grant UI may choose a command approval policy.
    pub fn grant_with_policy(
        &self,
        owner: &str,
        label: String,
        targets: Vec<(String, String)>,
        seconds: Option<u32>,
        ticket: &str,
        approval_mode: ApprovalMode,
    ) -> Result<()> {
        self.grant_with_limits(
            owner,
            label,
            targets,
            seconds,
            ticket,
            approval_mode,
            600_000,
        )
    }

    /// Grants with an explicit approval policy and timeout ceiling; errors when the
    /// limits are out of range, the ticket is stale or a target cannot be resolved.
    #[expect(
        clippy::too_many_arguments,
        reason = "signature mirrors the native grant UI contract; a params struct would be an API change"
    )]
    #[expect(
        clippy::map_err_ignore,
        reason = "ToolError is the fixed MCP wire error set and carries no source by design"
    )]
    pub fn grant_with_limits(
        &self,
        owner: &str,
        label: String,
        targets: Vec<(String, String)>,
        seconds: Option<u32>,
        ticket: &str,
        approval_mode: ApprovalMode,
        max_timeout_ms: u32,
    ) -> Result<()> {
        if !(1..=86_400_000).contains(&max_timeout_ms) {
            return Err(ToolError::TimeoutLimit);
        }
        if owner.is_empty() || targets.is_empty() || targets.len() > 64 || seconds == Some(0) {
            return Err(ToolError::TargetUnavailable);
        }
        let (generation, revision): (u64, [u64; 2]) =
            serde_json::from_str(ticket).map_err(|_| ToolError::GrantExpired)?;
        if self.revocation_epoch.load(Ordering::SeqCst) != generation
            || self.executor.revision()? != revision
        {
            return Err(ToolError::GrantExpired);
        }
        let fingerprint = self.executor.access_fingerprint()?;
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
        let _admission = self
            .admission
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.revocation_epoch.load(Ordering::SeqCst) != generation {
            return Err(ToolError::GrantExpired);
        }
        if self.suspended.load(Ordering::SeqCst) {
            return Err(ToolError::Locked);
        }
        {
            let state = lock(&self.state);
            if state.grants.len() >= GRANTS_TOTAL && !state.grants.contains_key(owner) {
                return Err(ToolError::Busy);
            }
        }
        self.save_grant(
            owner,
            &label,
            &resolved,
            seconds,
            approval_mode,
            max_timeout_ms,
            fingerprint,
        )?;
        self.revoke_inner(Some(owner));
        lock(&self.state).grants.insert(
            owner.into(),
            Grant {
                max_timeout_ms,
                approval_mode,
                slots: Arc::new(Semaphore::new(4)),
                epoch: id(),
                label,
                revision,
                until: seconds.map(|seconds| Instant::now() + Duration::from_secs(seconds.into())),
                targets: resolved,
            },
        );
        log::info!("MCP grant issued: integration={owner}, ttl_seconds={seconds:?}, approval_mode={approval_mode:?}");
        Ok(())
    }

    /// Invalidate live admission/output; saved consent is retained. Native explicit
    /// revocation uses `forget_access`. Cleanup runs without the state lock.
    pub fn revoke(&self, owner: Option<&str>) {
        let _admission = self
            .admission
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    fn revoke_expired(&self, owner: &str, epoch: &str) {
        let _admission = self
            .admission
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The sweep's revision/owner list may predate a concurrent native grant.
        // Recheck both identity and expiry under the same gate as grant publication.
        let revision = self.executor.revision().ok();
        let expired = lock(&self.state).grants.get(owner).is_some_and(|g| {
            g.epoch == epoch
                && (g.until.is_some_and(|until| Instant::now() >= until)
                    || Some(g.revision) != revision)
        });
        if expired {
            self.revocation_epoch.fetch_add(1, Ordering::SeqCst);
            self.revoke_inner(Some(owner));
        }
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "connection leases must stay held until the connections are closed after the state lock is released"
    )]
    fn sweep(&self) {
        let revision = self.executor.revision().ok();
        let now = Instant::now();
        let expired: Vec<_> = lock(&self.state)
            .grants
            .iter()
            .filter(|(_, g)| {
                g.until.is_some_and(|until| now >= until) || Some(g.revision) != revision
            })
            .map(|(o, g)| (o.clone(), g.epoch.clone()))
            .collect();
        for (owner, epoch) in expired {
            self.revoke_expired(&owner, &epoch);
        }
        self.restore_access();
        // Never call Core while holding the broker state: exec callbacks acquire
        // this mutex while Core serializes dispatch with vault mutation.
        #[expect(
            clippy::needless_collect,
            reason = "collecting releases the state lock before `valid()` calls into Core"
        )]
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

    #[expect(
        clippy::too_many_lines,
        reason = "sequential protocol dispatch; splitting hides the state machine"
    )]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the state guard must cover the grant check and the tool's state change atomically"
    )]
    #[expect(
        clippy::map_err_ignore,
        reason = "ToolError is the fixed MCP wire error set and carries no source by design"
    )]
    fn request(self: &Arc<Self>, owner: String, request: ToolRequest) -> Result<Value> {
        self.sweep();
        if let ToolRequest::GetAccessStatus(r) = &request {
            if r.cursor.is_some() {
                return Err(ToolError::TargetUnavailable);
            }
            let revision = self.executor.revision();
            let state = lock(&self.state);
            let grant = state.grants.get(&owner).filter(|g| {
                revision.as_ref().is_ok_and(|r| *r == g.revision)
                    && g.until.is_none_or(|d| Instant::now() < d)
            });
            let error = revision
                .err()
                .or_else(|| grant.is_none().then_some(ToolError::GrantRequired));
            let max = grant.map_or(600_000, |g| g.max_timeout_ms);
            return Ok(
                json!({"status": error.map_or_else(|| "ready".to_owned(), error_code),
                "message": error.map_or("Access is ready.", ToolError::message),
                "approval_mode": grant.map(|g| g.approval_mode),
                "remaining_seconds": grant.and_then(|g| g.until).map(|d| d.saturating_duration_since(Instant::now()).as_secs()),
                "limits": {"max_timeout_ms": max, "default_timeout_ms": 120_000_u32.min(max), "max_connections": 4, "max_active_commands": 8, "max_retained_commands": RECORDS_PER_GRANT, "max_session_records":32,
                    "output_per_run_bytes":OUTPUT_PER_RUN,"output_page_bytes":PAGE_BYTES,
                    "output_retention_seconds":null, "idle_session_seconds":300, "stdin_bytes":32768, "env_bytes":16384}}),
            );
        }
        // Authentication alone never unlocks Core or creates a grant.
        let revision = self.executor.revision()?;
        let _admission = matches!(
            &request,
            ToolRequest::CloseSession(_) | ToolRequest::CancelCommand(_)
        )
        .then(|| {
            self.admission
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        });
        let mut state = lock(&self.state);
        let grant = state.grants.get(&owner).ok_or(ToolError::GrantRequired)?;
        if grant.revision != revision || grant.until.is_some_and(|until| Instant::now() >= until) {
            return Err(ToolError::GrantExpired);
        }
        let epoch = grant.epoch.clone();
        match request {
            // Answered before the grant gate above; kept total without a panic.
            ToolRequest::GetAccessStatus(_) => Err(ToolError::TargetUnavailable),
            ToolRequest::ListCommands(r) => {
                if r.cursor.is_some() {
                    return Err(ToolError::TargetUnavailable);
                }
                Ok(
                    json!({"commands": state.runs.iter().filter(|(_, r)| r.owner == owner).map(|(id,r)| {
                    let mut value = run_json(id,r);
                    set_field(&mut value, "request_key", json!(r.key));
                    set_field(&mut value, "command_preview", json!(r.command.chars().take(256).collect::<String>()));
                    set_field(&mut value, "exit_code", json!(r.exit_code));
                    set_field(&mut value, "elapsed_ms", json!(r.started_at.map_or(0, |start| millis(r.finished_at.unwrap_or_else(Instant::now).saturating_duration_since(start)))));
                    value
                }).collect::<Vec<_>>()}),
                )
            }
            ToolRequest::ListTargets(r) => {
                if r.cursor.is_some() {
                    return Err(ToolError::TargetUnavailable);
                }
                Ok(
                    json!({"targets":grant.targets.iter().map(|(id,t)| json!({"target_id":id,"alias":t.info.label,"available":true,"vault":t.info.vault,"groups":t.info.groups,"tags":t.info.tags})).collect::<Vec<_>>()}),
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
                let session = Session {
                    created_unix_ms: unix_ms(),
                    connected_at: None,
                    connected_unix_ms: None,
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
                };
                let result = session_json(&sid, &session);
                state.sessions.insert(sid.clone(), session);
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
                                s.connected_at = Some(Instant::now());
                                s.connected_unix_ms = Some(unix_ms());
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
                    if matches!(run.state, "awaiting_approval" | "queued") {
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
                let (session, target_id, command, key, timeout_ms, cwd, stdin, env) = match r {
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
                            r.timeout_ms
                                .unwrap_or_else(|| 120_000.min(grant.max_timeout_ms)),
                            r.cwd,
                            r.stdin,
                            r.env,
                        )
                    }
                    RunCommand::OneShot(r) => (
                        None,
                        r.target_id,
                        r.command,
                        r.request_key,
                        r.timeout_ms
                            .unwrap_or_else(|| 120_000.min(grant.max_timeout_ms)),
                        r.cwd,
                        r.stdin,
                        r.env,
                    ),
                };
                if timeout_ms > grant.max_timeout_ms {
                    return Err(ToolError::TimeoutLimit);
                }
                if let Some((rid, r)) = state
                    .runs
                    .iter()
                    .find(|(_, r)| r.owner == owner && r.epoch == epoch && r.key == key)
                {
                    return if r.session == session
                        && r.target == target_id
                        && *r.command == command
                        && r.stdin.as_ref().map(|v| v.as_str()) == stdin.as_deref()
                        && *r.env == env
                        && r.timeout_ms == timeout_ms
                        && r.cwd.as_ref().map(|v| v.as_str()) == cwd.as_deref()
                    {
                        output::page(rid, r, None)
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
                    if state.sessions.get(sid).is_none_or(|s| s.state != "ready") {
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
                let approval_mode = grant.approval_mode;
                let rid = id();
                state.runs.insert(
                    rid.clone(),
                    Run {
                        created_unix_ms: unix_ms(),
                        started_unix_ms: None,
                        id: rid.clone(),
                        owner: owner.clone(),
                        epoch,
                        target: target_id,
                        session,
                        key,
                        command: Zeroizing::new(command),
                        stdin: stdin.map(Zeroizing::new),
                        env: Environment(env),
                        cwd: cwd.map(Zeroizing::new),
                        timeout_ms,
                        state: if approval_mode == ApprovalMode::Manual {
                            "awaiting_approval"
                        } else {
                            "queued"
                        },
                        error: None,
                        cancel: Arc::new(AtomicBool::new(false)),
                        approval_until: Instant::now() + Duration::from_secs(120),
                        finished_at: None,
                        started_at: None,
                        exit_code: None,
                        recording: None,
                        output: output::OutputBuffer::default(),
                        bytes: 0,
                        truncated: false,
                    },
                );
                drop(state);
                if approval_mode == ApprovalMode::Trusted {
                    if let Err(error) = self.start_run(&rid, true, ApprovalMode::Trusted) {
                        if let Some(run) = lock(&self.state)
                            .runs
                            .get_mut(&rid)
                            .filter(|run| run.finished_at.is_none())
                        {
                            finish(run, "failed", Some(error));
                        }
                        return Err(error);
                    }
                }
                self.request(
                    owner,
                    ToolRequest::GetCommand(unissh_mcp::contract::GetCommand {
                        run_id: rid,
                        output_cursor: None,
                        wait_ms: None,
                    }),
                )
            }
            ToolRequest::GetCommand(r) => {
                let run = state
                    .runs
                    .get(&r.run_id)
                    .filter(|r| r.owner == owner)
                    .ok_or(ToolError::OutcomeUnknown)?;
                output::page(&r.run_id, run, r.output_cursor.as_deref())
            }
            ToolRequest::CancelCommand(r) => {
                let run = state
                    .runs
                    .get_mut(&r.run_id)
                    .filter(|r| r.owner == owner)
                    .ok_or(ToolError::OutcomeUnknown)?;
                if run.finished_at.is_none() {
                    cancel(&run.cancel);
                    if matches!(run.state, "awaiting_approval" | "queued") {
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

    /// Cancels a run from the native UI on behalf of its owner; errors when the run is unknown.
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

    /// Snapshot of saved consents, live grants, sessions and runs for the native review UI.
    pub fn review(&self) -> Value {
        self.sweep();
        let saved_access = self.saved_access_review();
        let state = lock(&self.state);
        let target_of = |owner: &str, target: &str| {
            state
                .grants
                .get(owner)
                .and_then(|g| g.targets.get(target))
                .map_or(Value::Null, |t| json!(&t.info))
        };
        let grants = state.grants.iter().map(|(owner, g)| {
            json!({
                "integration_id": owner,
                "label": g.label,
                "approval_mode": g.approval_mode,
                "max_timeout_ms": g.max_timeout_ms,
                "remaining_seconds": g.until.map(|until| until.saturating_duration_since(Instant::now()).as_secs()),
                "targets": g.targets.values().map(|t| &t.info).collect::<Vec<_>>()
            })
        });
        let sessions = state.sessions.iter().map(|(id, s)| {
            let mut v = session_json(id, s);
            set_field(&mut v, "created_unix_ms", json!(s.created_unix_ms));
            set_field(&mut v, "connected_unix_ms", json!(s.connected_unix_ms));
            set_field(
                &mut v,
                "connected_elapsed_ms",
                json!(s
                    .connected_at
                    .filter(|_| s.state == "ready")
                    .map(|at| millis(at.elapsed()))),
            );
            set_field(&mut v, "integration_id", json!(s.owner));
            set_field(&mut v, "target", target_of(&s.owner, &s.target));
            set_field(
                &mut v,
                "idle_seconds",
                json!(Duration::from_secs(300)
                    .saturating_sub(s.idle.elapsed())
                    .as_secs()),
            );
            v
        });
        let runs = state.runs.iter().map(|(id, r)| {
            let mut v = native_run_json(id, r);
            set_field(&mut v, "integration_id", json!(r.owner));
            set_field(
                &mut v,
                "recording",
                r.recording.as_ref().map_or(Value::Null, |r| r.review()),
            );
            set_field(&mut v, "target", target_of(&r.owner, &r.target));
            if r.state == "awaiting_approval" {
                set_field(&mut v, "stdin", json!(r.stdin.as_ref().map(|s| s.as_str())));
                set_field(&mut v, "env", json!(&*r.env));
                set_field(&mut v, "cwd", json!(r.cwd.as_ref().map(|cwd| cwd.as_str())));
                set_field(&mut v, "command", json!(&*r.command));
                set_field(&mut v, "timeout_ms", json!(r.timeout_ms));
                set_field(
                    &mut v,
                    "approval_remaining_seconds",
                    json!(r
                        .approval_until
                        .saturating_duration_since(Instant::now())
                        .as_secs()),
                );
            }
            v
        });
        json!({
            "saved_access": saved_access,
            "grants": grants.collect::<Vec<_>>(),
            "sessions": sessions.collect::<Vec<_>>(),
            "runs": runs.collect::<Vec<_>>()
        })
    }

    /// Native-only search over full commands and target context, without
    /// copying command bodies or output into every desktop status poll.
    pub fn search_commands(&self, owner: &str, query: &str) -> Result<Vec<String>> {
        if query.chars().count() > 512 {
            return Err(ToolError::Busy);
        }
        self.sweep();
        let revision = self.executor.revision()?;
        let _admission = self
            .admission
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = lock(&self.state);
        let grant = state.grants.get(owner).ok_or(ToolError::GrantRequired)?;
        if grant.revision != revision || grant.until.is_some_and(|until| Instant::now() >= until) {
            return Err(ToolError::GrantExpired);
        }
        let query = query.to_lowercase();
        let terms: Vec<_> = query.split_whitespace().collect();
        Ok(state
            .runs
            .iter()
            .filter(|(_, run)| {
                if run.owner != owner || run.epoch != grant.epoch {
                    return false;
                }
                let Some(target) = grant.targets.get(&run.target) else {
                    return false;
                };
                let address = format!(
                    "{}@{}:{}",
                    target.info.user, target.info.host, target.info.port
                );
                let fields: [&str; 6] = [
                    &run.command,
                    run.cwd.as_ref().map_or("", |s| s.as_str()),
                    &target.info.label,
                    &target.info.host,
                    &target.info.user,
                    &address,
                ];
                let fields: Vec<_> = fields
                    .iter()
                    .map(|s| Zeroizing::new(s.to_lowercase()))
                    .collect();
                terms
                    .iter()
                    .all(|term| fields.iter().any(|field| field.contains(*term)))
            })
            .map(|(id, _)| id.clone())
            .collect())
    }

    /// Trusted desktop inspector. Reads the same bounded buffer as MCP without
    /// opening SSH or depending on optional persistent session recording.
    pub fn inspect_command(
        &self,
        owner: &str,
        run_id: &str,
        cursor: Option<&str>,
    ) -> Result<Value> {
        self.sweep();
        let revision = self.executor.revision()?;
        let _admission = self
            .admission
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = lock(&self.state);
        let grant = state.grants.get(owner).ok_or(ToolError::GrantRequired)?;
        if grant.revision != revision || grant.until.is_some_and(|until| Instant::now() >= until) {
            return Err(ToolError::GrantExpired);
        }
        let run = state
            .runs
            .get(run_id)
            .filter(|r| r.owner == owner && r.epoch == grant.epoch)
            .ok_or(ToolError::OutcomeUnknown)?;
        let mut value = match output::page(run_id, run, cursor) {
            Ok(value) => value,
            Err(ToolError::OutputExpired) => {
                json!({"chunks":[],"next_cursor":"0","output_error":"output_expired"})
            }
            Err(e) => return Err(e),
        };
        let has_more = field(&value, "output_error").is_null()
            && run
                .output
                .has_more(field(&value, "next_cursor").as_str().unwrap_or("0"));
        set_field(&mut value, "has_more", json!(has_more));
        set_field(&mut value, "command", json!(&*run.command));
        set_field(
            &mut value,
            "cwd",
            json!(run.cwd.as_deref().map(String::as_str)),
        );
        set_field(
            &mut value,
            "stdin",
            json!(run.stdin.as_deref().map(String::as_str)),
        );
        set_field(&mut value, "env", json!(&*run.env));
        set_field(&mut value, "timeout_ms", json!(run.timeout_ms));
        set_field(&mut value, "state", json!(run.state));
        set_field(&mut value, "error", json!(run.error));
        set_field(&mut value, "run_id", json!(run_id));
        set_field(&mut value, "exit_code", json!(run.exit_code));
        Ok(value)
    }

    /// Records the user's decision on a run awaiting manual approval and starts it when
    /// allowed; errors when the approval has expired or the grant no longer covers it.
    pub fn approve(self: &Arc<Self>, run_id: &str, allowed: bool) -> Result<()> {
        self.start_run(run_id, allowed, ApprovalMode::Manual)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "sequential authorize-connect-exec-publish steps; splitting hides the state machine"
    )]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "connection leases and the state guard must span the authorization and the run's publication"
    )]
    #[expect(
        clippy::map_err_ignore,
        reason = "ToolError is the fixed MCP wire error set and carries no source by design"
    )]
    fn start_run(self: &Arc<Self>, run_id: &str, allowed: bool, mode: ApprovalMode) -> Result<()> {
        self.sweep();
        let mut state = lock(&self.state);
        let run = state.runs.get(run_id).ok_or(ToolError::ApprovalExpired)?;
        if run.state
            != if mode == ApprovalMode::Manual {
                "awaiting_approval"
            } else {
                "queued"
            }
            || cancelled(&run.cancel)
            || Instant::now() >= run.approval_until
        {
            return Err(ToolError::ApprovalExpired);
        }
        if !allowed {
            finish(
                state
                    .runs
                    .get_mut(run_id)
                    .ok_or(ToolError::ApprovalExpired)?,
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
        if grant.approval_mode != mode {
            return Err(ToolError::ApprovalDenied);
        }
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
            "MCP run authorized: integration_id={}, target_id={}, run_id={run_id}, approval_mode={mode:?}",
            run.owner,
            run.target
        );
        let original_command = run.command.clone();
        let cwd = run.cwd.clone();
        let stdin = run.stdin.clone();
        let env = run.env.clone();
        let stop = run.cancel.clone();
        let command = working_directory::with_env(
            &run.command,
            run.cwd.as_ref().map(|cwd| cwd.as_str()),
            &run.env,
        );
        let rid = run_id.to_owned();
        let run = state
            .runs
            .get_mut(run_id)
            .ok_or(ToolError::ApprovalExpired)?;
        run.state = if connection.is_none() {
            "connecting"
        } else {
            "running"
        };
        run.started_at = Some(Instant::now());
        run.started_unix_ms = Some(unix_ms());
        let broker = self.clone();
        std::thread::spawn(move || {
            // Core state must never be acquired while holding broker state:
            // an exec callback may be waiting to publish output to the broker.
            let recording = match broker.executor.record(
                &target,
                &rid,
                &attribution,
                &original_command,
                cwd.as_ref().map(|cwd| cwd.as_str()),
                stdin.as_ref().map(|s| s.as_str()),
                &env,
            ) {
                Ok(recording) => recording,
                Err(error) => {
                    if let Some(run) = lock(&broker.state).runs.get_mut(&rid) {
                        finish(run, "failed", Some(error));
                    }
                    return;
                }
            };
            if let Some(run) = lock(&broker.state).runs.get_mut(&rid) {
                run.recording = recording.clone();
            }
            let implicit = connection.is_none();
            let connection = match (connection, slot) {
                (Some(c), _) => Ok(c),
                (None, Some((slot, owner_slot))) => broker
                    .connect(&target, stop.clone(), Some(deadline), &attribution)
                    .map(|c| {
                        Arc::new(LiveConnection {
                            inner: c,
                            _slot: slot,
                            _owner_slot: owner_slot,
                        })
                    }),
                // A one-shot run always reserves its slots above; without them there
                // is nothing to connect with.
                (None, None) => Err(ToolError::OutcomeUnknown),
            };
            let result = (|| -> Result<()> {
                let c = connection.as_ref().map_err(|e| *e)?;
                // Revocation's cancel flag precedes cleanup. Core adds a final gate
                // under its state lock, including target revision and connection lease.
                if cancelled(&stop) || Instant::now() >= deadline {
                    return Err(ToolError::GrantExpired);
                }
                let admission = broker
                    .admission
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if cancelled(&stop) || Instant::now() >= deadline {
                    return Err(ToolError::GrantExpired);
                }
                if let Some(run) = lock(&broker.state).runs.get_mut(&rid) {
                    run.state = "running";
                }
                let handle = c.inner.exec(
                    &command,
                    stdin.as_ref().map(|s| s.as_str()),
                    Arc::new(RunSink {
                        recording: recording.clone(),
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
            let mut outcome = if cancelled(&stop) {
                "cancelled"
            } else {
                "failed"
            };
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
                outcome = run.state;
                if let Some(sid) = run.session.clone() {
                    if let Some(s) = state.sessions.get_mut(&sid) {
                        s.idle = Instant::now();
                    }
                }
            }
            drop(state);
            if let Some(recording) = recording {
                recording.finish(outcome);
            }
        });
        Ok(())
    }
}

/// What an MCP call with `wait_ms` keeps polling for after the first answer.
enum Wait {
    Session,
    Run,
    Output(unissh_mcp::contract::GetCommand),
}

impl Backend for Broker {
    #[expect(
        clippy::map_err_ignore,
        reason = "ToolError is the fixed MCP wire error set and carries no source by design"
    )]
    fn call(&self, integration: IntegrationId, request: ToolRequest) -> BackendResult<'_> {
        let broker = self.weak.upgrade();
        Box::pin(async move {
            let broker = broker.ok_or(ToolError::GrantExpired)?;
            let (wait, ms) = match &request {
                ToolRequest::OpenSession(r) => (Some(Wait::Session), r.wait_ms),
                ToolRequest::RunCommand(RunCommand::Existing(r)) => (Some(Wait::Run), r.wait_ms),
                ToolRequest::RunCommand(RunCommand::OneShot(r)) => (Some(Wait::Run), r.wait_ms),
                ToolRequest::GetCommand(r) => (Some(Wait::Output(r.clone())), r.wait_ms),
                ToolRequest::GetAccessStatus(_)
                | ToolRequest::ListCommands(_)
                | ToolRequest::ListTargets(_)
                | ToolRequest::ListSessions(_)
                | ToolRequest::CloseSession(_)
                | ToolRequest::CancelCommand(_) => (None, None),
            };
            let until = tokio::time::Instant::now() + Duration::from_millis(ms.unwrap_or(0).into());
            let call_broker = broker.clone();
            let owner = integration.0;
            let call_owner = owner.clone();
            let first =
                tokio::task::spawn_blocking(move || call_broker.request(call_owner, request))
                    .await
                    .map_err(|_| ToolError::OutcomeUnknown)??;
            let Some(wait) = wait.filter(|_| ms.unwrap_or(0) > 0) else {
                return Ok(first);
            };
            let done = |result: &Value| {
                matches!(
                    field(result, "state").as_str(),
                    Some("completed" | "failed" | "cancelled" | "denied")
                )
            };
            match &wait {
                Wait::Session if field(&first, "state") != "connecting" => return Ok(first),
                Wait::Run if field(&first, "state") == "awaiting_approval" || done(&first) => {
                    return Ok(first)
                }
                Wait::Output(_)
                    if field(&first, "chunks")
                        .as_array()
                        .is_some_and(|c| !c.is_empty())
                        || done(&first) =>
                {
                    return Ok(first)
                }
                Wait::Session | Wait::Run | Wait::Output(_) => {}
            }
            loop {
                tokio::time::sleep_until(
                    until.min(tokio::time::Instant::now() + Duration::from_millis(20)),
                )
                .await;
                let b = broker.clone();
                let o = owner.clone();
                let poll = match &wait {
                    Wait::Session => ToolRequest::ListSessions(unissh_mcp::contract::ListRequest {
                        cursor: None,
                    }),
                    Wait::Run => ToolRequest::GetCommand(unissh_mcp::contract::GetCommand {
                        run_id: field(&first, "run_id")
                            .as_str()
                            .ok_or(ToolError::OutcomeUnknown)?
                            .into(),
                        output_cursor: None,
                        wait_ms: None,
                    }),
                    Wait::Output(poll) => ToolRequest::GetCommand(poll.clone()),
                };
                let mut result = tokio::task::spawn_blocking(move || b.request(o, poll))
                    .await
                    .map_err(|_| ToolError::OutcomeUnknown)??;
                let ready = match &wait {
                    Wait::Session => {
                        result = field(&result, "sessions")
                            .as_array()
                            .and_then(|sessions| {
                                sessions
                                    .iter()
                                    .find(|s| field(s, "session_id") == field(&first, "session_id"))
                            })
                            .cloned()
                            .ok_or(ToolError::SessionClosed)?;
                        field(&result, "state") != "connecting"
                    }
                    Wait::Run => done(&result),
                    Wait::Output(_) => result != first,
                };
                if ready || tokio::time::Instant::now() >= until {
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
    run.output.flush();
    run.finished_at = Some(Instant::now());
}
fn unix_ms() -> u64 {
    millis(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default(),
    )
}
fn native_run_json(id: &str, run: &Run) -> Value {
    let mut value = run_json(id, run);
    set_field(
        &mut value,
        "command_preview",
        json!(run.command.chars().take(256).collect::<String>()),
    );
    set_field(
        &mut value,
        "cwd",
        json!(run.cwd.as_deref().map(String::as_str)),
    );
    set_field(&mut value, "created_unix_ms", json!(run.created_unix_ms));
    set_field(&mut value, "started_unix_ms", json!(run.started_unix_ms));
    set_field(
        &mut value,
        "elapsed_ms",
        json!(run.started_at.map(|at| millis(
            run.finished_at
                .unwrap_or_else(Instant::now)
                .saturating_duration_since(at)
        ))),
    );
    set_field(&mut value, "exit_code", json!(run.exit_code));
    value
}
fn session_json(id: &str, s: &Session) -> Value {
    json!({"session_id":id,"target_id":s.target,"state":s.state,"error":s.error,"expires_at":s.expires_at})
}
fn run_json(id: &str, r: &Run) -> Value {
    json!({"run_id":id,"session_id":r.session,"target_id":r.target,"state":r.state,"error":r.error})
}

struct RunSink {
    recording: Option<Arc<dyn Recording>>,
    broker: Weak<Broker>,
    run: String,
}
impl Output for RunSink {
    fn data(&self, stderr: bool, bytes: Vec<u8>) {
        if let Some(recording) = &self.recording {
            recording.data(stderr, &bytes);
        }
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
        let Some(kept_bytes) = bytes.get(..kept) else {
            return;
        };
        let saved = run.output.push(stderr, kept_bytes);
        run.bytes += saved;
        run.truncated |= saved < bytes.len();
        state.retained_bytes += saved;
    }
    fn exited(&self, code: Option<u32>) {
        if let Some(recording) = &self.recording {
            recording.exited(code);
        }
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

/// BTreeMap keys cannot be mutated in place; wipe every secret value before drop.
#[derive(Clone)]
struct Environment(BTreeMap<String, String>);
impl std::ops::Deref for Environment {
    type Target = BTreeMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Environment {
    fn zeroize(&mut self) {
        for value in self.0.values_mut() {
            zeroize::Zeroize::zeroize(value);
        }
        self.0.clear();
    }
}
impl Drop for Environment {
    fn drop(&mut self) {
        self.zeroize();
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
                    vault: "Test vault".into(),
                    groups: vec![],
                    tags: vec![],
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
            .to_owned();
        (b, run)
    }
    #[test]
    fn native_approval_deadline_cannot_be_extended_by_polling() {
        let (b, rid) = pending();
        lock(&b.state).runs.get_mut(&rid).unwrap().approval_until =
            Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(b.approve(&rid, true), Err(ToolError::ApprovalExpired));
        assert_eq!(b.review()["runs"][0]["state"], "denied");
    }
    #[test]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the guard deliberately spans both mutations of the run"
    )]
    fn output_survives_elapsed_time_and_preserves_cursors_until_revocation() {
        let (b, rid) = pending();
        let sink = RunSink {
            recording: None,
            broker: Arc::downgrade(&b),
            run: rid.clone(),
        };
        sink.data(false, b"retained output".to_vec());
        {
            let mut state = lock(&b.state);
            let run = state.runs.get_mut(&rid).unwrap();
            finish(run, "failed", Some(ToolError::OutcomeUnknown));
            run.finished_at = Some(
                Instant::now()
                    .checked_sub(Duration::from_secs(24 * 3600))
                    .unwrap(),
            );
        }
        let details = b.inspect_command("a", &rid, None).unwrap();
        assert_eq!(details["error"], "outcome_unknown");
        assert_eq!(details["chunks"][0]["data"], "retained output");
        assert!(details["output_error"].is_null());
        let cursor = details["next_cursor"].as_str();
        sink.data(false, b"late callback".to_vec());
        assert_eq!(
            b.inspect_command("a", &rid, cursor).unwrap()["chunks"],
            json!([])
        );
        assert_eq!(lock(&b.state).retained_bytes, 15);
        b.revoke(Some("a"));
        assert_eq!(lock(&b.state).retained_bytes, 0);
        assert_eq!(
            b.inspect_command("a", &rid, None),
            Err(ToolError::GrantRequired)
        );
    }
    #[test]
    fn expired_lease_drops_output_before_housekeeping_runs() {
        let (b, rid) = pending();
        lock(&b.state).grants.get_mut("a").unwrap().until =
            Some(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
        RunSink {
            recording: None,
            broker: Arc::downgrade(&b),
            run: rid.clone(),
        }
        .data(false, vec![1, 2, 3]);
        assert_eq!(lock(&b.state).retained_bytes, 0);
        assert_eq!(b.approve(&rid, true), Err(ToolError::ApprovalExpired));
        assert!(b.review()["grants"].as_array().unwrap().is_empty());
    }
    #[test]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "`b` is the broker under test and is used until the last assertion"
    )]
    fn stale_expiry_work_cannot_revoke_replaced_or_currently_valid_grants() {
        let b = Broker::new(Arc::new(ExecutorFixture));
        b.grant("a", "old".into(), vec![("v".into(), "p".into())], 30)
            .unwrap();
        let old_epoch = lock(&b.state).grants["a"].epoch.clone();
        b.grant(
            "a",
            "replacement".into(),
            vec![("v".into(), "p".into())],
            None,
        )
        .unwrap();
        b.revoke_expired("a", &old_epoch);
        let current = lock(&b.state).grants["a"].epoch.clone();
        // Also handle a stale revision read followed by a snapshot of the new grant.
        b.revoke_expired("a", &current);
        assert_eq!(b.review()["grants"][0]["label"], "replacement");
        // Genuine expiration is still enforced by that same admission path.
        lock(&b.state).grants.get_mut("a").unwrap().until =
            Some(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
        b.revoke_expired("a", &current);
        assert!(b.review()["grants"].as_array().unwrap().is_empty());
    }
}
