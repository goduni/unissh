//! The system agent: an ssh-agent endpoint local programs (`ssh-add -l`, `git`,
//! `ssh`) can reach, offering the vault keys this device shares with it.
//!
//! Off by default; the setting persists. The protocol, key policy and the
//! per-signature approval are the core's (`unissh_ffi::SystemAgent`); this
//! module owns only the OS endpoint, the caller's identity and the lifecycle,
//! modelled on the MCP controller.
//!
//! Lifecycle: the listener runs only while the vault is unlocked and the screen
//! is not locked. [`revoke`] stops it at once (vault lock, screen lock, sleep,
//! exit) and [`resume_access`] brings it back after an unlock or a wake, if the
//! setting is on — both called, beside MCP's, from
//! `crate::commands::revoke_agent_access` / `resume_after_unlock`, so the user
//! never re-enables it by hand. A
//! connection open at a revoke is cut with the listener, and the core is told
//! at the same moment (`Core::revoke_system_agent_requests`), so the prompt on
//! screen is withdrawn and no request still waiting for its turn is shown
//! afterwards; the next listener starts with a fresh `SystemAgent`.
//!
//! The endpoint is a Unix socket on macOS and Linux (`endpoint`, `peer`) and
//! a per-user named pipe, `\\.\pipe\unissh-agent-<user SID>`, on Windows
//! (`pipe`). Both are served by the same `SystemAgent::serve`, which also
//! bounds what a caller can hold: the number of connections and how long one
//! may idle. The listener itself survives an accept (on Windows, the creation
//! of the next pipe instance) that fails for want of resources; one it cannot
//! survive ends it, cuts its connections and shows in the status.

#[cfg(unix)]
mod endpoint;
#[cfg(unix)]
mod peer;
#[cfg(windows)]
mod pipe;

use crate::error::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tauri::{Manager, State};
use unissh_ffi::Core;
use unissh_mcp::CancellationToken;

/// The persisted setting. Only whether the agent is on; which keys it offers is
/// the core's device-local metadata.
#[derive(Default, Serialize, Deserialize)]
struct Settings {
    enabled: bool,
}

fn load_settings(path: &Path) -> Settings {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_settings(path: &Path, settings: &Settings) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(settings)?)?;
    std::fs::rename(tmp, path)
}

struct Running {
    stop: CancellationToken,
    task: tauri::async_runtime::JoinHandle<()>,
}

/// The live listener's stop token, and a counter bumped by every revoke. Under
/// a plain lock rather than the async one: revoke fires from OS listener
/// threads and the event loop, and must cut the listener off at once.
#[derive(Default)]
struct Live {
    epoch: u64,
    stop: Option<CancellationToken>,
}

pub struct Controller {
    app: tauri::AppHandle,
    core: Arc<Core>,
    settings_path: PathBuf,
    /// The socket path, or on Windows the pipe name. `None` when it could not
    /// be worked out (the app data directory did not resolve; on Windows, the
    /// user's SID could not be read from the process token): nothing can
    /// listen then, and the status says `bind_failed` from the start.
    endpoint: Option<PathBuf>,
    running: tokio::sync::Mutex<Option<Running>>,
    live: Mutex<Live>,
    error: Arc<Mutex<Option<&'static str>>>,
}

impl Controller {
    pub fn new(app: &tauri::AppHandle, core: Arc<Core>, settings_path: PathBuf) -> Arc<Self> {
        #[cfg(unix)]
        let endpoint = app
            .path()
            .app_local_data_dir()
            .ok()
            .map(|data| endpoint::socket_path(app.path().runtime_dir().ok().as_deref(), &data));
        // The self-loop guard this feeds is a no-op on Windows by construction:
        // the transport always dials OpenSSH's own pipe, never this one. The
        // name is still handed over, so the core knows it either way.
        #[cfg(windows)]
        let endpoint = match pipe::name() {
            Ok(name) => Some(PathBuf::from(name)),
            Err(e) => {
                log::warn!("system agent: the pipe name could not be derived: {e}");
                None
            }
        };
        // Whether or not the listener is on: a host using "system agent" auth
        // with SSH_AUTH_SOCK pointed here is misconfigured either way, and gets
        // a typed error saying so instead of a loop (or a bare "not found").
        core.set_system_agent_endpoint(endpoint.clone());
        // Said before anyone tries to switch it on: the switch is disabled
        // without an endpoint, and the status is then the only explanation.
        let no_endpoint = endpoint.is_none().then_some("bind_failed");
        Arc::new(Self {
            app: app.clone(),
            core,
            settings_path,
            endpoint,
            running: tokio::sync::Mutex::new(None),
            live: Mutex::new(Live::default()),
            error: Arc::new(Mutex::new(no_endpoint)),
        })
    }

    /// The live-listener record, for paths that cannot return an error (stop,
    /// revoke, shutdown, background restarts). `Live` is two plain fields that
    /// are never left half-updated, and a revoke must still go through after a
    /// panic elsewhere, so a poisoned lock is recovered rather than skipped.
    fn live(&self) -> std::sync::MutexGuard<'_, Live> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Starts the listener if the setting is on, the vault unlocked and the
    /// screen not locked; otherwise does nothing. Called at boot (where the
    /// vault is still locked, so the first unlock starts it) and from
    /// [`resume_access`].
    pub fn resume(self: &Arc<Self>) {
        let epoch = self.live().epoch;
        let this = self.clone();
        tauri::async_runtime::spawn(async move { this.restart(epoch).await });
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the `running` guard serialises a restart against enable/stop for the whole start sequence"
    )]
    async fn restart(self: &Arc<Self>, epoch: u64) {
        if !self.may_serve().await {
            return;
        }
        let mut running = self.running.lock().await;
        if !load_settings(&self.settings_path).enabled || self.live().epoch != epoch {
            return;
        }
        let serving = self.live().stop.is_some()
            && running
                .as_ref()
                .is_some_and(|r| !r.task.inner().is_finished());
        if serving {
            return;
        }
        self.stop(&mut running).await;
        let Some(path) = self.endpoint.clone() else {
            self.set_error(Some("bind_failed"));
            return;
        };
        match self.listen(&path).await {
            Ok((stop, task)) => {
                // Checked again now that it is bound: a lock that landed while
                // binding must not leave it serving. (A lock revokes before it
                // locks the core, so either the epoch or this check sees it.)
                if self.core_unlocked().await {
                    self.arm(epoch, &stop);
                } else {
                    stop.cancel();
                }
                *running = Some(Running { stop, task });
                self.set_error(None);
            }
            Err(code) => self.set_error(Some(code)),
        }
    }

    /// Whether the vault is unlocked; a core that cannot be asked counts as
    /// locked.
    async fn core_unlocked(&self) -> bool {
        let core = self.core.clone();
        tauri::async_runtime::spawn_blocking(move || core.is_unlocked())
            .await
            .unwrap_or(false)
    }

    /// The condition for a listener to exist at all: the vault unlocked and
    /// the screen not locked.
    async fn may_serve(&self) -> bool {
        !crate::system_lock::is_screen_locked() && self.core_unlocked().await
    }

    /// Stops the listener now and cuts its connections, keeping the setting.
    /// Any start already under way sees the new epoch and stands down.
    fn revoke(&self) {
        let stop = {
            let mut live = self.live();
            live.epoch += 1;
            live.stop.take()
        };
        if let Some(stop) = stop {
            stop.cancel();
        }
    }

    /// Records a freshly started listener as the live one — unless a revoke
    /// came in since `epoch` was read, in which case it is stopped right away.
    fn arm(&self, epoch: u64, stop: &CancellationToken) {
        let armed = {
            let mut live = self.live();
            let current = live.epoch == epoch;
            if current {
                live.stop = Some(stop.clone());
            }
            current
        };
        // Our own fresh token: cancelling it outside the lock races with nothing.
        if !armed {
            stop.cancel();
        }
    }

    /// Refuses every signature request of the listener that is stopping: the
    /// prompt on screen, the requests still waiting for their turn, and any
    /// that its connections make from here on. With the listener gone an
    /// answer could reach no one. The core's line is closed first, so nothing
    /// is put on screen between that and the sweep of the window's own
    /// registry, which is kept as a second line of defence.
    ///
    /// Takes the core's approval-line lock and then, separately, the
    /// approver's registry lock; never the core's state lock, so it is safe
    /// on the threads a revoke fires from, ahead of the lock it announces.
    fn withdraw_prompts(&self) {
        self.core.revoke_system_agent_requests();
        if let Some(approver) = self.app.try_state::<Arc<crate::observers::AppApprover>>() {
            approver.cancel_system();
        }
    }

    /// Withdraws the listener's prompts and stops the listener held in
    /// `running`, waiting up to 2 s for it to remove its socket before
    /// aborting it. The prompts go first: cutting a connection frees the line
    /// for the request behind it, which must already be gone by then.
    async fn stop(&self, running: &mut Option<Running>) {
        self.withdraw_prompts();
        self.live().stop = None;
        if let Some(mut old) = running.take() {
            old.stop.cancel();
            if tokio::time::timeout(std::time::Duration::from_secs(2), &mut old.task)
                .await
                .is_err()
            {
                old.task.abort();
                await_aborted(old.task).await;
            }
        }
    }

    /// Records the status tag shown by `system_agent_status`. A tag holds no
    /// invariant, so a poisoned slot is recovered and overwritten.
    fn set_error(&self, error: Option<&'static str>) {
        *self
            .error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = error;
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the `running` guard serialises the stop/listen/save sequence against restarts and other enables"
    )]
    async fn enable(self: &Arc<Self>, enabled: bool) -> ApiResult<()> {
        let epoch = self
            .live
            .lock()
            .map_err(|e| {
                ApiError::other(format!(
                    "internal error: system agent state is unavailable ({e}); restart UniSSH"
                ))
            })?
            .epoch;
        let mut running = self.running.lock().await;
        self.stop(&mut running).await;
        // Every failure leaves a typed code in `error`; the UI words it from
        // the code (status), not from the message returned here.
        if !enabled {
            if save_settings(&self.settings_path, &Settings { enabled: false }).is_err() {
                return Err(self.fail("save_failed"));
            }
            self.set_error(self.endpoint.is_none().then_some("bind_failed"));
            return Ok(());
        }
        let Some(path) = self.endpoint.clone() else {
            return Err(self.fail("bind_failed"));
        };
        // Checked here rather than trusted to the caller: nothing listens
        // while the vault or the screen is locked, whoever asks. The setting
        // is saved all the same, so the next unlock starts the listener
        // (`resume_access`), exactly as after a restart of the app.
        if !self.may_serve().await {
            if save_settings(&self.settings_path, &Settings { enabled: true }).is_err() {
                return Err(self.fail("save_failed"));
            }
            self.set_error(None);
            return Ok(());
        }
        let (stop, mut task) = match self.listen(&path).await {
            Ok(started) => started,
            Err(code) => return Err(self.fail(code)),
        };
        if save_settings(&self.settings_path, &Settings { enabled: true }).is_err() {
            // Not left serving behind a setting that says off: stop the listener
            // we just started before reporting.
            stop.cancel();
            if tokio::time::timeout(std::time::Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
                await_aborted(task).await;
                #[cfg(unix)]
                remove_socket(&path);
            }
            return Err(self.fail("save_failed"));
        }
        // Checked again now that it is bound, as in `restart`: a lock that
        // landed meanwhile must not leave it serving.
        if self.core_unlocked().await {
            self.arm(epoch, &stop);
        } else {
            stop.cancel();
        }
        *running = Some(Running { stop, task });
        self.set_error(None);
        Ok(())
    }

    fn fail(&self, code: &'static str) -> ApiError {
        self.set_error(Some(code));
        ApiError::other(format!("system agent: {code}"))
    }

    /// Binds the socket and spawns the accept loop.
    #[cfg(unix)]
    async fn listen(
        &self,
        path: &Path,
    ) -> Result<(CancellationToken, tauri::async_runtime::JoinHandle<()>), &'static str> {
        use std::os::unix::fs::PermissionsExt;
        if !endpoint::fits_sun_path(path) {
            return Err("path_too_long");
        }
        let dir = path.parent().ok_or("bind_failed")?;
        endpoint::prepare_dir(dir).map_err(|e| bind_failed("socket directory", &e))?;
        endpoint::clear_stale_socket(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                "in_use"
            } else {
                "bind_failed"
            }
        })?;
        // A tokio listener needs the runtime's reactor: bound through std, then
        // registered from inside the runtime by the task.
        let listener = std::os::unix::net::UnixListener::bind(path).map_err(|e| {
            log::warn!("system agent: bind failed: {e}");
            "bind_failed"
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| bind_failed("socket permissions", &e))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| bind_failed("non-blocking mode", &e))?;

        let agent = self.core.system_agent();
        let stop = CancellationToken::new();
        let token = stop.clone();
        let error = self.error.clone();
        let socket = path.to_path_buf();
        let task = tauri::async_runtime::spawn(async move {
            let listener = match tokio::net::UnixListener::from_std(listener) {
                Ok(listener) => listener,
                Err(e) => {
                    log::warn!("system agent: listener registration failed: {e}");
                    set_tag(&error, "listener_failed");
                    return;
                }
            };
            log::info!("system agent: listening");
            // Whether the last accept failed, so a shortage is logged once.
            let mut starved = false;
            loop {
                let accepted = tokio::select! {
                    _ = token.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                match accepted {
                    Ok((stream, _)) => {
                        starved = false;
                        let agent = agent.clone();
                        let token = token.clone();
                        // `serve` closes a connection beyond its limit, and
                        // one that idles, by returning. It asks who the
                        // caller is only once the connection has a slot.
                        tauri::async_runtime::spawn(async move {
                            tokio::select! {
                                _ = token.cancelled() => {}
                                _ = agent.serve(stream, peer::caller) => {}
                            }
                        });
                    }
                    // Out of descriptors or memory, or a client that left
                    // before it was accepted: the listener is fine. Out of
                    // descriptors the connection stays queued and accept
                    // fails again at once, hence the pause.
                    Err(e) if endpoint::accept_error_is_transient(&e) => {
                        if !starved {
                            log::warn!("system agent: accept failed, still listening: {e}");
                        }
                        starved = true;
                        tokio::select! {
                            _ = token.cancelled() => break,
                            _ = tokio::time::sleep(ACCEPT_RETRY) => {}
                        }
                    }
                    Err(e) => {
                        log::warn!("system agent: accept failed: {e}");
                        set_tag(&error, "listener_failed");
                        break;
                    }
                }
            }
            drop(listener);
            remove_socket(&socket);
            // Already cancelled on a stop. After a listener failure this cuts
            // the open connections too (each withdraws its prompt), so nothing
            // is still served behind a status that says it stopped.
            token.cancel();
            log::info!("system agent: stopped");
        });
        Ok((stop, task))
    }

    /// Creates the pipe's first instance (current-user DACL, first-instance
    /// flag) and spawns the accept loop. The next instance is created before
    /// the connected one is handed off, so a client arriving meanwhile finds
    /// the pipe rather than "not found". The pipe disappears when the last
    /// instance closes, so there is nothing to clean up on stop: the loop
    /// waits for its connections, each of which disconnects its client, so
    /// the name is free again by the time `stop` sees the task end.
    #[cfg(windows)]
    async fn listen(
        &self,
        path: &Path,
    ) -> Result<(CancellationToken, tauri::async_runtime::JoinHandle<()>), &'static str> {
        let security = pipe::Security::current_user().map_err(|e| {
            log::warn!("system agent: pipe security descriptor failed: {e}");
            "bind_failed"
        })?;
        let first = Self::first_instance(path, &security).await?;

        let agent = self.core.system_agent();
        let stop = CancellationToken::new();
        let token = stop.clone();
        let error = self.error.clone();
        let name = path.as_os_str().to_owned();
        let task = tauri::async_runtime::spawn(async move {
            log::info!("system agent: listening");
            let mut server = first;
            let mut connections: Vec<tauri::async_runtime::JoinHandle<()>> = Vec::new();
            let mut failures = 0_u32;
            loop {
                // A persistent OS error must not turn this loop into a spin.
                if failures >= 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                let connected = tokio::select! {
                    _ = token.cancelled() => break,
                    connected = server.connect() => connected,
                };
                let Some(next) = Self::next_instance(&name, &security, &token, &error).await else {
                    break;
                };
                let mut stream = std::mem::replace(&mut server, next);
                // A client that gave up between connecting and being accepted
                // costs this instance only, not the listener.
                if let Err(e) = connected {
                    failures += 1;
                    log::debug!("system agent: pipe connect failed: {e}");
                    continue;
                }
                failures = 0;
                connections.retain(|c| !c.inner().is_finished());
                let agent = agent.clone();
                let token = token.clone();
                connections.push(tauri::async_runtime::spawn(async move {
                    // `serve` gives up a connection beyond its limit, and one
                    // that idles, by returning; the disconnect below closes it.
                    // It asks who the caller is only once the connection has
                    // a slot.
                    tokio::select! {
                        _ = token.cancelled() => {}
                        _ = agent.serve(&mut stream, |pipe| pipe::caller(pipe)) => {}
                    }
                    // Cut the client off rather than wait for it to close its
                    // end: an instance a client still holds keeps the name
                    // taken, and the next start needs it free.
                    if let Err(e) = stream.disconnect() {
                        log::debug!("system agent: pipe disconnect failed: {e}");
                    }
                }));
            }
            drop(server);
            // Already cancelled on a stop; after a listener failure this ends
            // the connections too, so the task finishes and status says so.
            token.cancel();
            for connection in connections {
                if let Err(e) = connection.await {
                    log::debug!("system agent: connection task ended with: {e}");
                }
            }
            log::info!("system agent: stopped");
        });
        Ok((stop, task))
    }

    /// Creates the instance the next client will connect to, as the Unix loop
    /// treats `accept`: a shortage (memory, handles, quota, every instance
    /// busy) is waited out, with the client that just connected held
    /// meanwhile and the shortage logged once; anything else ends the
    /// listener and is recorded in `error`. `None` is that, or a stop.
    #[cfg(windows)]
    async fn next_instance(
        name: &std::ffi::OsStr,
        security: &pipe::Security,
        token: &CancellationToken,
        error: &Mutex<Option<&'static str>>,
    ) -> Option<tokio::net::windows::named_pipe::NamedPipeServer> {
        let mut starved = false;
        loop {
            match pipe::create(name, security, false) {
                Ok(next) => return Some(next),
                Err(e) if pipe::create_error_is_transient(&e) => {
                    if !starved {
                        log::warn!("system agent: pipe creation failed, still listening: {e}");
                    }
                    starved = true;
                    tokio::select! {
                        _ = token.cancelled() => return None,
                        _ = tokio::time::sleep(ACCEPT_RETRY) => {}
                    }
                }
                Err(e) => {
                    log::warn!("system agent: pipe creation failed: {e}");
                    set_tag(error, "listener_failed");
                    return None;
                }
            }
        }
    }

    /// Creates the first instance. `ERROR_ACCESS_DENIED` means the name still
    /// exists; right after this app's own listener stopped that is usually its
    /// last instance on its way out, so it is retried for about two seconds
    /// before being reported as in use. (A name held by anyone else is
    /// reported the same way, just that much later.)
    #[cfg(windows)]
    async fn first_instance(
        path: &Path,
        security: &pipe::Security,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, &'static str> {
        let mut attempt = 0;
        loop {
            match pipe::create(path.as_os_str(), security, true) {
                Ok(first) => return Ok(first),
                Err(e) if pipe::in_use(&e) && attempt < 10 => {
                    log::debug!("system agent: pipe name still taken ({e}); retrying");
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
                Err(e) if pipe::in_use(&e) => {
                    log::debug!("system agent: pipe name taken: {e}");
                    return Err("in_use");
                }
                Err(e) => {
                    log::warn!("system agent: pipe creation failed: {e}");
                    return Err("bind_failed");
                }
            }
        }
    }

    async fn status(&self) -> ApiResult<Value> {
        let running = self.running.lock().await;
        let online = running
            .as_ref()
            .is_some_and(|r| !r.task.inner().is_finished());
        drop(running);
        let error = *self.error.lock().map_err(|e| {
            ApiError::other(format!(
                "internal error: system agent status is unavailable ({e}); restart UniSSH"
            ))
        })?;
        Ok(json!({
            "supported": self.endpoint.is_some(),
            "enabled": load_settings(&self.settings_path).enabled,
            "running": online,
            "endpoint": self.endpoint.as_ref().map(|p| p.to_string_lossy().into_owned()),
            "error": error,
        }))
    }

    /// Stops the listener on exit so the socket does not outlive the app. Runs
    /// on the event-loop thread and must not wait, so the socket is removed
    /// here rather than left to the listener task. Only a listener this
    /// instance owns has a stop token, so another instance's socket is never
    /// touched; one revoked earlier removed its own.
    fn shutdown(&self) {
        let stop = {
            let mut live = self.live();
            live.epoch += 1;
            live.stop.take()
        };
        if let Some(stop) = stop {
            stop.cancel();
            #[cfg(unix)]
            if let Some(path) = &self.endpoint {
                remove_socket(path);
            }
        }
    }
}

/// How long the accept loop waits after an accept (on Windows, the creation of
/// the next pipe instance) that failed for want of resources before trying
/// again.
const ACCEPT_RETRY: std::time::Duration = std::time::Duration::from_millis(200);

/// Sets the status tag from the listener task, which cannot return an error.
/// The slot holds only a tag, so a poisoned lock is recovered and overwritten.
fn set_tag(slot: &Mutex<Option<&'static str>>, tag: &'static str) {
    *slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tag);
}

/// Awaits a listener task after `abort()`, only to know it is gone; an error
/// (cancelled) is the expected outcome.
async fn await_aborted(task: tauri::async_runtime::JoinHandle<()>) {
    if let Err(e) = task.await {
        log::debug!("system agent: aborted listener task ended with: {e}");
    }
}

/// Removes the agent socket. Absence is the goal; anything else is logged,
/// since a stale socket makes the next start report `in_use`.
#[cfg(unix)]
fn remove_socket(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!("system agent: socket not removed: {e}");
        }
    }
}

/// Logs why binding failed and maps it to the `bind_failed` status code.
#[cfg(unix)]
fn bind_failed(step: &str, e: &std::io::Error) -> &'static str {
    log::warn!("system agent: bind failed at {step}: {e}");
    "bind_failed"
}

/// Stops the listener: vault lock, screen lock, sleep. Called with
/// `crate::mcp::revoke` from `crate::commands::revoke_agent_access`.
pub fn revoke(app: &tauri::AppHandle) {
    if let Some(controller) = app.try_state::<Arc<Controller>>() {
        // Prompts first, for the reason given at `Controller::stop`.
        controller.withdraw_prompts();
        controller.revoke();
    }
}

/// Restarts the listener after an unlock or a wake, if it is enabled and the
/// vault is unlocked. Called with `crate::mcp::resume_access` from
/// `crate::commands::resume_after_unlock`.
pub fn resume_access(app: &tauri::AppHandle) {
    if let Some(controller) = app.try_state::<Arc<Controller>>() {
        controller.resume();
    }
}

/// Stops the listener and removes its socket at app exit.
pub fn shutdown(app: &tauri::AppHandle) {
    if let Some(controller) = app.try_state::<Arc<Controller>>() {
        controller.withdraw_prompts();
        controller.shutdown();
    }
}

#[tauri::command]
pub async fn system_agent_status(state: State<'_, Arc<Controller>>) -> ApiResult<Value> {
    state.inner().status().await
}

#[tauri::command]
pub async fn system_agent_set_enabled(
    state: State<'_, Arc<Controller>>,
    enabled: bool,
) -> ApiResult<()> {
    state.inner().enable(enabled).await
}

/// The keys this device offers to the system agent, as `{vaultId, itemId}`.
#[tauri::command]
pub async fn system_agent_shared_keys(state: State<'_, Arc<Controller>>) -> ApiResult<Value> {
    let core = state.core.clone();
    let keys = tauri::async_runtime::spawn_blocking(move || core.system_agent_shared()).await??;
    Ok(Value::Array(
        keys.into_iter()
            .map(|k| json!({"vaultId": k.vault_id, "itemId": k.item_id}))
            .collect(),
    ))
}

#[tauri::command]
pub async fn system_agent_set_shared(
    state: State<'_, Arc<Controller>>,
    vault_id: String,
    item_id: String,
    shared: bool,
) -> ApiResult<()> {
    let core = state.core.clone();
    tauri::async_runtime::spawn_blocking(move || {
        core.set_system_agent_shared(vault_id, item_id, shared)
    })
    .await??;
    Ok(())
}
