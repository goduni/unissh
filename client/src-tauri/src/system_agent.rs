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
//! setting is on — the same call sites as `crate::mcp::revoke` /
//! `crate::mcp::resume_access`, so the user never re-enables it by hand. A
//! connection open at a revoke is cut with the listener.
//!
//! Unix sockets today; the Windows named pipe is not implemented yet, so there
//! the listener reports itself unavailable.

#[cfg(unix)]
mod endpoint;
#[cfg(unix)]
mod peer;

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
    core: Arc<Core>,
    settings_path: PathBuf,
    /// Where the socket goes; `None` where the platform has no listener yet.
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
        #[cfg(not(unix))]
        let endpoint = {
            let _ = app;
            None
        };
        Arc::new(Self {
            core,
            settings_path,
            endpoint,
            running: tokio::sync::Mutex::new(None),
            live: Mutex::new(Live::default()),
            error: Arc::new(Mutex::new(None)),
        })
    }

    /// Starts the listener if the setting is on, the vault unlocked and the
    /// screen not locked; otherwise does nothing. Called at boot (where the
    /// vault is still locked, so the first unlock starts it) and from
    /// [`resume_access`].
    pub fn resume(self: &Arc<Self>) {
        let epoch = self.live.lock().unwrap().epoch;
        let this = self.clone();
        tauri::async_runtime::spawn(async move { this.restart(epoch).await });
    }

    async fn restart(self: &Arc<Self>, epoch: u64) {
        if crate::system_lock::is_screen_locked() {
            return;
        }
        let core = self.core.clone();
        let unlocked = tauri::async_runtime::spawn_blocking(move || core.is_unlocked())
            .await
            .unwrap_or(false);
        if !unlocked {
            return;
        }
        let mut running = self.running.lock().await;
        if !load_settings(&self.settings_path).enabled || self.live.lock().unwrap().epoch != epoch {
            return;
        }
        let serving = self.live.lock().unwrap().stop.is_some()
            && running
                .as_ref()
                .is_some_and(|r| !r.task.inner().is_finished());
        if serving {
            return;
        }
        self.stop(&mut running).await;
        let Some(path) = self.endpoint.clone() else {
            self.set_error(Some("unsupported"));
            return;
        };
        match self.listen(&path) {
            Ok((stop, task)) => {
                self.arm(epoch, &stop);
                *running = Some(Running { stop, task });
                self.set_error(None);
            }
            Err(code) => self.set_error(Some(code)),
        }
    }

    /// Stops the listener now and cuts its connections, keeping the setting.
    /// Any start already under way sees the new epoch and stands down.
    fn revoke(&self) {
        let stop = {
            let mut live = self.live.lock().unwrap();
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
        let mut live = self.live.lock().unwrap();
        if live.epoch == epoch {
            live.stop = Some(stop.clone());
        } else {
            stop.cancel();
        }
    }

    /// Stops the listener held in `running`, waiting up to 2 s for it to
    /// remove its socket before aborting it.
    async fn stop(&self, running: &mut Option<Running>) {
        self.live.lock().unwrap().stop = None;
        if let Some(mut old) = running.take() {
            old.stop.cancel();
            if tokio::time::timeout(std::time::Duration::from_secs(2), &mut old.task)
                .await
                .is_err()
            {
                old.task.abort();
                let _ = old.task.await;
            }
        }
    }

    fn set_error(&self, error: Option<&'static str>) {
        *self.error.lock().unwrap() = error;
    }

    async fn enable(self: &Arc<Self>, enabled: bool) -> ApiResult<()> {
        let epoch = self.live.lock().unwrap().epoch;
        let mut running = self.running.lock().await;
        self.stop(&mut running).await;
        // Every failure leaves a typed code in `error`; the UI words it from
        // the code (status), not from the message returned here.
        if !enabled {
            if save_settings(&self.settings_path, &Settings { enabled: false }).is_err() {
                return Err(self.fail("save_failed"));
            }
            self.set_error(None);
            return Ok(());
        }
        let Some(path) = self.endpoint.clone() else {
            return Err(self.fail("unsupported"));
        };
        let (stop, mut task) = match self.listen(&path) {
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
                let _ = task.await;
                let _ = std::fs::remove_file(&path);
            }
            return Err(self.fail("save_failed"));
        }
        self.arm(epoch, &stop);
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
    fn listen(
        &self,
        path: &Path,
    ) -> Result<(CancellationToken, tauri::async_runtime::JoinHandle<()>), &'static str> {
        use std::os::unix::fs::PermissionsExt;
        if !endpoint::fits_sun_path(path) {
            return Err("path_too_long");
        }
        let dir = path.parent().ok_or("bind_failed")?;
        endpoint::prepare_dir(dir).map_err(|_| "bind_failed")?;
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
            .map_err(|_| "bind_failed")?;
        listener.set_nonblocking(true).map_err(|_| "bind_failed")?;

        let agent = self.core.system_agent();
        let stop = CancellationToken::new();
        let token = stop.clone();
        let error = self.error.clone();
        let socket = path.to_path_buf();
        let task = tauri::async_runtime::spawn(async move {
            let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
                *error.lock().unwrap() = Some("listener_failed");
                return;
            };
            log::info!("system agent: listening");
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => {
                            let agent = agent.clone();
                            let token = token.clone();
                            tauri::async_runtime::spawn(async move {
                                let caller = peer::caller(&stream);
                                tokio::select! {
                                    _ = token.cancelled() => {}
                                    _ = agent.serve(stream, caller) => {}
                                }
                            });
                        }
                        Err(e) => {
                            log::warn!("system agent: accept failed: {e}");
                            *error.lock().unwrap() = Some("listener_failed");
                            break;
                        }
                    },
                }
            }
            drop(listener);
            let _ = std::fs::remove_file(&socket);
            log::info!("system agent: stopped");
        });
        Ok((stop, task))
    }

    #[cfg(not(unix))]
    fn listen(
        &self,
        _path: &Path,
    ) -> Result<(CancellationToken, tauri::async_runtime::JoinHandle<()>), &'static str> {
        Err("unsupported")
    }

    async fn status(&self) -> Value {
        let running = self.running.lock().await;
        let online = running
            .as_ref()
            .is_some_and(|r| !r.task.inner().is_finished());
        drop(running);
        json!({
            "supported": self.endpoint.is_some(),
            "enabled": load_settings(&self.settings_path).enabled,
            "running": online,
            "endpoint": self.endpoint.as_ref().map(|p| p.to_string_lossy().into_owned()),
            "error": *self.error.lock().unwrap(),
        })
    }

    /// Stops the listener on exit so the socket does not outlive the app. Runs
    /// on the event-loop thread and must not wait, so the socket is removed
    /// here rather than left to the listener task. Only a listener this
    /// instance owns has a stop token, so another instance's socket is never
    /// touched; one revoked earlier removed its own.
    fn shutdown(&self) {
        let stop = {
            let mut live = self.live.lock().unwrap();
            live.epoch += 1;
            live.stop.take()
        };
        if let Some(stop) = stop {
            stop.cancel();
            #[cfg(unix)]
            if let Some(path) = &self.endpoint {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// Stops the listener: vault lock, screen lock, sleep. Beside every
/// `crate::mcp::revoke` call.
pub fn revoke(app: &tauri::AppHandle) {
    if let Some(controller) = app.try_state::<Arc<Controller>>() {
        controller.revoke();
    }
}

/// Restarts the listener after an unlock or a wake, if it is enabled and the
/// vault is unlocked. Beside every `crate::mcp::resume_access` call.
pub fn resume_access(app: &tauri::AppHandle) {
    if let Some(controller) = app.try_state::<Arc<Controller>>() {
        controller.resume();
    }
}

/// Stops the listener and removes its socket at app exit.
pub fn shutdown(app: &tauri::AppHandle) {
    if let Some(controller) = app.try_state::<Arc<Controller>>() {
        controller.shutdown();
    }
}

#[tauri::command]
pub async fn system_agent_status(state: State<'_, Arc<Controller>>) -> ApiResult<Value> {
    Ok(state.inner().status().await)
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
