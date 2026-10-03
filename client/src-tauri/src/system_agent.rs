//! The system agent: an ssh-agent endpoint local programs (`ssh-add -l`, `git`,
//! `ssh`) can reach, offering the vault keys this device shares with it.
//!
//! Off by default; the setting persists and the listener resumes at boot. The
//! protocol and key policy are the core's (`unissh_ffi::SystemAgent`); this
//! module owns only the OS endpoint and its lifecycle, modelled on the MCP
//! controller. Unix sockets today; the Windows named pipe is not implemented
//! yet, so there the listener reports itself unavailable.

#[cfg(unix)]
mod endpoint;

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

pub struct Controller {
    core: Arc<Core>,
    settings_path: PathBuf,
    /// Where the socket goes; `None` where the platform has no listener yet.
    endpoint: Option<PathBuf>,
    running: tokio::sync::Mutex<Option<Running>>,
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
            error: Arc::new(Mutex::new(None)),
        })
    }

    /// Starts the listener at boot if it was left on.
    pub fn resume(self: &Arc<Self>) {
        if load_settings(&self.settings_path).enabled {
            let this = self.clone();
            tauri::async_runtime::spawn(async move {
                let _ = this.enable(true).await;
            });
        }
    }

    fn set_error(&self, error: Option<&'static str>) {
        *self.error.lock().unwrap() = error;
    }

    async fn enable(self: &Arc<Self>, enabled: bool) -> ApiResult<()> {
        let mut running = self.running.lock().await;
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
        if !enabled {
            save_settings(&self.settings_path, &Settings { enabled: false })
                .map_err(|_| ApiError::other("Cannot save system agent settings."))?;
            self.set_error(None);
            return Ok(());
        }
        let Some(path) = self.endpoint.clone() else {
            self.set_error(Some("unsupported"));
            return Err(ApiError::other(
                "The system agent is not available on this platform yet.",
            ));
        };
        let (stop, task) = match self.listen(&path) {
            Ok(started) => started,
            Err(code) => {
                self.set_error(Some(code));
                return Err(ApiError::other(match code {
                    "in_use" => "Another agent is already listening on the UniSSH socket.",
                    _ => "The system agent socket could not be opened.",
                }));
            }
        };
        save_settings(&self.settings_path, &Settings { enabled: true })
            .map_err(|_| ApiError::other("Cannot save system agent settings."))?;
        *running = Some(Running { stop, task });
        self.set_error(None);
        Ok(())
    }

    /// Binds the socket and spawns the accept loop.
    #[cfg(unix)]
    fn listen(
        &self,
        path: &Path,
    ) -> Result<(CancellationToken, tauri::async_runtime::JoinHandle<()>), &'static str> {
        use std::os::unix::fs::PermissionsExt;
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
                                tokio::select! {
                                    _ = token.cancelled() => {}
                                    _ = agent.serve(stream) => {}
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

    /// Stops the listener on exit so the socket does not outlive the app.
    fn shutdown(&self) {
        if let Ok(mut running) = self.running.try_lock() {
            if let Some(r) = running.take() {
                r.stop.cancel();
                if let Some(path) = &self.endpoint {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
}

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
