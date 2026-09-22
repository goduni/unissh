//! Trusted desktop control plane. None of these commands is an MCP tool.
use crate::{
    error::{ApiError, ApiResult},
    observers::AppPrompter,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{atomic::Ordering, Arc, Mutex},
    time::Instant,
};
use tauri::{Manager, State};
use unissh_automation::{
    core::{CoreExecutor, PromptFactory},
    ApprovalMode, Broker, Cancel,
};
use unissh_ffi::{AuthPromptRequest, AuthPrompter, Core};
use unissh_mcp::{credentials::Credentials, CancellationToken, LocalServer};

struct Prompts(Arc<AppPrompter>);
struct AttributedPrompt {
    inner: Arc<AppPrompter>,
    label: String,
    cancel: Cancel,
    deadline: Instant,
}
impl PromptFactory for Prompts {
    fn for_connection(
        &self,
        label: &str,
        cancel: Cancel,
        deadline: Instant,
    ) -> Arc<dyn AuthPrompter> {
        Arc::new(AttributedPrompt {
            inner: self.0.clone(),
            label: label.into(),
            cancel,
            deadline,
        })
    }
}
impl AuthPrompter for AttributedPrompt {
    fn prompt(&self, mut request: AuthPromptRequest) -> Option<Vec<String>> {
        request.name = format!("MCP · {} · {}", self.label, request.name);
        self.inner.prompt_until(
            request,
            || self.cancel.load(Ordering::SeqCst),
            self.deadline,
        )
    }
}
struct Running {
    stop: CancellationToken,
    task: tauri::async_runtime::JoinHandle<()>,
    port: u16,
}
pub struct Controller {
    pub broker: Arc<Broker>,
    core: Arc<Core>,
    credentials: Option<Arc<Credentials>>,
    running: tokio::sync::Mutex<Option<Running>>,
    error: Mutex<Option<&'static str>>,
}
impl Controller {
    pub fn new(core: Arc<Core>, prompts: Arc<AppPrompter>, path: PathBuf) -> Arc<Self> {
        let credentials = Credentials::load(path).ok().map(Arc::new);
        let error = if credentials.is_none() {
            Some("configuration_invalid")
        } else {
            None
        };
        let broker = Broker::new(Arc::new(CoreExecutor {
            core: core.clone(),
            prompts: Arc::new(Prompts(prompts)),
        }));
        Arc::new(Self {
            broker,
            core,
            credentials,
            running: tokio::sync::Mutex::new(None),
            error: Mutex::new(error),
        })
    }
    fn credentials(&self) -> ApiResult<Arc<Credentials>> {
        self.credentials.clone().ok_or_else(|| {
            ApiError::other("Local MCP configuration is invalid; access is disabled.")
        })
    }
    pub fn resume(self: &Arc<Self>) {
        let Some(store) = &self.credentials else {
            return;
        };
        let (enabled, port) = store.settings();
        if enabled {
            let this = self.clone();
            tauri::async_runtime::spawn(async move {
                let _ = this.enable(true, port).await;
            });
        }
    }
    async fn enable(self: &Arc<Self>, enabled: bool, port: u16) -> ApiResult<()> {
        let mut running = self.running.lock().await;
        let broker = self.broker.clone();
        tauri::async_runtime::spawn_blocking(move || broker.revoke(None)).await?;
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
        let store = self.credentials()?;
        if !enabled {
            store
                .set_enabled(false, port)
                .map_err(|_| ApiError::other("Cannot save MCP settings."))?;
            *self.error.lock().unwrap() = None;
            return Ok(());
        }
        let server = match LocalServer::bind(port, store.clone(), self.broker.clone()).await {
            Ok(server) => server,
            Err(_) => {
                *self.error.lock().unwrap() = Some("port_unavailable");
                return Err(ApiError::other(
                    "MCP port is unavailable. Choose another local port.",
                ));
            }
        };
        let port = server
            .local_addr()
            .map_err(|_| ApiError::other("MCP listener failed."))?
            .port();
        store
            .set_enabled(true, port)
            .map_err(|_| ApiError::other("Cannot save MCP settings."))?;
        let stop = CancellationToken::new();
        let token = stop.clone();
        let weak = Arc::downgrade(self);
        let task = tauri::async_runtime::spawn(async move {
            if server.serve(token).await.is_err() {
                if let Some(this) = weak.upgrade() {
                    *this.error.lock().unwrap() = Some("listener_failed");
                    this.broker.revoke(None);
                }
            }
        });
        *running = Some(Running { stop, task, port });
        *self.error.lock().unwrap() = None;
        Ok(())
    }
    /// Called natively before screen lock/suspend/exit, independent of the webview.
    pub fn revoke(&self) {
        self.broker.revoke(None);
    }
    async fn status(self: &Arc<Self>) -> ApiResult<Value> {
        let running = self.running.lock().await;
        let port = running
            .as_ref()
            .map(|r| r.port)
            .or_else(|| self.credentials.as_ref().map(|c| c.settings().1))
            .unwrap_or(0);
        let online = running
            .as_ref()
            .is_some_and(|r| !r.task.inner().is_finished());
        let integrations = self
            .credentials
            .as_ref()
            .map(|c| c.list())
            .unwrap_or_default();
        let error = *self.error.lock().unwrap();
        drop(running);
        let broker = self.broker.clone();
        let review = tauri::async_runtime::spawn_blocking(move || broker.review()).await?;
        Ok(
            json!({"enabled":online,"port":port,"endpoint":format!("http://127.0.0.1:{port}/mcp"),"error":error,"integrations":integrations,"activity":review}),
        )
    }
}

pub fn revoke(app: &tauri::AppHandle) {
    if let Some(controller) = app.try_state::<Arc<Controller>>() {
        controller.revoke();
    }
}

#[tauri::command]
pub async fn mcp_status(state: State<'_, Arc<Controller>>) -> ApiResult<Value> {
    state.inner().status().await
}
#[tauri::command]
pub async fn mcp_set_enabled(
    state: State<'_, Arc<Controller>>,
    enabled: bool,
    port: u16,
) -> ApiResult<()> {
    state.inner().enable(enabled, port).await
}
#[tauri::command]
pub async fn mcp_create_integration(
    state: State<'_, Arc<Controller>>,
    label: String,
) -> ApiResult<Value> {
    let _serial = state.running.lock().await;
    let store = state.credentials()?;
    let (id, token) = store
        .create(label)
        .map_err(|_| ApiError::other("Cannot create MCP integration."))?;
    Ok(json!({"id":id,"token":token}))
}
#[tauri::command]
pub async fn mcp_rotate_integration(
    state: State<'_, Arc<Controller>>,
    id: String,
) -> ApiResult<Value> {
    let _serial = state.running.lock().await;
    let broker = state.broker.clone();
    let old = id.clone();
    tauri::async_runtime::spawn_blocking(move || broker.revoke(Some(&old))).await?;
    let (id, token) = state
        .credentials()?
        .rotate(&id)
        .map_err(|_| ApiError::other("Cannot rotate MCP token."))?;
    Ok(json!({"id":id,"token":token}))
}
#[tauri::command]
pub async fn mcp_delete_integration(
    state: State<'_, Arc<Controller>>,
    id: String,
) -> ApiResult<()> {
    let _serial = state.running.lock().await;
    let broker = state.broker.clone();
    let old = id.clone();
    tauri::async_runtime::spawn_blocking(move || broker.revoke(Some(&old))).await?;
    state
        .credentials()?
        .delete(&id)
        .map_err(|_| ApiError::other("Cannot remove MCP integration."))
}
#[derive(Deserialize)]
pub struct TargetRef {
    vault_id: String,
    profile_id: String,
}
#[tauri::command]
pub async fn mcp_grant(
    state: State<'_, Arc<Controller>>,
    id: String,
    targets: Vec<TargetRef>,
    seconds: Option<u32>,
    ticket: String,
    approval_mode: Option<ApprovalMode>,
    max_timeout_ms: Option<u32>,
) -> ApiResult<()> {
    let serial = state.running.lock().await;
    if serial.is_none() {
        return Err(ApiError::other("Enable local MCP first."));
    }
    let record = state
        .credentials()?
        .list()
        .into_iter()
        .find(|i| i.id == id)
        .ok_or_else(|| ApiError::other("Integration is unavailable."))?;
    let broker = state.broker.clone();
    tauri::async_runtime::spawn_blocking(move || {
        broker.grant_with_limits(
            &id,
            record.label,
            targets
                .into_iter()
                .map(|t| (t.vault_id, t.profile_id))
                .collect(),
            seconds,
            &ticket,
            approval_mode.unwrap_or_default(),
            max_timeout_ms.unwrap_or(600_000),
        )
    })
    .await?
    .map_err(|e| ApiError::other(e.message()))
}
#[tauri::command]
pub async fn mcp_revoke(state: State<'_, Arc<Controller>>, id: Option<String>) -> ApiResult<()> {
    let _serial = state.running.lock().await;
    let broker = state.broker.clone();
    tauri::async_runtime::spawn_blocking(move || broker.revoke(id.as_deref())).await?;
    Ok(())
}
#[tauri::command]
pub async fn mcp_approve(
    state: State<'_, Arc<Controller>>,
    run_id: String,
    allowed: bool,
) -> ApiResult<()> {
    let broker = state.broker.clone();
    tauri::async_runtime::spawn_blocking(move || broker.approve(&run_id, allowed))
        .await?
        .map_err(|e| ApiError::other(e.message()))
}
#[tauri::command]
pub async fn mcp_targets(state: State<'_, Arc<Controller>>) -> ApiResult<Value> {
    let core = state.core.clone();
    let broker = state.broker.clone();
    tauri::async_runtime::spawn_blocking(move||{
        let ticket = broker.grant_ticket().map_err(|e| ApiError::other(e.message()))?;
        let mut targets=Vec::new();
        let mut vaults=Vec::new();
        for vault in core.list_vaults()? {
            vaults.push(json!({"id":vault.vault_id,"name":vault.name}));
            for p in core.list_connections(vault.vault_id.clone())? {
                targets.push(json!({"vault_id":vault.vault_id,"profile_id":p.profile_id,"label":p.label,"host":p.host,"port":p.port,"user":p.user}));
            }
        }
        if broker.grant_ticket().map_err(|e| ApiError::other(e.message()))? != ticket {
            return Err(ApiError::other("Hosts changed. Select them again."));
        }
        Ok(json!({"targets":targets,"vaults":vaults,"ticket":ticket}))
    }).await?
}

#[tauri::command]
pub async fn mcp_close_session(
    state: State<'_, Arc<Controller>>,
    session_id: String,
) -> ApiResult<Value> {
    let broker = state.broker.clone();
    tauri::async_runtime::spawn_blocking(move || broker.close_session(&session_id))
        .await?
        .map_err(|e| ApiError::other(e.message()))
}
#[tauri::command]
pub async fn mcp_cancel_command(
    state: State<'_, Arc<Controller>>,
    run_id: String,
) -> ApiResult<Value> {
    let broker = state.broker.clone();
    tauri::async_runtime::spawn_blocking(move || broker.cancel_command(&run_id))
        .await?
        .map_err(|e| ApiError::other(e.message()))
}
