//! Adapter to the existing Core. Credentials and signing stay below this boundary.
use super::*;
use unissh_ffi::{
    automation::{ConnectionPolicy, ManagedConnection, ManagedExec},
    AuthPrompter, CancelToken, Core, ExecObserver, FfiError,
};

pub trait PromptFactory: Send + Sync {
    fn for_connection(
        &self,
        attribution: &str,
        cancel: Cancel,
        deadline: Instant,
    ) -> Arc<dyn AuthPrompter>;
}

pub struct CoreExecutor {
    pub core: Arc<Core>,
    pub prompts: Arc<dyn PromptFactory>,
}
fn error(e: FfiError) -> ToolError {
    match e {
        FfiError::Locked => ToolError::Locked,
        FfiError::HostUntrusted => ToolError::HostUntrusted,
        FfiError::HostKeyMismatch { .. } => ToolError::HostChanged,
        _ => ToolError::TargetUnavailable,
    }
}
impl Executor for CoreExecutor {
    fn revision(&self) -> Result<[u64; 2]> {
        self.core.automation_revision().map_err(error)
    }
    fn resolve(&self, vault: &str, profile: &str) -> Result<Target> {
        let t = self
            .core
            .automation_target(vault.into(), profile.into())
            .map_err(error)?;
        Ok(Target {
            info: TargetInfo {
                vault_id: t.vault_id.clone(),
                profile_id: t.profile_id.clone(),
                label: t.label.clone(),
                host: t.host.clone(),
                port: t.port,
                user: t.user.clone(),
            },
            revision: t.revision,
            payload: Arc::new(t),
        })
    }
    fn connect(
        &self,
        target: &Target,
        cancel: Cancel,
        deadline: Option<Instant>,
        attribution: &str,
    ) -> Result<Arc<dyn Connection>> {
        let target = target
            .payload
            .downcast_ref::<unissh_ffi::automation::Target>()
            .ok_or(ToolError::TargetUnavailable)?;
        let prompt = self.prompts.for_connection(
            attribution,
            cancel.clone(),
            deadline.map_or_else(
                || Instant::now() + Duration::from_secs(330),
                |until| until.min(Instant::now() + Duration::from_secs(330)),
            ),
        );
        self.core
            .automation_connect(
                target,
                ConnectionPolicy {
                    revision: target.revision,
                    cancel: CancelToken::from_shared(cancel),
                    deadline,
                },
                Some(prompt),
            )
            .map(|c| Arc::new(CoreConnection(c)) as Arc<dyn Connection>)
            .map_err(error)
    }
}
struct CoreConnection(Arc<ManagedConnection>);
impl Connection for CoreConnection {
    fn exec(
        &self,
        command: &str,
        sink: Arc<dyn Output>,
        cancel: Cancel,
        deadline: Instant,
    ) -> Result<Arc<dyn Command>> {
        self.0
            .exec(
                command,
                Arc::new(Sink(sink)),
                CancelToken::from_shared(cancel),
                deadline,
            )
            .map(|c| Arc::new(CoreCommand(c)) as Arc<dyn Command>)
            .map_err(|_| ToolError::OutcomeUnknown)
    }
    fn valid(&self) -> bool {
        self.0.is_valid()
    }
    fn close(&self) {
        self.0.close();
    }
}
struct CoreCommand(Arc<ManagedExec>);
impl Command for CoreCommand {
    fn close(&self) {
        self.0.close();
    }
}
struct Sink(Arc<dyn Output>);
impl ExecObserver for Sink {
    fn on_stdout(&self, data: Vec<u8>) {
        self.0.data(false, data);
    }
    fn on_stderr(&self, data: Vec<u8>) {
        self.0.data(true, data);
    }
    fn on_exit(&self, code: i32) {
        self.0.exited(u32::try_from(code).ok());
    }
}
