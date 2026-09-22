//! Native-only managed SSH connections. No generic Core dispatcher or secret DTOs.
use super::*;
use std::time::{Duration, Instant};

/// Immutable saved-target snapshot. Credential references remain private to Core.
#[derive(Clone)]
pub struct Target {
    pub vault_id: String,
    pub profile_id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub revision: [u64; 2],
    auth: AuthMethod,
    prompt_password: bool,
    jumps: Vec<JumpHost>,
    proxy: Option<ProxyConfig>,
}

/// A lifetime independent of the HTTP request that created it.
#[derive(Clone)]
pub struct ConnectionPolicy {
    pub revision: [u64; 2],
    pub cancel: Arc<CancelToken>,
    pub deadline: Option<Instant>,
}

impl ConnectionPolicy {
    pub(super) fn check(&self, state: &CoreState) -> Result<(), FfiError> {
        if self.cancel.is_cancelled()
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            || state
                .storage
                .automation_revision()
                .map_err(FfiError::other)?
                != self.revision
        {
            return Err(FfiError::Locked);
        }
        Ok(())
    }

    pub(super) async fn invalidated(&self, state: &Arc<Mutex<Option<CoreState>>>) {
        loop {
            {
                let guard = lock_recover(state);
                if guard.as_ref().is_none_or(|st| self.check(st).is_err()) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Core {
    /// A lock/unlock or security-relevant local/synced write changes this snapshot.
    pub fn automation_revision(&self) -> Result<[u64; 2], FfiError> {
        self.with_state(|s| s.storage.automation_revision().map_err(FfiError::other))
    }

    /// Resolve the existing Personal anti-redirect contract without revealing a secret.
    /// A revision sandwich rejects changes during the existing multi-read resolver.
    pub fn automation_target(
        &self,
        vault_id: String,
        profile_id: String,
    ) -> Result<Target, FfiError> {
        let revision = self.automation_revision()?;
        let p = self.get_connection(vault_id.clone(), profile_id.clone())?;
        let prompt_password = matches!(p.auth, ProfileAuth::PromptPassword);
        let (user, auth) = if matches!(p.auth, ProfileAuth::Personal) {
            let destination = self.personal_destination(
                p.host.clone(),
                p.port,
                p.username_template.clone(),
                p.jumps.clone(),
                p.proxy.clone(),
            );
            let personal =
                self.resolve_personal_auth(vault_id.clone(), p.uid, destination, p.user.clone())?;
            (personal.user, personal.auth)
        } else {
            let default = self.get_account_default_username()?;
            (
                pick_username("", &p.user, default.as_deref()),
                profile_auth_to_method(&vault_id, p.auth),
            )
        };
        if self.automation_revision()? != revision {
            return Err(FfiError::Locked);
        }
        Ok(Target {
            vault_id,
            profile_id,
            label: p.label,
            host: p.host,
            port: p.port,
            user: apply_username_template(&user, p.username_template.as_deref()),
            revision,
            auth,
            prompt_password,
            jumps: p.jumps,
            proxy: p.proxy,
        })
    }

    /// Called on a blocking worker. No PTY, startup snippets, agent forwarding or retries.
    pub fn automation_connect(
        &self,
        target: &Target,
        policy: ConnectionPolicy,
        prompter: Option<Arc<dyn AuthPrompter>>,
    ) -> Result<Arc<ManagedConnection>, FfiError> {
        if target.revision != policy.revision {
            return Err(FfiError::Locked);
        }
        let mut auth = target.auth.clone();
        // Password prompting uses the trusted native prompter, never an MCP argument.
        if target.prompt_password {
            let answer = prompter
                .as_ref()
                .and_then(|p| {
                    p.prompt(AuthPromptRequest {
                        host: target.host.clone(),
                        port: target.port,
                        user: target.user.clone(),
                        name: "SSH authentication".into(),
                        instruction: String::new(),
                        prompts: vec![AuthPromptField {
                            prompt: "Password".into(),
                            echo: false,
                        }],
                    })
                })
                .filter(|a| a.len() == 1)
                .ok_or(FfiError::InvalidCredentials)?;
            auth = AuthMethod::Password {
                password: answer.into_iter().next().expect("one answer"),
            };
        }
        let result = connect_with_policy(
            &self.state,
            &self.rt,
            &Arc::new(Mutex::new(prompter)),
            &self.approver,
            &auth,
            &target.jumps,
            target.proxy.as_ref(),
            target.host.clone(),
            target.port,
            target.user.clone(),
            false,
            Some(&policy),
        );
        if let AuthMethod::Password { password } = &mut auth {
            zeroize::Zeroize::zeroize(password);
        }
        let client = result?;
        let connection = Arc::new(ManagedConnection {
            client: Arc::new(client),
            state: self.state.clone(),
            rt: self.rt.clone(),
            policy,
            admission: Mutex::new(()),
        });
        if !connection.is_valid() {
            connection.close();
            return Err(FfiError::Locked);
        }
        // A weak monitor cannot keep the connection alive; revokes even if the UI stalls.
        let weak = Arc::downgrade(&connection);
        self.rt.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let Some(connection) = weak.upgrade() else {
                    break;
                };
                // The monitor runs on the SSH runtime. Never block one of its
                // workers on Core's mutex while an admitted exec awaits that runtime.
                let valid = match connection.state.try_lock() {
                    Ok(state) => {
                        !connection.client.is_closed()
                            && state
                                .as_ref()
                                .is_some_and(|s| connection.policy.check(s).is_ok())
                    }
                    Err(std::sync::TryLockError::WouldBlock) => continue,
                    Err(std::sync::TryLockError::Poisoned(_)) => false,
                };
                if !valid {
                    connection.policy.cancel.cancel();
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        connection.client.disconnect(),
                    )
                    .await;
                    break;
                }
            }
        });
        Ok(connection)
    }
}

/// Persistent connection; each command opens an independent channel.
pub struct ManagedConnection {
    client: Arc<SshClient>,
    state: Arc<Mutex<Option<CoreState>>>,
    rt: Arc<tokio::runtime::Runtime>,
    policy: ConnectionPolicy,
    admission: Mutex<()>,
}

impl ManagedConnection {
    pub fn is_valid(&self) -> bool {
        let state = lock_recover(&self.state);
        !self.client.is_closed() && state.as_ref().is_some_and(|s| self.policy.check(s).is_ok())
    }

    /// Serializes final exec dispatch with close and Core writes. The bounded send
    /// does not perform authentication and cannot call a signer/UI under the lock.
    pub fn exec(
        &self,
        command: &str,
        observer: Arc<dyn ExecObserver>,
        command_cancel: Arc<CancelToken>,
        deadline: Instant,
    ) -> Result<Arc<ManagedExec>, FfiError> {
        let _admission = lock_recover(&self.admission);
        let state = lock_recover(&self.state);
        self.policy.check(state.as_ref().ok_or(FfiError::Locked)?)?;
        if command_cancel.is_cancelled() || Instant::now() >= deadline {
            return Err(FfiError::Locked);
        }
        let result = self.rt.block_on(async {
            let dispatch = async {
                let handle = self.client.exec_stream(command, Arc::new(ExecSinkBridge(observer))).await?;
                handle.close_stdin().await?;
                Ok::<_, unissh_ssh_transport::TransportError>(handle)
            };
            let cancellation = async {
                loop {
                    if command_cancel.is_cancelled() || self.policy.cancel.is_cancelled() { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            tokio::select! {
                biased;
                _ = cancellation => Err(FfiError::ssh("command dispatch outcome unknown")),
                result = tokio::time::timeout(
                    Duration::from_secs(5).min(self.policy.deadline.map_or(deadline, |until| until.min(deadline)).saturating_duration_since(Instant::now())), dispatch
                ) => result.map_err(|_| FfiError::ssh("command dispatch outcome unknown"))?.map_err(map_transport_err),
            }
        });
        let handle = match result {
            Ok(handle) => handle,
            Err(error) => {
                // An interrupted dispatch may already have reached the peer. Close
                // this transport and never retry or continue on an ambiguous channel.
                self.policy.cancel.cancel();
                return Err(error);
            }
        };
        Ok(Arc::new(ManagedExec {
            handle,
            rt: self.rt.clone(),
        }))
    }

    /// Cancellation is visible immediately; return only after any admitted dispatch.
    pub fn close(&self) {
        self.policy.cancel.cancel();
        let _admission = lock_recover(&self.admission);
        let _ = self.rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), self.client.disconnect()).await
        });
    }
}

impl Drop for ManagedConnection {
    fn drop(&mut self) {
        self.policy.cancel.cancel();
        let client = self.client.clone();
        self.rt.spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(2), client.disconnect()).await;
        });
    }
}

pub struct ManagedExec {
    handle: ExecHandle,
    rt: Arc<tokio::runtime::Runtime>,
}
impl ManagedExec {
    pub fn has_exited(&self) -> bool {
        self.handle.has_exited()
    }
    pub fn close(&self) {
        let _ = self.rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), self.handle.close()).await
        });
    }
}
