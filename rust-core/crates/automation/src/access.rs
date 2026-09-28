//! Saved native consent, separate from live grants and SSH execution.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedAccess {
    integration_id: String,
    label: String,
    targets: Vec<TargetInfo>,
    fingerprint: Vec<u8>,
    expires_unix: Option<u64>,
    approval_mode: ApprovalMode,
    max_timeout_ms: u32,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl Broker {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn save_grant(
        &self,
        owner: &str,
        label: &str,
        targets: &BTreeMap<String, Target>,
        seconds: Option<u32>,
        approval_mode: ApprovalMode,
        max_timeout_ms: u32,
        fingerprint: Vec<u8>,
    ) -> Result<()> {
        let mut saved = self.executor.load_access()?;
        saved.retain(|s| s.integration_id != owner);
        if saved.len() >= GRANTS_TOTAL {
            return Err(ToolError::Busy);
        }
        saved.push(SavedAccess {
            integration_id: owner.into(),
            label: label.into(),
            targets: targets.values().map(|t| t.info.clone()).collect(),
            fingerprint,
            expires_unix: seconds.map(|s| now() + u64::from(s)),
            approval_mode,
            max_timeout_ms,
        });
        self.executor.save_access(&saved)
    }

    /// Explicit native revocation must remove consent before reporting success.
    pub fn forget_access(&self, owner: Option<&str>) -> Result<()> {
        let _admission = self.admission.write().unwrap_or_else(|e| e.into_inner());
        self.revocation_epoch.fetch_add(1, Ordering::SeqCst);
        self.revoke_inner(owner);
        let mut saved = self.executor.load_access()?;
        saved.retain(|s| owner.is_some_and(|o| s.integration_id != o));
        self.executor.save_access(&saved)
    }

    /// Native lock/sleep/exit stops execution without deleting the user's choices.
    pub fn suspend(&self) {
        let _admission = self.admission.write().unwrap_or_else(|e| e.into_inner());
        self.suspended.store(true, Ordering::SeqCst);
        self.revocation_epoch.fetch_add(1, Ordering::SeqCst);
        self.revoke_inner(None);
        *lock(&self.access_revision) = None;
    }
    /// Called only by the native unlock/wake/listener lifecycle, never by MCP.
    pub fn resume(&self) {
        self.resume_if_current(self.lifecycle_epoch());
    }
    pub fn lifecycle_epoch(&self) -> u64 {
        self.revocation_epoch.load(Ordering::SeqCst)
    }
    /// A queued native wake/unlock cannot undo a newer lock or revocation.
    pub fn resume_if_current(&self, epoch: u64) {
        let _admission = self.admission.write().unwrap_or_else(|e| e.into_inner());
        if self.lifecycle_epoch() != epoch {
            return;
        }
        self.suspended.store(false, Ordering::SeqCst);
        *lock(&self.access_revision) = None;
    }

    pub(super) fn restore_access(&self) {
        if self.suspended.load(Ordering::SeqCst) {
            return;
        }
        let Ok(revision) = self.executor.revision() else {
            return;
        };
        if *lock(&self.access_revision) == Some(revision) {
            return;
        }
        let _admission = self.admission.write().unwrap_or_else(|e| e.into_inner());
        if self.suspended.load(Ordering::SeqCst) {
            return;
        }
        let mut restored = lock(&self.access_revision);
        if *restored == Some(revision) {
            return;
        }
        let Ok(saved) = self.executor.load_access() else {
            return;
        };
        let Ok(fingerprint) = self.executor.access_fingerprint() else {
            return;
        };
        let mut grants = Vec::new();
        for consent in saved {
            if consent.fingerprint != fingerprint
                || consent.expires_unix.is_some_and(|until| until <= now())
                || consent.targets.is_empty()
                || consent.targets.len() > 64
                || !(1..=86_400_000).contains(&consent.max_timeout_ms)
            {
                continue;
            }
            if lock(&self.state)
                .grants
                .contains_key(&consent.integration_id)
            {
                continue;
            }
            let mut targets = BTreeMap::new();
            for info in &consent.targets {
                match self.executor.resolve(&info.vault_id, &info.profile_id) {
                    Ok(target) if target.revision == revision => {
                        targets.insert(id(), target);
                    }
                    _ => {
                        targets.clear();
                        break;
                    }
                }
            }
            if targets.len() != consent.targets.len() {
                continue;
            }
            // Do not revive an expiry crossed while resolving targets.
            let until = match consent.expires_unix {
                Some(expiry) => match expiry.checked_sub(now()).filter(|left| *left > 0) {
                    Some(left) => Some(Instant::now() + Duration::from_secs(left)),
                    None => continue,
                },
                None => None,
            };
            grants.push((
                consent.integration_id,
                Grant {
                    label: consent.label,
                    approval_mode: consent.approval_mode,
                    max_timeout_ms: consent.max_timeout_ms,
                    until,
                    targets,
                    revision,
                    epoch: id(),
                    slots: Arc::new(Semaphore::new(4)),
                },
            ));
        }
        if self.executor.revision().ok() != Some(revision) {
            return;
        }
        let mut state = lock(&self.state);
        for (owner, grant) in grants.into_iter().take(GRANTS_TOTAL) {
            state.grants.entry(owner).or_insert(grant);
        }
        *restored = Some(revision);
    }

    /// Native editor only: saved choices are not evidence of active permission.
    pub(super) fn saved_access_review(&self) -> Value {
        let saved = self.executor.load_access().unwrap_or_default();
        json!(saved
            .into_iter()
            .map(|s| json!({
                "integration_id":s.integration_id,"targets":s.targets,
                "remaining_seconds":s.expires_unix.map(|until| until.saturating_sub(now())),
                "approval_mode":s.approval_mode,"max_timeout_ms":s.max_timeout_ms
            }))
            .collect::<Vec<_>>())
    }
}
