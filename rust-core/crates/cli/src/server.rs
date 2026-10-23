//! Talking to the server: a session for the length of one command, and sync.
//!
//! A command that needs the server signs in with the unlocked keyset (the same
//! challenge signature the app uses) and signs out when it is done. Nothing
//! that could resume a session is written to disk: an unlocked keyset is the
//! only way in, so a copy of this directory without the master password and
//! Secret Key gets nobody a session.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use unissh_cloud::client::http;
use unissh_cloud::identity;
use unissh_cloud::transport::HttpSyncTransport;
use unissh_ffi::{Core, FfiSyncMode, FfiSyncReport, FfiSyncTransport};

use crate::device::Device;
use crate::failure::{best_effort, Res};
use crate::home::Link;

/// How old the local copy may get before a command that reads hosts syncs first.
pub const STALE_AFTER: Duration = Duration::from_secs(5 * 60);

/// A server session for one command, closed when dropped.
pub struct ServerSession<'link> {
    link: &'link Link,
    access: String,
}

impl<'link> ServerSession<'link> {
    /// Signs in as this device. The core must be unlocked.
    pub fn open(core: &Core, link: &'link Link) -> Res<Self> {
        let tokens = identity::login(
            http(),
            &link.base_url,
            core,
            &link.account_id,
            &link.device_id,
        )?;
        Ok(Self {
            link,
            access: tokens.access_token,
        })
    }

    /// The bearer for calls made in this session.
    pub fn access(&self) -> &str {
        &self.access
    }
}

impl Drop for ServerSession<'_> {
    fn drop(&mut self) {
        // Best effort: a server that cannot be reached lets the session expire.
        best_effort(identity::logout(http(), &self.link.base_url, &self.access));
    }
}

/// Pushes what changed here and pulls the account's vaults, verifying every
/// object before it is applied. The core must be unlocked.
pub fn sync(device: &Device) -> Res<FfiSyncReport> {
    let _one_at_a_time = device.home.sync_lock()?;
    let session = ServerSession::open(&device.core, &device.link)?;
    let transport: Arc<dyn FfiSyncTransport> = Arc::new(HttpSyncTransport::new(
        device.link.base_url.clone(),
        session.access().to_owned(),
    ));
    let report =
        device
            .core
            .sync_now(transport, device.link.space_id.clone(), FfiSyncMode::Full)?;
    device.home.mark_synced()?;
    Ok(report)
}

/// Syncs when the local copy is older than [`STALE_AFTER`]. A failure is a
/// warning: the command goes on with the copy on this machine.
pub fn sync_if_stale(device: &Device) {
    let fresh = device
        .home
        .last_sync()
        .and_then(|at| SystemTime::now().duration_since(at).ok())
        .is_some_and(|age| age < STALE_AFTER);
    if fresh {
        return;
    }
    match sync(device) {
        Ok(report) => warn_about(&report),
        Err(e) => eprintln!("unissh: sync failed, using the copy on this machine: {e}"),
    }
}

/// Sends a session recording made just now to the server. When that fails the
/// recording stays here, encrypted, until the next sync.
pub fn push_recording(device: &Device) {
    match sync(device) {
        Ok(report) => warn_about(&report),
        Err(e) => eprintln!(
            "unissh: the session recording stays on this machine until the next sync: {e}"
        ),
    }
}

/// One line about a sync, for `unissh sync`.
pub fn summary(report: &FfiSyncReport) -> String {
    format!(
        "synced: {} received, {} sent",
        report.applied, report.pushed
    )
}

/// Says what a sync could not do. Silent when it did everything.
pub fn warn_about(report: &FfiSyncReport) {
    if report.rejected > 0 {
        eprintln!(
            "unissh: {} object(s) from the server failed verification and were not applied \
             (signed by someone this account does not trust, or tampered with)",
            report.rejected
        );
    }
    if report.conflicts > 0 {
        eprintln!(
            "unissh: {} change(s) conflict with an edit made here at the same version; \
             the copy on this machine was kept",
            report.conflicts
        );
    }
    if !report.too_large.is_empty() {
        eprintln!(
            "unissh: {} item(s) are larger than the server accepts and stayed on this machine",
            report.too_large.len()
        );
    }
}
