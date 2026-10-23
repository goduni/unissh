//! Talking to the server: one session per process, and sync.
//!
//! A command that needs the server signs in with the unlocked keyset (the same
//! challenge signature the app uses), reuses that session for what else it
//! does, and signs out when it is done. Nothing that could resume a session is
//! written to disk: an unlocked keyset is the only way in, so a copy of this
//! directory without the master password and Secret Key gets nobody a session.

use std::cell::RefCell;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use unissh_cloud::client::http;
use unissh_cloud::identity;
use unissh_cloud::transport::HttpSyncTransport;
use unissh_ffi::{Core, FfiSyncMode, FfiSyncReport, FfiSyncTransport};

use crate::device::Device;
use crate::failure::{best_effort, Res};
use crate::home::Link;

/// How old the local copy may get before a command that reads hosts syncs first.
pub const STALE_AFTER: Duration = Duration::from_secs(5 * 60);

/// How long one sign-in is reused before the next call signs in again — well
/// inside the server's access-token lifetime (15 minutes by default), so a
/// long-running picker never sends an expired token.
const REUSE: Duration = Duration::from_secs(5 * 60);

/// One server session, closed when dropped.
struct ServerSession {
    base_url: String,
    access: String,
    opened: Instant,
}

impl ServerSession {
    /// Signs in as this device. The core must be unlocked.
    fn open(core: &Core, link: &Link) -> Res<Self> {
        let tokens = identity::login(
            http(),
            &link.base_url,
            core,
            &link.account_id,
            &link.device_id,
        )?;
        Ok(Self {
            base_url: link.base_url.clone(),
            access: tokens.access_token,
            opened: Instant::now(),
        })
    }

    fn reusable(&self) -> bool {
        self.opened.elapsed() < REUSE
    }
}

impl Drop for ServerSession {
    fn drop(&mut self) {
        // Best effort: a server that cannot be reached lets the session expire.
        best_effort(identity::logout(http(), &self.base_url, &self.access));
    }
}

/// The process's server session: opened on first use, renewed once stale,
/// closed with the process.
#[derive(Default)]
pub struct Sessions {
    current: RefCell<Option<ServerSession>>,
}

impl Sessions {
    /// A bearer for a call to the server about to be made.
    pub fn access(&self, core: &Core, link: &Link) -> Res<String> {
        let mut current = self.current.borrow_mut();
        if !current.as_ref().is_some_and(ServerSession::reusable) {
            // The stale session is closed before the next one opens.
            *current = None;
            *current = Some(ServerSession::open(core, link)?);
        }
        Ok(current
            .as_ref()
            .map_or_else(String::new, |s| s.access.clone()))
    }
}

/// Pushes what changed here and pulls the account's vaults, verifying every
/// object before it is applied. The core must be unlocked.
pub fn sync(device: &Device) -> Res<FfiSyncReport> {
    let _one_at_a_time = device.home.sync_lock()?;
    sync_locked(device)
}

/// [`sync`], with the sync lock already held.
fn sync_locked(device: &Device) -> Res<FfiSyncReport> {
    let transport: Arc<dyn FfiSyncTransport> = Arc::new(HttpSyncTransport::new(
        device.link.base_url.clone(),
        device.access()?,
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
    if is_fresh(device) {
        return;
    }
    let result = device.home.sync_lock().and_then(|_one_at_a_time| {
        // Another command may have synced while this one waited for the lock.
        if is_fresh(device) {
            return Ok(None);
        }
        sync_locked(device).map(Some)
    });
    match result {
        Ok(None) => {}
        Ok(Some(report)) => warn_about(&report),
        Err(e) => eprintln!("unissh: sync failed, using the copy on this machine: {e}"),
    }
}

fn is_fresh(device: &Device) -> bool {
    device
        .home
        .last_sync()
        .and_then(|at| SystemTime::now().duration_since(at).ok())
        .is_some_and(|age| age < STALE_AFTER)
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
