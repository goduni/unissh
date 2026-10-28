//! Talking to the server: one session per process, and sync.
//!
//! A command that needs the server signs in with the unlocked keyset (the same
//! challenge signature the app uses), reuses that session for what else it
//! does, and signs out when it is done. Nothing that could resume a session is
//! written to disk: an unlocked keyset is the only way in, so a copy of this
//! directory without the master password and Secret Key gets nobody a session.

use std::cell::RefCell;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use unissh_cloud::client::http;
use unissh_cloud::identity;
use unissh_cloud::transport::HttpSyncTransport;
use unissh_ffi::{
    Core, FfiDiscardReport, FfiSyncMode, FfiSyncReport, FfiSyncTransport, FfiUnpushableItem,
    FfiUnpushableReason,
};

use crate::device::Device;
use crate::failure::{best_effort, Failure, Res};
use crate::home::Link;
use crate::tty::one_line;

/// How old the local copy may get before a command that reads hosts syncs first.
pub const STALE_AFTER: Duration = Duration::from_secs(5 * 60);

/// The longest one sign-in is reused before the next call signs in again.
/// Shorter when the server's access tokens live shorter: see [`reuse_for`].
const REUSE: Duration = Duration::from_secs(5 * 60);

/// How long a session whose access token expires at `access_expires` (the
/// server's clock, unix seconds) is reused: half its remaining life, so a
/// clock a little off either way still never sends an expired token, and at
/// most [`REUSE`].
fn reuse_for(access_expires: Option<i64>, now_unix: i64) -> Duration {
    access_expires.map_or(REUSE, |at| {
        let half = at.saturating_sub(now_unix) / 2;
        Duration::from_secs(u64::try_from(half).unwrap_or(0)).min(REUSE)
    })
}

/// One server session, closed when dropped.
struct ServerSession {
    base_url: String,
    access: String,
    opened: Instant,
    reuse: Duration,
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
        )
        .map_err(|e| {
            Failure::from(e).hint_for(
                "not_found",
                "the server no longer has this machine's device (revoked over 30 days ago, \
                 or paired but never signed in within a week): `unissh logout --local`, \
                 then `unissh login` again",
            )
        })?;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        Ok(Self {
            base_url: link.base_url.clone(),
            access: tokens.access_token,
            opened: Instant::now(),
            reuse: reuse_for(tokens.access_expires, now_unix),
        })
    }

    fn reusable(&self) -> bool {
        self.opened.elapsed() < self.reuse
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

/// [`sync`] that first forgets which changes the server refused, so that they
/// are sent again (`unissh sync --retry-refused`): for a server whose limit
/// was raised, or a refusal that was not about the change after all.
pub fn sync_retrying_refused(device: &Device) -> Res<FfiSyncReport> {
    let _one_at_a_time = device.home.sync_lock()?;
    let access = device.access()?;
    let space = space_of(device, &access);
    device.core.retry_refused_uploads(space)?;
    sync_locked(device)
}

/// [`sync`], with the sync lock already held.
fn sync_locked(device: &Device) -> Res<FfiSyncReport> {
    let access = device.access()?;
    let space = space_of(device, &access);
    let transport: Arc<dyn FfiSyncTransport> =
        Arc::new(HttpSyncTransport::new(device.link.base_url.clone(), access));
    let report = device.core.sync_now(transport, space, FfiSyncMode::Full)?;
    device.home.mark_synced()?;
    Ok(report)
}

/// Drops this account's edits in vault `vault_id` (hex, as `list_vaults` names
/// it) that no push can deliver and puts back the server's copy (#166): the
/// vault is read from the server first, and the core pushes again before it
/// drops anything, so only a refusal confirmed now drops an edit (see
/// `HttpSyncTransport::discard_unpushable_and_pull`). The core must be
/// unlocked.
pub fn discard_unpushable(device: &Device, vault_id: &str) -> Res<FfiDiscardReport> {
    let _one_at_a_time = device.home.sync_lock()?;
    let access = device.access()?;
    let space = space_of(device, &access);
    HttpSyncTransport::new(device.link.base_url.clone(), access)
        .discard_unpushable_and_pull(&device.core, &space, vault_id)
        .map_err(Failure::from)
}

/// The space this device's cloud vaults are bound in — the account's first,
/// as the app picks it. A device that has none on record (an escrow sign-in
/// that could not read the spaces, or an account that had none yet) looks
/// again at every sync and keeps what it finds. Without one a sync still
/// pulls, but sends nothing, and that is said.
fn space_of(device: &Device, access: &str) -> String {
    if !device.link.space_id.is_empty() {
        return device.link.space_id.clone();
    }
    let found = identity::list_spaces(http(), &device.link.base_url, access).map(|spaces| {
        spaces
            .into_iter()
            .next()
            .map(|s| s.space_id)
            .unwrap_or_default()
    });
    match found {
        Ok(space) if !space.is_empty() => {
            let link = Link {
                space_id: space.clone(),
                ..device.link.clone()
            };
            if let Err(e) = device.home.save_link(&link) {
                eprintln!("unissh: could not record the account's space: {e}");
            }
            space
        }
        Ok(_) => {
            eprintln!(
                "unissh: the account has no space on the server yet, so nothing made here \
                 (a session recording, say) is sent until it has one"
            );
            String::new()
        }
        Err(e) => {
            eprintln!(
                "unissh: could not read the account's spaces ({e}); nothing made here is sent \
                 this time"
            );
            String::new()
        }
    }
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

/// After a write to a vault, sends it to the server the way the app does,
/// and says where the change stands: `done` ("Deleted", "Saved") is what
/// happened here.
///
/// A local vault never syncs; with `offline` the change waits for the next
/// sync. A sync that cannot reach the server is a warning — the change goes
/// with the next one. A server that refuses the change is a failure: the
/// change stays on this machine only, and the user must hear that rather than
/// believe it went through. The push leaves an item it cannot deliver out and
/// goes on with the rest (#166), so a refusal comes back two ways: the sync
/// fails (a refusal of the request), or it succeeds and names this account's
/// edits in `vault_id` among those it could not send. Either fails the
/// command. (A Viewer's write never gets here: the core refuses it before
/// storing anything, `FfiError::ReadOnlyVault`. A refusal here means the
/// server knows of a role or policy this device does not yet.)
pub fn push_after_write(
    device: &Device,
    vault_id: &str,
    cloud: bool,
    offline: bool,
    done: &str,
) -> Res<()> {
    if !cloud {
        println!("{done}.");
        return Ok(());
    }
    if offline {
        println!("{done} here; the change is sent with the next sync.");
        return Ok(());
    }
    match sync(device) {
        Ok(report) if left_out_here(&report, vault_id) => {
            warn_about(&report);
            Err(refused_here(done, "it cannot be sent"))
        }
        Ok(report) => {
            println!("{done}.");
            warn_about(&report);
            Ok(())
        }
        Err(e) if is_refusal(&e) => Err(refused_here(done, &e.to_string())),
        Err(e) => {
            println!("{done} here.");
            eprintln!("unissh: the change is sent with the next sync: {e}");
            Ok(())
        }
    }
}

/// The failure of a write the server will not take: it stays here only.
fn refused_here(done: &str, why: &str) -> Failure {
    Failure::msg(format!(
        "{done} on this machine only: the server refused the change ({why}). \
         This account may not change the vault; the other devices keep what it had."
    ))
}

/// Whether a sync left out an edit this account made in vault `vault_id`:
/// the change just written there is not on the server.
fn left_out_here(report: &FfiSyncReport, vault_id: &str) -> bool {
    report
        .unpushable
        .iter()
        .any(|item| item.mine && item.vault_id == vault_id)
}

/// Whether a sync failed because the server refused what this device sent —
/// not because it could not be reached — so that a retry changes nothing.
/// The push reports a refusal as `sync push rejected (<code>): …` (see
/// `unissh_cloud::transport`); `forbidden` is the vault's permission check.
fn is_refusal(failure: &Failure) -> bool {
    failure.message.contains("sync push rejected (forbidden)")
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
    for line in unpushable_lines(&report.unpushable) {
        eprintln!("unissh: {line}");
    }
}

/// What an item of the core's `item_type` is, in a few words.
pub const fn kind(item_type: u32) -> &'static str {
    match item_type {
        1 => "SSH key",
        2 => "certificate",
        3 => "host",
        4 => "password",
        5 => "group",
        6 => "note",
        7 => "identity",
        8 => "host binding",
        9 => "snippet",
        10 => "recording",
        _ => "item",
    }
}

/// One item no push can deliver, as a list entry: its kind and id (its name
/// is inside the encrypted content the sync does not read) and why.
pub fn unpushable_entry(item: &FfiUnpushableItem) -> String {
    let why = match item.reason {
        FfiUnpushableReason::NotAuthorized => "this account may not change the vault",
        FfiUnpushableReason::ServerRefused => "the server refused it",
    };
    format!(
        "{} {} ({why})",
        kind(item.item_type),
        one_line(&item.item_id)
    )
}

/// What a sync says about the edits it could not send (#166), one line per
/// vault: they stay on this machine, nothing else is held up, and how to drop
/// the ones made here in favour of the server's copy.
fn unpushable_lines(items: &[FfiUnpushableItem]) -> Vec<String> {
    let mut vaults: Vec<(&str, &str)> = Vec::new();
    for item in items {
        let vault = (item.vault_id.as_str(), item.vault_name.as_str());
        if !vaults.contains(&vault) {
            vaults.push(vault);
        }
    }
    vaults
        .into_iter()
        .map(|(id, name)| {
            let here: Vec<&FfiUnpushableItem> = items.iter().filter(|i| i.vault_id == id).collect();
            let shown = if name.is_empty() { id } else { name };
            let entries: Vec<String> = here.iter().copied().map(unpushable_entry).collect();
            let fix = if here.iter().any(|i| i.mine) {
                format!(
                    "; `unissh vaults discard-unpushable {id}` drops the ones made here \
                     and restores the server's copy"
                )
            } else {
                String::new()
            };
            format!(
                "{} change(s) in vault \"{}\" cannot be sent and stay on this machine: {}{fix}",
                here.len(),
                one_line(shown),
                entries.join(", ")
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use unissh_ffi::{FfiSyncReport, FfiUnpushableItem, FfiUnpushableReason};

    use super::{is_refusal, left_out_here, reuse_for, unpushable_lines, REUSE};
    use crate::failure::Failure;

    /// A sync names what it could not send by vault, by kind and id, and
    /// points at the discard only where this account made some of it.
    #[test]
    fn unsent_edits_are_listed_per_vault_with_the_way_out() {
        let item = |vault: &str, id: &str, mine, reason| FfiUnpushableItem {
            vault_id: vault.to_owned(),
            vault_name: format!("{vault}-name"),
            item_id: id.to_owned(),
            item_type: 3,
            mine,
            reason,
        };
        let lines = unpushable_lines(&[
            item("aa", "web", true, FfiUnpushableReason::NotAuthorized),
            item("bb", "db", false, FfiUnpushableReason::ServerRefused),
        ]);
        assert_eq!(
            lines,
            [
                "1 change(s) in vault \"aa-name\" cannot be sent and stay on this machine: \
                 host web (this account may not change the vault); \
                 `unissh vaults discard-unpushable aa` drops the ones made here and restores \
                 the server's copy",
                "1 change(s) in vault \"bb-name\" cannot be sent and stay on this machine: \
                 host db (the server refused it)",
            ]
        );
    }

    /// A write the sync left out — this account's edit in that vault — is
    /// not on the server; a teammate's item, or another vault's, says
    /// nothing about it.
    #[test]
    fn a_write_the_sync_left_out_is_one_the_server_refused() {
        let item = |vault: &str, mine| FfiUnpushableItem {
            vault_id: vault.to_owned(),
            vault_name: String::new(),
            item_id: "web".to_owned(),
            item_type: 3,
            mine,
            reason: FfiUnpushableReason::ServerRefused,
        };
        let report = |unpushable| FfiSyncReport {
            applied: 0,
            skipped_stale: 0,
            conflicts: 0,
            rejected: 0,
            pushed: 0,
            too_large: Vec::new(),
            unpushable,
        };
        assert!(left_out_here(&report(vec![item("aa", true)]), "aa"));
        assert!(!left_out_here(&report(vec![item("aa", false)]), "aa"));
        assert!(!left_out_here(&report(vec![item("bb", true)]), "aa"));
    }

    /// Half the token's remaining life, never more than the cap and nothing
    /// for one already expired; a server that does not say gets the cap.
    #[test]
    fn a_session_is_reused_for_half_its_token_life_at_most() {
        assert_eq!(reuse_for(Some(1_120), 1_000), Duration::from_secs(60));
        assert_eq!(reuse_for(Some(1_900), 1_000), REUSE);
        assert_eq!(reuse_for(Some(900), 1_000), Duration::ZERO);
        assert_eq!(reuse_for(None, 1_000), REUSE);
    }

    /// A push the vault's permissions refused fails the write; a server that
    /// could not be reached only delays it. The text is what the cloud
    /// transport reports for each.
    #[test]
    fn a_refused_push_is_told_apart_from_an_unreachable_server() {
        let refused = "sync push rejected (forbidden): viewer cannot write objects";
        assert!(is_refusal(&Failure::msg(refused)), "{refused}");
        for later in ["sync push: connection refused", "sync push http 502"] {
            assert!(!is_refusal(&Failure::msg(later)), "{later}");
        }
    }
}
