//! Session recordings: listed across every vault, found by id, replayed,
//! exported and deleted — what the app's Recordings screen does.
//!
//! A recording is the core's asciicast v2 document (`Core::get_recording`).
//! Export writes it unchanged, so it plays in `asciinema` and can be handed to
//! someone who does not run UniSSH.

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};
use unissh_ffi::{Core, FfiSyncTarget, RecordingMeta};
use zeroize::Zeroizing;

use crate::device::Device;
use crate::failure::{best_effort, Failure, Res};
use crate::replay::{self, Timing};
use crate::server;
use crate::tty::{confirm, one_line};

/// A recording and the vault it lives in.
pub struct Recording {
    /// The vault's id.
    pub vault_id: String,
    /// The vault's name.
    pub vault_name: String,
    /// Whether the vault syncs with the server.
    pub cloud: bool,
    /// What the core lists about it.
    pub meta: RecordingMeta,
}

impl Recording {
    /// `user@host`, or the host alone.
    fn target(&self) -> String {
        let m = &self.meta;
        if m.user.trim().is_empty() {
            m.host.clone()
        } else {
            format!("{}@{}", m.user, m.host)
        }
    }

    /// Whether `needle` (lowercase) occurs in the label, host or vault.
    fn mentions(&self, needle: &str) -> bool {
        [
            self.meta.label.as_str(),
            self.meta.host.as_str(),
            self.vault_name.as_str(),
        ]
        .into_iter()
        .any(|text| text.to_lowercase().contains(needle))
    }
}

/// Every recording of every vault, newest first.
///
/// A vault that cannot be read is reported and skipped, as with the hosts.
pub fn load(core: &Core) -> Res<Vec<Recording>> {
    let mut all = Vec::new();
    for vault in core.list_vaults()? {
        match core.list_recordings(vault.vault_id.clone()) {
            Ok(metas) => all.extend(metas.into_iter().map(|meta| Recording {
                vault_id: vault.vault_id.clone(),
                vault_name: vault.name.clone(),
                cloud: vault.sync_target == FfiSyncTarget::Cloud,
                meta,
            })),
            Err(e) => eprintln!("unissh: skipping vault \"{}\": {e}", one_line(&vault.name)),
        }
    }
    all.sort_by_key(|r| std::cmp::Reverse(r.meta.started_unix));
    Ok(all)
}

/// The recordings that mention `filter` (case-insensitive), or all of them.
pub fn filter<'r>(all: &'r [Recording], filter: Option<&str>) -> Vec<&'r Recording> {
    let needle = filter.map(str::to_lowercase);
    all.iter()
        .filter(|r| needle.as_deref().is_none_or(|n| r.mentions(n)))
        .collect()
}

/// The recording `query` names: its id, else the one id that contains it
/// (any case), so the distinctive end of an id is enough. Several matches are
/// an error that lists them, never a guess.
pub fn find<'r>(all: &'r [Recording], query: &str) -> Res<&'r Recording> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return Err(Failure::msg("name a recording by its id"));
    }
    if let Some(exact) = all.iter().find(|r| r.meta.recording_id.to_lowercase() == q) {
        return Ok(exact);
    }
    let found: Vec<_> = all
        .iter()
        .filter(|r| r.meta.recording_id.to_lowercase().contains(&q))
        .collect();
    match found.as_slice() {
        [] => Err(Failure::msg(format!(
            "no recording matches \"{query}\" (`unissh recordings list` lists them)"
        ))),
        [one] => Ok(*one),
        many => {
            let mut text = format!("\"{query}\" matches several recordings; give more of the id:");
            for r in many {
                let _ = write!(text, "\n  {}", line(r));
            }
            Err(Failure::msg(text))
        }
    }
}

/// `2026-10-26T14:03Z` for unix seconds.
fn utc(unix: u64) -> String {
    let days = unix / 86_400;
    let secs = unix % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60
    )
}

/// The calendar date `days` after 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, for days on or after the epoch).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

/// `45s`, `3m 05s`, `1h 02m`.
fn length(secs: f64) -> String {
    // A duration the core measured; a damaged one shows as nothing.
    let s = Duration::try_from_secs_f64(secs.max(0.0))
        .unwrap_or_default()
        .as_secs();
    match s {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m {:02}s", s / 60, s % 60),
        s => format!("{}h {:02}m", s / 3600, s % 3600 / 60),
    }
}

/// What is worth knowing beyond the columns: a recording the size cap cut
/// short, and one an MCP client's command made.
fn note(r: &Recording) -> String {
    let mut notes = Vec::new();
    if r.meta.truncated {
        notes.push("truncated".to_owned());
    }
    if let Some(mcp) = &r.meta.mcp {
        notes.push(format!("mcp: {} ({})", mcp.application, mcp.outcome));
    }
    notes.join(", ")
}

/// One recording on one line, for the ambiguity error and the delete prompt.
fn line(r: &Recording) -> String {
    format!(
        "{}  {}  {}  {}",
        one_line(&r.meta.recording_id),
        utc(r.meta.started_unix),
        one_line(&r.meta.label),
        one_line(&r.target())
    )
}

/// The recordings as a table.
pub fn table(shown: &[&Recording]) -> String {
    let width = |f: &dyn Fn(&Recording) -> usize| shown.iter().map(|&r| f(r)).max().unwrap_or(0);
    let id_w = width(&|r| r.meta.recording_id.chars().count());
    let label_w = width(&|r| r.meta.label.chars().count()).min(32);
    let target_w = width(&|r| r.target().chars().count()).min(40);
    let vault_w = width(&|r| r.vault_name.chars().count()).min(24);
    let mut text = String::new();
    for r in shown {
        let _ = writeln!(
            text,
            "{:<id_w$}  {}  {:>7}  {:<label_w$}  {:<target_w$}  {:<vault_w$}  {}",
            one_line(&r.meta.recording_id),
            utc(r.meta.started_unix),
            length(r.meta.duration_secs),
            one_line(&r.meta.label),
            one_line(&r.target()),
            one_line(&r.vault_name),
            one_line(&note(r)),
        );
    }
    text
}

/// The recordings as JSON, for scripts. What was recorded is not in it, and
/// neither is an MCP recording's command (`export` has both).
pub fn json(shown: &[&Recording]) -> Value {
    Value::Array(
        shown
            .iter()
            .map(|r| {
                let m = &r.meta;
                json!({
                    "id": m.recording_id,
                    "vault": r.vault_name,
                    "label": m.label,
                    "host": m.host,
                    "user": m.user,
                    "started_unix": m.started_unix,
                    "duration_secs": m.duration_secs,
                    "truncated": m.truncated,
                    "size_bytes": m.size_bytes,
                    "mcp": m.mcp.as_ref().map(|mcp| json!({
                        "application": mcp.application,
                        "outcome": mcp.outcome,
                        "exit_code": mcp.exit_code,
                    })),
                })
            })
            .collect(),
    )
}

/// `unissh recordings list`.
pub fn list(device: &Device, filter_by: Option<&str>, as_json: bool) -> Res<()> {
    let all = load(&device.core)?;
    let shown = filter(&all, filter_by);
    if as_json {
        let text =
            serde_json::to_string_pretty(&json(&shown)).map_err(|e| Failure::msg(e.to_string()))?;
        println!("{text}");
    } else if shown.is_empty() {
        eprintln!("unissh: no recordings to show");
    } else {
        print!("{}", table(&shown));
    }
    Ok(())
}

/// The recording `query` names, and its document.
fn document(device: &Device, query: &str) -> Res<(RecordingMeta, Zeroizing<String>)> {
    let all = load(&device.core)?;
    let found = find(&all, query)?;
    let cast = Zeroizing::new(
        device
            .core
            .get_recording(found.vault_id.clone(), found.meta.recording_id.clone())?,
    );
    Ok((found.meta.clone(), cast))
}

/// `unissh recordings play`. Returns the exit status ([`replay::play`]).
pub fn play(device: &Device, query: &str, timing: Timing) -> Res<u8> {
    let (meta, cast) = document(device, query)?;
    if meta.truncated {
        eprintln!("unissh: the size limit cut this recording short; the session went on after it");
    }
    replay::play(&cast, timing)
}

/// `unissh recordings export`: the asciicast as stored, to `path` (`-` is
/// stdout). The file is owner-only: it holds what the session showed.
pub fn export(device: &Device, query: &str, path: &Path, force: bool) -> Res<()> {
    let (meta, cast) = document(device, query)?;
    if path.as_os_str() == "-" {
        let mut out = io::stdout().lock();
        out.write_all(cast.as_bytes())?;
        out.flush()?;
        return Ok(());
    }
    save(path, cast.as_bytes(), force)?;
    println!(
        "Exported {} to {} (asciicast v2: `asciinema play` plays it).",
        one_line(&meta.label),
        path.display()
    );
    Ok(())
}

/// Writes `bytes` to `path`, owner-only (0600) however it got there.
///
/// Without `force` the file must not exist (`create_new`, which does not
/// follow a symbolic link either). With `force` an existing file is replaced,
/// not rewritten: the bytes go to a new owner-only file beside it that is then
/// renamed over it, so the old file's mode and owner do not carry over and a
/// failed write leaves the old file as it was. A symbolic link is refused
/// rather than replaced or followed: the user named a link, and either would
/// be a surprise.
fn save(path: &Path, bytes: &[u8], force: bool) -> Res<()> {
    let failed = |e: &dyn std::fmt::Display| Failure::msg(format!("{}: {e}", path.display()));
    if !force {
        let mut file = crate::home::create_private_file(path).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                Failure::msg(format!("{} exists; --force replaces it", path.display()))
            } else {
                failed(&e)
            }
        })?;
        if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            best_effort(std::fs::remove_file(path));
            return Err(failed(&e));
        }
        return Ok(());
    }
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(Failure::msg(format!(
            "{} is a symbolic link; name the file itself",
            path.display()
        )));
    }
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Private from creation on every native platform; removed on failure.
    let mut file = crate::home::private_tempfile(dir).map_err(|e| failed(&e))?;
    file.write_all(bytes)
        .and_then(|()| file.as_file().sync_all())
        .map_err(|e| failed(&e))?;
    file.persist(path).map_err(|e| failed(&e.error))?;
    Ok(())
}

/// `unissh recordings rm`: deletes the recording, then sends the deletion to
/// the server unless `offline` (or the vault is local). In a vault this
/// account can only view, the core refuses the deletion before anything is
/// stored (`FfiError::ReadOnlyVault`); a deletion the server still refuses
/// fails the command ([`server::push_after_write`]).
pub fn remove(device: &Device, query: &str, yes: bool, offline: bool) -> Res<()> {
    let all = load(&device.core)?;
    let found = find(&all, query)?;
    let reach = if found.cloud {
        "here and, once synced, on every device of the vault"
    } else {
        "from this machine"
    };
    confirm(
        yes,
        &format!(
            "This deletes the recording\n  {}\nof vault \"{}\" {reach}.\n",
            line(found),
            one_line(&found.vault_name)
        ),
    )?;
    device
        .core
        .delete_recording(found.vault_id.clone(), found.meta.recording_id.clone())?;
    server::push_after_write(device, &[&found.vault_id], found.cloud, offline, "Deleted")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recording(id: &str, label: &str, started_unix: u64) -> Recording {
        Recording {
            vault_id: "v".to_owned(),
            vault_name: "team".to_owned(),
            cloud: true,
            meta: RecordingMeta {
                mcp: None,
                recording_id: id.to_owned(),
                label: label.to_owned(),
                host: "10.0.0.1".to_owned(),
                user: "deploy".to_owned(),
                started_unix,
                duration_secs: 1.0,
                truncated: false,
                size_bytes: 10,
            },
        }
    }

    fn found<'r>(all: &'r [Recording], query: &str) -> Option<&'r str> {
        find(all, query).ok().map(|r| r.meta.recording_id.as_str())
    }

    /// The whole id, or the one id a part of it occurs in; a part shared by
    /// several ids is refused with the candidates listed.
    #[test]
    fn find_takes_an_id_or_a_unique_part_of_one_and_refuses_ambiguity() {
        let all = [
            recording("rec-web-1761487200000", "web", 1),
            recording("rec-web-1761487299999", "web", 2),
            recording("mcp-run-7", "db", 3),
        ];
        assert_eq!(
            found(&all, "MCP-RUN-7"),
            Some("mcp-run-7"),
            "whole id, any case"
        );
        assert_eq!(found(&all, "99999"), Some("rec-web-1761487299999"));
        assert_eq!(found(&all, "nope"), None);
        let Err(err) = find(&all, "rec-web") else {
            panic!("an ambiguous id must not pick a recording");
        };
        assert!(
            err.message.contains("rec-web-1761487200000")
                && err.message.contains("rec-web-1761487299999"),
            "{err}"
        );
    }

    #[test]
    fn filter_matches_label_host_or_vault() {
        let mut db = recording("b", "db", 1);
        db.meta.host = "db.internal".to_owned();
        let all = [recording("a", "web", 2), db];
        let ids = |v: Vec<&Recording>| {
            v.iter()
                .map(|r| r.meta.recording_id.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(filter(&all, Some("INTERNAL"))), ["b"]);
        assert_eq!(ids(filter(&all, Some("web"))), ["a"]);
        assert_eq!(ids(filter(&all, Some("team"))).len(), 2);
    }

    /// Times are shown in UTC, including across a leap day and a year end.
    #[test]
    fn start_times_are_utc_dates() {
        assert_eq!(utc(0), "1970-01-01T00:00Z");
        assert_eq!(utc(951_825_599), "2000-02-29T11:59Z");
        assert_eq!(utc(1_798_761_540), "2026-12-31T23:59Z");
    }

    #[test]
    fn lengths_read_in_the_largest_two_units() {
        assert_eq!(length(45.4), "45s");
        assert_eq!(length(185.0), "3m 05s");
        assert_eq!(length(3_720.0), "1h 02m");
        assert_eq!(length(f64::NAN), "0s");
    }

    /// Scripts get the metadata, never what was recorded nor an MCP command.
    #[test]
    fn json_lists_metadata_but_no_mcp_command() {
        let mut r = recording("mcp-1", "db", 1);
        r.meta.mcp = Some(unissh_ffi::McpRecordingMeta {
            command: Some("export TOKEN=s3cret".to_owned()),
            application: "Agent".to_owned(),
            outcome: "completed".to_owned(),
            exit_code: Some(0),
        });
        let value = json(&[&r]);
        assert_eq!(value[0]["mcp"]["application"], "Agent");
        assert_eq!(value[0]["id"], "mcp-1");
        assert!(!value.to_string().contains("s3cret"));
    }

    /// Without `--force` an existing file is left alone; with it the file is
    /// replaced by an owner-only one — never written through a symbolic link,
    /// never keeping the old file's wider mode.
    #[cfg(unix)]
    #[test]
    fn an_export_refuses_an_existing_file_and_force_replaces_it_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.cast");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused = save(&path, b"new", false).unwrap_err();
        assert!(refused.message.contains("--force"), "{refused}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");

        save(&path, b"new", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "replaced owner-only, not with the old mode");

        let link = dir.path().join("link.cast");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(save(&link, b"via link", true).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }
}
