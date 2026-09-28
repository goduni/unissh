//! Native MCP recording capture. No keys or plaintext spool files leave Core.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    sync::Weak,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

// Raw bytes plus JSON/base64 and a readable preview stay below the existing
// recording envelope's 8 MiB budget. Event count also bounds tiny-packet overhead.
const MAX_BYTES: usize = 512 * 1024;
const MAX_EVENTS: usize = 8192;

/// Device-local native preferences. No MCP tool may change capture or retention.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordingPreferences {
    pub max_bytes: u32,
    /// None keeps recordings until explicitly deleted. Cleanup runs on list/save.
    pub retention_days: Option<u32>,
}
impl Default for RecordingPreferences {
    fn default() -> Self {
        Self {
            max_bytes: MAX_BYTES as u32,
            retention_days: None,
        }
    }
}
const PREFERENCES_KEY: &str = "mcp.recording_preferences.v1";
fn preferences(state: &CoreState) -> Result<RecordingPreferences, FfiError> {
    state
        .storage
        .get_meta(PREFERENCES_KEY)
        .map_err(FfiError::other)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(FfiError::other))
        .transpose()
        .map(|p| p.unwrap_or_default())
}
impl Core {
    pub fn mcp_recording_preferences(&self) -> Result<RecordingPreferences, FfiError> {
        self.with_state(preferences)
    }
    pub fn set_mcp_recording_preferences(
        &self,
        value: RecordingPreferences,
    ) -> Result<(), FfiError> {
        if !(16 * 1024..=MAX_BYTES as u32).contains(&value.max_bytes)
            || value
                .retention_days
                .is_some_and(|days| !(1..=3650).contains(&days))
        {
            return Err(FfiError::other("invalid recording preferences"));
        }
        self.with_state(|state| {
            state
                .storage
                .set_meta(
                    PREFERENCES_KEY,
                    &serde_json::to_vec(&value).map_err(FfiError::other)?,
                )
                .map_err(FfiError::other)
        })
    }
}
/// Only authenticated/decrypted MCP recording metadata can authorize retention.
/// Tombstones propagate through normal encrypted vault sync.
pub(super) fn retention_cutoff(state: &CoreState) -> Result<Option<u64>, FfiError> {
    let Some(days) = preferences(state)?.retention_days else {
        return Ok(None);
    };
    Ok(Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(u64::from(days) * 86400),
    ))
}

#[derive(Default)]
pub(super) struct RetentionSweep {
    after: Option<Vec<u8>>,
    next: Option<Instant>,
}

/// Save-time cleanup is incremental: at most four payloads per minute per vault.
/// Listing already reads every recording and applies retention in that same pass.
fn prune(state: &CoreState, vault: &Vault<'_>, vault_key: &[u8]) -> Result<(), FfiError> {
    let Some(cutoff) = retention_cutoff(state)? else {
        return Ok(());
    };
    let mut sweeps = lock_recover(&state.recording_retention);
    let sweep = sweeps.entry(vault_key.to_vec()).or_default();
    if sweep.next.is_some_and(|next| Instant::now() < next) {
        return Ok(());
    }
    sweep.next = Some(Instant::now() + std::time::Duration::from_secs(60));
    let items = state
        .storage
        .item_ids_page(vault_key, ITEM_TYPE_RECORDING, sweep.after.as_deref(), 5)
        .map_err(FfiError::other)?;
    let finished = items.len() <= 4;
    for item_id in items.into_iter().take(4) {
        if let Some(record) = vault.get_item(&item_id).map_err(FfiError::other)? {
            if let Ok(meta) = serde_json::from_slice::<StoredRecordingMeta>(&record.content) {
                if meta.mcp.is_some() && meta.started_unix < cutoff {
                    vault.delete_item(&item_id).map_err(map_vault_err)?;
                }
            }
        }
        sweep.after = Some(item_id);
    }
    if finished {
        sweep.after = None;
    }
    Ok(())
}

struct Event {
    time: f64,
    stderr: bool,
    bytes: Zeroizing<Vec<u8>>,
}
struct Buffer {
    events: Vec<Event>,
    bytes: usize,
    truncated: bool,
    exit: Option<Option<u32>>,
    status: &'static str,
    command: Zeroizing<String>,
    stdin: Option<Zeroizing<String>>,
    env: Environment,
    cwd: Option<Zeroizing<String>>,
}

pub struct CommandRecording {
    state: Weak<Mutex<Option<CoreState>>>,
    pub vault_id: String,
    vault_key: Vec<u8>,
    pub recording_id: String,
    application: String,
    label: String,
    host: String,
    port: u16,
    user: String,
    started_unix: u64,
    start: Instant,
    buffer: Mutex<Buffer>,
    max_bytes: usize,
}

impl Core {
    /// Called after native authorization, before connection/exec. The preference
    /// is from the immutable target snapshot, never from an MCP argument.
    pub fn automation_recording(
        &self,
        target: &automation::Target,
        run_id: &str,
        application: &str,
        command: &str,
        cwd: Option<&str>,
    ) -> Result<Option<Arc<CommandRecording>>, FfiError> {
        self.automation_recording_with_input(
            target,
            run_id,
            application,
            command,
            cwd,
            None,
            &BTreeMap::new(),
        )
    }

    /// Capture all immutable inputs before registering the recorder, so a
    /// concurrent Core lock cannot persist a partially initialized transcript.
    #[allow(clippy::too_many_arguments)]
    pub fn automation_recording_with_input(
        &self,
        target: &automation::Target,
        run_id: &str,
        application: &str,
        command: &str,
        cwd: Option<&str>,
        stdin: Option<&str>,
        env: &BTreeMap<String, String>,
    ) -> Result<Option<Arc<CommandRecording>>, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        if state
            .storage
            .automation_revision()
            .map_err(FfiError::other)?
            != target.revision
        {
            return Err(FfiError::Locked);
        }
        if !target.record_sessions {
            return Ok(None);
        }
        if state.automation_recordings.len() >= 8 {
            return Err(FfiError::other("too many active command recordings"));
        }
        let recording_id = format!("mcp-{run_id}");
        let vault_id = target.vault_id.clone();
        let vault_key = resolve_vid(&state.storage, &vault_id);
        // Fail closed rather than run an enabled recording against an unavailable
        // vault or overwrite an existing item. Native broker IDs are random.
        Vault::open(&state.storage, &state.keyset, &vault_key).map_err(FfiError::other)?;
        if state
            .storage
            .get_item(&vault_key, recording_id.as_bytes())
            .map_err(FfiError::other)?
            .is_some()
            || state.automation_recordings.contains_key(&recording_id)
        {
            return Err(FfiError::other("recording already exists"));
        }
        let max_bytes = preferences(state)?.max_bytes as usize;
        let recording = Arc::new(CommandRecording {
            max_bytes,
            state: Arc::downgrade(&self.state),
            vault_id,
            vault_key,
            recording_id: recording_id.clone(),
            application: application.into(),
            label: target.label.clone(),
            host: target.host.clone(),
            port: target.port,
            user: target.user.clone(),
            started_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            start: Instant::now(),
            buffer: Mutex::new(Buffer {
                events: Vec::new(),
                bytes: 0,
                truncated: false,
                exit: None,
                status: "recording",
                command: Zeroizing::new(command.into()),
                stdin: stdin.map(|s| Zeroizing::new(s.to_owned())),
                env: Environment(env.clone()),
                cwd: cwd.map(|s| Zeroizing::new(s.into())),
            }),
        });
        state
            .automation_recordings
            .insert(recording_id, recording.clone());
        Ok(Some(recording))
    }
}

impl CommandRecording {
    /// Transport callbacks take only this buffer lock, never the Core lock.
    pub fn data(&self, stderr: bool, bytes: &[u8]) {
        let mut b = lock_recover(&self.buffer);
        if b.status != "recording" || bytes.is_empty() {
            return;
        }
        let keep = bytes.len().min(self.max_bytes.saturating_sub(b.bytes));
        if keep == 0 || b.events.len() == MAX_EVENTS {
            b.truncated = true;
            return;
        }
        b.truncated |= keep < bytes.len();
        b.bytes += keep;
        b.events.push(Event {
            time: self.start.elapsed().as_secs_f64(),
            stderr,
            bytes: Zeroizing::new(bytes[..keep].to_vec()),
        });
    }
    pub fn exited(&self, code: Option<u32>) {
        let mut b = lock_recover(&self.buffer);
        if b.status == "recording" && b.exit.is_none() {
            b.exit = Some(code);
        }
    }
    pub fn status(&self) -> &'static str {
        lock_recover(&self.buffer).status
    }

    /// Blocking worker only. Lock order is Core -> buffer, also used by lock/drop.
    pub fn finish(&self, outcome: &str) {
        if let Some(state) = self.state.upgrade() {
            let mut guard = lock_recover(&state);
            if let Some(state) = guard.as_mut() {
                // A handle from before lock/unlock must not touch the new registry.
                if state
                    .automation_recordings
                    .get(&self.recording_id)
                    .is_some_and(|registered| std::ptr::eq(registered.as_ref(), self))
                {
                    state.automation_recordings.remove(&self.recording_id);
                    self.save(state, outcome);
                }
            }
        }
    }

    pub(super) fn save(&self, state: &CoreState, fallback: &str) {
        let mut b = lock_recover(&self.buffer);
        if b.status != "recording" {
            return;
        }
        let outcome = match b.exit {
            Some(Some(_)) => "completed",
            Some(None) if fallback == "cancelled" => "cancelled",
            Some(None) => "failed",
            None => fallback,
        };
        let meta = McpRecordingMeta {
            application: self.application.clone(),
            command: Some(b.command.to_string()),
            outcome: outcome.into(),
            exit_code: b.exit.flatten(),
        };
        let duration = self.start.elapsed().as_secs_f64();
        let mut cast = Zeroizing::new(
            serde_json::json!({
                "version": 2, "width": 100, "height": 30, "timestamp": self.started_unix,
                "title": self.label,
                "unissh_mcp": { "version": 1, "application": self.application,
                    "host": self.host, "port": self.port, "user": self.user,
                    "stdin": b.stdin.as_ref().map(|s| s.as_str()), "env": &*b.env,
                    "command": b.command.as_str(), "cwd": b.cwd.as_deref().map(|s| s.as_str()),
                    "outcome": outcome, "exit_code": meta.exit_code,
                    "truncated": b.truncated, "duration_secs": duration,
                    "events": b.events.iter().map(|e| serde_json::json!({
                        "time": e.time, "stream": if e.stderr {"stderr"} else {"stdout"},
                        "encoding": "base64", "data": STANDARD.encode(e.bytes.as_slice())
                    })).collect::<Vec<_>>() }
            })
            .to_string(),
        );
        cast.push('\n');
        // A normal asciicast player sees only readable output. Independent UTF-8
        // decoders preserve split characters even when stderr interleaves.
        let mut pending = [Vec::new(), Vec::new()];
        for e in &b.events {
            let text = preview(&mut pending[usize::from(e.stderr)], &e.bytes, false);
            append_preview(&mut cast, e.time, &text);
        }
        for p in &mut pending {
            append_preview(&mut cast, duration, &preview(p, &[], true));
        }
        let mut stored = StoredRecording {
            label: self.label.clone(),
            host: self.host.clone(),
            user: self.user.clone(),
            started_unix: self.started_unix,
            duration_secs: duration,
            truncated: b.truncated,
            asciicast: std::mem::take(&mut *cast),
            mcp: Some(meta),
            extra: BTreeMap::new(),
        };
        let result = (|| -> Result<(), FfiError> {
            let json = Zeroizing::new(serde_json::to_vec(&stored).map_err(FfiError::other)?);
            // Never overwrite an item created/synced since capture started,
            // including a tombstone that expresses a user's deletion.
            if state
                .storage
                .get_item(&self.vault_key, self.recording_id.as_bytes())
                .map_err(FfiError::other)?
                .is_some()
            {
                return Err(FfiError::AlreadyExists);
            }
            let vault = Vault::open(&state.storage, &state.keyset, &self.vault_key)
                .map_err(FfiError::other)?;
            vault
                .put_item(self.recording_id.as_bytes(), ITEM_TYPE_RECORDING, &json)
                .map_err(FfiError::other)?;
            if prune(state, &vault, &self.vault_key).is_err() {
                log::warn!("MCP recording retention cleanup failed");
            }
            Ok(())
        })();
        b.status = if result.is_ok() { "saved" } else { "failed" };
        if result.is_err() {
            log::warn!("MCP recording could not be saved");
        }
        stored.asciicast.zeroize();
        b.events.clear();
        b.command.zeroize();
        b.stdin = None;
        b.env.zeroize();
        if let Some(meta) = &mut stored.mcp {
            if let Some(command) = &mut meta.command {
                command.zeroize();
            }
        }
        b.cwd = None;
    }
}

fn append_preview(cast: &mut String, time: f64, text: &str) {
    if !text.is_empty() {
        cast.push_str(&serde_json::json!([time, "o", text]).to_string());
        cast.push('\n');
    }
}
fn preview(pending: &mut Vec<u8>, bytes: &[u8], final_chunk: bool) -> String {
    pending.extend_from_slice(bytes);
    let mut text = String::new();
    let mut offset = 0;
    while offset < pending.len() {
        match std::str::from_utf8(&pending[offset..]) {
            Ok(valid) => {
                text.push_str(valid);
                offset = pending.len();
            }
            Err(e) => {
                let end = offset + e.valid_up_to();
                text.push_str(std::str::from_utf8(&pending[offset..end]).expect("valid prefix"));
                offset = end;
                if let Some(len) = e.error_len() {
                    text.push('\u{fffd}');
                    offset += len;
                } else if final_chunk {
                    text.push('\u{fffd}');
                    offset = pending.len();
                } else {
                    break;
                }
            }
        }
    }
    pending.drain(..offset);
    // Preserve basic terminal formatting, escape other controls in the preview.
    // This is a command transcript, not an interactive terminal recording.
    let mut safe = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() && !matches!(c, '\n' | '\r' | '\t') {
            safe.extend(c.escape_default());
        } else {
            safe.push(c);
        }
    }
    safe
}

/// BTreeMap keys cannot be mutated in place; wipe every secret value before drop.
#[derive(Clone)]
struct Environment(BTreeMap<String, String>);
impl std::ops::Deref for Environment {
    type Target = BTreeMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Environment {
    fn zeroize(&mut self) {
        for value in self.0.values_mut() {
            zeroize::Zeroize::zeroize(value);
        }
        self.0.clear();
    }
}
impl Drop for Environment {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_is_disabled_by_default_and_never_deletes_terminal_recordings() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("db").to_str().unwrap().into(),
            dir.path().join("keyset").to_str().unwrap().into(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "Vault".into()).unwrap();
        core.with_state(|state| {
            let vault = Vault::open(&state.storage, &state.keyset, b"v").map_err(FfiError::other)?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            for (id, mcp, started) in [("old-mcp",true,1),("old-terminal",false,1),("recent-mcp",true,now)] {
                let body = serde_json::json!({"label":"recording","host":"example","user":"user","started_unix":started,
                    "duration_secs":1.0,"truncated":false,"asciicast":"{\"version\":2,\"unissh_mcp\":{\"command\":\"legacy command\"}}\n",
                    "mcp":if mcp { serde_json::json!({"application":"Agent","outcome":"completed","exitCode":0}) } else { serde_json::Value::Null }});
                vault.put_item(id.as_bytes(), ITEM_TYPE_RECORDING, &serde_json::to_vec(&body).unwrap()).map_err(FfiError::other)?;
            }
            Ok(())
        }).unwrap();
        let records = core.list_recordings("v".into()).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records
                .iter()
                .find(|r| r.recording_id == "old-mcp")
                .unwrap()
                .mcp
                .as_ref()
                .unwrap()
                .command
                .as_deref(),
            Some("legacy command")
        );
        core.set_mcp_recording_preferences(RecordingPreferences {
            max_bytes: MAX_BYTES as u32,
            retention_days: Some(30),
        })
        .unwrap();
        let revision = core.automation_revision().unwrap();
        let remaining = core.list_recordings("v".into()).unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().any(|r| r.recording_id == "old-terminal"));
        assert!(remaining.iter().any(|r| r.recording_id == "recent-mcp"));
        assert_eq!(core.automation_revision().unwrap(), revision);
    }

    #[test]
    fn save_time_retention_is_bounded_and_throttled() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("db").to_str().unwrap().into(),
            dir.path().join("keyset").to_str().unwrap().into(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "Vault".into()).unwrap();
        core.set_mcp_recording_preferences(RecordingPreferences {
            max_bytes: MAX_BYTES as u32,
            retention_days: Some(30),
        })
        .unwrap();
        core.with_state(|state| {
            let vault = Vault::open(&state.storage,&state.keyset,b"v").map_err(FfiError::other)?;
            for n in 0..9 {
                let body = serde_json::json!({"label":"old","host":"example","user":"u","started_unix":1,"duration_secs":1.0,"truncated":false,"asciicast":"", "mcp":{"application":"Agent","outcome":"completed","exitCode":0}});
                vault.put_item(format!("old-{n}").as_bytes(),ITEM_TYPE_RECORDING,&serde_json::to_vec(&body).unwrap()).map_err(FfiError::other)?;
            }
            prune(state,&vault,b"v")?;
            assert_eq!(vault.list_items().unwrap().len(),5);
            prune(state,&vault,b"v")?;
            assert_eq!(vault.list_items().unwrap().len(),5);
            lock_recover(&state.recording_retention).get_mut(b"v".as_slice()).unwrap().next = None;
            prune(state,&vault,b"v")?;
            assert_eq!(vault.list_items().unwrap().len(),1);
            Ok(())
        }).unwrap();
        assert!(core.list_recordings("v".into()).unwrap().is_empty());
    }

    #[test]
    fn preview_handles_split_utf8_binary_and_terminal_controls() {
        let mut p = Vec::new();
        assert_eq!(preview(&mut p, &[0xe2, 0x82], false), "");
        assert_eq!(
            preview(&mut p, &[0xac, 0, 0xff, 27, b'\n'], false),
            "€\\u{0}�\\u{1b}\n"
        );
        assert_eq!(preview(&mut p, &[0xe2], false), "");
        assert_eq!(preview(&mut p, &[], true), "�");
        assert!(p.is_empty());
    }
}
