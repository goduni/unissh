//! `HttpSyncTransport` — the network implementation of the core's sync transport.
//!
//! The core's sync engine (`Core::sync_now`) drives an `FfiSyncTransport` it does
//! NOT trust: it pushes local objects, pulls the delta, and verifies every object
//! (signature / epoch-floor / authority / anti-rollback) before applying. So this
//! transport is a thin, dumb HTTP relay — on any read error it simply yields
//! nothing and lets the engine re-verify what it did receive. Ported from the
//! server's byte-compat oracle (`server/tests/oracle_sync.rs::HttpTransport`).

use serde_json::{json, Value};
use unissh_ffi::{FfiError, FfiSyncTransport, SyncDeltaItem};

use crate::cloud::client;

/// Page size for `/v1/sync/delta` (server clamps to its max, default 1000).
const DELTA_LIMIT: u64 = 1000;

/// A content hash of the pushed object set → a stable Idempotency-Key. Lengths are
/// prefixed so concatenation can't alias two different sets to the same key.
fn idempotency_key(objects: &[Vec<u8>]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((objects.len() as u64).to_be_bytes());
    for o in objects {
        h.update((o.len() as u64).to_be_bytes());
        h.update(o);
    }
    let digest = h.finalize();
    client::b64(&digest)
}

pub struct HttpSyncTransport {
    base_url: String,
    bearer: String,
}

impl HttpSyncTransport {
    pub fn new(base_url: String, bearer: String) -> Self {
        HttpSyncTransport { base_url, bearer }
    }
}

impl FfiSyncTransport for HttpSyncTransport {
    fn push_objects(&self, objects: Vec<Vec<u8>>) -> Result<Vec<u64>, FfiError> {
        let http = client::http();
        let objs: Vec<String> = objects.iter().map(|o| client::b64(o)).collect();
        // Content-stable Idempotency-Key: a retry of the SAME object set replays
        // server-side (no duplicate rows, no audit double-apply on a lost
        // response); a genuinely different set gets a fresh key. The server keys
        // replay on (idempotency-key, request body), so the key must track content.
        let idem = idempotency_key(&objects);
        let resp = client::headers(
            http.post(client::url(&self.base_url, "/v1/sync/push")),
            Some(&self.bearer),
        )
        .header("Idempotency-Key", idem)
        .json(&json!({ "objects": objs }))
        .send()
        .map_err(|e| FfiError::Other {
            msg: format!("sync push: {e}"),
        })?;

        let status = resp.status();
        let bytes = resp.bytes().map_err(|e| FfiError::Other {
            msg: format!("sync push: {e}"),
        })?;
        if !status.is_success() {
            return Err(FfiError::Other {
                msg: push_error_message(status, &bytes),
            });
        }
        let v: Value = serde_json::from_slice(&bytes).map_err(|e| FfiError::Other {
            msg: format!("sync push: bad JSON: {e}"),
        })?;
        let seqs = v["server_seq"]
            .as_array()
            .ok_or_else(|| FfiError::Other {
                msg: "sync push: response missing 'server_seq'".into(),
            })?
            .iter()
            .filter_map(|x| x.as_u64())
            .collect();
        Ok(seqs)
    }

    fn delta_since(&self, cursor: u64) -> Vec<SyncDeltaItem> {
        let http = client::http();
        let mut out = Vec::new();
        let mut cur = cursor;
        loop {
            let path = format!("/v1/sync/delta?cursor={cur}&limit={DELTA_LIMIT}");
            let resp = match client::headers(
                http.get(client::url(&self.base_url, &path)),
                Some(&self.bearer),
            )
            .send()
            {
                Ok(r) if r.status().is_success() => r,
                // Untrusted transport: stop on any error; the engine verifies what
                // it has and the next sync resumes from the persisted cursor.
                _ => break,
            };
            let v: Value = match resp.json() {
                Ok(v) => v,
                Err(_) => break,
            };
            if let Some(items) = v["items"].as_array() {
                for item in items {
                    if let (Some(seq), Some(obj_b64)) =
                        (item["server_seq"].as_u64(), item["object"].as_str())
                    {
                        if let Ok(bytes) = client::unb64(obj_b64) {
                            out.push(SyncDeltaItem {
                                server_seq: seq,
                                object: bytes,
                            });
                        }
                    }
                }
            }
            if v["has_more"].as_bool().unwrap_or(false) {
                cur = v["next_cursor"].as_u64().unwrap_or(cur);
            } else {
                break;
            }
        }
        out
    }

    fn report_version(&self) -> u64 {
        let http = client::http();
        // The engine treats `report_version < cursor` as a rollback attack, so a
        // transient network blip here must not masquerade as one — retry a few
        // times. On total failure it returns 0, which surfaces as a recoverable
        // per-sync error (cursor untouched), never data corruption.
        for attempt in 0..3 {
            let resp = client::headers(
                http.get(client::url(&self.base_url, "/v1/sync/version")),
                Some(&self.bearer),
            )
            .send();
            if let Ok(r) = resp {
                if let Some(v) = r
                    .json::<Value>()
                    .ok()
                    .and_then(|v| v["report_version"].as_u64())
                {
                    return v;
                }
            }
            if attempt < 2 {
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        }
        0
    }
}

/// Extract the server error code/message for a failed push (best-effort).
fn push_error_message(status: reqwest::StatusCode, body: &[u8]) -> String {
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        if let Some(err) = v.get("error") {
            let code = err.get("code").and_then(|c| c.as_str()).unwrap_or("error");
            let message = err.get("message").and_then(|m| m.as_str()).unwrap_or("");
            return format!("sync push rejected ({code}): {message}");
        }
    }
    format!("sync push http {}", status.as_u16())
}
