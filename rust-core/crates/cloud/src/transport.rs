//! `HttpSyncTransport` — the network implementation of the core's sync transport.
//!
//! The core's sync engine (`Core::sync_now`) drives an `FfiSyncTransport` it does
//! NOT trust: it pushes local objects, pulls the delta, and verifies every object
//! (signature / epoch-floor / authority / anti-rollback) before applying. So this
//! transport is a thin, dumb HTTP relay — on any read error it simply yields
//! nothing and lets the engine re-verify what it did receive. Ported from the
//! server's byte-compat oracle (`server/tests/oracle_sync.rs::HttpTransport`).

use std::sync::{Mutex, PoisonError};

use reqwest::blocking::{RequestBuilder, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};
use unissh_ffi::{
    Core, FfiError, FfiSyncReport, FfiSyncTransport, FfiTrustOutcome, SharedVaultInfo,
    SyncDeltaItem, VaultPage,
};

use crate::client::{self, Reauth};

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

/// One instance serves one sync (see `drained_at`).
pub struct HttpSyncTransport {
    base_url: String,
    /// The bearer, replaced when the server rejects it and a fresh one is had
    /// (see [`HttpSyncTransport::send`]).
    bearer: Mutex<String>,
    reauth: Option<Reauth>,
    /// Set once the server answered a delta request with "nothing follows":
    /// the `server_seq` its answer ended at. The core asks again after every
    /// page that moved its cursor; asked from exactly this point, the answer is
    /// already known and no request is made.
    drained_at: Mutex<Option<u64>>,
}

/// One entry of the server vault catalog (`GET /v1/vaults`).
pub struct CatalogEntry {
    /// hex vault_id.
    pub vault_id: String,
    /// Highest version of the vault record the server holds.
    pub latest_version: i64,
    /// The server's latest record is a deletion.
    pub tombstone: bool,
}

impl HttpSyncTransport {
    /// A transport for one sync against `base_url`, authenticated with
    /// `bearer`, rotated through the refresher of [`client::set_reauth`].
    pub fn new(base_url: String, bearer: String) -> Self {
        Self::with_reauth(base_url, bearer, client::installed_reauth())
    }

    /// [`Self::new`] with the refresher given rather than the installed one.
    fn with_reauth(base_url: String, bearer: String, reauth: Option<Reauth>) -> Self {
        Self {
            base_url,
            bearer: Mutex::new(bearer),
            reauth,
            drained_at: Mutex::new(None),
        }
    }

    /// Sends the request `build` makes for the current bearer. A `401` rotates
    /// the bearer once and sends again, and every later request of this
    /// transport carries the fresh one.
    ///
    /// An access token is short-lived and a sync runs on a timer, so meeting an
    /// expired one is routine. Without this the first call of a sync — the
    /// version probe — came back 401, read as version 0, and the engine
    /// reported a rollback below its trusted cursor instead of signing in
    /// again. Replaying is safe: the server authenticates before any handler
    /// runs, and a push is idempotent on its key anyway.
    fn send(&self, build: impl Fn(&str) -> RequestBuilder) -> reqwest::Result<Response> {
        let stale = self.bearer();
        let resp = build(&stale).send()?;
        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }
        let Some(fresh) = self.reauth.as_ref().and_then(|rotate| rotate(&stale)) else {
            return Ok(resp);
        };
        self.bearer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone_from(&fresh);
        build(&fresh).send()
    }

    fn bearer(&self) -> String {
        self.bearer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// `GET /v1/vaults` — the member-facing catalog of vaults this caller can access.
    /// Unlike the sync flow this is a plain read (not part of the untrusted-transport
    /// verify loop); a non-2xx is surfaced as an error so the UI can report it.
    pub fn list_vaults(&self) -> Result<Vec<CatalogEntry>, FfiError> {
        let http = client::http();
        let url = client::url(&self.base_url, "/v1/vaults");
        let resp = self
            .send(|bearer| client::headers(http.get(&url), Some(bearer)))
            .map_err(|e| FfiError::Other {
                msg: format!("list vaults: {e}"),
            })?;
        if !resp.status().is_success() {
            return Err(FfiError::Other {
                msg: format!("list vaults: http {}", resp.status().as_u16()),
            });
        }
        let v: Value = resp.json().map_err(|e| FfiError::Other {
            msg: format!("list vaults: bad JSON: {e}"),
        })?;
        let mut out = Vec::new();
        for it in v
            .get("vaults")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(vid) = it.get("vault_id").and_then(Value::as_str) {
                out.push(CatalogEntry {
                    vault_id: vid.to_owned(),
                    latest_version: it
                        .get("latest_version")
                        .and_then(Value::as_i64)
                        .unwrap_or(0),
                    tombstone: it
                        .get("tombstone")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                });
            }
        }
        Ok(out)
    }

    /// One page of `GET /v1/sync/delta?vault=<hex>`: the raw object blobs of ONE
    /// vault that follow `cursor` (0 for the first page), and the cursor of the
    /// next page — `None` after the last one. The caller hands each page to the
    /// core before it asks for the next, so a large vault is never held in
    /// memory whole.
    ///
    /// Unlike `delta_since`, a page that cannot be read — a transport error, a
    /// non-2xx, bad JSON, or "more follows" without a usable cursor — is an
    /// error: the targeted pull and the share-accept inspection must not take
    /// a cut-short set for the whole vault.
    pub fn vault_delta_page(&self, vault_id_hex: &str, cursor: u64) -> Result<VaultPage, FfiError> {
        let failed = |why: String| FfiError::Other {
            msg: format!("the server's objects for this vault could not be read: {why}"),
        };
        let path =
            format!("/v1/sync/delta?cursor={cursor}&limit={DELTA_LIMIT}&vault={vault_id_hex}");
        let url = client::url(&self.base_url, &path);
        let resp = self
            .send(|bearer| client::headers(client::http().get(&url), Some(bearer)))
            .map_err(|e| failed(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(failed(format!("http {}", resp.status().as_u16())));
        }
        let v = resp
            .json::<Value>()
            .map_err(|e| failed(format!("bad JSON: {e}")))?;
        let objects = items_of(&v)
            .filter_map(|item| item.get("object").and_then(Value::as_str))
            .filter_map(|obj_b64| client::unb64(obj_b64).ok())
            .collect();
        let next = next_page(&v, cursor);
        let more = v.get("has_more").and_then(Value::as_bool).unwrap_or(false);
        if more && next.is_none() {
            return Err(failed(
                "more follows, but no usable cursor came with it".to_owned(),
            ));
        }
        Ok((objects, next))
    }

    /// **Pulls ONE vault** (by hex id) onto this device: its objects page by
    /// page through the core's verify-before-apply, born-bound to `tenant_b64`,
    /// WITHOUT moving the pull cursor (see [`Core::pull_vault_paged`]). The
    /// recovery for a vault an earlier sync rejected — a teammate's vault
    /// before its owner was pinned — and the app's "Pull from server". A page
    /// that cannot be read is an error saying the pull was cut short.
    pub fn pull_vault(
        &self,
        core: &Core,
        tenant_b64: &str,
        vault_id_hex: &str,
    ) -> Result<FfiSyncReport, FfiError> {
        core.pull_vault_paged(tenant_b64, |cursor| {
            self.vault_delta_page(vault_id_hex, cursor)
        })
    }

    /// Inspects a vault shared with this account before its owner is trusted
    /// (see [`Core::inspect_shared_vault_paged`]): the vault's objects are read
    /// page by page and only its membership is kept. `Ok(None)`: this account
    /// created the vault and it needs no trust. Writes nothing.
    pub fn inspect_vault(
        &self,
        core: &Core,
        vault_id_hex: &str,
    ) -> Result<Option<SharedVaultInfo>, FfiError> {
        core.inspect_shared_vault_paged(vault_id_hex, |cursor| {
            self.vault_delta_page(vault_id_hex, cursor)
        })
    }

    /// Trusts the owner of a vault shared with this account: the core
    /// inspects the vault's membership read from the server, compares
    /// `expected_fingerprint` and pins in one step (see
    /// [`Core::trust_shared_vault_paged`]). Pull the vault after.
    pub fn trust_vault(
        &self,
        core: &Core,
        vault_id_hex: &str,
        expected_fingerprint: Option<&str>,
        confirmed_displayed: bool,
    ) -> Result<FfiTrustOutcome, FfiError> {
        core.trust_shared_vault_paged(
            vault_id_hex,
            expected_fingerprint,
            confirmed_displayed,
            |cursor| self.vault_delta_page(vault_id_hex, cursor),
        )
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
        // The core cuts a large push into several calls of this function: each
        // call is one request with the key of exactly its own objects.
        let idem = idempotency_key(&objects);
        let url = client::url(&self.base_url, "/v1/sync/push");
        let body = json!({ "objects": objs });
        let resp = self
            .send(|bearer| {
                client::headers(http.post(&url), Some(bearer))
                    .header("Idempotency-Key", &idem)
                    .json(&body)
            })
            .map_err(|e| FfiError::Other {
                msg: format!("sync push: {e}"),
            })?;

        let status = resp.status();
        let bytes = resp.bytes().map_err(|e| FfiError::Other {
            msg: format!("sync push: {e}"),
        })?;
        // 413 is the server's `payload_too_large` (an object over its
        // `limits.max_object_bytes`, too many objects) or a body limit — its own
        // or a reverse proxy's, which answers without the JSON error body. The
        // core splits the request on it and singles out an item that cannot fit.
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            return Err(FfiError::PayloadTooLarge {
                msg: push_error_message(status, &bytes),
            });
        }
        if !status.is_success() {
            return Err(FfiError::Other {
                msg: push_error_message(status, &bytes),
            });
        }
        let v: Value = serde_json::from_slice(&bytes).map_err(|e| FfiError::Other {
            msg: format!("sync push: bad JSON: {e}"),
        })?;
        let seqs = v
            .get("server_seq")
            .and_then(Value::as_array)
            .ok_or_else(|| FfiError::Other {
                msg: "sync push: response missing 'server_seq'".into(),
            })?
            .iter()
            .filter_map(Value::as_u64)
            .collect();
        Ok(seqs)
    }

    /// One page per call: the core verifies and applies it, then asks again from
    /// its cursor, so a first sync of a large vault is never held in memory
    /// whole. (A page is bounded by the server: by count, and from 0.6 by size.)
    fn delta_since(&self, cursor: u64) -> Vec<SyncDeltaItem> {
        if self.drained_at.lock().is_ok_and(|at| *at == Some(cursor)) {
            return Vec::new();
        }
        let http = client::http();
        let mut cur = cursor;
        loop {
            let url = client::url(
                &self.base_url,
                &format!("/v1/sync/delta?cursor={cur}&limit={DELTA_LIMIT}"),
            );
            let resp = match self.send(|bearer| client::headers(http.get(&url), Some(bearer))) {
                Ok(r) if r.status().is_success() => r,
                // Untrusted transport: stop on any error; the engine verified
                // what it got and the next sync resumes from the persisted cursor.
                _ => return Vec::new(),
            };
            let Ok(v) = resp.json::<Value>() else {
                return Vec::new();
            };
            let items: Vec<SyncDeltaItem> = items_of(&v)
                .filter_map(|item| {
                    let seq = item.get("server_seq").and_then(Value::as_u64)?;
                    let obj_b64 = item.get("object").and_then(Value::as_str)?;
                    let object = client::unb64(obj_b64).ok()?;
                    Some(SyncDeltaItem {
                        server_seq: seq,
                        object,
                    })
                })
                .collect();
            match next_page(&v, cur) {
                // A page with nothing usable in it is not the end of the delta:
                // an empty answer would stop the core, so the next page is
                // fetched here.
                Some(next) if items.is_empty() => cur = next,
                Some(_) => return items,
                None => {
                    let end = items.iter().map(|i| i.server_seq).max().unwrap_or(cur);
                    if let Ok(mut at) = self.drained_at.lock() {
                        *at = Some(end);
                    }
                    return items;
                }
            }
        }
    }

    fn report_version(&self) -> u64 {
        let http = client::http();
        // The engine treats `report_version < cursor` as a rollback attack, so a
        // transient network blip here must not masquerade as one — retry a few
        // times. On total failure it returns 0, which surfaces as a recoverable
        // per-sync error (cursor untouched), never data corruption.
        let url = client::url(&self.base_url, "/v1/sync/version");
        for attempt in 0..3 {
            let resp = self.send(|bearer| client::headers(http.get(&url), Some(bearer)));
            if let Ok(r) = resp {
                if let Some(v) = r
                    .json::<Value>()
                    .ok()
                    .and_then(|v| v.get("report_version").and_then(Value::as_u64))
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

/// The `items` array of a delta page; a missing or non-array field is empty.
fn items_of(page: &Value) -> impl Iterator<Item = &Value> {
    page.get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

/// Paging of a delta page: the cursor to request next, or `None` to stop.
///
/// A page that says `has_more` but carries no usable `next_cursor` (absent or not
/// a `u64`) counts as the LAST page: re-requesting the same cursor would loop
/// forever and append the same items every round. Stopping is safe — the engine
/// verifies what it has and the next sync resumes from the persisted cursor.
///
/// A `next_cursor` that does not advance past `cur` stops the same way: the
/// server returns rows with `server_seq > cursor` in ascending order and sets
/// `has_more` only when a row follows the page, so an honest `next_cursor` is
/// always greater than the cursor that was requested.
fn next_page(page: &Value, cur: u64) -> Option<u64> {
    let has_more = page
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !has_more {
        return None;
    }
    let Some(next) = page.get("next_cursor").and_then(Value::as_u64) else {
        log::warn!("cloud: delta page has more items but no usable next_cursor; stopping");
        return None;
    };
    if next <= cur {
        log::warn!("cloud: delta page next_cursor does not advance; stopping");
        return None;
    }
    Some(next)
}

/// Extract the server error code/message for a failed push (best-effort).
fn push_error_message(status: StatusCode, body: &[u8]) -> String {
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        if let Some(err) = v.get("error") {
            let code = err.get("code").and_then(|c| c.as_str()).unwrap_or("error");
            let message = err.get("message").and_then(|m| m.as_str()).unwrap_or("");
            return format!("sync push rejected ({code}): {message}");
        }
    }
    format!("sync push http {}", status.as_u16())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use unissh_ffi::FfiSyncTransport;

    use super::{next_page, HttpSyncTransport};
    use crate::client::Reauth;
    use crate::test_server::{serve, UNAUTH};

    /// A sync that starts with (or runs into) an expired access token signs in
    /// again instead of failing — and keeps the fresh token for the rest of
    /// the sync, so the refresher is asked once, not per request.
    #[test]
    fn an_expired_bearer_is_rotated_once_and_kept_for_the_rest_of_the_sync() {
        let (base, seen) = serve(vec![
            UNAUTH,
            ("200 OK", r#"{"report_version":5}"#),
            ("200 OK", r#"{"items":[],"has_more":false}"#),
        ]);
        let asked = Arc::new(std::sync::Mutex::new(0_u32));
        let counter = Arc::clone(&asked);
        let reauth: Reauth = Arc::new(move |stale: &str| {
            *counter.lock().unwrap() += 1;
            (stale == "stale").then(|| "fresh".to_owned())
        });
        let transport = HttpSyncTransport::with_reauth(base, "stale".to_owned(), Some(reauth));

        assert_eq!(
            transport.report_version(),
            5,
            "not a 0 that reads as a rollback"
        );
        assert!(transport.delta_since(0).is_empty());
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["bearer stale", "bearer fresh", "bearer fresh"],
            "the rejected request is retried with the fresh token, and so is the next one"
        );
        assert_eq!(*asked.lock().unwrap(), 1, "one rotation for the whole sync");
    }

    #[test]
    fn next_page_stops_unless_more_pages_come_with_a_cursor() {
        assert_eq!(
            next_page(&json!({ "has_more": true, "next_cursor": 7 }), 0),
            Some(7),
            "more pages with a cursor continue from it"
        );
        assert_eq!(
            next_page(&json!({ "has_more": true }), 0),
            None,
            "more pages without a cursor stop instead of re-requesting forever"
        );
        assert_eq!(
            next_page(&json!({ "has_more": false, "next_cursor": 7 }), 0),
            None,
            "the last page stops"
        );
        assert_eq!(
            next_page(&json!({ "has_more": true, "next_cursor": 7 }), 7),
            None,
            "a cursor that does not advance stops instead of re-requesting forever"
        );
    }
}
