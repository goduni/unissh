//! Byte-compat oracle §15.2: an HTTP adapter of the core `SyncTransport` trait,
//! run (a) for parity with the reference `InMemoryTransport` and (b) through the REAL
//! core `sync_pull` engine against a live server. The server must produce
//! identical observable results (assigned seqs, delta seq>cursor,
//! report_version=max) and round-trip bytes verbatim.

mod common;

use common::spawn;
use unissh_server::ids;
use unissh_storage::{CachePolicy, ItemRecord, Storage, SyncTarget, VaultRecord};
use unissh_sync::{
    AuditObject, InMemoryTransport, RejectReason, SyncContext, SyncError, SyncObject,
    SyncTransport, pull_cursor_key, sync_pull,
};

const TID: &[u8] = b"tenant-oracle-01";

/// HTTP adapter of the core `SyncTransport` (blocking reqwest → live server).
struct HttpTransport {
    base: String,
    tenant_b64: String,
    bearer: String,
    client: reqwest::blocking::Client,
}

impl HttpTransport {
    fn new(base: String, tenant_id: &[u8], bearer: String) -> Self {
        Self {
            base,
            tenant_b64: ids::b64(tenant_id),
            bearer,
            client: reqwest::blocking::Client::new(),
        }
    }
    fn auth(&self, rb: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        rb.header("UniSSH-Tenant", &self.tenant_b64)
            .header("Authorization", format!("Bearer {}", self.bearer))
    }
}

impl SyncTransport for HttpTransport {
    fn push_objects(&mut self, objects: &[SyncObject]) -> Result<Vec<u64>, SyncError> {
        let objs: Vec<String> = objects
            .iter()
            .map(|o| ids::b64(&o.to_bytes().unwrap()))
            .collect();
        let resp = self
            .auth(self.client.post(format!("{}/v1/sync/push", self.base)))
            .json(&serde_json::json!({ "objects": objs }))
            .send()
            .map_err(|_| SyncError::Format)?;
        if !resp.status().is_success() {
            return Err(SyncError::Format);
        }
        let v: serde_json::Value = resp.json().map_err(|_| SyncError::Format)?;
        let seqs = v["server_seq"]
            .as_array()
            .ok_or(SyncError::Format)?
            .iter()
            .map(|x| x.as_u64().unwrap())
            .collect();
        Ok(seqs)
    }

    fn delta_since(&self, cursor: u64) -> Vec<(u64, SyncObject)> {
        let mut out = Vec::new();
        let mut cur = cursor;
        loop {
            let resp = self
                .auth(self.client.get(format!(
                    "{}/v1/sync/delta?cursor={}&limit=1000",
                    self.base, cur
                )))
                .send()
                .unwrap();
            let v: serde_json::Value = resp.json().unwrap();
            for item in v["items"].as_array().unwrap() {
                let seq = item["server_seq"].as_u64().unwrap();
                let bytes = ids::unb64(item["object"].as_str().unwrap()).unwrap();
                if let Ok(o) = SyncObject::from_bytes(&bytes) {
                    out.push((seq, o));
                }
            }
            if !v["has_more"].as_bool().unwrap_or(false) {
                break;
            }
            cur = v["next_cursor"].as_u64().unwrap();
        }
        out
    }

    fn report_version(&self) -> u64 {
        let resp = self
            .auth(self.client.get(format!("{}/v1/sync/version", self.base)))
            .send()
            .unwrap();
        let v: serde_json::Value = resp.json().unwrap();
        v["report_version"].as_u64().unwrap()
    }
}

fn audit(n: u8, author: u8) -> SyncObject {
    SyncObject::Audit(AuditObject {
        vault_id: vec![],
        entry_blob: vec![n],
        signature: vec![1u8; 67],
        author_pubkey: vec![author; 32],
    })
}

fn vault(id: &[u8], owner: &[u8]) -> SyncObject {
    SyncObject::Vault(VaultRecord {
        vault_id: id.to_vec(),
        sync_target: SyncTarget::Cloud,
        name_blob: vec![1, 2, 3],
        wrapped_vk: vec![4, 5, 6],
        version: 1,
        tombstone: false,
        signature: vec![9u8; 67],
        // A1: delta filters by membership — the vault must be owned (claimed) by
        // the requesting device, otherwise its objects aren't visible in the delta.
        author_pubkey: owner.to_vec(),
        key_epoch: 1,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    })
}

fn item(vid: &[u8], iid: &[u8]) -> SyncObject {
    SyncObject::Item(ItemRecord {
        vault_id: vid.to_vec(),
        item_id: iid.to_vec(),
        item_type: 1,
        content_blob: vec![7, 7, 7],
        wrapped_item_key: vec![8, 8],
        version: 1,
        tombstone: false,
        signature: vec![6u8; 67],
        author_pubkey: vec![0xAA; 32],
        created_at: 0,
        updated_at: 0,
        key_epoch: 1,
    })
}

fn keyset() -> SyncObject {
    SyncObject::Keyset(vec![2, 0, 0, 0, 1, 9, 9, 9])
}

fn seq_bytes(d: &[(u64, SyncObject)]) -> Vec<(u64, Vec<u8>)> {
    d.iter().map(|(s, o)| (*s, o.to_bytes().unwrap())).collect()
}

/// Oracle A: the HTTP transport == the reference InMemoryTransport on observable results.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_transport_matches_inmemory_reference() {
    let app = spawn().await;
    let s = app.seed_session(TID, "personal").await;
    let (base, bearer) = (app.base.clone(), s.access_token_b64.clone());
    // The vault is claimed by this device to pass the A1 membership filter of the delta.
    let owner = s.ed25519_pub.clone();

    tokio::task::spawn_blocking(move || {
        let objs = vec![
            audit(1, 2),
            vault(b"v-oracle-a", &owner),
            item(b"v-oracle-a", b"i-1"),
            keyset(),
            audit(2, 2),
        ];

        let mut mem = InMemoryTransport::new();
        let mut http = HttpTransport::new(base, TID, bearer);

        let mem_seqs = mem.push_objects(&objs).unwrap();
        let http_seqs = http.push_objects(&objs).unwrap();
        assert_eq!(mem_seqs, vec![1, 2, 3, 4, 5]);
        assert_eq!(
            http_seqs, mem_seqs,
            "assigned seqs must match reference (input order)"
        );

        assert_eq!(
            http.report_version(),
            mem.report_version(),
            "report_version=max"
        );

        // delta parity (seq>cursor), bytes verbatim
        for cursor in [0u64, 2, 5] {
            let mut md = seq_bytes(&mem.delta_since(cursor));
            let mut hd = seq_bytes(&http.delta_since(cursor));
            md.sort();
            hd.sort();
            assert_eq!(
                hd, md,
                "delta at cursor {cursor} must match reference verbatim"
            );
        }

        // round-trip: pulled objects byte-identical to pushed
        let pulled: Vec<SyncObject> = http.delta_since(0).into_iter().map(|(_, o)| o).collect();
        assert_eq!(pulled, objs, "verbatim round-trip via from_bytes");
    })
    .await
    .unwrap();
}

/// Oracle B: the REAL core `sync_pull` engine against a live server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn core_sync_pull_against_live_server() {
    let app = spawn().await;
    let s = app.seed_session(TID, "personal").await;
    let (base, bearer) = (app.base.clone(), s.access_token_b64.clone());

    tokio::task::spawn_blocking(move || {
        let mut http = HttpTransport::new(base, TID, bearer);

        // Two audit objects from the genesis owner [2;32] + one from a stranger [9;32].
        let seqs = http
            .push_objects(&[audit(1, 2), audit(2, 2), audit(3, 9)])
            .unwrap();
        assert_eq!(seqs, vec![1, 2, 3]);

        // Fresh client storage; genesis_owner = [2;32].
        let storage = Storage::open_in_memory(&[7u8; 32]).unwrap();
        let ctx = SyncContext {
            genesis_owner: vec![2u8; 32],
            tenant: b"oracle-tenant".to_vec(),
        };

        let report = sync_pull(&mut http, &storage, &ctx).unwrap();

        // A stranger author → AuthorityFailed (on seq 3); genesis authors are not rejected.
        let rejected_seqs: Vec<u64> = report
            .rejected
            .iter()
            .filter(|r| matches!(r.reason, RejectReason::AuthorityFailed))
            .map(|r| r.server_seq)
            .collect();
        assert_eq!(rejected_seqs, vec![3], "non-genesis audit author rejected");

        // The cursor is advanced to max seq; report_version is monotonic and >= the cursor.
        assert_eq!(
            storage
                .get_sync_cursor(&pull_cursor_key(b"oracle-tenant"))
                .unwrap(),
            Some(3)
        );
        assert!(http.report_version() >= 3);

        // A repeat pull: nothing new (everything <= the cursor), the cursor doesn't drop.
        let report2 = sync_pull(&mut http, &storage, &ctx).unwrap();
        assert_eq!(report2.applied, 0);
        assert_eq!(
            storage
                .get_sync_cursor(&pull_cursor_key(b"oracle-tenant"))
                .unwrap(),
            Some(3)
        );
    })
    .await
    .unwrap();
}
