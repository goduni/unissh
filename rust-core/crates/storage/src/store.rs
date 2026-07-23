//! `Storage` — opening the instance's encrypted DB and CRUD.
//!
//! **Instance isolation (spec 2A):** each instance is a separate encrypted DB
//! file with its own key. Data from different instances is never physically
//! mixed; compromising one instance's key does not expose another.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::error::StorageError;
use crate::records::{
    AccountStateRecord, AuditEntry, CachePolicy, ConsistencyIssue, ConsistencyKind,
    ConsistencyReport, ItemRecord, KnownHost, MemberRole, MembershipGrant, MembershipManifest,
    PinnedMemberKey, SyncTarget, VaultRecord, VaultTrustAnchor,
};
use crate::schema::{migrate, SCHEMA_VERSION};

/// Ed25519 public-key length (sanity check on `author_pubkey` length).
const ED25519_PUBKEY_LEN: i64 = 32;
/// Minimum acceptable signature length (versioned Ed25519).
const MIN_SIG_LEN: i64 = 64;

/// DB key length (SQLCipher raw key).
pub const DB_KEY_LEN: usize = 32;

/// Storage for a single instance.
pub struct Storage {
    conn: Connection,
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Storage").finish_non_exhaustive()
    }
}

/// SQLCipher sets up process-global crypto state the first time a connection
/// is keyed; two first-opens racing from different threads can observe that
/// state half-built ("sqlcipherCodecAttach: sqlcipher not initialized",
/// surfacing as a PRAGMA key error). Opens are rare (once per instance /
/// unlock), so serialize them entirely rather than special-casing the first.
static OPEN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl Storage {
    /// Opens (creating if needed) the instance's encrypted DB at the given path.
    pub fn open(path: &Path, db_key: &[u8]) -> Result<Self, StorageError> {
        let _serialized = OPEN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let conn = Connection::open(path)?;
        Self::init(conn, db_key)
    }

    /// Opens an in-memory encrypted DB (for tests / ephemeral instances).
    pub fn open_in_memory(db_key: &[u8]) -> Result<Self, StorageError> {
        let _serialized = OPEN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let conn = Connection::open_in_memory()?;
        Self::init(conn, db_key)
    }

    fn init(conn: Connection, db_key: &[u8]) -> Result<Self, StorageError> {
        if db_key.len() != DB_KEY_LEN {
            return Err(StorageError::BadKeyLength);
        }
        // The key must be set before any DB operation. Both the hex encoding
        // and the PRAGMA itself contain the raw key — keep them in Zeroizing
        // and wipe them.
        let hex = Zeroizing::new(hex::encode(db_key));
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex.as_str()));
        conn.execute_batch(&pragma)?;

        // The first read operation forces decryption of the header: a wrong key
        // or a foreign/corrupt file → SQLITE_NOTADB.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(map_cipher_error)?;

        // NB: the schema does NOT declare any FOREIGN KEY (sync semantics: an
        // item may arrive before its vault), so this PRAGMA is effectively a
        // no-op right now. We keep it enabled for the future (should FKs
        // appear) — referential integrity is actually checked by
        // `check_consistency`, NOT the engine.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        let storage = Storage { conn };
        migrate(&storage.conn)?;
        Ok(storage)
    }

    // --- meta (arbitrary open instance metadata) ---

    /// Writes an instance metadata value (e.g. instance_id).
    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO meta (k, v) VALUES (?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![key, value],
        )?;
        Ok(())
    }

    /// Reads an instance metadata value.
    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT v FROM meta WHERE k = ?1", params![key], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?)
    }

    /// Schema version of the open DB.
    pub fn schema_version(&self) -> i64 {
        SCHEMA_VERSION
    }

    /// Runs a closure inside a single SQLite transaction (`BEGIN`/`COMMIT`, or
    /// `ROLLBACK` on error). Lets upper layers perform atomic multi-step
    /// operations (e.g. rename = put+tombstone). The closure's error must be
    /// convertible from [`StorageError`].
    pub fn transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
        E: From<StorageError>,
    {
        self.conn
            .execute_batch("BEGIN")
            .map_err(|e| E::from(StorageError::from(e)))?;
        match f() {
            Ok(v) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(|e| E::from(StorageError::from(e)))?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    // --- vaults ---

    /// Inserts or updates a vault. The version must grow monotonically
    /// (anti-rollback in a single UPSERT via `WHERE excluded.version > vaults.version`).
    pub fn put_vault(&self, v: &VaultRecord) -> Result<(), StorageError> {
        let version = checked_version(v.version)?;
        let key_epoch = checked_version(v.key_epoch)?;
        let changed = self.conn.execute(
            "INSERT INTO vaults
               (vault_id, sync_target, name_blob, wrapped_vk, version, tombstone, signature, author_pubkey, key_epoch, cache_policy, sync_tenant)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(vault_id) DO UPDATE SET
               sync_target=excluded.sync_target, name_blob=excluded.name_blob,
               wrapped_vk=excluded.wrapped_vk, version=excluded.version,
               tombstone=excluded.tombstone, signature=excluded.signature,
               author_pubkey=excluded.author_pubkey, key_epoch=excluded.key_epoch,
               cache_policy=excluded.cache_policy,
               sync_tenant=CASE WHEN length(excluded.sync_tenant)=0 THEN vaults.sync_tenant ELSE excluded.sync_tenant END
             WHERE excluded.version > vaults.version",
            params![
                v.vault_id,
                v.sync_target.to_i64(),
                v.name_blob,
                v.wrapped_vk,
                version,
                v.tombstone as i64,
                v.signature,
                v.author_pubkey,
                key_epoch,
                v.cache_policy.to_i64(),
                v.sync_tenant,
            ],
        )?;
        if changed == 0 {
            // PK conflict and the WHERE rejected the update → version rollback.
            let cur: i64 = self.conn.query_row(
                "SELECT version FROM vaults WHERE vault_id = ?1",
                params![v.vault_id],
                |r| r.get(0),
            )?;
            return Err(StorageError::VersionRollback {
                current: cur as u64,
                attempted: v.version,
            });
        }
        Ok(())
    }

    /// Returns a vault by id (including tombstoned ones).
    pub fn get_vault(&self, vault_id: &[u8]) -> Result<Option<VaultRecord>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, sync_target, name_blob, wrapped_vk, version, tombstone, signature, author_pubkey, key_epoch, cache_policy, sync_tenant
             FROM vaults WHERE vault_id = ?1",
        )?;
        Ok(stmt
            .query_row(params![vault_id], map_vault_row)
            .optional()?)
    }

    /// List of non-deleted vaults.
    pub fn list_vaults(&self) -> Result<Vec<VaultRecord>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, sync_target, name_blob, wrapped_vk, version, tombstone, signature, author_pubkey, key_epoch, cache_policy, sync_tenant
             FROM vaults WHERE tombstone = 0 ORDER BY vault_id",
        )?;
        let rows = stmt
            .query_map([], map_vault_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Cloud vaults deleted LOCALLY (tombstone). `list_vaults` hides them
    /// (`tombstone=0`), and pull does not resurrect them (LWW: the local
    /// tombstone is newer than the live server copy), so restoring from the
    /// server requires explicit access to them.
    pub fn list_tombstoned_cloud_vaults(&self) -> Result<Vec<VaultRecord>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, sync_target, name_blob, wrapped_vk, version, tombstone, signature, author_pubkey, key_epoch, cache_policy, sync_tenant
             FROM vaults WHERE tombstone = 1 AND sync_target = ?1 ORDER BY vault_id",
        )?;
        let rows = stmt
            .query_map(params![SyncTarget::Cloud.to_i64()], map_vault_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// **One-time binding of legacy cloud vaults to a server** (1:1 binding):
    /// sets `sync_tenant = tenant` on EVERY cloud (`sync_target=Cloud`) vault
    /// whose `sync_tenant` is currently empty (unbound). Local vaults and
    /// already-bound cloud vaults are left untouched. Returns the number of
    /// affected rows.
    ///
    /// A direct `UPDATE` of the routing label (NOT part of the signature) — the
    /// record's version/signature do NOT change, so the existing signature stays
    /// valid. Call ONLY when exactly one server is bound (otherwise you may bind
    /// to the wrong one).
    pub fn bind_unbound_cloud_vaults(&self, tenant: &[u8]) -> Result<usize, StorageError> {
        let cloud = SyncTarget::Cloud.to_i64();
        // Dirty the about-to-be-bound vaults + their contents FIRST (while still identifiable
        // by an empty sync_tenant), so binding triggers a full push to the newly-bound server.
        let unbound = "sync_target = ?1 AND length(sync_tenant) = 0";
        let in_unbound =
            "vault_id IN (SELECT vault_id FROM vaults WHERE sync_target = ?1 AND length(sync_tenant) = 0)";
        self.conn.execute(
            &format!("UPDATE vaults SET dirty = 1 WHERE {unbound}"),
            params![cloud],
        )?;
        self.conn.execute(
            &format!("UPDATE items SET dirty = 1 WHERE {in_unbound}"),
            params![cloud],
        )?;
        self.conn.execute(
            &format!("UPDATE membership_manifests SET dirty = 1 WHERE {in_unbound}"),
            params![cloud],
        )?;
        self.conn.execute(
            &format!("UPDATE membership_grants SET dirty = 1 WHERE {in_unbound}"),
            params![cloud],
        )?;
        let n = self.conn.execute(
            "UPDATE vaults SET sync_tenant = ?1
             WHERE sync_target = ?2 AND length(sync_tenant) = 0",
            params![tenant, cloud],
        )?;
        Ok(n)
    }

    /// Bind EXACTLY ONE cloud vault to `tenant` (1:1). Unlike
    /// [`Self::bind_unbound_cloud_vaults`], this touches only the given
    /// `vault_id` — used when creating a new cloud vault, so as not to affect
    /// other legacy vaults. A direct `UPDATE` of the routing label (NOT part of
    /// the signature) — the version/signature do not change.
    pub fn set_vault_tenant(&self, vault_id: &[u8], tenant: &[u8]) -> Result<(), StorageError> {
        let n = self.conn.execute(
            "UPDATE vaults SET sync_tenant = ?1 WHERE vault_id = ?2 AND sync_target = ?3",
            params![tenant, vault_id, SyncTarget::Cloud.to_i64()],
        )?;
        // Binding is a routing-label change that dirties nothing — so re-mark the vault and
        // its contents dirty, or a previously-synced vault never re-pushes to the new server.
        if n > 0 {
            self.mark_vault_and_contents_dirty(vault_id)?;
        }
        Ok(())
    }

    /// Record that a vault BELONGS to `tenant` — for a vault that came FROM it.
    ///
    /// Same routing-label `UPDATE` as [`Self::set_vault_tenant`] and, like it, no
    /// version or signature changes. It differs in one way, and that is the whole
    /// point: it does NOT dirty the vault. `set_vault_tenant` binds a vault to a
    /// server it has never been on, so a full push has to follow. A vault that was
    /// just pulled is already on that server, byte for byte — dirtying it would push
    /// a copy back at the version it just arrived at, which is exactly the pointless
    /// round trip the born-bound work exists to prevent.
    ///
    /// Only for a binding the caller can PROVE from the sync itself (the record
    /// arrived in that tenant's delta and passed authority). Never infer a binding.
    pub fn adopt_pulled_binding(&self, vault_id: &[u8], tenant: &[u8]) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE vaults SET sync_tenant = ?1
             WHERE vault_id = ?2 AND sync_target = ?3 AND length(sync_tenant) = 0",
            params![tenant, vault_id, SyncTarget::Cloud.to_i64()],
        )?;
        Ok(())
    }

    /// Unbind all cloud vaults bound to `tenant` (e.g. when a server is
    /// removed): they become unbound and can be bound again. A direct `UPDATE`
    /// of the routing label — the version/signature do not change. Returns the
    /// number of affected rows.
    pub fn clear_binding_for_tenant(&self, tenant: &[u8]) -> Result<usize, StorageError> {
        let n = self.conn.execute(
            "UPDATE vaults SET sync_tenant = X''
             WHERE sync_target = ?1 AND sync_tenant = ?2",
            params![SyncTarget::Cloud.to_i64(), tenant],
        )?;
        Ok(n)
    }

    /// Unbind EXACTLY ONE cloud vault from its server (the per-vault inverse of
    /// [`Self::set_vault_tenant`]): clears its routing label so it stops syncing.
    /// The vault and its data stay on this device; any server-side copy is left
    /// as-is (orphaned). A direct `UPDATE` of the label — the version/signature
    /// do not change. Nothing is re-dirtied: an unbound vault matches no server's
    /// tenant, so there is nothing to push. Returns the rows affected (0 or 1).
    pub fn unbind_vault(&self, vault_id: &[u8]) -> Result<usize, StorageError> {
        // `length(sync_tenant) > 0` scopes the UPDATE to a *bound* vault, so a
        // repeat on an already-unbound (or never-bound) vault matches nothing and
        // returns 0 — SQLite otherwise counts an X''→X'' no-op write as a change.
        let n = self.conn.execute(
            "UPDATE vaults SET sync_tenant = X''
             WHERE vault_id = ?1 AND sync_target = ?2 AND length(sync_tenant) > 0",
            params![vault_id, SyncTarget::Cloud.to_i64()],
        )?;
        Ok(n)
    }

    // --- items ---

    /// Inserts or updates an item. The version must grow monotonically. A
    /// deletion is a record with `tombstone = true` and an incremented version.
    pub fn put_item(&self, it: &ItemRecord) -> Result<(), StorageError> {
        let version = checked_version(it.version)?;
        // Timestamps are storage-owned: created_at is set only on insert
        // (preserved on conflict), updated_at is always refreshed. Values from
        // the passed-in record are ignored.
        let now = now_secs();
        let key_epoch = checked_version(it.key_epoch)?;
        let changed = self.conn.execute(
            "INSERT INTO items
               (vault_id, item_id, item_type, content_blob, wrapped_item_key, version, tombstone, signature, author_pubkey, created_at, updated_at, key_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11)
             ON CONFLICT(vault_id, item_id) DO UPDATE SET
               item_type=excluded.item_type, content_blob=excluded.content_blob,
               wrapped_item_key=excluded.wrapped_item_key, version=excluded.version,
               tombstone=excluded.tombstone, signature=excluded.signature,
               author_pubkey=excluded.author_pubkey, updated_at=excluded.updated_at,
               key_epoch=excluded.key_epoch
             WHERE excluded.version > items.version",
            params![
                it.vault_id,
                it.item_id,
                it.item_type as i64,
                it.content_blob,
                it.wrapped_item_key,
                version,
                it.tombstone as i64,
                it.signature,
                it.author_pubkey,
                now,
                key_epoch,
            ],
        )?;
        if changed == 0 {
            let cur: i64 = self.conn.query_row(
                "SELECT version FROM items WHERE vault_id = ?1 AND item_id = ?2",
                params![it.vault_id, it.item_id],
                |r| r.get(0),
            )?;
            return Err(StorageError::VersionRollback {
                current: cur as u64,
                attempted: it.version,
            });
        }
        Ok(())
    }

    /// Returns an item by (vault_id, item_id), including tombstoned ones.
    pub fn get_item(
        &self,
        vault_id: &[u8],
        item_id: &[u8],
    ) -> Result<Option<ItemRecord>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, item_id, item_type, content_blob, wrapped_item_key, version, tombstone, signature, author_pubkey, created_at, updated_at, key_epoch
             FROM items WHERE vault_id = ?1 AND item_id = ?2",
        )?;
        Ok(stmt
            .query_row(params![vault_id, item_id], map_item_row)
            .optional()?)
    }

    /// List of non-deleted items in a vault.
    pub fn list_items(&self, vault_id: &[u8]) -> Result<Vec<ItemRecord>, StorageError> {
        self.query_items(vault_id, false)
    }

    /// List of a vault's items, including tombstones (for sync).
    pub fn list_items_including_tombstones(
        &self,
        vault_id: &[u8],
    ) -> Result<Vec<ItemRecord>, StorageError> {
        self.query_items(vault_id, true)
    }

    fn query_items(
        &self,
        vault_id: &[u8],
        include_tombstones: bool,
    ) -> Result<Vec<ItemRecord>, StorageError> {
        let sql = if include_tombstones {
            "SELECT vault_id, item_id, item_type, content_blob, wrapped_item_key, version, tombstone, signature, author_pubkey, created_at, updated_at, key_epoch
             FROM items WHERE vault_id = ?1 ORDER BY item_id"
        } else {
            "SELECT vault_id, item_id, item_type, content_blob, wrapped_item_key, version, tombstone, signature, author_pubkey, created_at, updated_at, key_epoch
             FROM items WHERE vault_id = ?1 AND tombstone = 0 ORDER BY item_id"
        };
        let mut stmt = self.conn.prepare_cached(sql)?;
        let rows = stmt
            .query_map(params![vault_id], map_item_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // --- item version history (archive of past secret versions) ---

    /// Stores `record` and clears its version history **in a single
    /// transaction** — an atomic secret tombstone: a crash cannot leave a
    /// tombstone with live history (otherwise the deleted plaintext
    /// "resurrects" via `get_item_version`).
    pub fn put_item_and_clear_history(&self, record: &ItemRecord) -> Result<(), StorageError> {
        self.transaction(|| {
            self.put_item(record)?;
            self.clear_item_history(&record.vault_id, &record.item_id)?;
            Ok::<(), StorageError>(())
        })
    }

    /// Stores `record`, first archiving the current (live) version of the item
    /// into `item_history` — all in a single transaction. After writing, it
    /// trims history down to the `retain` newest versions. For secrets with
    /// history (password/note).
    pub fn archive_and_put(&self, record: &ItemRecord, retain: usize) -> Result<(), StorageError> {
        self.transaction(|| {
            if let Some(existing) = self.get_item(&record.vault_id, &record.item_id)? {
                if !existing.tombstone {
                    self.insert_history(&existing)?;
                }
            }
            self.put_item(record)?;
            self.trim_history(&record.vault_id, &record.item_id, retain)?;
            Ok::<(), StorageError>(())
        })
    }

    fn insert_history(&self, r: &ItemRecord) -> Result<(), StorageError> {
        // OR IGNORE: UNIQUE(vault_id,item_id,version) makes archiving idempotent.
        self.conn.execute(
            "INSERT OR IGNORE INTO item_history
             (vault_id, item_id, item_type, content_blob, wrapped_item_key, version, tombstone, signature, author_pubkey, created_at, updated_at, key_epoch)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                r.vault_id, r.item_id, r.item_type as i64, r.content_blob, r.wrapped_item_key,
                checked_version(r.version)?, r.tombstone as i64, r.signature, r.author_pubkey,
                r.created_at, r.updated_at, checked_version(r.key_epoch)?
            ],
        )?;
        Ok(())
    }

    fn trim_history(
        &self,
        vault_id: &[u8],
        item_id: &[u8],
        retain: usize,
    ) -> Result<(), StorageError> {
        // Clamp to i64: otherwise a huge `retain` would yield a negative LIMIT,
        // which SQLite treats as "no limit" (history would not be trimmed).
        let retain = i64::try_from(retain).unwrap_or(i64::MAX);
        self.conn.execute(
            "DELETE FROM item_history WHERE vault_id=?1 AND item_id=?2 AND hseq NOT IN
             (SELECT hseq FROM item_history WHERE vault_id=?1 AND item_id=?2 ORDER BY hseq DESC LIMIT ?3)",
            params![vault_id, item_id, retain],
        )?;
        Ok(())
    }

    /// Archived versions of an item (newest first). The current version is not stored here.
    pub fn list_item_history(
        &self,
        vault_id: &[u8],
        item_id: &[u8],
    ) -> Result<Vec<ItemRecord>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, item_id, item_type, content_blob, wrapped_item_key, version, tombstone, signature, author_pubkey, created_at, updated_at, key_epoch
             FROM item_history WHERE vault_id = ?1 AND item_id = ?2 ORDER BY version DESC",
        )?;
        let rows = stmt
            .query_map(params![vault_id, item_id], map_item_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// All archived history records of a vault (for integrity auditing). Newest first.
    pub fn list_all_history(&self, vault_id: &[u8]) -> Result<Vec<ItemRecord>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, item_id, item_type, content_blob, wrapped_item_key, version, tombstone, signature, author_pubkey, created_at, updated_at, key_epoch
             FROM item_history WHERE vault_id = ?1 ORDER BY item_id, version DESC",
        )?;
        let rows = stmt
            .query_map(params![vault_id], map_item_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Clears an item's version history (e.g. on deletion — so that the old
    /// plaintext does not "resurrect" after a tombstone).
    pub fn clear_item_history(&self, vault_id: &[u8], item_id: &[u8]) -> Result<(), StorageError> {
        self.conn.execute(
            "DELETE FROM item_history WHERE vault_id = ?1 AND item_id = ?2",
            params![vault_id, item_id],
        )?;
        Ok(())
    }

    /// **Hard-delete** of all data for a single vault (cooperative `purge` on a
    /// revoke signal, server-spec §6.4): removes the vault record, ALL items
    /// (including tombstones), ALL version history, ALL membership manifests and
    /// grants, and the vault epoch floor — in a single transaction (atomically).
    /// Unlike a tombstone (`put_vault`/`put_item` with `tombstone=true`), rows
    /// here are physically deleted: no ciphertext or vault metadata remains on
    /// the device.
    ///
    /// **Best-effort/hygiene, NOT a remote-wipe** (server-spec §6.4): data
    /// already synced to OTHER or modified clients is not revoked by this —
    /// enforcement is cooperative. The decision of "when to purge" is made by
    /// the `vault` layer (`Vault::purge_vault`) on a verified signal; storage
    /// only deletes.
    pub fn purge_vault_data(&self, vault_id: &[u8]) -> Result<(), StorageError> {
        self.transaction(|| {
            self.conn.execute(
                "DELETE FROM item_history WHERE vault_id = ?1",
                params![vault_id],
            )?;
            self.conn
                .execute("DELETE FROM items WHERE vault_id = ?1", params![vault_id])?;
            self.conn.execute(
                "DELETE FROM membership_grants WHERE vault_id = ?1",
                params![vault_id],
            )?;
            self.conn.execute(
                "DELETE FROM membership_manifests WHERE vault_id = ?1",
                params![vault_id],
            )?;
            self.conn.execute(
                "DELETE FROM vault_epoch_floor WHERE vault_id = ?1",
                params![vault_id],
            )?;
            self.conn.execute(
                "DELETE FROM vault_trust_anchor WHERE vault_id = ?1",
                params![vault_id],
            )?;
            self.conn
                .execute("DELETE FROM vaults WHERE vault_id = ?1", params![vault_id])?;
            self.conn.execute(
                "DELETE FROM cert_meta WHERE vault_id = ?1",
                params![vault_id],
            )?;
            Ok::<(), StorageError>(())
        })
    }

    // --- known hosts (SSH TOFU/pinning, spec 10.4) ---

    /// Returns the pinned host key for (host, port), if any.
    pub fn get_known_host(&self, host: &str, port: u16) -> Result<Option<Vec<u8>>, StorageError> {
        // Canonicalization: hostnames are case-insensitive (DNS). Without it
        // `Host`/`host`/alias variants get pinned into DIFFERENT rows and each
        // silently re-TOFUs — narrowing the MITM-protection window. Lowercasing
        // does not change IP literals.
        let host = host.to_ascii_lowercase();
        Ok(self
            .conn
            .query_row(
                "SELECT host_key FROM known_hosts WHERE host = ?1 AND port = ?2",
                params![host, port as i64],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?)
    }

    /// Pins a host key (TOFU). Overwrites an existing one — a key change
    /// (re-pinning) is controlled by the calling layer.
    pub fn put_known_host(
        &self,
        host: &str,
        port: u16,
        host_key: &[u8],
    ) -> Result<(), StorageError> {
        let host = host.to_ascii_lowercase(); // canonical (see get_known_host)
        let added_at = now_secs();
        self.conn.execute(
            "INSERT INTO known_hosts (host, port, host_key, added_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(host, port) DO UPDATE SET host_key=excluded.host_key, added_at=excluded.added_at",
            params![host, port as i64, host_key, added_at],
        )?;
        Ok(())
    }

    /// List of all pinned host keys.
    pub fn list_known_hosts(&self) -> Result<Vec<KnownHost>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT host, port, host_key, added_at FROM known_hosts ORDER BY host, port",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(KnownHost {
                    host: r.get(0)?,
                    port: r.get::<_, i64>(1)? as u16,
                    host_key: r.get(2)?,
                    added_at: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Removes a pinned host key ("forget host"). Returns whether a row existed.
    pub fn remove_known_host(&self, host: &str, port: u16) -> Result<bool, StorageError> {
        let host = host.to_ascii_lowercase(); // canonical (see get_known_host)
        let n = self.conn.execute(
            "DELETE FROM known_hosts WHERE host = ?1 AND port = ?2",
            params![host, port as i64],
        )?;
        Ok(n > 0)
    }

    // --- membership: manifests + grants (storage for sharing, spec §13) ---
    //
    // Storage keeps the signed blobs/wrappers as-is and does **not** verify
    // signatures/epochs/issuance authority — that is the `vault` layer (P3).

    /// Inserts or updates a membership manifest (UPSERT on `(vault_id, key_epoch)`).
    pub fn put_membership_manifest(&self, m: &MembershipManifest) -> Result<(), StorageError> {
        let key_epoch = checked_version(m.key_epoch)?;
        self.conn.execute(
            "INSERT INTO membership_manifests
               (vault_id, key_epoch, manifest_blob, signature, author_pubkey)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(vault_id, key_epoch) DO UPDATE SET
               manifest_blob=excluded.manifest_blob, signature=excluded.signature,
               author_pubkey=excluded.author_pubkey",
            params![
                m.vault_id,
                key_epoch,
                m.manifest_blob,
                m.signature,
                m.author_pubkey
            ],
        )?;
        Ok(())
    }

    /// Returns a vault's membership manifest for the given epoch, if any.
    pub fn get_membership_manifest(
        &self,
        vault_id: &[u8],
        key_epoch: u64,
    ) -> Result<Option<MembershipManifest>, StorageError> {
        let epoch = checked_version(key_epoch)?;
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, key_epoch, manifest_blob, signature, author_pubkey
             FROM membership_manifests WHERE vault_id = ?1 AND key_epoch = ?2",
        )?;
        Ok(stmt
            .query_row(params![vault_id, epoch], map_manifest_row)
            .optional()?)
    }

    /// The highest epoch for which the vault has a membership manifest (`None`
    /// if there are no manifests — a single-owner local vault). Read-only; used
    /// by the `vault` layer to determine the current membership epoch before a
    /// VK rotation (a freshly created vault's record carries `key_epoch=0`,
    /// while the genesis manifest lives at epoch 1 — a mismatch until the first
    /// rotation).
    pub fn latest_membership_epoch(&self, vault_id: &[u8]) -> Result<Option<u64>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT MAX(key_epoch) FROM membership_manifests WHERE vault_id = ?1",
        )?;
        let epoch: Option<i64> = stmt.query_row(params![vault_id], |r| r.get(0))?;
        Ok(epoch.map(|e| e as u64))
    }

    /// Inserts or updates an access grant (UPSERT on
    /// `(vault_id, member_pubkey, key_epoch)`).
    pub fn put_membership_grant(&self, g: &MembershipGrant) -> Result<(), StorageError> {
        let key_epoch = checked_version(g.key_epoch)?;
        self.conn.execute(
            "INSERT INTO membership_grants
               (vault_id, member_pubkey, key_epoch, role, not_after, wrapped_vk, signature, author_pubkey)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(vault_id, member_pubkey, key_epoch) DO UPDATE SET
               role=excluded.role, not_after=excluded.not_after, wrapped_vk=excluded.wrapped_vk,
               signature=excluded.signature, author_pubkey=excluded.author_pubkey",
            params![
                g.vault_id,
                g.member_pubkey,
                key_epoch,
                g.role.to_i64(),
                g.not_after,
                g.wrapped_vk,
                g.signature,
                g.author_pubkey,
            ],
        )?;
        Ok(())
    }

    /// List of a vault's grants for a specific key epoch.
    pub fn list_membership_grants(
        &self,
        vault_id: &[u8],
        key_epoch: u64,
    ) -> Result<Vec<MembershipGrant>, StorageError> {
        let epoch = checked_version(key_epoch)?;
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, member_pubkey, key_epoch, role, not_after, wrapped_vk, signature, author_pubkey
             FROM membership_grants WHERE vault_id = ?1 AND key_epoch = ?2 ORDER BY member_pubkey",
        )?;
        let rows = stmt
            .query_map(params![vault_id, epoch], map_grant_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ── sync dirty-tracking ─────────────────────────────────────────
    // The `vault` layer sets `dirty=1` on a LOCAL edit; `sync_push` sends only
    // the dirty objects of bound cloud vaults and clears the flag after a
    // successful push. Data arriving from the server goes through the
    // low-level `put_*` (not through `vault`) → stays `dirty=0` and is not
    // sent back.

    /// Marks a vault record as edited locally (needs to be pushed).
    pub fn mark_vault_dirty(&self, vault_id: &[u8]) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE vaults SET dirty = 1 WHERE vault_id = ?1",
            params![vault_id],
        )?;
        Ok(())
    }

    /// Marks an item as edited locally (needs to be pushed).
    pub fn mark_item_dirty(&self, vault_id: &[u8], item_id: &[u8]) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE items SET dirty = 1 WHERE vault_id = ?1 AND item_id = ?2",
            params![vault_id, item_id],
        )?;
        Ok(())
    }

    /// Mark a vault record AND all of its items / manifests / grants dirty, so the next
    /// `sync_push` re-uploads the ENTIRE vault. Used when (re-)binding an existing vault to
    /// a server: the routing-label change (`sync_tenant`) alone touches no `dirty` flag, so
    /// without this a previously-synced vault never re-pushes its record to the newly-bound
    /// server — the classic "I bound my vault but it never uploaded" bug.
    pub fn mark_vault_and_contents_dirty(&self, vault_id: &[u8]) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE vaults SET dirty = 1 WHERE vault_id = ?1",
            params![vault_id],
        )?;
        self.conn.execute(
            "UPDATE items SET dirty = 1 WHERE vault_id = ?1",
            params![vault_id],
        )?;
        self.conn.execute(
            "UPDATE membership_manifests SET dirty = 1 WHERE vault_id = ?1",
            params![vault_id],
        )?;
        self.conn.execute(
            "UPDATE membership_grants SET dirty = 1 WHERE vault_id = ?1",
            params![vault_id],
        )?;
        Ok(())
    }

    /// Marks the manifest AND grants of a vault at the given epoch as dirty (a membership edit).
    pub fn mark_membership_dirty(
        &self,
        vault_id: &[u8],
        key_epoch: u64,
    ) -> Result<(), StorageError> {
        let e = checked_version(key_epoch)?;
        self.conn.execute(
            "UPDATE membership_manifests SET dirty = 1 WHERE vault_id = ?1 AND key_epoch = ?2",
            params![vault_id, e],
        )?;
        self.conn.execute(
            "UPDATE membership_grants SET dirty = 1 WHERE vault_id = ?1 AND key_epoch = ?2",
            params![vault_id, e],
        )?;
        Ok(())
    }

    /// Dirty vault records bound to `tenant` (for sync_push).
    pub fn list_dirty_bound_vaults(&self, tenant: &[u8]) -> Result<Vec<VaultRecord>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, sync_target, name_blob, wrapped_vk, version, tombstone, signature, author_pubkey, key_epoch, cache_policy, sync_tenant
             FROM vaults WHERE dirty = 1 AND sync_tenant = ?1 ORDER BY vault_id",
        )?;
        let rows = stmt
            .query_map(params![tenant], map_vault_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Dirty items of vaults bound to `tenant`.
    pub fn list_dirty_bound_items(&self, tenant: &[u8]) -> Result<Vec<ItemRecord>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT i.vault_id, i.item_id, i.item_type, i.content_blob, i.wrapped_item_key, i.version, i.tombstone, i.signature, i.author_pubkey, i.created_at, i.updated_at, i.key_epoch
             FROM items i JOIN vaults v ON i.vault_id = v.vault_id
             WHERE v.sync_tenant = ?1 AND i.dirty = 1 ORDER BY i.vault_id, i.item_id",
        )?;
        let rows = stmt
            .query_map(params![tenant], map_item_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Dirty membership manifests of vaults bound to `tenant`.
    pub fn list_dirty_bound_manifests(
        &self,
        tenant: &[u8],
    ) -> Result<Vec<MembershipManifest>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT m.vault_id, m.key_epoch, m.manifest_blob, m.signature, m.author_pubkey
             FROM membership_manifests m JOIN vaults v ON m.vault_id = v.vault_id
             WHERE v.sync_tenant = ?1 AND m.dirty = 1 ORDER BY m.vault_id, m.key_epoch",
        )?;
        let rows = stmt
            .query_map(params![tenant], map_manifest_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Dirty membership grants of vaults bound to `tenant`.
    pub fn list_dirty_bound_grants(
        &self,
        tenant: &[u8],
    ) -> Result<Vec<MembershipGrant>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT g.vault_id, g.member_pubkey, g.key_epoch, g.role, g.not_after, g.wrapped_vk, g.signature, g.author_pubkey
             FROM membership_grants g JOIN vaults v ON g.vault_id = v.vault_id
             WHERE v.sync_tenant = ?1 AND g.dirty = 1 ORDER BY g.vault_id, g.member_pubkey, g.key_epoch",
        )?;
        let rows = stmt
            .query_map(params![tenant], map_grant_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Clears the dirty flag on all objects of vaults bound to `tenant` — after
    /// a successful push. The bulk clear is safe: local edits and sync run under
    /// the same lock, and nothing mutates between list+push and clear.
    pub fn clear_dirty_for_tenant(&self, tenant: &[u8]) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE vaults SET dirty = 0 WHERE sync_tenant = ?1",
            params![tenant],
        )?;
        for table in ["items", "membership_manifests", "membership_grants"] {
            self.conn.execute(
                &format!(
                    "UPDATE {table} SET dirty = 0 WHERE vault_id IN \
                     (SELECT vault_id FROM vaults WHERE sync_tenant = ?1)"
                ),
                params![tenant],
            )?;
        }
        Ok(())
    }

    /// Removes a grant (revokes a member's access for an epoch). Returns whether a row existed.
    pub fn remove_membership_grant(
        &self,
        vault_id: &[u8],
        member_pubkey: &[u8],
        key_epoch: u64,
    ) -> Result<bool, StorageError> {
        let epoch = checked_version(key_epoch)?;
        let n = self.conn.execute(
            "DELETE FROM membership_grants
             WHERE vault_id = ?1 AND member_pubkey = ?2 AND key_epoch = ?3",
            params![vault_id, member_pubkey, epoch],
        )?;
        Ok(n > 0)
    }

    // --- member-pubkey pinning (anti-spoof, spec §13 item 12) ---

    /// Pins a member's public key to an account (UPSERT on `account_id`;
    /// `added_at` is set by storage). An overwrite is a re-pin; the decision to
    /// change the key is made by the layer above.
    pub fn pin_member_key(
        &self,
        account_id: &[u8],
        member_pubkey: &[u8],
        fingerprint: &str,
    ) -> Result<(), StorageError> {
        let added_at = now_secs();
        self.conn.execute(
            "INSERT INTO pinned_member_keys (account_id, member_pubkey, fingerprint, added_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(account_id) DO UPDATE SET
               member_pubkey=excluded.member_pubkey, fingerprint=excluded.fingerprint,
               added_at=excluded.added_at",
            params![account_id, member_pubkey, fingerprint, added_at],
        )?;
        Ok(())
    }

    /// Returns the pinned member key by `account_id`, if any.
    pub fn get_pinned_member_key(
        &self,
        account_id: &[u8],
    ) -> Result<Option<PinnedMemberKey>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT account_id, member_pubkey, fingerprint, added_at
             FROM pinned_member_keys WHERE account_id = ?1",
        )?;
        Ok(stmt
            .query_row(params![account_id], map_pinned_row)
            .optional()?)
    }

    /// List of all pinned member keys.
    pub fn list_pinned_member_keys(&self) -> Result<Vec<PinnedMemberKey>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT account_id, member_pubkey, fingerprint, added_at
             FROM pinned_member_keys ORDER BY account_id",
        )?;
        let rows = stmt
            .query_map([], map_pinned_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Removes a pinned member key. Returns whether a row existed.
    pub fn remove_pinned_member_key(&self, account_id: &[u8]) -> Result<bool, StorageError> {
        let n = self.conn.execute(
            "DELETE FROM pinned_member_keys WHERE account_id = ?1",
            params![account_id],
        )?;
        Ok(n > 0)
    }

    // --- append-only audit log (storage of signed events, spec §13) ---
    //
    // Append-only: insert at the end only, no update/delete. Storage does not
    // sign — `entry_blob` arrives already signed (the layer above).

    /// Appends a record to the audit log. Returns the assigned `seq` (monotonic).
    /// `recorded_at` is set by storage.
    pub fn append_audit(
        &self,
        entry_blob: &[u8],
        signature: &[u8],
        author_pubkey: &[u8],
    ) -> Result<u64, StorageError> {
        let recorded_at = now_secs();
        self.conn.execute(
            "INSERT INTO audit_log (entry_blob, signature, author_pubkey, recorded_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![entry_blob, signature, author_pubkey, recorded_at],
        )?;
        Ok(self.conn.last_insert_rowid() as u64)
    }

    /// Audit records with `seq > since_seq`, in ascending `seq` order. A
    /// cursor-based drain for sync/verification by the layer above.
    pub fn list_audit(&self, since_seq: u64) -> Result<Vec<AuditEntry>, StorageError> {
        // seq is an autoincrement rowid (i64). A since_seq beyond i64 → empty
        // (no seq can be larger), without overflow when binding.
        let since = match i64::try_from(since_seq) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let mut stmt = self.conn.prepare_cached(
            "SELECT seq, entry_blob, signature, author_pubkey, recorded_at
             FROM audit_log WHERE seq > ?1 ORDER BY seq ASC",
        )?;
        let rows = stmt
            .query_map(params![since], map_audit_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // --- sync-state: sync cursor and vault epoch floor (spec §13 item 2) ---
    //
    // Storage only (read/write). Floor monotonicity (no lowering) and cursor
    // anti-rollback are enforced by the `vault`/`sync` layer (P4/P6) — this is
    // raw storage.

    /// Writes a sync cursor by key (UPSERT). `v` is stored as INTEGER (i64).
    pub fn set_sync_cursor(&self, key: &str, v: u64) -> Result<(), StorageError> {
        let value = checked_version(v)?;
        self.conn.execute(
            "INSERT INTO sync_state (k, v) VALUES (?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![key, value],
        )?;
        Ok(())
    }

    /// Reads a sync cursor by key.
    pub fn get_sync_cursor(&self, key: &str) -> Result<Option<u64>, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT v FROM sync_state WHERE k = ?1", params![key], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
            .map(|v| v as u64))
    }

    /// Writes the vault epoch floor (the minimum acceptable epoch, anti-rollback)
    /// (UPSERT on `vault_id`).
    pub fn set_vault_epoch_floor(&self, vault_id: &[u8], epoch: u64) -> Result<(), StorageError> {
        let value = checked_version(epoch)?;
        self.conn.execute(
            "INSERT INTO vault_epoch_floor (vault_id, key_epoch) VALUES (?1, ?2)
             ON CONFLICT(vault_id) DO UPDATE SET key_epoch = excluded.key_epoch",
            params![vault_id, value],
        )?;
        Ok(())
    }

    /// Reads the vault epoch floor.
    pub fn get_vault_epoch_floor(&self, vault_id: &[u8]) -> Result<Option<u64>, StorageError> {
        Ok(self
            .conn
            .query_row(
                "SELECT key_epoch FROM vault_epoch_floor WHERE vault_id = ?1",
                params![vault_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|v| v as u64))
    }

    // --- per-vault trust anchor (genesis-owner, A0) ---

    /// Writes the per-vault anchor (UPSERT on `vault_id`; `pinned_at` is set by storage).
    /// Storage only: the TOFU control (no silent re-binding) is enforced by the
    /// `vault` layer (`pin_and_verify_vault_anchor`), as with `pin_member_key`.
    pub fn set_vault_trust_anchor(
        &self,
        vault_id: &[u8],
        genesis_owner_pubkey: &[u8],
    ) -> Result<(), StorageError> {
        let pinned_at = now_secs();
        self.conn.execute(
            "INSERT INTO vault_trust_anchor (vault_id, genesis_owner_pubkey, pinned_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(vault_id) DO UPDATE SET
               genesis_owner_pubkey=excluded.genesis_owner_pubkey, pinned_at=excluded.pinned_at",
            params![vault_id, genesis_owner_pubkey, pinned_at],
        )?;
        Ok(())
    }

    /// Returns the per-vault anchor by `vault_id`, if pinned.
    pub fn get_vault_trust_anchor(
        &self,
        vault_id: &[u8],
    ) -> Result<Option<VaultTrustAnchor>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, genesis_owner_pubkey, pinned_at
             FROM vault_trust_anchor WHERE vault_id = ?1",
        )?;
        Ok(stmt
            .query_row(params![vault_id], map_vault_trust_anchor_row)
            .optional()?)
    }

    // --- per-account state (A3) ---

    /// Writes per-account state (UPSERT on `author_pubkey`; `updated_at` is set
    /// by storage). Storage only: LWW by `version` is enforced by the sync/ffi layer.
    pub fn set_account_state(
        &self,
        author_pubkey: &[u8],
        version: u64,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), StorageError> {
        let v = checked_version(version)?;
        self.conn.execute(
            "INSERT INTO account_state (author_pubkey, version, payload, signature, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(author_pubkey) DO UPDATE SET
               version=excluded.version, payload=excluded.payload,
               signature=excluded.signature, updated_at=excluded.updated_at",
            params![author_pubkey, v, payload, signature, now_secs()],
        )?;
        Ok(())
    }

    /// Returns per-account state by `author_pubkey`, if any.
    pub fn get_account_state(
        &self,
        author_pubkey: &[u8],
    ) -> Result<Option<AccountStateRecord>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT author_pubkey, version, payload, signature, updated_at
             FROM account_state WHERE author_pubkey = ?1",
        )?;
        Ok(stmt
            .query_row(params![author_pubkey], map_account_state_row)
            .optional()?)
    }

    /// All local account-state records (by construction, exactly one — for the
    /// own account: `process_account_state` stores only author==own keyset). For
    /// push (the engine does not know the own pubkey directly).
    pub fn list_account_states(&self) -> Result<Vec<AccountStateRecord>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT author_pubkey, version, payload, signature, updated_at FROM account_state",
        )?;
        let rows = stmt
            .query_map([], map_account_state_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // --- structural integrity check ---

    /// Structural DB check (read-only): SQLCipher page HMAC + orphans (items
    /// with no row in `vaults`) + domain invariants (version≥1,
    /// `author_pubkey` length==32, signature length, tombstone⇒empty content).
    /// Pulls only lengths and ids from the DB (via `length(col)`), not the blobs
    /// themselves — the report contains no secrets/ciphertext.
    pub fn check_consistency(&self) -> Result<ConsistencyReport, StorageError> {
        let mut issues = Vec::new();
        let integrity_ok = self.integrity_ok()?;

        // Orphans: an item whose vault_id is absent from the vaults table.
        {
            let mut stmt = self.conn.prepare(
                "SELECT i.vault_id, i.item_id FROM items i
                 LEFT JOIN vaults v ON i.vault_id = v.vault_id
                 WHERE v.vault_id IS NULL",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (vid, iid) = row?;
                issues.push(ConsistencyIssue {
                    kind: ConsistencyKind::OrphanItem,
                    vault_id_hex: to_hex(&vid),
                    item_id_hex: to_hex(&iid),
                    detail: "item references no vault row".to_string(),
                });
            }
        }

        // Domain invariants — lengths/versions only, without selecting blobs.
        {
            let mut stmt = self.conn.prepare(
                "SELECT vault_id, item_id, version, tombstone,
                        length(content_blob), length(signature), length(author_pubkey)
                 FROM items",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })?;
            for row in rows {
                let (vid, iid, version, tombstone, clen, slen, alen) = row?;
                let vhex = to_hex(&vid);
                let ihex = to_hex(&iid);
                let mut push = |kind, detail: String| {
                    issues.push(ConsistencyIssue {
                        kind,
                        vault_id_hex: vhex.clone(),
                        item_id_hex: ihex.clone(),
                        detail,
                    });
                };
                if version < 1 {
                    push(ConsistencyKind::BadVersion, format!("version={version}"));
                }
                if alen != ED25519_PUBKEY_LEN {
                    push(
                        ConsistencyKind::BadAuthorLen,
                        format!("author_pubkey length={alen}"),
                    );
                }
                if slen < MIN_SIG_LEN {
                    push(
                        ConsistencyKind::BadSignatureLen,
                        format!("signature length={slen}"),
                    );
                }
                if tombstone != 0 && clen != 0 {
                    push(
                        ConsistencyKind::TombstoneNotEmpty,
                        format!("tombstone with content length={clen}"),
                    );
                }
            }
        }

        // Stale history: a version archive exists while the item itself is
        // deleted (tombstone) or absent — the old plaintext must not outlive the
        // deletion of the secret.
        {
            let mut stmt = self.conn.prepare(
                "SELECT h.vault_id, h.item_id FROM item_history h
                 LEFT JOIN items i ON h.vault_id = i.vault_id AND h.item_id = i.item_id
                 WHERE i.vault_id IS NULL OR i.tombstone = 1
                 GROUP BY h.vault_id, h.item_id",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (vid, iid) = row?;
                issues.push(ConsistencyIssue {
                    kind: ConsistencyKind::StaleHistory,
                    vault_id_hex: to_hex(&vid),
                    item_id_hex: to_hex(&iid),
                    detail: "version history for a deleted/absent item".to_string(),
                });
            }
        }

        // The same length() invariants (author_pubkey/signature, version/epoch)
        // for the remaining signed tables — previously the structural audit
        // covered only items, and a forged-shaped vault/history/membership row
        // passed it unnoticed (the signature is verified in the vault layer
        // anyway; this is just structural-audit completeness). Without selecting
        // blobs — lengths only.
        {
            let mut push_lens = |table: &str,
                                 vid: &[u8],
                                 id: &[u8],
                                 ver_or_epoch: i64,
                                 ver_label: &str,
                                 slen: i64,
                                 alen: i64| {
                let vhex = to_hex(vid);
                let ihex = if id.is_empty() {
                    String::new()
                } else {
                    to_hex(id)
                };
                if ver_or_epoch < 1 {
                    issues.push(ConsistencyIssue {
                        kind: ConsistencyKind::BadVersion,
                        vault_id_hex: vhex.clone(),
                        item_id_hex: ihex.clone(),
                        detail: format!("{table} {ver_label}={ver_or_epoch}"),
                    });
                }
                if alen != ED25519_PUBKEY_LEN {
                    issues.push(ConsistencyIssue {
                        kind: ConsistencyKind::BadAuthorLen,
                        vault_id_hex: vhex.clone(),
                        item_id_hex: ihex.clone(),
                        detail: format!("{table} author_pubkey length={alen}"),
                    });
                }
                if slen < MIN_SIG_LEN {
                    issues.push(ConsistencyIssue {
                        kind: ConsistencyKind::BadSignatureLen,
                        vault_id_hex: vhex,
                        item_id_hex: ihex,
                        detail: format!("{table} signature length={slen}"),
                    });
                }
            };
            // vaults (item_id empty): version >= 1
            let mut s = self.conn.prepare(
                "SELECT vault_id, version, length(signature), length(author_pubkey) FROM vaults",
            )?;
            for row in s.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })? {
                let (vid, ver, slen, alen) = row?;
                push_lens("vault", &vid, &[], ver, "version", slen, alen);
            }
            // item_history: version >= 1
            let mut s = self.conn.prepare(
                "SELECT vault_id, item_id, version, length(signature), length(author_pubkey) FROM item_history",
            )?;
            for row in s.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })? {
                let (vid, iid, ver, slen, alen) = row?;
                push_lens("history", &vid, &iid, ver, "version", slen, alen);
            }
            // membership_manifests: key_epoch >= 1
            let mut s = self.conn.prepare(
                "SELECT vault_id, key_epoch, length(signature), length(author_pubkey) FROM membership_manifests",
            )?;
            for row in s.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })? {
                let (vid, epoch, slen, alen) = row?;
                push_lens("manifest", &vid, &[], epoch, "key_epoch", slen, alen);
            }
            // membership_grants: key_epoch >= 1 (member_pubkey acts as item_id)
            let mut s = self.conn.prepare(
                "SELECT vault_id, member_pubkey, key_epoch, length(signature), length(author_pubkey) FROM membership_grants",
            )?;
            for row in s.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })? {
                let (vid, member, epoch, slen, alen) = row?;
                push_lens("grant", &vid, &member, epoch, "key_epoch", slen, alen);
            }
        }

        Ok(ConsistencyReport {
            ok: integrity_ok && issues.is_empty(),
            integrity_ok,
            issues,
        })
    }

    /// Structural DB check via `PRAGMA integrity_check` (works for both the
    /// encrypted and the in-memory DB; the HMAC level is covered by the vault
    /// layer's crypto verification). Returns `true` if the result is strictly `"ok"`.
    fn integrity_ok(&self) -> Result<bool, StorageError> {
        let res: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        Ok(res == "ok")
    }
}

// --- helpers ---

/// Versions are stored as SQLite INTEGER (i64). We reject out-of-range values
/// so as not to break monotonicity via sign overflow.
fn checked_version(v: u64) -> Result<i64, StorageError> {
    i64::try_from(v).map_err(|_| StorageError::VersionOutOfRange)
}

/// Encodes bytes as hex (ids are open metadata; the report holds no secrets).
fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Current unix time (secs). Pre-epoch/broken clocks → 0 (the timestamp is informational).
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn map_cipher_error(e: rusqlite::Error) -> StorageError {
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == rusqlite::ErrorCode::NotADatabase {
            return StorageError::WrongKeyOrCorrupt;
        }
    }
    StorageError::Sqlite(e)
}

fn map_vault_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<VaultRecord> {
    let sync_i: i64 = row.get(1)?;
    let sync_target =
        SyncTarget::from_i64(sync_i).ok_or(rusqlite::Error::IntegralValueOutOfRange(1, sync_i))?;
    let cache_i: i64 = row.get(9)?;
    let cache_policy = CachePolicy::from_i64(cache_i)
        .ok_or(rusqlite::Error::IntegralValueOutOfRange(9, cache_i))?;
    Ok(VaultRecord {
        vault_id: row.get(0)?,
        sync_target,
        name_blob: row.get(2)?,
        wrapped_vk: row.get(3)?,
        version: row.get::<_, i64>(4)? as u64,
        tombstone: row.get::<_, i64>(5)? != 0,
        signature: row.get(6)?,
        author_pubkey: row.get(7)?,
        key_epoch: row.get::<_, i64>(8)? as u64,
        cache_policy,
        sync_tenant: row.get(10)?,
    })
}

fn map_audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        seq: row.get::<_, i64>(0)? as u64,
        entry_blob: row.get(1)?,
        signature: row.get(2)?,
        author_pubkey: row.get(3)?,
        recorded_at: row.get(4)?,
    })
}

fn map_pinned_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PinnedMemberKey> {
    Ok(PinnedMemberKey {
        account_id: row.get(0)?,
        member_pubkey: row.get(1)?,
        fingerprint: row.get(2)?,
        added_at: row.get(3)?,
    })
}

fn map_vault_trust_anchor_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<VaultTrustAnchor> {
    Ok(VaultTrustAnchor {
        vault_id: row.get(0)?,
        genesis_owner_pubkey: row.get(1)?,
        pinned_at: row.get(2)?,
    })
}

fn map_account_state_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountStateRecord> {
    Ok(AccountStateRecord {
        author_pubkey: row.get(0)?,
        version: row.get::<_, i64>(1)? as u64,
        payload: row.get(2)?,
        signature: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn map_manifest_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MembershipManifest> {
    Ok(MembershipManifest {
        vault_id: row.get(0)?,
        key_epoch: row.get::<_, i64>(1)? as u64,
        manifest_blob: row.get(2)?,
        signature: row.get(3)?,
        author_pubkey: row.get(4)?,
    })
}

fn map_grant_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MembershipGrant> {
    let role_i: i64 = row.get(3)?;
    let role =
        MemberRole::from_i64(role_i).ok_or(rusqlite::Error::IntegralValueOutOfRange(3, role_i))?;
    Ok(MembershipGrant {
        vault_id: row.get(0)?,
        member_pubkey: row.get(1)?,
        key_epoch: row.get::<_, i64>(2)? as u64,
        role,
        not_after: row.get(4)?,
        wrapped_vk: row.get(5)?,
        signature: row.get(6)?,
        author_pubkey: row.get(7)?,
    })
}

fn map_item_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ItemRecord> {
    Ok(ItemRecord {
        vault_id: row.get(0)?,
        item_id: row.get(1)?,
        item_type: row.get::<_, i64>(2)? as u32,
        content_blob: row.get(3)?,
        wrapped_item_key: row.get(4)?,
        version: row.get::<_, i64>(5)? as u64,
        tombstone: row.get::<_, i64>(6)? != 0,
        signature: row.get(7)?,
        author_pubkey: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        key_epoch: row.get::<_, i64>(11)? as u64,
    })
}

#[cfg(test)]
mod purge_tests {
    use super::*;
    use crate::records::{
        CachePolicy, ItemRecord, MemberRole, MembershipGrant, MembershipManifest, SyncTarget,
        VaultRecord,
    };

    fn st() -> Storage {
        Storage::open_in_memory(&[9u8; 32]).unwrap()
    }

    fn vrec(id: &[u8]) -> VaultRecord {
        VaultRecord {
            vault_id: id.to_vec(),
            sync_target: SyncTarget::Cloud,
            name_blob: vec![1, 2, 3],
            wrapped_vk: vec![4, 5, 6],
            version: 1,
            tombstone: false,
            signature: vec![0u8; 67],
            author_pubkey: vec![0u8; 32],
            key_epoch: 1,
            cache_policy: CachePolicy::OfflineAllowed,
            sync_tenant: Vec::new(),
        }
    }
    fn irec(vid: &[u8], iid: &[u8]) -> ItemRecord {
        ItemRecord {
            vault_id: vid.to_vec(),
            item_id: iid.to_vec(),
            item_type: 1,
            content_blob: vec![7, 8, 9],
            wrapped_item_key: vec![1, 1, 1],
            version: 1,
            tombstone: false,
            signature: vec![0u8; 67],
            author_pubkey: vec![0u8; 32],
            created_at: 0,
            updated_at: 0,
            key_epoch: 1,
        }
    }

    #[test]
    fn purge_vault_data_removes_all_rows() {
        let s = st();
        let vid = b"vault-purge".to_vec();
        let other = b"vault-keep".to_vec();
        // target vault: record + item + history + manifest + grant
        s.put_vault(&vrec(&vid)).unwrap();
        s.put_item(&irec(&vid, b"i1")).unwrap();
        // history: put a new version with keep-history
        let mut i2 = irec(&vid, b"i1");
        i2.version = 2;
        s.archive_and_put(&i2, 20).unwrap();
        s.put_membership_manifest(&MembershipManifest {
            vault_id: vid.clone(),
            key_epoch: 1,
            manifest_blob: vec![1],
            signature: vec![0u8; 67],
            author_pubkey: vec![0u8; 32],
        })
        .unwrap();
        s.put_membership_grant(&MembershipGrant {
            vault_id: vid.clone(),
            member_pubkey: vec![2u8; 32],
            key_epoch: 1,
            role: MemberRole::Editor,
            not_after: 0,
            wrapped_vk: vec![3],
            signature: vec![0u8; 67],
            author_pubkey: vec![0u8; 32],
        })
        .unwrap();
        s.set_vault_epoch_floor(&vid, 1).unwrap();
        // another vault — must NOT be affected
        s.put_vault(&vrec(&other)).unwrap();
        s.put_item(&irec(&other, b"keep")).unwrap();

        s.purge_vault_data(&vid).unwrap();

        // target vault wiped from all tables
        assert!(s.get_vault(&vid).unwrap().is_none());
        assert!(s.list_items_including_tombstones(&vid).unwrap().is_empty());
        assert!(s.list_all_history(&vid).unwrap().is_empty());
        assert!(s.get_membership_manifest(&vid, 1).unwrap().is_none());
        assert!(s.list_membership_grants(&vid, 1).unwrap().is_empty());
        assert!(s.get_vault_epoch_floor(&vid).unwrap().is_none());
        // neighboring vault intact
        assert!(s.get_vault(&other).unwrap().is_some());
        assert_eq!(s.list_items(&other).unwrap().len(), 1);
    }

    #[test]
    fn sync_tenant_roundtrips_and_binds_only_unbound_cloud() {
        let s = st();
        // legacy cloud vault: sync_tenant empty (as after a schema migration of old data).
        let legacy = b"vault-legacy".to_vec();
        s.put_vault(&vrec(&legacy)).unwrap();
        assert!(s
            .get_vault(&legacy)
            .unwrap()
            .unwrap()
            .sync_tenant
            .is_empty());

        // local vault: also an empty sync_tenant, but must NOT be bound.
        let mut local = vrec(b"vault-local");
        local.sync_target = SyncTarget::Local;
        s.put_vault(&local).unwrap();

        // a cloud vault already bound to a DIFFERENT server — the migration must not overwrite it.
        let mut bound = vrec(b"vault-bound");
        bound.sync_tenant = b"tenant-B".to_vec();
        s.put_vault(&bound).unwrap();

        let n = s.bind_unbound_cloud_vaults(b"tenant-A").unwrap();
        assert_eq!(n, 1, "only the one unbound cloud vault is bound");
        assert_eq!(
            s.get_vault(&legacy).unwrap().unwrap().sync_tenant,
            b"tenant-A".to_vec()
        );
        // local untouched; already-bound cloud not overwritten.
        assert!(s
            .get_vault(b"vault-local")
            .unwrap()
            .unwrap()
            .sync_tenant
            .is_empty());
        assert_eq!(
            s.get_vault(b"vault-bound").unwrap().unwrap().sync_tenant,
            b"tenant-B".to_vec()
        );

        // a repeat call is idempotent (the already-bound legacy vault no longer counts as unbound).
        assert_eq!(s.bind_unbound_cloud_vaults(b"tenant-A").unwrap(), 0);
    }
}
