//! DB schema and migrations.

use rusqlite::Connection;

use crate::error::StorageError;

/// Current schema version.
pub(crate) const SCHEMA_VERSION: i64 = 9;

/// Version 1 DDL.
const MIGRATION_V1: &str = "
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS vaults (
    vault_id      BLOB PRIMARY KEY,
    sync_target   INTEGER NOT NULL,
    name_blob     BLOB NOT NULL,
    wrapped_vk    BLOB NOT NULL,
    version       INTEGER NOT NULL,
    tombstone     INTEGER NOT NULL,
    signature     BLOB NOT NULL,
    author_pubkey BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
    vault_id         BLOB NOT NULL,
    item_id          BLOB NOT NULL,
    item_type        INTEGER NOT NULL,
    content_blob     BLOB NOT NULL,
    wrapped_item_key BLOB NOT NULL,
    version          INTEGER NOT NULL,
    tombstone        INTEGER NOT NULL,
    signature        BLOB NOT NULL,
    author_pubkey    BLOB NOT NULL,
    server_seq       INTEGER,
    PRIMARY KEY (vault_id, item_id)
);

CREATE INDEX IF NOT EXISTS idx_items_vault ON items (vault_id);

CREATE TABLE IF NOT EXISTS known_hosts (
    host     TEXT NOT NULL,
    port     INTEGER NOT NULL,
    host_key BLOB NOT NULL,
    added_at INTEGER NOT NULL,
    PRIMARY KEY (host, port)
);
";

/// Version 2 DDL: open (non-synced) item timestamps.
const MIGRATION_V2: &str = "
ALTER TABLE items ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE items ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
";

/// Version 3 DDL: item version history (archive of past secret versions). `hseq` is
/// an autoincrement for ordering and retention; (vault_id, item_id, version)
/// are unique (the same version is not archived twice).
const MIGRATION_V3: &str = "
CREATE TABLE IF NOT EXISTS item_history (
    hseq             INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id         BLOB NOT NULL,
    item_id          BLOB NOT NULL,
    item_type        INTEGER NOT NULL,
    content_blob     BLOB NOT NULL,
    wrapped_item_key BLOB NOT NULL,
    version          INTEGER NOT NULL,
    tombstone        INTEGER NOT NULL,
    signature        BLOB NOT NULL,
    author_pubkey    BLOB NOT NULL,
    created_at       INTEGER NOT NULL DEFAULT 0,
    updated_at       INTEGER NOT NULL DEFAULT 0,
    UNIQUE (vault_id, item_id, version)
);
CREATE INDEX IF NOT EXISTS idx_history_item ON item_history (vault_id, item_id);
";

/// Version 4 DDL (server prerequisites for Milestone 2). Storage of ciphertext and
/// metadata only: signatures/epochs/membership are **not verified** at this layer — that
/// is the `vault`/`crypto` layer (P3/P4). Here are tables for:
/// - `key_epoch` in records (spec §13 item 9) + `cache_policy` (item 11);
/// - membership manifests and access grants (storage of signed blobs, 6/7/12);
/// - pinning of member-pubkey (item 12);
/// - append-only audit log (storage of signed records);
/// - anti-rollback sync cursor and vault epoch floor (item 2). **Important:** "outside
///   replicated data" here means only that these rows (`sync_state`,
///   `vault_epoch_floor`) are NOT transferred over sync and are not accessible to an untrusted
///   transport/peer — they protect against rollback of individual *replicated records*.
///   They do NOT protect against **snapshot-replay by swapping the whole DB file**: the floor/cursor
///   live in the same SQLite file, and rolling back the whole file to an old copy rolls
///   them back too. Protection against full snapshot-replay is a higher layer (a trusted last-seen
///   anchor outside the DB file, e.g. in keychain/secure-enclave; ⏳ Milestone 2+);
/// - a seam for the CA orchestrator (`cert_meta`, item 15) — without CRUD logic for now.
const MIGRATION_V4: &str = "
ALTER TABLE vaults ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vaults ADD COLUMN cache_policy INTEGER NOT NULL DEFAULT 0;
ALTER TABLE items ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE item_history ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS membership_manifests (
    vault_id      BLOB NOT NULL,
    key_epoch     INTEGER NOT NULL,
    manifest_blob BLOB NOT NULL,
    signature     BLOB NOT NULL,
    author_pubkey BLOB NOT NULL,
    PRIMARY KEY (vault_id, key_epoch)
);
CREATE TABLE IF NOT EXISTS membership_grants (
    vault_id      BLOB NOT NULL,
    member_pubkey BLOB NOT NULL,
    key_epoch     INTEGER NOT NULL,
    role          INTEGER NOT NULL,
    wrapped_vk    BLOB NOT NULL,
    signature     BLOB NOT NULL,
    author_pubkey BLOB NOT NULL,
    PRIMARY KEY (vault_id, member_pubkey, key_epoch)
);
CREATE INDEX IF NOT EXISTS idx_grants_epoch ON membership_grants (vault_id, key_epoch);
CREATE TABLE IF NOT EXISTS pinned_member_keys (
    account_id    BLOB PRIMARY KEY,
    member_pubkey BLOB NOT NULL,
    fingerprint   TEXT NOT NULL,
    added_at      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_blob    BLOB NOT NULL,
    signature     BLOB NOT NULL,
    author_pubkey BLOB NOT NULL,
    recorded_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_epoch_floor (
    vault_id  BLOB PRIMARY KEY,
    key_epoch INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sync_state (
    k TEXT PRIMARY KEY,
    v INTEGER NOT NULL
);
-- ⏳ seam for the CA orchestrator (spec §15): certificate metadata, without CRUD logic for now.
CREATE TABLE IF NOT EXISTS cert_meta (
    vault_id   BLOB NOT NULL,
    item_id    BLOB NOT NULL,
    not_before INTEGER,
    not_after  INTEGER,
    serial     BLOB,
    PRIMARY KEY (vault_id, item_id)
);
";

/// Version 5 DDL (1:1 binding of a cloud vault to a server). A cloud vault syncs
/// with exactly ONE server, identified by its `tenant_id` (the same one that
/// already keys the sync transport). `sync_tenant` is an **open client-side routing
/// label** (NOT part of the signed content of a vault record, like
/// `sync_target`/`key_epoch`/`cache_policy`): existing signatures stay
/// valid. Empty (`X''`) = unbound/legacy (a vault created before multi-server,
/// or a local vault that never syncs). Filled for exactly
/// one server via the one-shot `bind_unbound_cloud_vaults` migration on
/// the client, when a single server is bound.
const MIGRATION_V5: &str = "
ALTER TABLE vaults ADD COLUMN sync_tenant BLOB NOT NULL DEFAULT X'';
";

/// Version 6 DDL: per-grant `not_after` (unix seconds; sentinel `<=0` = no
/// expiry). WARNING: `not_after` enters the SIGNED grant content at a new
/// position (`GRANT_DOMAIN || role || not_after:i64be(8) || wrapped_vk`). The signature
/// of a grant issued before V6 covered the old layout WITHOUT these 8 bytes, so
/// after the migration `verify_grant` will reassemble the content with the 8 bytes inserted and
/// the signature will NOT match — pre-V6 grants require re-issuance (epoch rotation). This
/// is safe here only because the schema is introduced before the first release (grants
/// of the previous format do not exist in the wild); with old data present, a
/// bump of `GRANT_DOMAIN` and an explicit re-issuance would be needed.
const MIGRATION_V6: &str = "
ALTER TABLE membership_grants ADD COLUMN not_after INTEGER NOT NULL DEFAULT 0;
";

/// Version 7 DDL: per-vault trusted anchor (genesis-owner). A vault created
/// by ANOTHER account (a teammate) is verified against its creator-pubkey, not against
/// the local keyset. The value is pinned TOFU on share-accept (OOB confirmation
/// of the fingerprint), NOT taken from an untrusted transport: an injected self-consistent
/// genesis manifest would otherwise become its own anchor. Absence of a row = own
/// vault (fallback to the local keyset).
const MIGRATION_V7: &str = "
CREATE TABLE IF NOT EXISTS vault_trust_anchor (
    vault_id             BLOB PRIMARY KEY,
    genesis_owner_pubkey BLOB NOT NULL,
    pinned_at            INTEGER NOT NULL
);
";

/// Version 8 DDL: per-account state (A3) — a signed+versioned,
/// HPKE-self-sealed blob (pointer to the personal vault + account-default username).
/// The key is the account's Ed25519 pubkey; LWW by `version` (enforced by the sync/ffi layer).
const MIGRATION_V8: &str = "
CREATE TABLE IF NOT EXISTS account_state (
    author_pubkey BLOB PRIMARY KEY,
    version       INTEGER NOT NULL,
    payload       BLOB NOT NULL,
    signature     BLOB NOT NULL,
    updated_at    INTEGER NOT NULL
);
";

/// Version 9 DDL: per-object sync dirty flag. Before this, `sync_push` re-sent ALL
/// objects of bound cloud vaults on EVERY sync (the server deduplicated by version-LWW,
/// but the ciphertext was re-uploaded on each run). `dirty=1` is set by the `vault` layer
/// on a LOCAL edit; `sync_push` sends only `dirty=1` and clears the flag after
/// a successful push; `sync_pull` writes via the low-level `put_*` (not via `vault`),
/// so what is applied from the server stays `dirty=0` and does not go back. Existing
/// rows are marked `dirty=1` once — so that local, but not-yet-pushed data
/// does not settle unsynced; after the first push the flag is cleared. account_state is NOT
/// covered by the flag (it is broadcast to EVERY server) — its dirty-tracking is done by a
/// per-tenant version cursor in `sync_state`.
const MIGRATION_V9: &str = "
ALTER TABLE vaults ADD COLUMN dirty INTEGER NOT NULL DEFAULT 0;
ALTER TABLE items ADD COLUMN dirty INTEGER NOT NULL DEFAULT 0;
ALTER TABLE membership_manifests ADD COLUMN dirty INTEGER NOT NULL DEFAULT 0;
ALTER TABLE membership_grants ADD COLUMN dirty INTEGER NOT NULL DEFAULT 0;
UPDATE vaults SET dirty = 1;
UPDATE items SET dirty = 1;
UPDATE membership_manifests SET dirty = 1;
UPDATE membership_grants SET dirty = 1;
CREATE INDEX IF NOT EXISTS idx_items_dirty ON items (vault_id, dirty);
";

/// Applies migrations up to [`SCHEMA_VERSION`].
///
/// Each step is atomic: the version's DDL and the `user_version` bump run in one transaction
/// (DDL in SQLite is transactional). A crash/failure mid-step → full rollback,
/// `user_version` is unchanged, and a repeat `open()` safely re-runs the step.
/// Without this, a non-idempotent `ALTER TABLE ADD COLUMN` (V2) after a partial
/// application would forever break opening the DB.
pub(crate) fn migrate(conn: &Connection) -> Result<(), StorageError> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(StorageError::SchemaVersion(current));
    }
    if current < 1 {
        run_step(conn, MIGRATION_V1, 1)?;
    }
    if current < 2 {
        run_step(conn, MIGRATION_V2, 2)?;
    }
    if current < 3 {
        run_step(conn, MIGRATION_V3, 3)?;
    }
    if current < 4 {
        run_step(conn, MIGRATION_V4, 4)?;
    }
    if current < 5 {
        run_step(conn, MIGRATION_V5, 5)?;
    }
    if current < 6 {
        run_step(conn, MIGRATION_V6, 6)?;
    }
    if current < 7 {
        run_step(conn, MIGRATION_V7, 7)?;
    }
    if current < 8 {
        run_step(conn, MIGRATION_V8, 8)?;
    }
    if current < 9 {
        run_step(conn, MIGRATION_V9, 9)?;
    }
    Ok(())
}

/// Runs one migration step and commits `user_version` atomically. On error, an
/// explicit `ROLLBACK`, so the connection is not left in an open transaction.
fn run_step(conn: &Connection, ddl: &str, version: i64) -> Result<(), StorageError> {
    let batch = format!("BEGIN;\n{ddl}\nPRAGMA user_version = {version};\nCOMMIT;");
    conn.execute_batch(&batch).map_err(|e| {
        drop(conn.execute_batch("ROLLBACK"));
        StorageError::from(e)
    })?;
    Ok(())
}
