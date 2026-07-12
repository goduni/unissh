-- UniSSH Server schema v2: "one account, many spaces".
-- Identity plane is INSTANCE-scoped; spaces are server-trusted groupings; vault
-- crypto tables keep their exact blob semantics, minus tenant scoping.
-- Conventions unchanged: ids/pubkeys/blobs = BLOB; ints/bools/ts = INTEGER; text = TEXT.

CREATE TABLE instance (
  id               INTEGER PRIMARY KEY CHECK (id = 1),   -- singleton row
  instance_id      BLOB    NOT NULL,                     -- random 16B; auth-challenge host binding
  name             TEXT,
  claimed          INTEGER NOT NULL DEFAULT 0,
  owner_account_id BLOB,
  setup_code_hash  BLOB,                                 -- sha256("XXXX-XXXX-XXXX"); NULL once claimed
  next_seq         INTEGER NOT NULL DEFAULT 0,           -- instance-wide monotonic object seq
  created_at       INTEGER NOT NULL
);

CREATE TABLE accounts (
  account_id       BLOB PRIMARY KEY,
  ed25519_pub      BLOB    NOT NULL UNIQUE,              -- canonical member-id, server-wide
  x25519_pub       BLOB    NOT NULL,
  handle           TEXT    UNIQUE,
  display_name     TEXT,
  status           TEXT    NOT NULL DEFAULT 'active',    -- 'active' | 'disabled'
  is_owner         INTEGER NOT NULL DEFAULT 0,
  external_issuer  TEXT,                                 -- SSO seam (Phase 5)
  external_subject TEXT,
  reg_payload      BLOB    NOT NULL,
  reg_signature    BLOB    NOT NULL,
  created_at       INTEGER NOT NULL,
  UNIQUE (external_issuer, external_subject)
);

CREATE TABLE devices (
  device_id     BLOB PRIMARY KEY,
  account_id    BLOB    NOT NULL REFERENCES accounts(account_id),
  ed25519_pub   BLOB    NOT NULL,                        -- shared account keyset
  x25519_pub    BLOB    NOT NULL,
  kind          TEXT    NOT NULL DEFAULT 'app',          -- 'app' | 'web' (panel, Phase 4)
  label         TEXT,
  status        TEXT    NOT NULL DEFAULT 'active',       -- 'active' | 'revoked'
  registered_at INTEGER NOT NULL,
  expires_at    INTEGER                                  -- web devices auto-expire; NULL for app
);
CREATE INDEX idx_dev_account ON devices(account_id);
CREATE INDEX idx_dev_ed      ON devices(ed25519_pub);

CREATE TABLE sessions (
  session_id      BLOB PRIMARY KEY,
  account_id      BLOB    NOT NULL,
  device_id       BLOB    NOT NULL REFERENCES devices(device_id),
  access_hash     BLOB    NOT NULL,
  refresh_hash    BLOB    NOT NULL,
  access_expires  INTEGER NOT NULL,
  refresh_expires INTEGER NOT NULL,
  auth_source     TEXT    NOT NULL DEFAULT 'keyset',     -- 'keyset' | 'oidc' (Phase 5)
  created_at      INTEGER NOT NULL,
  revoked         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_sessions_device ON sessions(device_id);

CREATE TABLE auth_nonces (
  nonce      BLOB PRIMARY KEY,
  device_id  BLOB,
  expires_at INTEGER NOT NULL,
  consumed   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE spaces (
  space_id   BLOB PRIMARY KEY,
  name       TEXT    NOT NULL,
  status     TEXT    NOT NULL DEFAULT 'active',          -- 'active' | 'suspended'
  created_by BLOB,
  created_at INTEGER NOT NULL
);

CREATE TABLE space_members (
  space_id   BLOB    NOT NULL REFERENCES spaces(space_id),
  account_id BLOB    NOT NULL REFERENCES accounts(account_id),
  role       TEXT    NOT NULL DEFAULT 'member',          -- 'admin' | 'member' (server-trusted)
  added_by   BLOB,
  added_at   INTEGER NOT NULL,
  PRIMARY KEY (space_id, account_id)
);
CREATE INDEX idx_sm_account ON space_members(account_id);

-- Vault snapshot: crypto columns unchanged; + space/personal scope + access policy.
CREATE TABLE vaults (
  vault_id         BLOB PRIMARY KEY,
  space_id         BLOB REFERENCES spaces(space_id),     -- NULL → personal vault
  owner_account_id BLOB,                                 -- set for personal vaults
  owner_pubkey     BLOB    NOT NULL,
  access_policy    TEXT    NOT NULL DEFAULT 'selective', -- 'selective' | 'space_wide'
  space_wide_role  INTEGER,                              -- 0|1|2 when access_policy='space_wide'
  manual_approve   INTEGER NOT NULL DEFAULT 0,
  latest_version   INTEGER NOT NULL,
  latest_epoch     INTEGER NOT NULL,
  sync_target      INTEGER NOT NULL,
  cache_policy     INTEGER NOT NULL,
  tombstone        INTEGER NOT NULL DEFAULT 0,
  created_at       INTEGER NOT NULL
);
CREATE INDEX idx_vaults_space ON vaults(space_id);

-- Append-only object log; seq is INSTANCE-wide (allocated from instance.next_seq).
CREATE TABLE objects (
  server_seq    INTEGER PRIMARY KEY,
  object_tag    INTEGER NOT NULL,
  object_bytes  BLOB    NOT NULL,
  vault_id      BLOB,
  item_id       BLOB,
  member_pubkey BLOB,
  obj_version   INTEGER,
  key_epoch     INTEGER,
  tombstone     INTEGER,
  item_type     INTEGER,
  sync_target   INTEGER,
  cache_policy  INTEGER,
  role          INTEGER,
  author_pubkey BLOB,
  received_at   INTEGER NOT NULL
);
CREATE INDEX idx_obj_vault    ON objects(vault_id, obj_version);
CREATE INDEX idx_obj_logical  ON objects(object_tag, vault_id, item_id, obj_version);

CREATE TABLE membership_manifests (
  vault_id      BLOB    NOT NULL,
  key_epoch     INTEGER NOT NULL,
  manifest_blob BLOB    NOT NULL,
  signature     BLOB    NOT NULL,
  author_pubkey BLOB    NOT NULL,
  server_seq    INTEGER NOT NULL,
  received_at   INTEGER NOT NULL,
  PRIMARY KEY (vault_id, key_epoch)
);

CREATE TABLE membership_grants (
  vault_id      BLOB    NOT NULL,
  member_pubkey BLOB    NOT NULL,
  key_epoch     INTEGER NOT NULL,
  role          INTEGER NOT NULL,
  wrapped_vk    BLOB    NOT NULL,
  signature     BLOB    NOT NULL,
  author_pubkey BLOB    NOT NULL,
  not_after     INTEGER,
  revoked       INTEGER NOT NULL DEFAULT 0,
  server_seq    INTEGER NOT NULL,
  received_at   INTEGER NOT NULL,
  PRIMARY KEY (vault_id, member_pubkey, key_epoch)
);
CREATE INDEX idx_grants_epoch  ON membership_grants(vault_id, key_epoch);
CREATE INDEX idx_grants_member ON membership_grants(member_pubkey);

CREATE TABLE audit_log (
  seq           INTEGER PRIMARY KEY,                     -- instance-wide monotonic
  source        TEXT    NOT NULL,
  entry_blob    BLOB    NOT NULL,
  signature     BLOB,
  author_pubkey BLOB,
  vault_id      BLOB,
  space_id      BLOB,
  recorded_at   INTEGER NOT NULL,
  server_seq    INTEGER,
  prev_hash     BLOB
);

CREATE TABLE keyset_blobs (
  account_id   BLOB    NOT NULL REFERENCES accounts(account_id),
  generation   INTEGER NOT NULL,
  keyset_bytes BLOB    NOT NULL,
  ed25519_pub  BLOB    NOT NULL,
  x25519_pub   BLOB    NOT NULL,
  uploaded_at  INTEGER NOT NULL,
  PRIMARY KEY (account_id, generation)
);

-- v2 invites: one mechanism, intents inside. Only sha256(token) stored.
CREATE TABLE invites (
  invite_id     BLOB PRIMARY KEY,
  token_hash    BLOB    NOT NULL UNIQUE,
  space_intents TEXT    NOT NULL,                        -- JSON [{"space_id":"<b64>","role":"member"|"admin"}]
  vault_intents TEXT    NOT NULL DEFAULT '[]',           -- JSON [{"vault_id":"<b64>","role":0|1|2}]
  expires_at    INTEGER NOT NULL,
  state         TEXT    NOT NULL DEFAULT 'pending',      -- pending|redeemed|expired|revoked
  redeemed_by   BLOB,
  redeemed_at   INTEGER,
  created_by    BLOB,                                    -- creator account_id
  created_at    INTEGER NOT NULL
);

-- Queue of crypto work for vault-admin clients (grant/revoke fulfilment).
CREATE TABLE pending_actions (
  action_id   BLOB PRIMARY KEY,
  kind        TEXT    NOT NULL,                          -- 'grant' | 'revoke'
  vault_id    BLOB    NOT NULL,
  account_id  BLOB    NOT NULL,
  crypto_role INTEGER,                                   -- for 'grant'
  source      TEXT    NOT NULL,                          -- 'invite' | 'directory' | 'policy' | 'oidc'
  proof       BLOB,                                      -- invite binding MAC (opaque to server)
  state       TEXT    NOT NULL DEFAULT 'pending',        -- pending|done|cancelled
  created_at  INTEGER NOT NULL,
  done_at     INTEGER,
  done_epoch  INTEGER
);
CREATE INDEX idx_pending_vault ON pending_actions(vault_id, state);

-- Key-binding attestations (signed by a space-admin keyset; server stores verbatim).
CREATE TABLE key_attestations (
  account_id      BLOB    NOT NULL,
  attestor_pubkey BLOB    NOT NULL,
  blob            BLOB    NOT NULL,
  signature       BLOB    NOT NULL,
  created_at      INTEGER NOT NULL,
  PRIMARY KEY (account_id, attestor_pubkey)
);

CREATE TABLE pake_relay (
  channel_id BLOB PRIMARY KEY,
  msg1       BLOB,
  msg2       BLOB,
  msg3       BLOB,
  state      TEXT    NOT NULL DEFAULT 'open',
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE idempotency_keys (
  idem_key      BLOB PRIMARY KEY,
  request_hash  BLOB    NOT NULL,
  response_blob BLOB    NOT NULL,
  status_code   INTEGER NOT NULL,
  created_at    INTEGER NOT NULL
);
