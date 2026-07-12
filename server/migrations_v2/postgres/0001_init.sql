-- UniSSH Server schema v2: "one account, many spaces".
-- Identity plane is INSTANCE-scoped; spaces are server-trusted groupings; vault
-- crypto tables keep their exact blob semantics, minus tenant scoping.
-- Conventions unchanged: ids/pubkeys/blobs = BYTEA; ints/bools/ts = BIGINT; text = TEXT.

CREATE TABLE instance (
  id               BIGINT PRIMARY KEY CHECK (id = 1),    -- singleton row
  instance_id      BYTEA   NOT NULL,                      -- random 16B; auth-challenge host binding
  name             TEXT,
  claimed          BIGINT NOT NULL DEFAULT 0,
  owner_account_id BYTEA,
  setup_code_hash  BYTEA,                                 -- sha256("XXXX-XXXX-XXXX"); NULL once claimed
  next_seq         BIGINT NOT NULL DEFAULT 0,             -- instance-wide monotonic object seq
  created_at       BIGINT NOT NULL
);

CREATE TABLE accounts (
  account_id       BYTEA PRIMARY KEY,
  ed25519_pub      BYTEA   NOT NULL UNIQUE,               -- canonical member-id, server-wide
  x25519_pub       BYTEA   NOT NULL,
  handle           TEXT    UNIQUE,
  display_name     TEXT,
  status           TEXT    NOT NULL DEFAULT 'active',     -- 'active' | 'disabled'
  is_owner         BIGINT NOT NULL DEFAULT 0,
  external_issuer  TEXT,                                  -- SSO seam (Phase 5)
  external_subject TEXT,
  reg_payload      BYTEA   NOT NULL,
  reg_signature    BYTEA   NOT NULL,
  created_at       BIGINT NOT NULL,
  UNIQUE (external_issuer, external_subject)
);

CREATE TABLE devices (
  device_id     BYTEA PRIMARY KEY,
  account_id    BYTEA   NOT NULL REFERENCES accounts(account_id),
  ed25519_pub   BYTEA   NOT NULL,                         -- shared account keyset
  x25519_pub    BYTEA   NOT NULL,
  kind          TEXT    NOT NULL DEFAULT 'app',           -- 'app' | 'web' (panel, Phase 4)
  label         TEXT,
  status        TEXT    NOT NULL DEFAULT 'active',        -- 'active' | 'revoked'
  registered_at BIGINT NOT NULL,
  expires_at    BIGINT                                    -- web devices auto-expire; NULL for app
);
CREATE INDEX idx_dev_account ON devices(account_id);
CREATE INDEX idx_dev_ed      ON devices(ed25519_pub);

CREATE TABLE sessions (
  session_id      BYTEA PRIMARY KEY,
  account_id      BYTEA   NOT NULL,
  device_id       BYTEA   NOT NULL REFERENCES devices(device_id),
  access_hash     BYTEA   NOT NULL,
  refresh_hash    BYTEA   NOT NULL,
  access_expires  BIGINT NOT NULL,
  refresh_expires BIGINT NOT NULL,
  auth_source     TEXT    NOT NULL DEFAULT 'keyset',      -- 'keyset' | 'oidc' (Phase 5)
  created_at      BIGINT NOT NULL,
  revoked         BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX idx_sessions_device ON sessions(device_id);

CREATE TABLE auth_nonces (
  nonce      BYTEA PRIMARY KEY,
  device_id  BYTEA,
  expires_at BIGINT NOT NULL,
  consumed   BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE spaces (
  space_id   BYTEA PRIMARY KEY,
  name       TEXT    NOT NULL,
  status     TEXT    NOT NULL DEFAULT 'active',           -- 'active' | 'suspended'
  created_by BYTEA,
  created_at BIGINT NOT NULL
);

CREATE TABLE space_members (
  space_id   BYTEA   NOT NULL REFERENCES spaces(space_id),
  account_id BYTEA   NOT NULL REFERENCES accounts(account_id),
  role       TEXT    NOT NULL DEFAULT 'member',           -- 'admin' | 'member' (server-trusted)
  added_by   BYTEA,
  added_at   BIGINT NOT NULL,
  PRIMARY KEY (space_id, account_id)
);
CREATE INDEX idx_sm_account ON space_members(account_id);

-- Vault snapshot: crypto columns unchanged; + space/personal scope + access policy.
CREATE TABLE vaults (
  vault_id         BYTEA PRIMARY KEY,
  space_id         BYTEA REFERENCES spaces(space_id),     -- NULL → personal vault
  owner_account_id BYTEA,                                 -- set for personal vaults
  owner_pubkey     BYTEA   NOT NULL,
  access_policy    TEXT    NOT NULL DEFAULT 'selective',  -- 'selective' | 'space_wide'
  space_wide_role  BIGINT,                                -- 0|1|2 when access_policy='space_wide'
  manual_approve   BIGINT NOT NULL DEFAULT 0,
  latest_version   BIGINT NOT NULL,
  latest_epoch     BIGINT NOT NULL,
  sync_target      BIGINT NOT NULL,
  cache_policy     BIGINT NOT NULL,
  tombstone        BIGINT NOT NULL DEFAULT 0,
  created_at       BIGINT NOT NULL
);
CREATE INDEX idx_vaults_space ON vaults(space_id);

-- Append-only object log; seq is INSTANCE-wide (allocated from instance.next_seq).
CREATE TABLE objects (
  server_seq    BIGINT PRIMARY KEY,
  object_tag    BIGINT NOT NULL,
  object_bytes  BYTEA   NOT NULL,
  vault_id      BYTEA,
  item_id       BYTEA,
  member_pubkey BYTEA,
  obj_version   BIGINT,
  key_epoch     BIGINT,
  tombstone     BIGINT,
  item_type     BIGINT,
  sync_target   BIGINT,
  cache_policy  BIGINT,
  role          BIGINT,
  author_pubkey BYTEA,
  received_at   BIGINT NOT NULL
);
CREATE INDEX idx_obj_vault    ON objects(vault_id, obj_version);
CREATE INDEX idx_obj_logical  ON objects(object_tag, vault_id, item_id, obj_version);

CREATE TABLE membership_manifests (
  vault_id      BYTEA   NOT NULL,
  key_epoch     BIGINT NOT NULL,
  manifest_blob BYTEA   NOT NULL,
  signature     BYTEA   NOT NULL,
  author_pubkey BYTEA   NOT NULL,
  server_seq    BIGINT NOT NULL,
  received_at   BIGINT NOT NULL,
  PRIMARY KEY (vault_id, key_epoch)
);

CREATE TABLE membership_grants (
  vault_id      BYTEA   NOT NULL,
  member_pubkey BYTEA   NOT NULL,
  key_epoch     BIGINT NOT NULL,
  role          BIGINT NOT NULL,
  wrapped_vk    BYTEA   NOT NULL,
  signature     BYTEA   NOT NULL,
  author_pubkey BYTEA   NOT NULL,
  not_after     BIGINT,
  revoked       BIGINT NOT NULL DEFAULT 0,
  server_seq    BIGINT NOT NULL,
  received_at   BIGINT NOT NULL,
  PRIMARY KEY (vault_id, member_pubkey, key_epoch)
);
CREATE INDEX idx_grants_epoch  ON membership_grants(vault_id, key_epoch);
CREATE INDEX idx_grants_member ON membership_grants(member_pubkey);

CREATE TABLE audit_log (
  seq           BIGINT PRIMARY KEY,                       -- instance-wide monotonic
  source        TEXT    NOT NULL,
  entry_blob    BYTEA   NOT NULL,
  signature     BYTEA,
  author_pubkey BYTEA,
  vault_id      BYTEA,
  space_id      BYTEA,
  recorded_at   BIGINT NOT NULL,
  server_seq    BIGINT,
  prev_hash     BYTEA
);

CREATE TABLE keyset_blobs (
  account_id   BYTEA   NOT NULL REFERENCES accounts(account_id),
  generation   BIGINT NOT NULL,
  keyset_bytes BYTEA   NOT NULL,
  ed25519_pub  BYTEA   NOT NULL,
  x25519_pub   BYTEA   NOT NULL,
  uploaded_at  BIGINT NOT NULL,
  PRIMARY KEY (account_id, generation)
);

-- v2 invites: one mechanism, intents inside. Only sha256(token) stored.
CREATE TABLE invites (
  invite_id     BYTEA PRIMARY KEY,
  token_hash    BYTEA   NOT NULL UNIQUE,
  space_intents TEXT    NOT NULL,                         -- JSON [{"space_id":"<b64>","role":"member"|"admin"}]
  vault_intents TEXT    NOT NULL DEFAULT '[]',            -- JSON [{"vault_id":"<b64>","role":0|1|2}]
  expires_at    BIGINT NOT NULL,
  state         TEXT    NOT NULL DEFAULT 'pending',       -- pending|redeemed|expired|revoked
  redeemed_by   BYTEA,
  redeemed_at   BIGINT,
  created_by    BYTEA,                                    -- creator account_id
  created_at    BIGINT NOT NULL
);

-- Queue of crypto work for vault-admin clients (grant/revoke fulfilment).
CREATE TABLE pending_actions (
  action_id   BYTEA PRIMARY KEY,
  kind        TEXT    NOT NULL,                           -- 'grant' | 'revoke'
  vault_id    BYTEA   NOT NULL,
  account_id  BYTEA   NOT NULL,
  crypto_role BIGINT,                                     -- for 'grant'
  source      TEXT    NOT NULL,                           -- 'invite' | 'directory' | 'policy' | 'oidc'
  proof       BYTEA,                                      -- invite binding MAC (opaque to server)
  state       TEXT    NOT NULL DEFAULT 'pending',         -- pending|done|cancelled
  created_at  BIGINT NOT NULL,
  done_at     BIGINT,
  done_epoch  BIGINT
);
CREATE INDEX idx_pending_vault ON pending_actions(vault_id, state);

-- Key-binding attestations (signed by a space-admin keyset; server stores verbatim).
CREATE TABLE key_attestations (
  account_id      BYTEA   NOT NULL,
  attestor_pubkey BYTEA   NOT NULL,
  blob            BYTEA   NOT NULL,
  signature       BYTEA   NOT NULL,
  created_at      BIGINT NOT NULL,
  PRIMARY KEY (account_id, attestor_pubkey)
);

CREATE TABLE pake_relay (
  channel_id BYTEA PRIMARY KEY,
  msg1       BYTEA,
  msg2       BYTEA,
  msg3       BYTEA,
  state      TEXT    NOT NULL DEFAULT 'open',
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL
);

CREATE TABLE idempotency_keys (
  idem_key      BYTEA PRIMARY KEY,
  request_hash  BYTEA   NOT NULL,
  response_blob BYTEA   NOT NULL,
  status_code   BIGINT NOT NULL,
  created_at    BIGINT NOT NULL
);
