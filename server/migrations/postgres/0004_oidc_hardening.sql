-- OIDC hardening (Phase 5, PASS 2). Postgres mirror of the sqlite migration.
--
-- (1) Group→space de-provisioning: mark each membership's provenance so an
--     OIDC-mapped grant can be reconciled (upserted/removed) on every callback
--     WITHOUT touching manually-granted memberships (invite/direct-add). Existing
--     rows and every manual add default to 'manual'; the OIDC callback writes 'oidc'.
ALTER TABLE space_members ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';

-- (2) id_token one-time / replay guard: a consumed id_token (keyed by its `jti`
--     claim, or a hash of the token when `jti` is absent) is recorded here and
--     rejected on replay. `exp` is the token's expiry so expired rows can be pruned.
CREATE TABLE oidc_used_jti (
  jti TEXT   PRIMARY KEY,
  exp BIGINT NOT NULL
);
