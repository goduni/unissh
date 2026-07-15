-- Escrow sign-in (Phase 2): a fresh device fetches this blob with a password+SecretKey
-- derived credential (K_auth), no prior session. Server stores only sha256(K_auth) plus
-- the Argon2id salt/params a fresh device needs to re-derive K_auth. NULL = escrow not enabled.
ALTER TABLE keyset_blobs ADD COLUMN k_auth_hash       BYTEA;
ALTER TABLE keyset_blobs ADD COLUMN argon_salt        BYTEA;
ALTER TABLE keyset_blobs ADD COLUMN argon_mem_kib     BIGINT;
ALTER TABLE keyset_blobs ADD COLUMN argon_iterations  BIGINT;
ALTER TABLE keyset_blobs ADD COLUMN argon_parallelism BIGINT;

-- Server-PRIVATE secret (32 random bytes) that keys the enumeration-resistant
-- decoy salt returned by GET /v1/escrow/params for unknown/unenrolled handles.
-- MUST never be returned by any endpoint (unlike the PUBLIC instance_id). Set
-- once by ensure_instance on first boot; NULL only transiently before backfill.
ALTER TABLE instance ADD COLUMN escrow_decoy_secret BYTEA;
