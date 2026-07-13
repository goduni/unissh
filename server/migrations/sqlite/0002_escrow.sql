-- Escrow sign-in (Phase 2): a fresh device fetches this blob with a password+SecretKey
-- derived credential (K_auth), no prior session. Server stores only sha256(K_auth) plus
-- the Argon2id salt/params a fresh device needs to re-derive K_auth. NULL = escrow not enabled.
ALTER TABLE keyset_blobs ADD COLUMN k_auth_hash       BLOB;
ALTER TABLE keyset_blobs ADD COLUMN argon_salt        BLOB;
ALTER TABLE keyset_blobs ADD COLUMN argon_mem_kib     INTEGER;
ALTER TABLE keyset_blobs ADD COLUMN argon_iterations  INTEGER;
ALTER TABLE keyset_blobs ADD COLUMN argon_parallelism INTEGER;
