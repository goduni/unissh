-- OIDC sign-in (Phase 5): when an SSO session is minted, the server records when
-- the id_token's assertion must be re-checked. NULL for keyset sessions (which
-- never reassert). auth_source already exists (0001_init.sql); this adds only the
-- reassertion deadline.
ALTER TABLE sessions ADD COLUMN reassert_expires INTEGER;
