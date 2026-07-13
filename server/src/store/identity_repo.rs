//! Identity repository (§4.2/§4.9/§4.10/§4.11/§4.12): accounts, devices,
//! sessions, nonces, keysets, PAKE relay. Instance-scoped (v2). Creation/CAS used
//! by identity endpoints (claim/auth) and the test harness.

use super::models::{KeysetRow, RelayRow};
use super::{Store, Tx, Val};
use crate::error::{AppError, AppResult};

impl Store {
    /// Create an account with a canonical keyset (= member-id) + human-readable
    /// identifiers + owner flag.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_account(
        &self,
        account_id: &[u8],
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        display_name: Option<&str>,
        handle: Option<&str>,
        is_owner: bool,
        // Self-attested registration: the RAW bytes signed (canonical payload) +
        // its signature, stored verbatim so the admin panel can re-verify the
        // x25519<->ed25519 binding (M14). NOT re-serialized.
        reg_payload: &[u8],
        reg_signature: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO accounts \
             (account_id, created_at, status, ed25519_pub, x25519_pub, \
              display_name, handle, is_owner, reg_payload, reg_signature) \
             VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)",
            vec![
                Val::b(account_id),
                Val::I(now),
                Val::b(ed25519_pub),
                Val::b(x25519_pub),
                Val::OptT(display_name.map(|s| s.to_string())),
                Val::OptT(handle.map(|s| s.to_string())),
                Val::I(is_owner as i64),
                Val::b(reg_payload),
                Val::b(reg_signature),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn create_device(
        &self,
        account_id: &[u8],
        device_id: &[u8],
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO devices \
             (account_id, device_id, ed25519_pub, x25519_pub, registered_at, status) \
             VALUES (?, ?, ?, ?, ?, 'active')",
            vec![
                Val::b(account_id),
                Val::b(device_id),
                Val::b(ed25519_pub),
                Val::b(x25519_pub),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn set_device_status(&self, device_id: &[u8], status: &str) -> AppResult<()> {
        self.exec(
            "UPDATE devices SET status = ? WHERE device_id = ?",
            vec![Val::t(status), Val::b(device_id)],
        )
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_session(
        &self,
        session_id: &[u8],
        account_id: &[u8],
        device_id: &[u8],
        access_hash: &[u8],
        refresh_hash: &[u8],
        access_expires: i64,
        refresh_expires: i64,
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO sessions \
             (session_id, account_id, device_id, access_hash, refresh_hash, \
              access_expires, refresh_expires, created_at, revoked) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
            vec![
                Val::b(session_id),
                Val::b(account_id),
                Val::b(device_id),
                Val::b(access_hash),
                Val::b(refresh_hash),
                Val::I(access_expires),
                Val::I(refresh_expires),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn revoke_session(&self, session_id: &[u8]) -> AppResult<()> {
        self.exec(
            "UPDATE sessions SET revoked = 1 WHERE session_id = ?",
            vec![Val::b(session_id)],
        )
        .await?;
        Ok(())
    }

    pub async fn revoke_device_sessions(&self, device_id: &[u8]) -> AppResult<()> {
        self.exec(
            "UPDATE sessions SET revoked = 1 WHERE device_id = ?",
            vec![Val::b(device_id)],
        )
        .await?;
        Ok(())
    }

    /// Rotate the access/refresh hashes + expiries for a session (refresh flow).
    ///
    /// Compare-and-swap on the OLD refresh hash: the row is updated ONLY if its
    /// current `refresh_hash` still equals the presented one. Returns the number
    /// of rows changed (1 = rotated, 0 = the token was already rotated by a
    /// concurrent/replayed refresh).
    #[allow(clippy::too_many_arguments)]
    pub async fn rotate_session(
        &self,
        session_id: &[u8],
        expected_refresh_hash: &[u8],
        access_hash: &[u8],
        refresh_hash: &[u8],
        access_expires: i64,
        refresh_expires: i64,
    ) -> AppResult<u64> {
        self.exec(
            "UPDATE sessions SET access_hash = ?, refresh_hash = ?, \
             access_expires = ?, refresh_expires = ? \
             WHERE session_id = ? AND refresh_hash = ? AND revoked = 0",
            vec![
                Val::b(access_hash),
                Val::b(refresh_hash),
                Val::I(access_expires),
                Val::I(refresh_expires),
                Val::b(session_id),
                Val::b(expected_refresh_hash),
            ],
        )
        .await
    }

    // ---- auth nonces (§4.11) ----

    pub async fn insert_nonce(
        &self,
        nonce: &[u8],
        device_id: Option<&[u8]>,
        expires_at: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO auth_nonces (nonce, device_id, expires_at, consumed) \
             VALUES (?, ?, ?, 0)",
            vec![
                Val::b(nonce),
                Val::OptB(device_id.map(|d| d.to_vec())),
                Val::I(expires_at),
            ],
        )
        .await?;
        Ok(())
    }

    /// Single-use CAS: mark the nonce consumed, only if it is not consumed, not
    /// expired, AND was issued to the SAME device_id (§4.11/§5.3 step 3).
    pub async fn consume_nonce(&self, nonce: &[u8], device_id: &[u8], now: i64) -> AppResult<bool> {
        let n = self
            .exec(
                "UPDATE auth_nonces SET consumed = 1 \
                 WHERE nonce = ? AND device_id = ? AND consumed = 0 AND expires_at > ?",
                vec![Val::b(nonce), Val::b(device_id), Val::I(now)],
            )
            .await?;
        Ok(n == 1)
    }

    // ---- keyset blobs (§4.8, Path A) ----

    pub async fn keyset_max_generation(&self, account_id: &[u8]) -> AppResult<Option<i64>> {
        self.fetch_scalar_i64(
            "SELECT MAX(generation) FROM keyset_blobs WHERE account_id = ?",
            vec![Val::b(account_id)],
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_keyset(
        &self,
        account_id: &[u8],
        generation: i64,
        keyset_bytes: &[u8],
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO keyset_blobs \
             (account_id, generation, keyset_bytes, ed25519_pub, x25519_pub, uploaded_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
            vec![
                Val::b(account_id),
                Val::I(generation),
                Val::b(keyset_bytes),
                Val::b(ed25519_pub),
                Val::b(x25519_pub),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn get_latest_keyset(&self, account_id: &[u8]) -> AppResult<Option<KeysetRow>> {
        self.fetch_optional_as::<KeysetRow>(
            "SELECT generation, keyset_bytes FROM keyset_blobs \
             WHERE account_id = ? ORDER BY generation DESC LIMIT 1",
            vec![Val::b(account_id)],
        )
        .await
    }

    // ---- PAKE relay (§4.12) ----

    pub async fn relay_open(&self, channel_id: &[u8], expires_at: i64, now: i64) -> AppResult<()> {
        self.exec(
            "INSERT INTO pake_relay (channel_id, state, expires_at, created_at) \
             VALUES (?, 'open', ?, ?)",
            vec![Val::b(channel_id), Val::I(expires_at), Val::I(now)],
        )
        .await?;
        Ok(())
    }

    pub async fn relay_get(&self, channel_id: &[u8]) -> AppResult<Option<RelayRow>> {
        self.fetch_optional_as::<RelayRow>(
            "SELECT msg1, msg2, msg3, state, expires_at FROM pake_relay WHERE channel_id = ?",
            vec![Val::b(channel_id)],
        )
        .await
    }

    /// Store msgN verbatim and advance the state. `slot` ∈ {"msg1","msg2","msg3"}.
    pub async fn relay_put(&self, channel_id: &[u8], slot: &str, msg: &[u8]) -> AppResult<()> {
        let (col, new_state) = match slot {
            "msg1" => ("msg1", "msg1"),
            "msg2" => ("msg2", "msg2"),
            "msg3" => ("msg3", "done"),
            _ => return Err(AppError::malformed("bad relay slot")),
        };
        let sql = format!("UPDATE pake_relay SET {col} = ?, state = ? WHERE channel_id = ?");
        let n = self
            .exec(
                &sql,
                vec![Val::b(msg), Val::t(new_state), Val::b(channel_id)],
            )
            .await?;
        if n == 0 {
            return Err(AppError::not_found("relay channel"));
        }
        Ok(())
    }
}

/// Transactional helpers for claim (atomic with the instance CAS + space creation).
impl Tx<'_> {
    /// Transactional mirror of [`Store::create_account`] — same columns, same binds,
    /// same order — for use inside the claim transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_account(
        &mut self,
        account_id: &[u8],
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        display_name: Option<&str>,
        handle: Option<&str>,
        is_owner: bool,
        reg_payload: &[u8],
        reg_signature: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO accounts \
             (account_id, created_at, status, ed25519_pub, x25519_pub, \
              display_name, handle, is_owner, reg_payload, reg_signature) \
             VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)",
            vec![
                Val::b(account_id),
                Val::I(now),
                Val::b(ed25519_pub),
                Val::b(x25519_pub),
                Val::OptT(display_name.map(|s| s.to_string())),
                Val::OptT(handle.map(|s| s.to_string())),
                Val::I(is_owner as i64),
                Val::b(reg_payload),
                Val::b(reg_signature),
            ],
        )
        .await?;
        Ok(())
    }

    /// Transactional mirror of [`Store::create_device`].
    pub async fn create_device(
        &mut self,
        account_id: &[u8],
        device_id: &[u8],
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO devices \
             (account_id, device_id, ed25519_pub, x25519_pub, registered_at, status) \
             VALUES (?, ?, ?, ?, ?, 'active')",
            vec![
                Val::b(account_id),
                Val::b(device_id),
                Val::b(ed25519_pub),
                Val::b(x25519_pub),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }
}
