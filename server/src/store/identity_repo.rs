//! Identity repository (§4.2/§4.9/§4.10/§4.11/§4.12): accounts, devices,
//! sessions, invites, nonces, keysets, PAKE relay. Creation/CAS used by
//! identity endpoints (Phase 5) and the test harness.

use super::models::{InviteRow, KeysetRow, RelayRow};
use super::{Store, Tx, Val};
use crate::error::{AppError, AppResult};

impl Store {
    /// Create an account with a canonical keyset (= member-id) + human-readable
    /// identifiers + instance-admin flag.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_account(
        &self,
        tid: &[u8],
        account_id: &[u8],
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        display_name: Option<&str>,
        handle: Option<&str>,
        is_admin: bool,
        // Self-attested registration: the RAW bytes signed (canonical payload) +
        // its signature, stored verbatim so the admin panel can re-verify the
        // x25519<->ed25519 binding (M14). NOT re-serialized.
        reg_payload: &[u8],
        reg_signature: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO accounts \
             (tenant_id, account_id, created_at, status, ed25519_pub, x25519_pub, \
              display_name, handle, is_admin, reg_payload, reg_signature) \
             VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)",
            vec![
                Val::b(tid),
                Val::b(account_id),
                Val::I(now),
                Val::b(ed25519_pub),
                Val::b(x25519_pub),
                Val::OptT(display_name.map(|s| s.to_string())),
                Val::OptT(handle.map(|s| s.to_string())),
                Val::I(is_admin as i64),
                Val::b(reg_payload),
                Val::b(reg_signature),
            ],
        )
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_device(
        &self,
        tid: &[u8],
        account_id: &[u8],
        device_id: &[u8],
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO device_pubkeys \
             (tenant_id, account_id, device_id, ed25519_pub, x25519_pub, registered_at, status) \
             VALUES (?, ?, ?, ?, ?, ?, 'active')",
            vec![
                Val::b(tid),
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

    pub async fn set_device_status(
        &self,
        tid: &[u8],
        device_id: &[u8],
        status: &str,
    ) -> AppResult<()> {
        self.exec(
            "UPDATE device_pubkeys SET status = ? WHERE tenant_id = ? AND device_id = ?",
            vec![Val::t(status), Val::b(tid), Val::b(device_id)],
        )
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_session(
        &self,
        tid: &[u8],
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
             (tenant_id, session_id, account_id, device_id, access_hash, refresh_hash, \
              access_expires, refresh_expires, created_at, revoked) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            vec![
                Val::b(tid),
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

    pub async fn revoke_session(&self, tid: &[u8], session_id: &[u8]) -> AppResult<()> {
        self.exec(
            "UPDATE sessions SET revoked = 1 WHERE tenant_id = ? AND session_id = ?",
            vec![Val::b(tid), Val::b(session_id)],
        )
        .await?;
        Ok(())
    }

    pub async fn revoke_device_sessions(&self, tid: &[u8], device_id: &[u8]) -> AppResult<()> {
        self.exec(
            "UPDATE sessions SET revoked = 1 WHERE tenant_id = ? AND device_id = ?",
            vec![Val::b(tid), Val::b(device_id)],
        )
        .await?;
        Ok(())
    }

    /// Rotate the access/refresh hashes + expiries for a session (refresh flow).
    ///
    /// Compare-and-swap on the OLD refresh hash: the row is updated ONLY if its
    /// current `refresh_hash` still equals the presented one. Returns the number
    /// of rows changed (1 = rotated, 0 = the token was already rotated by a
    /// concurrent/replayed refresh). The caller treats 0 as a failed refresh, so
    /// two parallel refreshes with the same token can never both mint live tokens.
    ///
    /// Reuse detection no longer relies on `prev_refresh_hash`: `session_refresh`
    /// resolves the session from the token's embedded id and flags ANY non-current
    /// refresh hash as reuse, so the old single-step `prev` column is unused.
    #[allow(clippy::too_many_arguments)]
    pub async fn rotate_session(
        &self,
        tid: &[u8],
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
             WHERE tenant_id = ? AND session_id = ? AND refresh_hash = ? AND revoked = 0",
            vec![
                Val::b(access_hash),
                Val::b(refresh_hash),
                Val::I(access_expires),
                Val::I(refresh_expires),
                Val::b(tid),
                Val::b(session_id),
                Val::b(expected_refresh_hash),
            ],
        )
        .await
    }

    // ---- auth nonces (§4.11) ----

    pub async fn insert_nonce(
        &self,
        tid: &[u8],
        nonce: &[u8],
        device_id: Option<&[u8]>,
        expires_at: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO auth_nonces (tenant_id, nonce, device_id, expires_at, consumed) \
             VALUES (?, ?, ?, ?, 0)",
            vec![
                Val::b(tid),
                Val::b(nonce),
                Val::OptB(device_id.map(|d| d.to_vec())),
                Val::I(expires_at),
            ],
        )
        .await?;
        Ok(())
    }

    /// Single-use CAS: mark the nonce consumed, only if it is not consumed, not
    /// expired, AND was issued to the SAME device_id (§4.11/§5.3 step 3 — the nonce
    /// is bound to the issuing device). The server MUST enforce this itself (the
    /// crypto layer does not).
    pub async fn consume_nonce(
        &self,
        tid: &[u8],
        nonce: &[u8],
        device_id: &[u8],
        now: i64,
    ) -> AppResult<bool> {
        let n = self
            .exec(
                "UPDATE auth_nonces SET consumed = 1 \
                 WHERE tenant_id = ? AND nonce = ? AND device_id = ? AND consumed = 0 AND expires_at > ?",
                vec![Val::b(tid), Val::b(nonce), Val::b(device_id), Val::I(now)],
            )
            .await?;
        Ok(n == 1)
    }

    // ---- keyset blobs (§4.8, Path A) ----

    pub async fn keyset_max_generation(
        &self,
        tid: &[u8],
        account_id: &[u8],
    ) -> AppResult<Option<i64>> {
        self.fetch_scalar_i64(
            "SELECT MAX(generation) FROM keyset_blobs WHERE tenant_id = ? AND account_id = ?",
            vec![Val::b(tid), Val::b(account_id)],
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_keyset(
        &self,
        tid: &[u8],
        account_id: &[u8],
        generation: i64,
        keyset_bytes: &[u8],
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO keyset_blobs \
             (tenant_id, account_id, generation, keyset_bytes, ed25519_pub, x25519_pub, uploaded_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                Val::b(tid),
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

    pub async fn get_latest_keyset(
        &self,
        tid: &[u8],
        account_id: &[u8],
    ) -> AppResult<Option<KeysetRow>> {
        self.fetch_optional_as::<KeysetRow>(
            "SELECT generation, keyset_bytes FROM keyset_blobs \
             WHERE tenant_id = ? AND account_id = ? ORDER BY generation DESC LIMIT 1",
            vec![Val::b(tid), Val::b(account_id)],
        )
        .await
    }

    // ---- invites (§4.9) ----

    #[allow(clippy::too_many_arguments)]
    pub async fn create_invite(
        &self,
        tid: &[u8],
        invite_id: &[u8],
        token_hash: &[u8],
        role: i64,
        scope: Option<&str>,
        expires_at: i64,
        created_by: Option<&[u8]>,
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO invites \
             (tenant_id, invite_id, token_hash, role, scope, expires_at, state, created_by, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
            vec![
                Val::b(tid),
                Val::b(invite_id),
                Val::b(token_hash),
                Val::I(role),
                Val::OptT(scope.map(|s| s.to_string())),
                Val::I(expires_at),
                Val::OptB(created_by.map(|c| c.to_vec())),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn get_invite_by_token_hash(
        &self,
        tid: &[u8],
        token_hash: &[u8],
    ) -> AppResult<Option<InviteRow>> {
        self.fetch_optional_as::<InviteRow>(
            "SELECT invite_id, role, scope, expires_at, state FROM invites \
             WHERE tenant_id = ? AND token_hash = ?",
            vec![Val::b(tid), Val::b(token_hash)],
        )
        .await
    }

    // ---- PAKE relay (§4.12) ----

    pub async fn relay_open(
        &self,
        tid: &[u8],
        channel_id: &[u8],
        expires_at: i64,
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO pake_relay (tenant_id, channel_id, state, expires_at, created_at) \
             VALUES (?, ?, 'open', ?, ?)",
            vec![
                Val::b(tid),
                Val::b(channel_id),
                Val::I(expires_at),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn relay_get(&self, tid: &[u8], channel_id: &[u8]) -> AppResult<Option<RelayRow>> {
        self.fetch_optional_as::<RelayRow>(
            "SELECT msg1, msg2, msg3, state, expires_at FROM pake_relay \
             WHERE tenant_id = ? AND channel_id = ?",
            vec![Val::b(tid), Val::b(channel_id)],
        )
        .await
    }

    /// Store msgN verbatim and advance the state. `slot` ∈ {"msg1","msg2","msg3"}.
    pub async fn relay_put(
        &self,
        tid: &[u8],
        channel_id: &[u8],
        slot: &str,
        msg: &[u8],
    ) -> AppResult<()> {
        let (col, new_state) = match slot {
            "msg1" => ("msg1", "msg1"),
            "msg2" => ("msg2", "msg2"),
            "msg3" => ("msg3", "done"),
            _ => return Err(AppError::malformed("bad relay slot")),
        };
        let sql = format!(
            "UPDATE pake_relay SET {col} = ?, state = ? WHERE tenant_id = ? AND channel_id = ?"
        );
        let n = self
            .exec(
                &sql,
                vec![
                    Val::b(msg),
                    Val::t(new_state),
                    Val::b(tid),
                    Val::b(channel_id),
                ],
            )
            .await?;
        if n == 0 {
            return Err(AppError::not_found("relay channel"));
        }
        Ok(())
    }
}

/// Transactional helper for register (Phase 5): atomic invite-CAS + account/device.
impl Tx<'_> {
    /// Transactional mirror of [`Store::create_account`] — same columns, same binds,
    /// same order — for use inside the bootstrap/register transaction (atomic with the
    /// genesis-CAS / invite-CAS). The `Store` version takes `&self` and cannot run
    /// inside an open `Tx`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_account(
        &mut self,
        tid: &[u8],
        account_id: &[u8],
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        display_name: Option<&str>,
        handle: Option<&str>,
        is_admin: bool,
        reg_payload: &[u8],
        reg_signature: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO accounts \
             (tenant_id, account_id, created_at, status, ed25519_pub, x25519_pub, \
              display_name, handle, is_admin, reg_payload, reg_signature) \
             VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)",
            vec![
                Val::b(tid),
                Val::b(account_id),
                Val::I(now),
                Val::b(ed25519_pub),
                Val::b(x25519_pub),
                Val::OptT(display_name.map(|s| s.to_string())),
                Val::OptT(handle.map(|s| s.to_string())),
                Val::I(is_admin as i64),
                Val::b(reg_payload),
                Val::b(reg_signature),
            ],
        )
        .await?;
        Ok(())
    }

    /// Transactional mirror of [`Store::create_device`] — same columns, same binds,
    /// same order — for use inside the bootstrap/register transaction.
    pub async fn create_device(
        &mut self,
        tid: &[u8],
        account_id: &[u8],
        device_id: &[u8],
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO device_pubkeys \
             (tenant_id, account_id, device_id, ed25519_pub, x25519_pub, registered_at, status) \
             VALUES (?, ?, ?, ?, ?, ?, 'active')",
            vec![
                Val::b(tid),
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

    /// CAS redeem of an invite with invitee-pubkey binding (§6.2). Returns
    /// `(role, scope)` on success; otherwise classifies the reason.
    pub async fn redeem_invite_cas(
        &mut self,
        tid: &[u8],
        token_hash: &[u8],
        invitee_pubkey: &[u8],
        now: i64,
    ) -> AppResult<(i64, Option<String>)> {
        // First read the role/scope/state for classification.
        let row = self
            .fetch_optional_as::<InviteRow>(
                "SELECT invite_id, role, scope, expires_at, state FROM invites \
                 WHERE tenant_id = ? AND token_hash = ?",
                vec![Val::b(tid), Val::b(token_hash)],
            )
            .await?
            .ok_or_else(|| AppError::not_found("invite"))?;

        let n = self
            .exec(
                "UPDATE invites SET state = 'redeemed', redeemed_by = ?, redeemed_at = ? \
                 WHERE tenant_id = ? AND token_hash = ? AND state = 'pending' AND expires_at > ?",
                vec![
                    Val::b(invitee_pubkey),
                    Val::I(now),
                    Val::b(tid),
                    Val::b(token_hash),
                    Val::I(now),
                ],
            )
            .await?;
        if n == 1 {
            Ok((row.role, row.scope))
        } else if row.expires_at <= now {
            Err(AppError::gone("invite expired"))
        } else {
            Err(AppError::gone("invite already redeemed"))
        }
    }
}
