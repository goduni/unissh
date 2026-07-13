//! Accounts repository (instance-scoped): canonical keyset (= member-id), human
//! identifiers (display_name/handle), owner flag, admin listing.

use super::models::{AccountListRow, AccountRow};
use super::{Store, Val};
use crate::error::{AppError, AppResult};

const ACCOUNT_COLS: &str =
    "account_id, display_name, handle, is_owner, ed25519_pub, x25519_pub, status";

impl Store {
    pub async fn get_account_by_id(&self, account_id: &[u8]) -> AppResult<Option<AccountRow>> {
        self.fetch_optional_as::<AccountRow>(
            &format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE account_id = ?"),
            vec![Val::b(account_id)],
        )
        .await
    }

    /// Account by canonical ed25519 keyset (= member-id).
    pub async fn get_account_by_ed(&self, ed25519_pub: &[u8]) -> AppResult<Option<AccountRow>> {
        self.fetch_optional_as::<AccountRow>(
            &format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE ed25519_pub = ?"),
            vec![Val::b(ed25519_pub)],
        )
        .await
    }

    pub async fn handle_taken(&self, handle: &str) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM accounts WHERE handle = ?",
                vec![Val::t(handle)],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }

    /// handle taken by ANOTHER account (for update profile, where one's own handle is ok).
    pub async fn handle_taken_by_other(&self, handle: &str, account_id: &[u8]) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM accounts WHERE handle = ? AND account_id != ?",
                vec![Val::t(handle), Val::b(account_id)],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }

    /// Admin listing of the instance's accounts + device count.
    pub async fn list_accounts(&self) -> AppResult<Vec<AccountListRow>> {
        self.fetch_all_as::<AccountListRow>(
            "SELECT a.account_id, a.display_name, a.handle, a.is_owner, a.ed25519_pub, a.x25519_pub, a.status, \
             a.reg_payload, a.reg_signature, \
             (SELECT COUNT(*) FROM devices d WHERE d.account_id = a.account_id) AS device_count \
             FROM accounts a ORDER BY a.created_at ASC",
            vec![],
        )
        .await
    }

    /// Update the profile (display_name/handle). Empty fields leave existing values untouched.
    pub async fn update_account_profile(
        &self,
        account_id: &[u8],
        display_name: Option<&str>,
        handle: Option<&str>,
    ) -> AppResult<()> {
        if let Some(dn) = display_name {
            self.exec(
                "UPDATE accounts SET display_name = ? WHERE account_id = ?",
                vec![Val::t(dn), Val::b(account_id)],
            )
            .await?;
        }
        if let Some(h) = handle {
            self.exec(
                "UPDATE accounts SET handle = ? WHERE account_id = ?",
                vec![Val::t(h), Val::b(account_id)],
            )
            .await?;
        }
        Ok(())
    }

    pub async fn owner_count(&self) -> AppResult<i64> {
        Ok(self
            .fetch_scalar_i64("SELECT COUNT(*) FROM accounts WHERE is_owner = 1", vec![])
            .await?
            .unwrap_or(0))
    }

    /// Whether the account is the instance owner (server-trusted, §10). Does NOT
    /// grant decryption — only the owner-role authority. Nonexistent → false.
    pub async fn account_is_owner(&self, account_id: &[u8]) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT is_owner FROM accounts WHERE account_id = ?",
                vec![Val::b(account_id)],
            )
            .await?
            .unwrap_or(0)
            == 1)
    }

    /// Owner check keyed by the canonical ed25519 keyset (used by the policy read-deny
    /// where only the device keyset is in scope).
    pub async fn account_is_owner_by_ed(&self, ed25519_pub: &[u8]) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT is_owner FROM accounts WHERE ed25519_pub = ?",
                vec![Val::b(ed25519_pub)],
            )
            .await?
            .unwrap_or(0)
            == 1)
    }

    /// Grant/revoke instance-owner (server-trusted, §10). Does NOT grant decryption.
    pub async fn set_account_owner(&self, account_id: &[u8], is_owner: bool) -> AppResult<()> {
        let n = self
            .exec(
                "UPDATE accounts SET is_owner = ? WHERE account_id = ?",
                vec![Val::I(is_owner as i64), Val::b(account_id)],
            )
            .await?;
        if n == 0 {
            return Err(AppError::not_found("account"));
        }
        Ok(())
    }
}
