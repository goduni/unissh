//! Spaces (server-trusted groupings), memberships, shared people directory.

use super::{Store, Tx, Val};
use crate::error::AppResult;
use crate::store::models::{DirectoryRow, SpaceMemberRow, SpaceRow};

const SPACE_SEL: &str = "SELECT space_id, name, status, created_by, created_at FROM spaces";

#[derive(sqlx::FromRow)]
struct RoleOnly {
    role: String,
}

impl Store {
    pub async fn create_space(
        &self,
        tx: &mut Tx<'_>,
        space_id: &[u8],
        name: &str,
        created_by: Option<&[u8]>,
        now: i64,
    ) -> AppResult<()> {
        tx.exec(
            "INSERT INTO spaces (space_id, name, status, created_by, created_at) \
             VALUES (?, ?, 'active', ?, ?)",
            vec![
                Val::b(space_id),
                Val::t(name),
                Val::OptB(created_by.map(|b| b.to_vec())),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn get_space(&self, space_id: &[u8]) -> AppResult<Option<SpaceRow>> {
        self.fetch_optional_as(
            &format!("{SPACE_SEL} WHERE space_id = ?"),
            vec![Val::b(space_id)],
        )
        .await
    }

    pub async fn list_spaces_for(&self, account_id: &[u8]) -> AppResult<Vec<SpaceRow>> {
        self.fetch_all_as(
            &format!(
                "{SPACE_SEL} WHERE space_id IN \
                 (SELECT space_id FROM space_members WHERE account_id = ?) ORDER BY created_at"
            ),
            vec![Val::b(account_id)],
        )
        .await
    }

    pub async fn space_member_add(
        &self,
        tx: &mut Tx<'_>,
        space_id: &[u8],
        account_id: &[u8],
        role: &str,
        added_by: Option<&[u8]>,
        now: i64,
    ) -> AppResult<()> {
        tx.exec(
            "INSERT INTO space_members (space_id, account_id, role, added_by, added_at) \
             VALUES (?, ?, ?, ?, ?) ON CONFLICT (space_id, account_id) DO NOTHING",
            vec![
                Val::b(space_id),
                Val::b(account_id),
                Val::t(role),
                Val::OptB(added_by.map(|b| b.to_vec())),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn space_member_remove(&self, space_id: &[u8], account_id: &[u8]) -> AppResult<u64> {
        self.exec(
            "DELETE FROM space_members WHERE space_id = ? AND account_id = ?",
            vec![Val::b(space_id), Val::b(account_id)],
        )
        .await
    }

    pub async fn space_member_set_role(
        &self,
        space_id: &[u8],
        account_id: &[u8],
        role: &str,
    ) -> AppResult<()> {
        self.exec(
            "UPDATE space_members SET role = ? WHERE space_id = ? AND account_id = ?",
            vec![Val::t(role), Val::b(space_id), Val::b(account_id)],
        )
        .await?;
        Ok(())
    }

    pub async fn list_space_members(&self, space_id: &[u8]) -> AppResult<Vec<SpaceMemberRow>> {
        self.fetch_all_as(
            "SELECT space_id, account_id, role, added_by, added_at FROM space_members \
             WHERE space_id = ? ORDER BY added_at",
            vec![Val::b(space_id)],
        )
        .await
    }

    pub async fn is_space_member(&self, space_id: &[u8], account_id: &[u8]) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM space_members WHERE space_id = ? AND account_id = ?",
                vec![Val::b(space_id), Val::b(account_id)],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }

    pub async fn is_space_admin(&self, space_id: &[u8], account_id: &[u8]) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM space_members \
                 WHERE space_id = ? AND account_id = ? AND role = 'admin'",
                vec![Val::b(space_id), Val::b(account_id)],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }

    /// Number of `admin`-role members of a space — the anti-orphan guard reads this
    /// before removing/demoting an admin (a space with no admin has no recovery path:
    /// the instance owner is NOT auto-admin of spaces they did not create).
    pub async fn space_admin_count(&self, space_id: &[u8]) -> AppResult<i64> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM space_members WHERE space_id = ? AND role = 'admin'",
                vec![Val::b(space_id)],
            )
            .await?
            .unwrap_or(0))
    }

    /// The target account's current role in a space (`None` if not a member).
    pub async fn space_member_role(
        &self,
        space_id: &[u8],
        account_id: &[u8],
    ) -> AppResult<Option<String>> {
        Ok(self
            .fetch_optional_as::<RoleOnly>(
                "SELECT role FROM space_members WHERE space_id = ? AND account_id = ?",
                vec![Val::b(space_id), Val::b(account_id)],
            )
            .await?
            .map(|r| r.role))
    }

    /// Shared people directory (any authenticated member may read — company model).
    pub async fn directory_list(&self) -> AppResult<Vec<DirectoryRow>> {
        self.fetch_all_as(
            "SELECT account_id, handle, display_name, ed25519_pub, x25519_pub, status \
             FROM accounts ORDER BY created_at",
            vec![],
        )
        .await
    }
}
