//! Spaces (server-trusted groupings), memberships, shared people directory.

use super::{Store, Tx, Val};
use crate::error::AppResult;
use crate::store::models::{DirectoryRow, SpaceMemberRow, SpaceRow};

const SPACE_SEL: &str = "SELECT space_id, name, status, created_by, created_at FROM spaces";

#[derive(sqlx::FromRow)]
struct RoleOnly {
    role: String,
}

#[derive(sqlx::FromRow)]
struct SpaceIdOnly {
    space_id: Vec<u8>,
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

    /// Add a MANUAL membership (invite redemption / direct add / space creation).
    /// Writes `source = 'manual'` explicitly so the OIDC de-provisioning reconciler
    /// never removes or overrides it (it only touches `source = 'oidc'` rows).
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
            "INSERT INTO space_members (space_id, account_id, role, added_by, added_at, source) \
             VALUES (?, ?, ?, ?, ?, 'manual') ON CONFLICT (space_id, account_id) DO NOTHING",
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

    /// Upsert an OIDC-sourced membership (Phase 5 group→space mapping). Sets
    /// `source = 'oidc'` and the mapped `role`; on an existing OIDC row it UPDATES the
    /// role (so a role change in the IdP token is reflected on reassertion). The
    /// `WHERE space_members.source = 'oidc'` guard on the conflict path means a MANUAL
    /// row for the same (space, account) is left completely untouched — OIDC never
    /// overrides a manually-granted membership.
    pub async fn space_member_upsert_oidc(
        &self,
        tx: &mut Tx<'_>,
        space_id: &[u8],
        account_id: &[u8],
        role: &str,
        now: i64,
    ) -> AppResult<()> {
        tx.exec(
            "INSERT INTO space_members (space_id, account_id, role, added_by, added_at, source) \
             VALUES (?, ?, ?, ?, ?, 'oidc') \
             ON CONFLICT (space_id, account_id) \
             DO UPDATE SET role = excluded.role WHERE space_members.source = 'oidc'",
            vec![
                Val::b(space_id),
                Val::b(account_id),
                Val::t(role),
                Val::OptB(None),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    /// The space_ids of this account's OIDC-sourced memberships — the reconciler reads
    /// this to compute which OIDC grants to de-provision (those no longer in the token).
    pub async fn list_oidc_member_spaces(
        &self,
        tx: &mut Tx<'_>,
        account_id: &[u8],
    ) -> AppResult<Vec<Vec<u8>>> {
        let rows = tx
            .fetch_all_as::<SpaceIdOnly>(
                "SELECT space_id FROM space_members WHERE account_id = ? AND source = 'oidc'",
                vec![Val::b(account_id)],
            )
            .await?;
        Ok(rows.into_iter().map(|r| r.space_id).collect())
    }

    /// Delete a single OIDC-sourced membership (never a manual one — the `source`
    /// predicate guarantees a manually-granted row survives). Used to de-provision an
    /// account from a space it was dropped from in the IdP.
    pub async fn delete_oidc_member(
        &self,
        tx: &mut Tx<'_>,
        space_id: &[u8],
        account_id: &[u8],
    ) -> AppResult<()> {
        tx.exec(
            "DELETE FROM space_members \
             WHERE space_id = ? AND account_id = ? AND source = 'oidc'",
            vec![Val::b(space_id), Val::b(account_id)],
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
