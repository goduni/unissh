//! Policy/membership repository (§4.4/§4.5/§4.6/§8/§9): vault claim, manifest/
//! grant reads, atomic grants_publish (revoke/add). Instance-scoped (v2).

use super::models::{DeltaRow, GrantRow, ManifestRow};
use super::sync_repo::{PushObj, alloc_seqs, insert_object, materialize};
use super::{Store, Val};
use crate::codec::parse_open;
use crate::error::{AppError, AppResult};

const GRANT_COLS: &str = "vault_id, member_pubkey, key_epoch, role, wrapped_vk, signature, \
                          author_pubkey, not_after, revoked";

#[derive(sqlx::FromRow)]
struct OwnerOnly {
    owner_pubkey: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct VaultIdRow {
    vault_id: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct VaultScope {
    space_id: Option<Vec<u8>>,
    owner_account_id: Option<Vec<u8>>,
    owner_pubkey: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct VaultAdminScope {
    space_id: Option<Vec<u8>>,
    owner_account_id: Option<Vec<u8>>,
}

impl Store {
    /// Explicit claim of vault_id (§5.4/§8.2): reject-if-exists-different-owner.
    /// Returns true if the namespace was created, false if it already belongs to the
    /// author. `space_id` NULL → personal vault (owner_account_id set).
    #[allow(clippy::too_many_arguments)]
    pub async fn claim_vault(
        &self,
        vault_id: &[u8],
        owner_pubkey: &[u8],
        owner_account_id: Option<&[u8]>,
        space_id: Option<&[u8]>,
        access_policy: &str,
        space_wide_role: Option<i64>,
        manual_approve: bool,
        now: i64,
    ) -> AppResult<bool> {
        let existing = self
            .fetch_optional_as::<OwnerOnly>(
                "SELECT owner_pubkey FROM vaults WHERE vault_id = ?",
                vec![Val::b(vault_id)],
            )
            .await?;
        match existing {
            Some(row) => {
                if row.owner_pubkey != owner_pubkey {
                    Err(AppError::conflict(
                        "vault_id already claimed by a different owner",
                    ))
                } else {
                    Ok(false)
                }
            }
            None => {
                self.exec(
                    "INSERT INTO vaults (vault_id, space_id, owner_account_id, owner_pubkey, \
                     access_policy, space_wide_role, manual_approve, latest_version, \
                     latest_epoch, sync_target, cache_policy, tombstone, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 1, 0, 0, ?)",
                    vec![
                        Val::b(vault_id),
                        Val::OptB(space_id.map(|b| b.to_vec())),
                        Val::OptB(owner_account_id.map(|b| b.to_vec())),
                        Val::b(owner_pubkey),
                        Val::t(access_policy),
                        Val::OptI(space_wide_role),
                        Val::I(manual_approve as i64),
                        Val::I(now),
                    ],
                )
                .await?;
                Ok(true)
            }
        }
    }

    /// Coarse authorization precheck for grants_publish: the caller may touch the
    /// vault if it does not exist yet (first publish establishes it), OR it is a
    /// personal vault owned by the account, OR a space vault where the account is a
    /// member. The real gate is the S4 vault-admin authorship check on the manifest.
    pub async fn can_touch_vault(&self, account_id: &[u8], vault_id: &[u8]) -> AppResult<bool> {
        let row = self
            .fetch_optional_as::<VaultScope>(
                "SELECT space_id, owner_account_id, owner_pubkey FROM vaults WHERE vault_id = ?",
                vec![Val::b(vault_id)],
            )
            .await?;
        match row {
            None => Ok(true),
            Some(v) => match v.space_id {
                Some(sid) => self.is_space_member(&sid, account_id).await,
                None => {
                    // Personal vault: owned by account_id, OR by the account's keyset
                    // (owner_pubkey) — the canonical way ownership is recorded.
                    if v.owner_account_id.as_deref() == Some(account_id) {
                        return Ok(true);
                    }
                    let ed = self.account_ed(account_id).await?;
                    Ok(ed.as_deref() == Some(v.owner_pubkey.as_slice()))
                }
            },
        }
    }

    /// Whether `account_id` holds ADMIN authority over `vault_id`. A space vault is
    /// admin-able by an admin of its space; a personal vault only by its owning account.
    /// A NONEXISTENT vault is NOT admin-able (false) — an invite `vault_intent` must
    /// reference a real vault, so this deliberately rejects unknown vaults (unlike the
    /// looser `can_touch_vault`, whose first-publish path treats an unknown vault as OK).
    pub async fn can_admin_vault(&self, account_id: &[u8], vault_id: &[u8]) -> AppResult<bool> {
        let row = self
            .fetch_optional_as::<VaultAdminScope>(
                "SELECT space_id, owner_account_id FROM vaults WHERE vault_id = ?",
                vec![Val::b(vault_id)],
            )
            .await?;
        match row {
            None => Ok(false),
            Some(v) => match v.space_id {
                Some(sid) => self.is_space_admin(&sid, account_id).await,
                None => Ok(v.owner_account_id.as_deref() == Some(account_id)),
            },
        }
    }

    /// Vaults of `space_id` where `member_ed` still holds a live (non-revoked) grant at
    /// the vault's latest epoch — the `revoke` enqueue set when a member is dropped from
    /// a space (Task 9). Cross-dialect: plain equi-joins + `?` placeholders (rewritten to
    /// `$n` for Postgres by the bind layer). `vault_id` is aliased so the row column name
    /// is unambiguous on both dialects.
    pub async fn vaults_with_live_grant_in_space(
        &self,
        member_ed: &[u8],
        space_id: &[u8],
    ) -> AppResult<Vec<Vec<u8>>> {
        let rows = self
            .fetch_all_as::<VaultIdRow>(
                "SELECT g.vault_id AS vault_id FROM membership_grants g \
                 JOIN vaults v ON v.vault_id = g.vault_id \
                 WHERE g.member_pubkey = ? AND g.revoked = 0 \
                   AND g.key_epoch = v.latest_epoch AND v.space_id = ?",
                vec![Val::b(member_ed), Val::b(space_id)],
            )
            .await?;
        Ok(rows.into_iter().map(|r| r.vault_id).collect())
    }

    /// Same as [`Self::vaults_with_live_grant_in_space`] but across ALL vaults (no space
    /// filter) — the `revoke` enqueue set when an account is disabled instance-wide.
    pub async fn vaults_with_live_grant(&self, member_ed: &[u8]) -> AppResult<Vec<Vec<u8>>> {
        let rows = self
            .fetch_all_as::<VaultIdRow>(
                "SELECT g.vault_id AS vault_id FROM membership_grants g \
                 JOIN vaults v ON v.vault_id = g.vault_id \
                 WHERE g.member_pubkey = ? AND g.revoked = 0 \
                   AND g.key_epoch = v.latest_epoch",
                vec![Val::b(member_ed)],
            )
            .await?;
        Ok(rows.into_iter().map(|r| r.vault_id).collect())
    }

    pub async fn get_vault_owner(&self, vault_id: &[u8]) -> AppResult<Option<Vec<u8>>> {
        Ok(self
            .fetch_optional_as::<OwnerOnly>(
                "SELECT owner_pubkey FROM vaults WHERE vault_id = ?",
                vec![Val::b(vault_id)],
            )
            .await?
            .map(|r| r.owner_pubkey))
    }

    pub async fn get_manifest(
        &self,
        vault_id: &[u8],
        epoch: i64,
    ) -> AppResult<Option<ManifestRow>> {
        self.fetch_optional_as::<ManifestRow>(
            "SELECT vault_id, key_epoch, manifest_blob, signature, author_pubkey \
             FROM membership_manifests WHERE vault_id = ? AND key_epoch = ?",
            vec![Val::b(vault_id), Val::I(epoch)],
        )
        .await
    }

    pub async fn latest_manifest_epoch(&self, vault_id: &[u8]) -> AppResult<Option<i64>> {
        // MAX returns NULL (None) when no rows.
        self.fetch_scalar_i64(
            "SELECT MAX(key_epoch) FROM membership_manifests WHERE vault_id = ?",
            vec![Val::b(vault_id)],
        )
        .await
    }

    pub async fn list_grants(
        &self,
        vault_id: &[u8],
        epoch: i64,
        non_revoked_only: bool,
    ) -> AppResult<Vec<GrantRow>> {
        let filter = if non_revoked_only {
            " AND revoked = 0"
        } else {
            ""
        };
        let sql = format!(
            "SELECT {GRANT_COLS} FROM membership_grants \
             WHERE vault_id = ? AND key_epoch = ?{filter} \
             ORDER BY member_pubkey ASC"
        );
        self.fetch_all_as::<GrantRow>(&sql, vec![Val::b(vault_id), Val::I(epoch)])
            .await
    }

    /// Whether the member has an active (not revoked, not expired) grant for the epoch.
    pub async fn member_has_active_grant(
        &self,
        vault_id: &[u8],
        epoch: i64,
        member: &[u8],
        now: i64,
    ) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM membership_grants \
                 WHERE vault_id = ? AND key_epoch = ? AND member_pubkey = ? \
                 AND revoked = 0 AND (not_after IS NULL OR not_after > ?)",
                vec![Val::b(vault_id), Val::I(epoch), Val::b(member), Val::I(now)],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }

    /// Atomic publish (§9.3): accept the manifest + grants of the new epoch (append to
    /// the objects log + materialize the ACL), then read-deny the old revoke_epoch (mark
    /// revoked — the log is NOT touched). All in one transaction.
    pub async fn grants_publish(
        &self,
        vault_id: &[u8],
        manifest: &PushObj,
        grants: &[PushObj],
        revoke_epoch: Option<i64>,
        now: i64,
    ) -> AppResult<Vec<i64>> {
        let n = (1 + grants.len()) as i64;
        let mut tx = self.begin().await?;
        // Atomic seq allocation under a row write-lock (like push_objects).
        let base = alloc_seqs(&mut tx, n).await?;

        let mut seqs = Vec::with_capacity(n as usize);
        // First the manifest of the new epoch, then the grants under VK' (§9.3).
        for (i, obj) in std::iter::once(manifest).chain(grants.iter()).enumerate() {
            let seq = base + 1 + i as i64;
            insert_object(&mut tx, seq, &obj.parsed, &obj.bytes, now).await?;
            materialize(&mut tx, seq, &obj.parsed, now).await?;
            seqs.push(seq);
        }

        // A1b: re-emit the CURRENT vault set (the vault record + manifests of epochs < E +
        // live items) on FRESH seqs so a newly-added member whose cursor has already moved
        // past these objects still receives them.
        let new_epoch = manifest.parsed.key_epoch.unwrap_or(0) as i64;
        let reemit = tx
            .fetch_all_as::<DeltaRow>(
                "SELECT server_seq, object_bytes FROM objects o \
                 WHERE o.vault_id = ? AND ( \
                   (o.object_tag = 1 AND o.server_seq = (SELECT MAX(server_seq) FROM objects \
                      WHERE vault_id=o.vault_id AND object_tag=1)) \
                   OR (o.object_tag = 3 AND o.key_epoch < ? AND o.server_seq = (SELECT MAX(server_seq) \
                      FROM objects WHERE vault_id=o.vault_id \
                        AND object_tag=3 AND key_epoch=o.key_epoch)) \
                   OR (o.object_tag = 2 AND o.tombstone = 0 AND o.server_seq = (SELECT MAX(server_seq) \
                      FROM objects WHERE vault_id=o.vault_id \
                        AND object_tag=2 AND item_id=o.item_id)) \
                 ) \
                 ORDER BY (CASE o.object_tag WHEN 1 THEN 0 WHEN 3 THEN 1 ELSE 2 END), o.server_seq ASC",
                vec![Val::b(vault_id), Val::I(new_epoch)],
            )
            .await?;
        if !reemit.is_empty() {
            let m = reemit.len() as i64;
            let rbase = alloc_seqs(&mut tx, m).await?;
            for (i, row) in reemit.iter().enumerate() {
                let seq = rbase + 1 + i as i64;
                let parsed = parse_open(&row.object_bytes)?;
                insert_object(&mut tx, seq, &parsed, &row.object_bytes, now).await?;
                materialize(&mut tx, seq, &parsed, now).await?;
            }
        }

        // Then read-deny the old epoch in the ACL (idempotent, last).
        if let Some(re) = revoke_epoch {
            tx.exec(
                "UPDATE membership_grants SET revoked = 1 \
                 WHERE vault_id = ? AND key_epoch = ?",
                vec![Val::b(vault_id), Val::I(re)],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(seqs)
    }
}
