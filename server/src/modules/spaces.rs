//! Spaces, memberships, and the shared people directory (v2 §Task 7).
//! Spaces are *server-trusted* groupings — a role here (`admin`/`member`) is an
//! authority label, NOT a decryption capability (vault crypto grants live in
//! `sync`/`grants`). Owner creates spaces; a space admin manages that space's
//! membership; any authenticated caller may read the directory (company model).
//! Instance-scoped: every row belongs to this one instance. All SQL goes through the Task-3 repo.

use crate::error::{AppError, AppResult};
use crate::http::extract::AuthCtx;
use crate::ids;
use crate::state::AppState;
use crate::store::models::EdOnly;
use crate::store::{Tx, Val};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/spaces", post(spaces_create).get(spaces_list))
        .route("/v1/spaces/members", post(members_add).get(members_list))
        .route("/v1/spaces/members/remove", post(members_remove))
        .route("/v1/spaces/members/role", post(members_set_role))
        .route("/v1/directory", get(directory))
}

// ---- helpers ----

/// Server-trusted role labels. Anything else is a malformed request (400).
fn validate_role(role: &str) -> AppResult<()> {
    match role {
        "admin" | "member" => Ok(()),
        _ => Err(AppError::malformed("role must be 'admin' or 'member'")),
    }
}

/// Space-admin gate: the caller must be an `admin` of `space_id` (a non-member or a
/// plain member — or an unknown space — all fail identically with 403).
async fn require_space_admin(
    state: &AppState,
    space_id: &[u8],
    account_id: &[u8],
) -> AppResult<()> {
    if state.store.is_space_admin(space_id, account_id).await? {
        Ok(())
    } else {
        Err(AppError::forbidden("space admin required"))
    }
}

async fn audit_space(state: &AppState, event: &str, space_id: &[u8], account_id: &[u8]) {
    let ev = json!({
        "event": event,
        "space_id": ids::b64(space_id),
        "account_id": ids::b64(account_id),
        "ts": state.now(),
    });
    state.audit_event(&ev, None).await;
}

/// Mirror of the join step-6 policy-grant loop: enqueue a `grant` pending-action for
/// every space_wide vault of `space_id` for `account_id`, at the vault's
/// `space_wide_role` (source `"policy"`), so a member added directly (or transitioned via
/// the role endpoint) gets the same space-wide access a joiner would.
///
/// Idempotent: a vault is skipped when the member already holds a live grant at its latest
/// epoch, or already has an outstanding pending `grant` — so repeated adds / role changes
/// never pile up duplicate work for the vault-admin. Must run INSIDE the caller's tx
/// (single-connection SQLite: no `Store` pool call may interleave with the open tx).
async fn enqueue_space_wide_grants(
    state: &AppState,
    tx: &mut Tx<'_>,
    space_id: &[u8],
    account_id: &[u8],
    now: i64,
) -> AppResult<()> {
    // The member's canonical keyset (grants are keyed by ed25519 pubkey). A member with no
    // keyset row can hold no live grant, so a None here just skips the live-grant probe.
    let member_ed = tx
        .fetch_optional_as::<EdOnly>(
            "SELECT ed25519_pub FROM accounts WHERE account_id = ?",
            vec![Val::b(account_id)],
        )
        .await?
        .map(|r| r.ed25519_pub);

    for v in tx.space_wide_vaults(space_id).await? {
        if let Some(ed) = member_ed.as_deref() {
            let live = tx
                .fetch_scalar_i64(
                    "SELECT COUNT(*) FROM membership_grants g \
                     WHERE g.vault_id = ? AND g.member_pubkey = ? AND g.revoked = 0 \
                       AND (g.not_after IS NULL OR g.not_after > ?) \
                       AND g.key_epoch = (SELECT MAX(m.key_epoch) FROM membership_manifests m \
                                          WHERE m.vault_id = g.vault_id)",
                    vec![Val::b(v.vault_id.as_slice()), Val::b(ed), Val::I(now)],
                )
                .await?
                .unwrap_or(0);
            if live > 0 {
                continue;
            }
        }
        let pending = tx
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM pending_actions \
                 WHERE vault_id = ? AND account_id = ? AND kind = 'grant' AND state = 'pending'",
                vec![Val::b(v.vault_id.as_slice()), Val::b(account_id)],
            )
            .await?
            .unwrap_or(0);
        if pending > 0 {
            continue;
        }
        let action_id = ids::random_id16().to_vec();
        state
            .store
            .pending_enqueue(
                tx,
                &action_id,
                "grant",
                &v.vault_id,
                account_id,
                v.space_wide_role,
                "policy",
                None,
                now,
            )
            .await?;
    }
    Ok(())
}

/// Owner hardening: a space admin who is NOT the instance owner must not be able to evict
/// (remove or demote) the instance owner from a space. The instance owner is the claim
/// owner (`instance.owner_account_id`) and is NOT auto-admin of the spaces they belong to,
/// so without this a co-admin could orphan them. The instance owner may still manage their
/// own membership (actor == target is allowed).
async fn guard_instance_owner_eviction(
    state: &AppState,
    target: &[u8],
    actor: &[u8],
) -> AppResult<()> {
    let inst = state.store.instance().await?;
    if inst.owner_account_id.as_deref() == Some(target) && actor != target {
        return Err(AppError::forbidden(
            "cannot remove or demote the instance owner from a space",
        ));
    }
    Ok(())
}

// ---- spaces ----

#[derive(Deserialize)]
struct CreateSpaceReq {
    name: String,
}

#[derive(Serialize)]
struct CreateSpaceResp {
    space_id: String,
}

/// `POST /v1/spaces` (owner): create a space; the creator is auto-added as its
/// admin in the same transaction.
async fn spaces_create(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<CreateSpaceReq>,
) -> AppResult<(StatusCode, Json<CreateSpaceResp>)> {
    auth.require_owner(&state.store).await?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::malformed("space name required"));
    }
    let now = state.now();
    let space_id = ids::random_id16().to_vec();
    let creator = auth.account_id();

    let mut tx = state.store.begin().await?;
    state
        .store
        .create_space(&mut tx, &space_id, name, Some(creator), now)
        .await?;
    state
        .store
        .space_member_add(&mut tx, &space_id, creator, "admin", Some(creator), now)
        .await?;
    tx.commit().await?;

    audit_space(&state, "space_create", &space_id, creator).await;
    Ok((
        StatusCode::CREATED,
        Json(CreateSpaceResp {
            space_id: ids::b64(&space_id),
        }),
    ))
}

#[derive(Serialize)]
struct SpaceMembership {
    space_id: String,
    name: String,
    role: String,
}

/// `GET /v1/spaces` (any member): the caller's own memberships, each tagged with
/// the caller's role in that space.
async fn spaces_list(auth: AuthCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let acct = auth.account_id();
    let rows = state.store.list_spaces_for(acct).await?;
    let mut spaces = Vec::with_capacity(rows.len());
    for r in rows {
        let role = if state.store.is_space_admin(&r.space_id, acct).await? {
            "admin"
        } else {
            "member"
        };
        spaces.push(SpaceMembership {
            space_id: ids::b64(&r.space_id),
            name: r.name,
            role: role.to_string(),
        });
    }
    Ok(Json(json!({ "spaces": spaces })))
}

// ---- memberships ----

#[derive(Deserialize)]
struct MemberAddReq {
    space_id: String,
    account_id: String,
    role: String,
}

/// `POST /v1/spaces/members` (space admin): add a NEW member of the space at the given
/// role. An already-present member is a 409 (the role endpoint changes roles). Space-wide
/// vault grants are enqueued for the new member, mirroring the join flow's step 6.
async fn members_add(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<MemberAddReq>,
) -> AppResult<StatusCode> {
    let space_id = ids::unb64(&req.space_id)?;
    let account_id = ids::unb64(&req.account_id)?;
    validate_role(&req.role)?;
    // Admin gate first (an outsider probing an unknown account still gets 403, not 404),
    // then reject an unknown target account with 404 instead of a raw FK-violation 500.
    require_space_admin(&state, &space_id, auth.account_id()).await?;
    if state.store.get_account_by_id(&account_id).await?.is_none() {
        return Err(AppError::not_found("account"));
    }
    // An already-present member is NOT silently re-affirmed: `space_member_add` upserts
    // with ON CONFLICT DO NOTHING, so re-adding at a NEW role would 204 while changing
    // nothing. Reject with 409 (the add path never mutates an existing member's role —
    // that is the role endpoint's job).
    if state
        .store
        .space_member_role(&space_id, &account_id)
        .await?
        .is_some()
    {
        return Err(AppError::conflict(
            "account is already a member of this space; use the role endpoint to change its role",
        ));
    }

    let now = state.now();
    let mut tx = state.store.begin().await?;
    state
        .store
        .space_member_add(
            &mut tx,
            &space_id,
            &account_id,
            &req.role,
            Some(auth.account_id()),
            now,
        )
        .await?;
    // Space-wide vault grants, exactly as the join flow (step 6): a directly added member
    // receives a pending `grant` for each of the space's space_wide vaults.
    enqueue_space_wide_grants(&state, &mut tx, &space_id, &account_id, now).await?;
    tx.commit().await?;

    audit_space(&state, "space_member_add", &space_id, &account_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct MemberRemoveReq {
    space_id: String,
    account_id: String,
}

/// `POST /v1/spaces/members/remove` (space admin): drop a membership edge, and enqueue
/// a crypto `revoke` (Task 9) for every space vault where the removed account still
/// holds a live grant at the latest epoch — the vault-admin fulfils it by rotating.
async fn members_remove(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<MemberRemoveReq>,
) -> AppResult<StatusCode> {
    let space_id = ids::unb64(&req.space_id)?;
    let account_id = ids::unb64(&req.account_id)?;
    require_space_admin(&state, &space_id, auth.account_id()).await?;
    // Owner hardening: a co-admin (not the instance owner) cannot evict the instance owner.
    guard_instance_owner_eviction(&state, &account_id, auth.account_id()).await?;
    // Anti-orphan: refuse to remove the LAST admin of a space (no recovery path).
    if state
        .store
        .space_member_role(&space_id, &account_id)
        .await?
        .as_deref()
        == Some("admin")
        && state.store.space_admin_count(&space_id).await? <= 1
    {
        return Err(AppError::forbidden(
            "cannot remove the last admin of a space",
        ));
    }
    state
        .store
        .space_member_remove(&space_id, &account_id)
        .await?;

    // Enqueue a `revoke` per space vault the removed account can still decrypt.
    if let Some(member_ed) = state.store.account_ed(&account_id).await? {
        let vaults = state
            .store
            .vaults_with_live_grant_in_space(&member_ed, &space_id)
            .await?;
        if !vaults.is_empty() {
            let now = state.now();
            let mut tx = state.store.begin().await?;
            for vault_id in &vaults {
                let action_id = ids::random_id16().to_vec();
                state
                    .store
                    .pending_enqueue(
                        &mut tx,
                        &action_id,
                        "revoke",
                        vault_id,
                        &account_id,
                        None,
                        "directory",
                        None,
                        now,
                    )
                    .await?;
            }
            tx.commit().await?;
        }
    }

    audit_space(&state, "space_member_remove", &space_id, &account_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct MemberRoleReq {
    space_id: String,
    account_id: String,
    role: String,
}

/// `POST /v1/spaces/members/role` (space admin): change a member's role.
async fn members_set_role(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<MemberRoleReq>,
) -> AppResult<StatusCode> {
    let space_id = ids::unb64(&req.space_id)?;
    let account_id = ids::unb64(&req.account_id)?;
    validate_role(&req.role)?;
    require_space_admin(&state, &space_id, auth.account_id()).await?;
    let current_role = state.store.space_member_role(&space_id, &account_id).await?;
    // Owner hardening: demoting (role → non-admin) the instance owner is a form of
    // eviction — a co-admin (not the instance owner) must not be able to do it.
    if req.role != "admin" {
        guard_instance_owner_eviction(&state, &account_id, auth.account_id()).await?;
    }
    // Anti-orphan: refuse to demote the LAST admin of a space (no recovery path).
    if req.role != "admin"
        && current_role.as_deref() == Some("admin")
        && state.store.space_admin_count(&space_id).await? <= 1
    {
        return Err(AppError::forbidden(
            "cannot demote the last admin of a space",
        ));
    }
    let now = state.now();
    let mut tx = state.store.begin().await?;
    // Role change (kept as the space_members UPDATE, mirroring `space_member_set_role`).
    tx.exec(
        "UPDATE space_members SET role = ? WHERE space_id = ? AND account_id = ?",
        vec![
            Val::t(req.role.as_str()),
            Val::b(space_id.as_slice()),
            Val::b(account_id.as_slice()),
        ],
    )
    .await?;
    // Mirror join step-6 (idempotent) so a member transitioned via the role endpoint holds
    // the space's space_wide grants. Only a real member is granted — a role change on a
    // non-member is a no-op UPDATE and enqueues nothing.
    if current_role.is_some() {
        enqueue_space_wide_grants(&state, &mut tx, &space_id, &account_id, now).await?;
    }
    tx.commit().await?;
    audit_space(&state, "space_member_role", &space_id, &account_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct MembersQuery {
    space_id: String,
}

#[derive(Serialize)]
struct MemberInfo {
    account_id: String,
    role: String,
    handle: Option<String>,
    display_name: Option<String>,
    /// Canonical member-id (Ed25519 keyset).
    member_pubkey: Option<String>,
    x25519_pub: Option<String>,
    status: Option<String>,
}

/// `GET /v1/spaces/members?space_id=` (space member): the space roster, enriched
/// with each account's human labels and canonical keys.
async fn members_list(
    auth: AuthCtx,
    State(state): State<AppState>,
    Query(q): Query<MembersQuery>,
) -> AppResult<Json<Value>> {
    let space_id = ids::unb64(&q.space_id)?;
    if !state
        .store
        .is_space_member(&space_id, auth.account_id())
        .await?
    {
        return Err(AppError::forbidden("space member required"));
    }
    let rows = state.store.list_space_members(&space_id).await?;
    let mut members = Vec::with_capacity(rows.len());
    for m in rows {
        let acct = state.store.get_account_by_id(&m.account_id).await?;
        let (handle, display_name, ed, x, status) = match acct {
            Some(a) => (
                a.handle,
                a.display_name,
                a.ed25519_pub,
                a.x25519_pub,
                Some(a.status),
            ),
            None => (None, None, None, None, None),
        };
        members.push(MemberInfo {
            account_id: ids::b64(&m.account_id),
            role: m.role,
            handle,
            display_name,
            member_pubkey: ed.as_deref().map(ids::b64),
            x25519_pub: x.as_deref().map(ids::b64),
            status,
        });
    }
    Ok(Json(json!({ "members": members })))
}

// ---- shared directory ----

#[derive(Serialize)]
struct DirEntry {
    account_id: String,
    handle: Option<String>,
    display_name: Option<String>,
    /// Canonical member-id (Ed25519 keyset).
    member_pubkey: String,
    x25519_pub: String,
    status: String,
}

/// `GET /v1/directory` (any authenticated caller): the shared people directory —
/// open metadata (handles + canonical keys), the company-model address book.
async fn directory(_auth: AuthCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = state.store.directory_list().await?;
    let accounts: Vec<DirEntry> = rows
        .into_iter()
        .map(|r| DirEntry {
            account_id: ids::b64(&r.account_id),
            handle: r.handle,
            display_name: r.display_name,
            member_pubkey: ids::b64(&r.ed25519_pub),
            x25519_pub: ids::b64(&r.x25519_pub),
            status: r.status,
        })
        .collect();
    Ok(Json(json!({ "accounts": accounts })))
}
