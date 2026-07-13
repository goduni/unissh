//! Spaces, memberships, and the shared people directory (v2 §Task 7).
//! Spaces are *server-trusted* groupings — a role here (`admin`/`member`) is an
//! authority label, NOT a decryption capability (vault crypto grants live in
//! `sync`/`grants`). Owner creates spaces; a space admin manages that space's
//! membership; any authenticated caller may read the directory (company model).
//! Instance-scoped: no tenant. All SQL goes through the Task-3 repo.

use crate::error::{AppError, AppResult};
use crate::http::extract::AuthCtx;
use crate::ids;
use crate::state::AppState;
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

/// `POST /v1/spaces/members` (space admin): add (or re-affirm — idempotent) a
/// member of the space at the given role. (Pending-grant enqueue is Task 9.)
async fn members_add(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<MemberAddReq>,
) -> AppResult<StatusCode> {
    let space_id = ids::unb64(&req.space_id)?;
    let account_id = ids::unb64(&req.account_id)?;
    validate_role(&req.role)?;
    require_space_admin(&state, &space_id, auth.account_id()).await?;

    let mut tx = state.store.begin().await?;
    state
        .store
        .space_member_add(
            &mut tx,
            &space_id,
            &account_id,
            &req.role,
            Some(auth.account_id()),
            state.now(),
        )
        .await?;
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
    state
        .store
        .space_member_set_role(&space_id, &account_id, &req.role)
        .await?;
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
