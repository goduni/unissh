//! backend-policy-rbac (spec §5.5/§9/§10): grants/publish (atomic revoke/add),
//! grants get, RBAC write-accept/read-deny.

use crate::codec::{ObjectTag, parse_open};
use crate::domain::manifest::parse_member_set;
use crate::domain::rbac::Role;
use crate::error::{AppError, AppResult};
use crate::http::extract::AuthCtx;
use crate::ids;
use crate::state::AppState;
use crate::store::sync_repo::PushObj;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/grants", get(grants_get))
        .route("/v1/grants/publish", post(grants_publish))
}

// ---- write-accept (§9.3/§9.4/§10) ----

/// Resolve the author's role for the vault STRICTLY at manifest@(record.key_epoch);
/// if it is absent (or the author is not in it) → owner (implicit admin). `None` —
/// the author is neither a member nor the owner. We do NOT fall back to the
/// latest-manifest (the role must resolve at the epoch of the record itself, §9.4).
async fn author_role(
    state: &AppState,
    vault_id: &[u8],
    epoch: i64,
    author: &[u8],
) -> AppResult<Option<Role>> {
    // Strictly at manifest@(record.key_epoch) — we do NOT fall back to latest
    // (otherwise the role resolves at a different epoch than the one the record
    // carries; the §9.4 predicate is author∈members@epoch of THIS EXACT record).
    if let Some(m) = state.store.get_manifest(vault_id, epoch).await? {
        let ms = parse_member_set(&m.manifest_blob)?;
        // Bind the signed blob's embedded epoch to the row/record epoch the RBAC
        // predicate reasons under — otherwise a manifest could be indexed at one
        // epoch while its signed body claims another (defense-in-depth; the blob
        // is admin-signed, so this only tightens, never forges).
        if ms.key_epoch != epoch as u64 {
            return Err(AppError::malformed("manifest epoch mismatch"));
        }
        if let Some(r) = ms.role_of(author) {
            return Ok(Some(r));
        }
        // Not in member-set@epoch, but the namespace owner → implicit admin (creator).
    }
    match state.store.get_vault_owner(vault_id).await? {
        Some(owner) if owner == author => Ok(Some(Role::Admin)),
        Some(_) => Ok(None),
        None => Ok(Some(Role::Admin)), // vault does not exist yet → the first push establishes ownership
    }
}

/// Write-accept on push (validate_signatures). Defense-in-depth on top of client
/// verification (§8.5): the client re-verifies on read anyway.
pub async fn write_accept(
    state: &AppState,
    author_ed25519: &[u8],
    items: &[PushObj],
    acl_only: bool,
) -> AppResult<()> {
    // Instance owner keyset (for the audit-author gate, §11.3): None until claimed.
    let genesis = match state.store.instance().await?.owner_account_id {
        Some(aid) => state.store.account_ed(&aid).await?,
        None => None,
    };

    for it in items {
        let p = &it.parsed;
        match p.tag() {
            // S5: under `acl_only` (validate_signatures disabled) we check ONLY
            // ACL objects (manifest/grant) — their integrity is mandatory, since
            // the delta visibility filter trusts them; other tiers are skipped (the
            // client re-verifies them on read, server-side RBAC is under the toggle).
            Some(ObjectTag::Vault) | Some(ObjectTag::Item) if acl_only => {}
            Some(ObjectTag::Vault) | Some(ObjectTag::Item) => {
                let vault_id = p
                    .vault_id
                    .as_deref()
                    .ok_or_else(|| AppError::malformed("missing vault_id"))?;
                let epoch = p.key_epoch.map(|e| e as i64).unwrap_or(0);
                // The record's author is taken from the object itself (also the
                // signer); it must match the authenticated device (anti-spoofing).
                let obj_author = p.author_pubkey.as_deref().unwrap_or(author_ed25519);
                match author_role(state, vault_id, epoch, obj_author).await? {
                    Some(r) if r >= Role::Editor => {}
                    Some(_) => {
                        return Err(AppError::forbidden("viewer cannot write objects"));
                    }
                    None => {
                        return Err(AppError::forbidden(
                            "author is not a member of the vault at this epoch",
                        ));
                    }
                }
            }
            Some(ObjectTag::MembershipManifest) | Some(ObjectTag::MembershipGrant) => {
                let vault_id = p
                    .vault_id
                    .as_deref()
                    .ok_or_else(|| AppError::malformed("missing vault_id"))?;
                let epoch = p.key_epoch.map(|e| e as i64).unwrap_or(0);
                let obj_author = p.author_pubkey.as_deref().unwrap_or(author_ed25519);
                if author_role(state, vault_id, epoch, obj_author).await? != Some(Role::Admin) {
                    return Err(AppError::forbidden(
                        "only admins can publish membership records",
                    ));
                }
            }
            Some(ObjectTag::Audit) if acl_only => {}
            Some(ObjectTag::Audit) => {
                // author == genesis_owner (§11.3).
                let obj_author = p.author_pubkey.as_deref().unwrap_or_default();
                match &genesis {
                    Some(g) if g == obj_author => {}
                    _ => return Err(AppError::forbidden("audit author must be genesis owner")),
                }
            }
            Some(ObjectTag::Keyset) => { /* instance-level, allow */ }
            // AccountState self-authorship is already checked unconditionally in the
            // sync handler (§A3) — here, under acl_only, we skip it.
            Some(ObjectTag::AccountState) if acl_only => {}
            Some(ObjectTag::AccountState) => {
                // A3: the state MUST be self-authored by the authoring account —
                // author == the pushing device (an account's devices share a keyset).
                // Otherwise one account could write someone else's account-state.
                let obj_author = p.author_pubkey.as_deref().unwrap_or_default();
                if obj_author != author_ed25519 {
                    return Err(AppError::forbidden("account state must be self-authored"));
                }
            }
            // Unknown tag: under acl_only we do not tighten (preserving the prior
            // validate-off behavior); on the full pass — we reject.
            None if acl_only => {}
            None => return Err(AppError::malformed("unknown object tag")),
        }
    }
    Ok(())
}

// ---- grants/publish ----

#[derive(Deserialize)]
struct PublishReq {
    manifest: String,
    grants: Vec<String>,
    revoke_epoch: Option<i64>,
    new_epoch: Option<i64>,
}

#[derive(Serialize)]
struct PublishResp {
    new_epoch: i64,
    server_seq: Vec<i64>,
}

async fn grants_publish(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<PublishReq>,
) -> AppResult<Json<PublishResp>> {
    let m_bytes = ids::unb64(&req.manifest)?;
    let m_parsed = parse_open(&m_bytes)?;
    if m_parsed.tag() != Some(ObjectTag::MembershipManifest) {
        return Err(AppError::malformed("manifest object expected"));
    }
    // S4/S5: re-verify the manifest's signature UNCONDITIONALLY. author_pubkey
    // carries the vault-admin check below; without signature verification it is
    // forgeable, and grants_publish would become an RBAC bypass (the delta
    // visibility filter trusts materialized manifests/grants). The push path
    // (sync.rs) already verifies ACL objects unconditionally — this parallel ACL
    // write path must too.
    crate::crypto::verify_record_sig(&m_bytes)?;
    let vault_id = m_parsed
        .vault_id
        .clone()
        .ok_or_else(|| AppError::malformed("manifest missing vault_id"))?;
    let new_epoch = req
        .new_epoch
        .or(m_parsed.key_epoch.map(|e| e as i64))
        .ok_or_else(|| AppError::malformed("missing new_epoch"))?;
    // The manifest must carry exactly the new epoch.
    if m_parsed.key_epoch.map(|e| e as i64) != Some(new_epoch) {
        return Err(AppError::malformed(
            "manifest key_epoch must equal new_epoch",
        ));
    }
    // Cannot revoke the same epoch we are publishing (self-revoke of fresh grants).
    if req.revoke_epoch == Some(new_epoch) {
        return Err(AppError::conflict(
            "revoke_epoch must differ from new_epoch",
        ));
    }
    // Coarse precheck (replaces the old instance-admin gate): the caller must be able
    // to touch the vault — its personal owner OR a member of its space. Defense-in-depth
    // in front of the real S4 gate below.
    if !state
        .store
        .can_touch_vault(auth.account_id(), &vault_id)
        .await?
    {
        return Err(AppError::forbidden(
            "not authorized to publish grants for this vault",
        ));
    }
    // S4: the grant publisher must be a vault-admin. Mirrors author_role==Admin from
    // write_accept (§9.4): the role resolves at the manifest's epoch; for a new epoch
    // (the manifest is not yet in the store) it reduces to an owner check. author_pubkey
    // is already AUTHENTICATED by verify_record_sig above — the role check on it cannot
    // be bypassed by forging the field.
    let m_author = m_parsed.author_pubkey.as_deref().unwrap_or_default();
    if author_role(&state, &vault_id, new_epoch, m_author).await? != Some(Role::Admin) {
        return Err(AppError::forbidden("grant publisher must be a vault admin"));
    }
    let manifest = PushObj {
        bytes: m_bytes,
        parsed: m_parsed,
    };

    let mut grants = Vec::with_capacity(req.grants.len());
    for g in &req.grants {
        let b = ids::unb64(g)?;
        let parsed = parse_open(&b)?;
        if parsed.tag() != Some(ObjectTag::MembershipGrant) {
            return Err(AppError::malformed("grant object expected"));
        }
        // As with the manifest — we verify the grant's signature unconditionally
        // (authentication of the grant's author_pubkey; delta/read-deny trust
        // materialized grants).
        crate::crypto::verify_record_sig(&b)?;
        grants.push(PushObj { bytes: b, parsed });
    }

    let seqs = state
        .store
        .grants_publish(&vault_id, &manifest, &grants, req.revoke_epoch, state.now())
        .await?;

    // Auto-done (Task 9): the server marks pending crypto-actions done by OBSERVING
    // this publish — clients never self-report. Members present in the new grant set
    // have had their `grant` action fulfilled; on a rotation (revoke_epoch set), any
    // account ABSENT from the new grant set has had its `revoke` action fulfilled.
    // A follow-up tx (the publish above already committed atomically); a no-op when
    // nothing is queued, so pre-Task-9 callers are unaffected.
    let grant_member_eds: Vec<Vec<u8>> = grants
        .iter()
        .filter_map(|g| g.parsed.member_pubkey.clone())
        .collect();
    let now = state.now();
    let mut tx = state.store.begin().await?;
    state
        .store
        .pending_mark_grants_done(&mut tx, &vault_id, &grant_member_eds, new_epoch, now)
        .await?;
    if req.revoke_epoch.is_some() {
        state
            .store
            .pending_mark_revokes_done(&mut tx, &vault_id, &grant_member_eds, new_epoch, now)
            .await?;
    }
    tx.commit().await?;

    // Audit (server-observed): publish/rotate/revoke.
    let ev = serde_json::json!({
        "event": "access_grant", "vault_id": ids::b64(&vault_id),
        "new_epoch": new_epoch, "revoke_epoch": req.revoke_epoch, "ts": state.now(),
    });
    state.audit_event(&ev, Some(&vault_id)).await;

    Ok(Json(PublishResp {
        new_epoch,
        server_seq: seqs,
    }))
}

// ---- grants get ----

#[derive(Deserialize)]
struct GrantsQuery {
    vault_id: String,
    key_epoch: Option<i64>,
}

#[derive(Serialize)]
struct GrantsResp {
    manifest: String,
    grants: Vec<String>,
    key_epoch: i64,
}

async fn grants_get(
    auth: AuthCtx,
    State(state): State<AppState>,
    Query(q): Query<GrantsQuery>,
) -> AppResult<Json<GrantsResp>> {
    let vault_id = ids::unb64(&q.vault_id)?;

    // We resolve the epoch WITHOUT an early 404: a nonexistent vault/manifest must
    // not differ in its response from "the vault exists, but you are not a member" —
    // otherwise a revoked member who knows the vault_id could detect the vault's
    // existence/liveness (existence-oracle, S6). Therefore the RBAC check GOES FIRST
    // and collapses both cases into a single 403.
    let epoch_opt = match q.key_epoch {
        Some(e) => Some(e),
        None => state.store.latest_manifest_epoch(&vault_id).await?,
    };

    // RBAC read-deny (§5.5/invariant 2): the requester must be the instance owner OR
    // hold an active (non-revoked) grant at this epoch. For a non-owner, an absent
    // vault/epoch == an absent grant → the same 403 (no existence leak).
    let is_admin = state
        .store
        .account_is_owner_by_ed(auth.device_ed25519())
        .await?;
    // We ALWAYS run the grant query, even when there is no epoch (epoch_opt=None →
    // a dummy epoch 0, which never has grants — epochs start at 1): otherwise an
    // existing vault would make one more store query than a nonexistent one,
    // leaving a TIMING existence-oracle for the same non-member for whose sake S6
    // closed the status-code oracle. Now the number of queries does not depend on
    // the vault's presence.
    let authorized = is_admin
        || state
            .store
            .member_has_active_grant(
                &vault_id,
                epoch_opt.unwrap_or(0),
                auth.device_ed25519(),
                state.now(),
            )
            .await?;
    if !authorized {
        return Err(AppError::forbidden("not a member of this vault epoch"));
    }

    // Authorized. From here informative 404s are safe: the member/owner has already
    // passed RBAC, so disclosing "no manifest" gives them no oracle advantage.
    let epoch = epoch_opt.ok_or_else(|| AppError::not_found("no manifest for vault"))?;
    let manifest = state
        .store
        .get_manifest(&vault_id, epoch)
        .await?
        .ok_or_else(|| AppError::not_found("manifest@epoch"))?;

    // Reconstruct the manifest object's bytes for the response (as SyncObject::Manifest).
    let manifest_b64 = ids::b64(&manifest_object_bytes(&manifest));
    let grants = state.store.list_grants(&vault_id, epoch, true).await?;
    let grant_b64 = grants
        .iter()
        .map(|g| ids::b64(&grant_object_bytes(g)))
        .collect();

    Ok(Json(GrantsResp {
        manifest: manifest_b64,
        grants: grant_b64,
        key_epoch: epoch,
    }))
}

/// Reconstruct the bytes of `SyncObject::MembershipManifest` (§5.2 tag 3).
fn manifest_object_bytes(m: &crate::store::models::ManifestRow) -> Vec<u8> {
    let mut out = vec![3u8];
    put(&mut out, &m.vault_id);
    out.extend_from_slice(&(m.key_epoch as u64).to_be_bytes());
    put(&mut out, &m.manifest_blob);
    put(&mut out, &m.signature);
    put(&mut out, &m.author_pubkey);
    out
}

/// Reconstruct the bytes of `SyncObject::MembershipGrant` (§5.2 tag 4).
fn grant_object_bytes(g: &crate::store::models::GrantRow) -> Vec<u8> {
    let mut out = vec![4u8];
    put(&mut out, &g.vault_id);
    put(&mut out, &g.member_pubkey);
    out.extend_from_slice(&(g.key_epoch as u64).to_be_bytes());
    out.push(g.role.clamp(0, 2) as u8);
    // not_after:i64be(8) — exactly the position in the grant's signed content
    // (tag 4) that both canonical deserializers expect (server `codec.rs`, native
    // `sync/object.rs`). Without it, a native client would read the first 8 bytes of
    // the wrapped_vk length as not_after and desync the entire grant. sentinel:
    // NULL/<=0 = "no expiry" = 0.
    out.extend_from_slice(&g.not_after.unwrap_or(0).max(0).to_be_bytes());
    put(&mut out, &g.wrapped_vk);
    put(&mut out, &g.signature);
    put(&mut out, &g.author_pubkey);
    out
}

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{ObjectTag, parse_open};
    use crate::store::models::GrantRow;

    fn grant_row(not_after: Option<i64>) -> GrantRow {
        GrantRow {
            vault_id: vec![0xAA; 16],
            member_pubkey: vec![0xBB; 32],
            key_epoch: 7,
            role: 1,
            wrapped_vk: vec![0xCC; 48],
            signature: vec![0xDD; 67],
            author_pubkey: vec![0xEE; 32],
            not_after,
            revoked: 0,
        }
    }

    /// G3: the hand-written GET /v1/grants reconstruction MUST stay byte-compatible
    /// with the canonical tag-4 deserializer. If `grant_object_bytes` ever drops a
    /// field (e.g. `not_after`), the reader desyncs — this test fails BEFORE a native
    /// client misparses the grant in the field.
    #[test]
    fn grant_object_bytes_roundtrips_through_canonical_reader() {
        for (na, want) in [(Some(1_900_000_000i64), 1_900_000_000i64), (None, 0)] {
            let g = grant_row(na);
            let bytes = grant_object_bytes(&g);
            let p = parse_open(&bytes).expect("canonical reader must parse our own bytes");
            assert_eq!(p.tag(), Some(ObjectTag::MembershipGrant));
            assert_eq!(p.vault_id.as_deref(), Some(g.vault_id.as_slice()));
            assert_eq!(p.member_pubkey.as_deref(), Some(g.member_pubkey.as_slice()));
            assert_eq!(p.key_epoch, Some(g.key_epoch as u64));
            assert_eq!(p.role, Some(g.role as u8));
            // The crux: not_after lands where the reader expects it, so wrapped_vk /
            // sig / author are NOT shifted.
            assert_eq!(p.not_after, Some(want));
            assert_eq!(p.wrapped_vk.as_deref(), Some(g.wrapped_vk.as_slice()));
            assert_eq!(p.signature.as_deref(), Some(g.signature.as_slice()));
            assert_eq!(p.author_pubkey.as_deref(), Some(g.author_pubkey.as_slice()));
        }
    }
}
