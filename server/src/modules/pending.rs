//! Pending crypto-queue surface (§ Task 9): the vault-admin's to-do list.
//!
//! `GET /v1/pending` returns the `grant`/`revoke` actions the calling keyset must
//! fulfil — one row per (vault, target account) where the caller holds a live
//! Admin(2) grant at the vault's latest epoch. Each row is joined with the TARGET
//! account's canonical keys: `member_pubkey` (Ed25519, to verify the binding proof)
//! and `x25519_pub` (to HPKE-wrap the vault key). The server marks rows done ITSELF
//! by observing published manifests/grants (see `policy::grants_publish`) — clients
//! never self-report completion.

use crate::error::AppResult;
use crate::http::extract::AuthCtx;
use crate::ids;
use crate::state::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{Value, json};

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/pending", get(pending_list))
}

#[derive(Serialize)]
struct PendingAction {
    action_id: String,
    kind: String,
    vault_id: String,
    account_id: String,
    /// The target account's canonical Ed25519 keyset (base64) — null if the account
    /// carries no key. Fulfillers verify the binding proof against it.
    member_pubkey: Option<String>,
    /// The target account's X25519 key (base64) — recipient of the HPKE-wrapped VK.
    x25519_pub: Option<String>,
    crypto_role: Option<i64>,
    source: String,
    /// Opaque binding MAC (base64) or null.
    proof: Option<String>,
    created_at: i64,
}

/// `GET /v1/pending` (Bearer): the caller's outstanding crypto actions as a
/// vault-admin. Rows come from `pending_for_admin(device_ed25519)`, each enriched
/// with the target account's pubkeys.
async fn pending_list(auth: AuthCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = state.store.pending_for_admin(auth.device_ed25519()).await?;
    let mut actions = Vec::with_capacity(rows.len());
    for r in rows {
        // Join the TARGET account's keys (nonexistent/keyless account → null).
        let (member_pubkey, x25519_pub) = match state.store.get_account_by_id(&r.account_id).await?
        {
            Some(a) => (
                a.ed25519_pub.as_deref().map(ids::b64),
                a.x25519_pub.as_deref().map(ids::b64),
            ),
            None => (None, None),
        };
        actions.push(PendingAction {
            action_id: ids::b64(&r.action_id),
            kind: r.kind,
            vault_id: ids::b64(&r.vault_id),
            account_id: ids::b64(&r.account_id),
            member_pubkey,
            x25519_pub,
            crypto_role: r.crypto_role,
            source: r.source,
            proof: r.proof.as_deref().map(ids::b64),
            created_at: r.created_at,
        });
    }
    Ok(Json(json!({ "actions": actions })))
}
