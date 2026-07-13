//! Escrow sign-in (Phase 2): the two PUBLIC endpoints that let a fresh device —
//! one holding only the password + Secret Key, with no session and no enrolled
//! device — recover its encrypted keyset by handle.
//!
//! - `GET  /v1/escrow/params?handle=` → the Argon2id salt/params a client needs to
//!   re-derive `K_auth`.
//! - `POST /v1/escrow/fetch { handle, k_auth }` → the encrypted keyset blob, gated
//!   on `sha256(k_auth) == stored sha256(K_auth)`.
//!
//! Both are UNAUTHENTICATED and enumeration-resistant: an unknown handle (or a
//! known handle whose latest keyset never enabled escrow) is INDISTINGUISHABLE from
//! an enrolled one. `params` always answers 200 — a real account returns its stored
//! params, everything else a DETERMINISTIC per-handle decoy of the same shape.
//! `fetch` always answers 403 on any failure after a CONSTANT-TIME compare against
//! either the real hash or a fixed dummy, so unknown-handle, not-enrolled, and
//! wrong-credential are timing-indistinguishable. The server only ever stores
//! `sha256(K_auth)` (see `set_escrow`); it never learns the raw credential or the
//! Unlock Key.

use crate::error::{AppError, AppResult};
use crate::http::extract::ct_eq;
use crate::ids;
use crate::state::AppState;
use crate::store::models::EscrowRow;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// The recommended Argon2id parameters (`KdfParams::recommended()`: 64 MiB, t=3,
/// p=1), used verbatim for the decoy so a decoy response is shaped exactly like a
/// real enrollment (which the client is expected to make at these defaults).
const DECOY_MEM_KIB: i64 = 65536;
const DECOY_ITERATIONS: i64 = 3;
const DECOY_PARALLELISM: i64 = 1;

/// Domain-separation label folded into the decoy HMAC key. Distinct per purpose so
/// the decoy key can never coincide with any other server-side derivation.
const DECOY_LABEL: &[u8] = b"escrow-params-decoy";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/escrow/params", get(escrow_params))
        .route("/v1/escrow/fetch", post(escrow_fetch))
}

// ---- params (deterministic decoy on any miss) ----

#[derive(Deserialize)]
struct ParamsQuery {
    handle: String,
}

#[derive(Serialize)]
struct ParamsResp {
    argon_salt: String,
    argon_mem_kib: i64,
    argon_iterations: i64,
    argon_parallelism: i64,
}

/// The escrow Argon2id params actually stored for a keyset row, if it enabled escrow
/// (all fields are written together by `set_escrow`, so they are all-or-nothing).
fn stored_params(row: &EscrowRow) -> Option<(Vec<u8>, i64, i64, i64)> {
    match (
        &row.argon_salt,
        row.argon_mem_kib,
        row.argon_iterations,
        row.argon_parallelism,
    ) {
        (Some(salt), Some(mem), Some(iters), Some(par)) => Some((salt.clone(), mem, iters, par)),
        _ => None,
    }
}

/// A stable, per-handle 16-byte decoy salt: `HMAC-SHA256(key = sha256(decoy_secret ‖
/// DECOY_LABEL), msg = handle)[..16]`. The key material is the SERVER-PRIVATE
/// `escrow_decoy_secret` — a value NO endpoint ever returns — so the decoy is
/// genuinely unforgeable off-server, yet deterministic (the same handle yields the
/// same salt across calls) and per-handle distinct — a probe learns nothing about
/// whether the handle exists.
///
/// It must NOT be keyed from `instance_id`: that is PUBLIC (`GET /v1/instance`
/// returns it), so an attacker could recompute the decoy and tell an enrolled
/// account (real random salt) apart from an unenrolled one (salt == recomputed
/// decoy), defeating enumeration resistance. The private secret closes that leak.
fn decoy_salt(decoy_secret: &[u8], handle: &str) -> Vec<u8> {
    let mut key_material = Vec::with_capacity(decoy_secret.len() + DECOY_LABEL.len());
    key_material.extend_from_slice(decoy_secret);
    key_material.extend_from_slice(DECOY_LABEL);
    let key = ids::sha256(&key_material);
    let mut mac = <Hmac<Sha256>>::new_from_slice(&key).expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(handle.as_bytes());
    mac.finalize().into_bytes()[..16].to_vec()
}

/// `GET /v1/escrow/params?handle=` (PUBLIC): the salt/params to re-derive `K_auth`.
/// Always 200 — a real, escrow-enabled account returns its stored params; anything
/// else (unknown handle, or a keyset with escrow disabled) returns a deterministic
/// decoy of the same shape.
async fn escrow_params(
    State(state): State<AppState>,
    Query(q): Query<ParamsQuery>,
) -> AppResult<Json<ParamsResp>> {
    let row = state.store.get_escrow_by_handle(&q.handle).await?;
    let resp = match row.as_ref().and_then(stored_params) {
        Some((salt, mem, iters, par)) => ParamsResp {
            argon_salt: ids::b64(&salt),
            argon_mem_kib: mem,
            argon_iterations: iters,
            argon_parallelism: par,
        },
        None => {
            let salt = decoy_salt(&state.escrow_decoy_secret, &q.handle);
            ParamsResp {
                argon_salt: ids::b64(&salt),
                argon_mem_kib: DECOY_MEM_KIB,
                argon_iterations: DECOY_ITERATIONS,
                argon_parallelism: DECOY_PARALLELISM,
            }
        }
    };
    Ok(Json(resp))
}

// ---- fetch (constant-time; 403 on every failure) ----

#[derive(Deserialize)]
struct FetchReq {
    handle: String,
    k_auth: String,
}

#[derive(Serialize)]
struct FetchResp {
    keyset_blob: String,
    generation: i64,
    account_id: String,
}

/// `POST /v1/escrow/fetch { handle, k_auth }` (PUBLIC): the encrypted keyset blob for
/// a handle, gated on `sha256(k_auth) == stored sha256(K_auth)`. Any failure — unknown
/// handle, escrow not enabled, or a wrong credential — returns 403 after the SAME
/// constant-time comparison, so the three are indistinguishable to a caller.
async fn escrow_fetch(
    State(state): State<AppState>,
    Json(req): Json<FetchReq>,
) -> AppResult<Json<FetchResp>> {
    // Always hash the presented credential, regardless of whether the handle exists.
    let got = ids::sha256(&ids::unb64(&req.k_auth)?);
    let row = state.store.get_escrow_by_handle(&req.handle).await?;

    // `want` is the enrolled hash when present, else a FIXED 32-byte dummy — so the
    // constant-time compare runs identically on the unknown-handle / not-enrolled /
    // wrong-credential paths, with no early-out that would leak which case it was.
    let want: Vec<u8> = row
        .as_ref()
        .and_then(|r| r.k_auth_hash.clone())
        .unwrap_or_else(|| vec![0u8; 32]);
    let enrolled = row.as_ref().and_then(|r| r.k_auth_hash.as_ref()).is_some();
    let matched = ct_eq(&got, &want);

    if enrolled && matched {
        let r = row.expect("enrolled => the escrow row is present");
        return Ok(Json(FetchResp {
            keyset_blob: ids::b64(&r.keyset_bytes),
            generation: r.generation,
            account_id: ids::b64(&r.account_id),
        }));
    }
    Err(AppError::forbidden("escrow fetch denied"))
}
