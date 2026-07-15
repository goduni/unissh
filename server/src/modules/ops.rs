//! Ops surface (`/v1/ops/*`): break-glass, server-trusted operator console.
//! Auth — `X-UniSSH-Ops-Token` (`OpsCtx`), NOT a keyset. Instance-scoped (v2):
//! only infrastructure aggregates + anti-rollback seq-bump. Zero-knowledge
//! preserved — no content, only open metadata.

use crate::error::{AppError, AppResult};
use crate::http::extract::OpsCtx;
use crate::state::AppState;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/ops/overview", get(ops_overview))
        .route("/v1/ops/instance", get(ops_instance))
        .route("/v1/ops/seq-bump", post(ops_seq_bump))
}

async fn ops_overview(_ops: OpsCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let (accounts, objects) = state.store.ops_counts().await?;
    let generation = state.store.instance_generation().await?;
    Ok(Json(json!({
        "accounts": accounts,
        "objects": objects,
        "instance_generation": generation,
    })))
}

async fn ops_instance(_ops: OpsCtx, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let generation = state.store.instance_generation().await?;
    Ok(Json(json!({
        "generation": generation,
        "min_floor": state.config.sync.min_instance_generation,
    })))
}

#[derive(Deserialize)]
struct OpsSeqBumpReq {
    by: Option<i64>,
    to: Option<i64>,
}

async fn ops_seq_bump(
    _ops: OpsCtx,
    State(state): State<AppState>,
    Json(req): Json<OpsSeqBumpReq>,
) -> AppResult<Json<Value>> {
    let (old, new) = if let Some(to) = req.to {
        state.store.bump_instance_seq_to(to).await?
    } else if let Some(by) = req.by {
        state.store.bump_instance_seq_by(by).await?
    } else {
        return Err(AppError::malformed("seq-bump requires `by` or `to`"));
    };
    Ok(Json(json!({ "old": old, "new": new })))
}
