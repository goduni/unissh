//! axum router + tower layers. Assembling the router from modules (§2.2).

pub mod extract;
pub mod ratelimit;

use crate::modules;
use crate::state::AppState;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

/// Cursor-pagination tail of `admin::objects_list`. The caller fetches ONE row
/// more than `limit`; this cuts `rows` back to `limit` and decides `has_more` (a
/// row remains after the page — not "the page came back full", which sends a
/// reader after an empty page whenever the total is a multiple of `limit`) and
/// `next_cursor` (the last row's sequence, or the incoming `cursor` when the page
/// is empty). `sync::delta` pages the same way, with a byte budget on top — see
/// `Store::delta_page`.
pub(crate) fn page<T>(
    rows: &mut Vec<T>,
    limit: i64,
    cursor: i64,
    key: impl Fn(&T) -> i64,
) -> (bool, i64) {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = rows.last().map(key).unwrap_or(cursor);
    (has_more, next_cursor)
}

/// Public service endpoints (§5.7), without auth/rate-limit.
/// `/metrics` is NOT included here — it lives on a separate internal listener (§5.7/§13:
/// "protected by config/network"), see `build_metrics_router` + main.rs.
fn service_routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/version", get(version))
}

/// A separate router for Prometheus `/metrics` — brought up on `metrics_bind`
/// (usually 127.0.0.1), not on the public API listener.
pub fn build_metrics_router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(state)
}

/// Build the full application router.
pub fn build_router(state: AppState) -> Router {
    let max_body = state.config.limits.max_body_bytes;
    let cors = cors_layer(&state.config.server.cors_allowed_origins);

    // /v1 API routes: rate-limited + authn extractors inside the handlers.
    let v1 = Router::new()
        .merge(modules::instance::routes())
        .merge(modules::identity::routes())
        .merge(modules::oidc::routes())
        .merge(modules::escrow::routes())
        .merge(modules::spaces::routes())
        .merge(modules::sync::routes(max_body))
        .merge(modules::vault_meta::routes())
        .merge(modules::policy::routes())
        .merge(modules::pending::routes())
        .merge(modules::audit::routes())
        .merge(modules::admin::routes())
        .merge(modules::ops::routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            ratelimit::rate_limit_mw,
        ));

    let router = Router::new()
        .merge(service_routes())
        .merge(v1)
        // The `UniSSH-API-Version: 1` response header (§5.0).
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("unissh-api-version"),
            HeaderValue::from_static("1"),
        ))
        // The outer cap on any request body. Under it the extractors (`Bytes`,
        // `Json`) apply axum's own 2 MiB default; only the push route raises
        // that to `limits.max_body_bytes` (see `modules::sync::routes`), so the
        // routes that answer without a session never buffer more than 2 MiB.
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // CORS — the outermost layer: preflight OPTIONS is answered BEFORE rate-limit/auth.
    match cors {
        Some(c) => router.layer(c),
        None => router,
    }
}

/// Build the CORS layer from the allowlist of origins. Empty/no valid ones → `None`
/// (the panel is behind the same origin/proxy — the layer isn't needed). Allows the headers and
/// methods the admin panel sends (§ handoff P2.6); exposes the API version, Retry-After and
/// Content-Disposition (the audit export's file name).
fn cors_layer(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    let parsed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| match HeaderValue::from_str(o) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::warn!(origin = %o, "ignoring invalid cors_allowed_origins entry");
                None
            }
        })
        .collect();
    if parsed.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                HeaderName::from_static("x-unissh-ops-token"),
                HeaderName::from_static("idempotency-key"),
            ])
            .expose_headers([
                HeaderName::from_static("unissh-api-version"),
                header::RETRY_AFTER,
                // The audit export's file name carries the pinned seq range.
                header::CONTENT_DISPOSITION,
            ]),
    )
}

async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.ping().await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    match &state.metrics {
        Some(h) => (StatusCode::OK, h.render()),
        None => (StatusCode::NOT_FOUND, String::new()),
    }
}

async fn version() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "api": 1,
        "server": env!("CARGO_PKG_VERSION"),
    }))
}
