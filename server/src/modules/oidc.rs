//! OIDC sign-in (Phase 5, redesign/server): `POST /v1/oidc/callback`.
//!
//! SECURITY-CRITICAL. This endpoint turns an IdP-signed `id_token` + a self-attested
//! keyset registration into a UniSSH account + device + session. The two credentials
//! are cryptographically stitched together by a **nonce key-binding**: the id_token's
//! `nonce` MUST equal `base64(sha256(ed25519_pub ‖ x25519_pub))` of the presented
//! keyset. Because the nonce is inside the IdP's signature, a hostile relay cannot
//! swap the keyset without breaking that signature.
//!
//! ZK boundary: this handler only ever touches *identity + memberships + session*. It
//! never sees keyset/escrow/vault-key material — the registration payload/signature it
//! receives are PUBLIC self-attestation, exactly like `claim`/`join`.

use crate::config::OidcConfig;
use crate::crypto::{self, RegistrationPayload};
use crate::error::{AppError, AppResult};
use crate::http::extract::ct_eq;
use crate::ids;
use crate::modules::identity::{SessionTokens, mint_session};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/oidc/callback", post(oidc_callback))
}

#[derive(Deserialize)]
struct CallbackReq {
    /// The IdP-signed OpenID Connect `id_token` (compact JWS). The credential.
    id_token: String,
    /// Canonical registration payload (base64) — same self-attestation as claim/join.
    registration_payload: String,
    /// Ed25519 signature over the payload (base64), proving keyset possession.
    registration_signature: String,
}

#[derive(Serialize)]
struct CallbackResp {
    account_id: String,
    device_id: String,
    /// The space_ids (base64) this login was provisioned into via group→space mapping.
    spaces: Vec<String>,
    /// The freshly minted session (access/refresh + expiries + session_id).
    #[serde(flatten)]
    session: SessionTokens,
}

/// `POST /v1/oidc/callback` (PUBLIC — the id_token IS the credential; no bearer).
///
/// Steps: (1) verify the id_token against the issuer JWKS (iss/aud/exp/signature);
/// (2) verify the self-attested keyset registration; (3) enforce the nonce
/// key-binding; (4) find-or-create the SSO account + a fresh device; (5) map IdP
/// groups → space memberships; (6) mint an `oidc` session with a reassertion deadline.
async fn oidc_callback(
    State(state): State<AppState>,
    Json(req): Json<CallbackReq>,
) -> AppResult<(StatusCode, Json<CallbackResp>)> {
    let config = &state.config.oidc;
    if !config.enabled {
        // Not a hint about a valid-but-forbidden token: the SSO surface simply does
        // not exist on this instance.
        return Err(AppError::not_found("oidc disabled"));
    }

    // 1. Verify the IdP-signed id_token (signature against the issuer JWKS + iss/aud/exp).
    //    Every failure returns a uniform "invalid id_token" (never leak which check failed).
    let claims = verify_id_token(config, state.now(), &req.id_token).await?;

    // 2. Verify the self-attested keyset registration (proves the caller holds the keyset).
    let payload_bytes = ids::unb64(&req.registration_payload)?;
    let payload = RegistrationPayload::parse_canonical(&payload_bytes)?;
    let sig = ids::unb64(&req.registration_signature)?;
    crypto::verify_registration(&payload, &sig)?;

    // 3. NONCE KEY-BINDING (mandatory). Bind the keyset to THIS id_token:
    //    nonce == base64(sha256(ed25519_pub ‖ x25519_pub)) — ed FIRST, then x (the
    //    canonical order the client/FFI `oidc_nonce` uses). A missing or mismatched
    //    nonce is fatal: it is precisely what stops a stolen id_token from being bound
    //    to an attacker's keyset.
    let mut bind = Vec::with_capacity(64);
    bind.extend_from_slice(&payload.ed25519_pub);
    bind.extend_from_slice(&payload.x25519_pub);
    let expected_nonce = ids::b64(&ids::sha256(&bind));
    let nonce_ok = claims
        .nonce
        .as_deref()
        .is_some_and(|n| ct_eq(n.as_bytes(), expected_nonce.as_bytes()));
    if !nonce_ok {
        return Err(AppError::forbidden("nonce mismatch"));
    }

    let now = state.now();

    // 4. Find-or-create by external identity (issuer, subject).
    let existing = state
        .store
        .get_account_by_external(&claims.iss, &claims.sub)
        .await?;
    let (account_id, is_new) = match &existing {
        Some(acct) => {
            if acct.status != "active" {
                return Err(AppError::forbidden("account is not active"));
            }
            (acct.account_id.clone(), false)
        }
        None => {
            // A brand-new SSO identity. Its canonical keyset (ed25519_pub) is
            // server-wide UNIQUE; if it already belongs to a (necessarily different,
            // non-SSO) account, that is a conflict, not a silent takeover.
            if state
                .store
                .get_account_by_ed(&payload.ed25519_pub)
                .await?
                .is_some()
            {
                return Err(AppError::conflict(
                    "identity already registered without SSO",
                ));
            }
            (ids::random_id16().to_vec(), true)
        }
    };
    // A fresh device on every login (mirrors the join reattach path).
    let device_id = ids::random_id16().to_vec();
    // An optional friendly label from the token's `name` claim (never a `handle`, to
    // avoid the unique-handle contention path; SSO accounts key off (iss, sub)).
    let display_name = claims.name.as_deref();

    // 5. ONE transaction: account (new only) + device + memberships all roll back
    //    together if anything fails (mirrors claim/join).
    let mut tx = state.store.begin().await?;
    if is_new {
        tx.create_account(
            &account_id,
            &payload.ed25519_pub,
            &payload.x25519_pub,
            display_name,
            None,  // handle: SSO accounts are addressed by (iss, sub), not a handle
            false, // SSO joiners are never instance owners
            &payload_bytes,
            &sig,
            Some(claims.iss.as_str()),
            Some(claims.sub.as_str()),
            now,
        )
        .await?;
    }
    tx.create_device(
        &account_id,
        &device_id,
        &payload.ed25519_pub,
        &payload.x25519_pub,
        now,
    )
    .await?;

    // 6. Group → space mapping. For each configured GroupMap whose `group` appears in
    //    the token's groups claim, add an (idempotent) membership. Unmapped/no groups
    //    → the account still exists, just with no memberships.
    let mut spaces: Vec<String> = Vec::new();
    for gm in &config.group_map {
        if !claims.groups.iter().any(|g| g == &gm.group) {
            continue;
        }
        let space_id = ids::unb64(&gm.space_id)?;
        state
            .store
            .space_member_add(&mut tx, &space_id, &account_id, &gm.role, None, now)
            .await?;
        if !spaces.contains(&gm.space_id) {
            spaces.push(gm.space_id.clone());
        }
    }

    tx.commit().await?;

    // 7. Mint an `oidc` session with a reassertion deadline (after which the client must
    //    re-run the OIDC dance rather than silently refreshing).
    let reassert_expires = Some(now + config.max_reassertion_age_seconds);
    let session = mint_session(&state, &account_id, &device_id, "oidc", reassert_expires).await?;

    // 8. Audit + metric.
    let ev = serde_json::json!({
        "event": "oidc_login",
        "account_id": ids::b64(&account_id),
        "device_id": ids::b64(&device_id),
        "issuer": claims.iss,
        "ts": now,
    });
    state.audit_event(&ev, None).await;
    metrics::counter!("unissh_oidc_login_total").increment(1);

    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(CallbackResp {
            account_id: ids::b64(&account_id),
            device_id: ids::b64(&device_id),
            spaces,
            session,
        }),
    ))
}

// ---- id_token verification (JWKS-backed) --------------------------------------------
//
// The verified subset we act on. `iss`/`aud`/`exp` are enforced *inside* `decode`
// (against the issuer JWKS); here we surface only the fields the handler consumes.

struct VerifiedClaims {
    iss: String,
    sub: String,
    nonce: Option<String>,
    name: Option<String>,
    groups: Vec<String>,
}

/// TTL of a cached JWK (bounds staleness when an IdP rotates a key *under the same
/// kid*; a rotation to a NEW kid is picked up immediately via cache-miss refetch).
const JWKS_TTL_SECONDS: i64 = 3600;

/// Cache-miss refetch keyed by `"{jwks_url}\n{kid}"`. Storing the parsed `Jwk` (not a
/// `DecodingKey`) keeps the entry cheaply cloneable and rebuilds the key per request.
/// Keying by the full jwks_url isolates distinct issuers/mock-servers from each other.
fn jwks_cache() -> &'static Mutex<HashMap<String, (Jwk, i64)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Jwk, i64)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A shared TLS client for JWKS fetches. Redirects are DISABLED so a hostile/misconfig
/// redirect can never bounce the fetch to a foreign host (host-pinning by construction);
/// a short timeout keeps a hung IdP from stalling the request.
fn http_client() -> &'static reqwest::Client {
    static HTTP: OnceLock<reqwest::Client> = OnceLock::new();
    HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("build reqwest client for JWKS fetch")
    })
}

/// `config.jwks_url` if set, else the OIDC-standard `{issuer}/.well-known/jwks.json`.
fn resolve_jwks_url(config: &OidcConfig) -> String {
    if !config.jwks_url.is_empty() {
        config.jwks_url.clone()
    } else {
        format!(
            "{}/.well-known/jwks.json",
            config.issuer.trim_end_matches('/')
        )
    }
}

fn select_key<'a>(set: &'a JwkSet, kid: Option<&str>) -> Option<&'a Jwk> {
    match kid {
        Some(kid) => set
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid)),
        // No `kid` in the header: only unambiguous when the set has exactly one key.
        None => {
            if set.keys.len() == 1 {
                set.keys.first()
            } else {
                None
            }
        }
    }
}

/// Resolve the signing `Jwk` for `kid`: serve a fresh cache entry, else fetch the JWKS
/// (over TLS, no redirects), repopulate the cache, and select the key. Never holds the
/// cache mutex across the network await.
async fn resolve_jwk(config: &OidcConfig, now: i64, kid: Option<&str>) -> AppResult<Jwk> {
    let jwks_url = resolve_jwks_url(config);
    let cache_key = |kid: &str| format!("{jwks_url}\n{kid}");

    if let Some(kid) = kid {
        let ck = cache_key(kid);
        let mut guard = jwks_cache().lock().unwrap_or_else(|e| e.into_inner());
        // Clone out first (ending the borrow) so we can evict a stale entry below.
        let hit = match guard.get(&ck) {
            Some((jwk, ts)) if now.saturating_sub(*ts) < JWKS_TTL_SECONDS => Some(jwk.clone()),
            _ => None,
        };
        match hit {
            Some(jwk) => return Ok(jwk),
            None => {
                // Absent or stale → drop it; the refetch below repopulates the cache.
                guard.remove(&ck);
            }
        }
    }

    let set = fetch_jwks(&jwks_url).await?;
    {
        let mut guard = jwks_cache().lock().unwrap_or_else(|e| e.into_inner());
        for k in &set.keys {
            if let Some(id) = &k.common.key_id {
                guard.insert(cache_key(id), (k.clone(), now));
            }
        }
    }
    select_key(&set, kid)
        .cloned()
        .ok_or_else(|| AppError::unauthenticated("invalid id_token"))
}

/// Fetch + parse the JWKS. Any transport/parse failure is logged server-side but
/// surfaced to the caller as the uniform "invalid id_token" (no detail leak).
async fn fetch_jwks(url: &str) -> AppResult<JwkSet> {
    let resp = http_client().get(url).send().await.map_err(|e| {
        tracing::warn!(error = %e, "oidc: JWKS fetch failed");
        AppError::unauthenticated("invalid id_token")
    })?;
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "oidc: JWKS fetch non-success");
        return Err(AppError::unauthenticated("invalid id_token"));
    }
    resp.json::<JwkSet>().await.map_err(|e| {
        tracing::warn!(error = %e, "oidc: JWKS parse failed");
        AppError::unauthenticated("invalid id_token")
    })
}

/// Verify the id_token's signature (against the issuer JWKS) and its `iss`/`aud`/`exp`,
/// then extract the fields the handler needs. ALL failures return an identical
/// `unauthenticated("invalid id_token")` — the specific failed check is never leaked.
async fn verify_id_token(
    config: &OidcConfig,
    now: i64,
    id_token: &str,
) -> AppResult<VerifiedClaims> {
    let header =
        decode_header(id_token).map_err(|_| AppError::unauthenticated("invalid id_token"))?;
    let jwk = resolve_jwk(config, now, header.kid.as_deref()).await?;
    let key =
        DecodingKey::from_jwk(&jwk).map_err(|_| AppError::unauthenticated("invalid id_token"))?;

    // Expected audience: the configured `audience`, or `client_id` when unset.
    let audience: &str = if config.audience.is_empty() {
        &config.client_id
    } else {
        &config.audience
    };

    // Restrict to asymmetric algorithms only. This — combined with a public-key
    // DecodingKey — defeats the classic RS256→HS256 key-confusion attack (an HMAC alg
    // is neither in this allowlist nor constructible from the JWK) and rejects `alg:none`.
    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = vec![
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
        Algorithm::ES256,
        Algorithm::ES384,
        Algorithm::EdDSA,
    ];
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[audience]);

    let data = decode::<serde_json::Value>(id_token, &key, &validation)
        .map_err(|_| AppError::unauthenticated("invalid id_token"))?;
    let claims = data.claims;

    // `iss` is already constrained by `set_issuer`; `sub` is mandatory to provision.
    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::unauthenticated("invalid id_token"))?
        .to_string();
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::unauthenticated("invalid id_token"))?
        .to_string();
    let nonce = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .map(String::from);
    let name = claims
        .get("name")
        .and_then(|v| v.as_str())
        .map(String::from);
    // The groups claim name is operator-configured; read it out of the raw claims.
    let groups = claims
        .get(config.groups_claim.as_str())
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(VerifiedClaims {
        iss,
        sub,
        nonce,
        name,
        groups,
    })
}
