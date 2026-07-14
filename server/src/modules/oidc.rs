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
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet};
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

    // 5a. id_token one-time / replay guard. The nonce is deterministic (a key-binding,
    //     not a freshness token) and nothing else consumes the id_token, so a captured
    //     full callback body is otherwise replayable until `exp`. Key on the `jti`
    //     claim, or a hash of the token when absent, and reject a second use (401).
    //     Inside the tx: a login that later fails/rolls back does NOT burn the token.
    let jti_key = match claims.jti.as_deref() {
        Some(j) if !j.is_empty() => j.to_string(),
        _ => format!("h:{}", ids::b64(&ids::sha256(req.id_token.as_bytes()))),
    };
    state.store.oidc_prune_expired_jti(&mut tx, now).await?;
    if !state.store.oidc_consume_jti(&mut tx, &jti_key, claims.exp).await? {
        return Err(AppError::unauthenticated("id_token already used"));
    }

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

    // 6. Group → space mapping, RECONCILED against the token (not merely additive).
    //    Compute the DESIRED {(space_id, role)} set from this token's groups, then:
    //      * upsert each as `source='oidc'` (updating the role if the IdP changed it),
    //      * DELETE the account's `source='oidc'` memberships NOT in the desired set,
    //    so a user dropped from an IdP group loses that space on reassertion. Manual
    //    (`source='manual'`) memberships — invite / direct-add — are NEVER touched.
    //    Each `group_map[].space_id` / `role` was validated at config load, so the
    //    per-login path can't be broken by one bad entry (the `unb64` is defensive).
    let mut desired: Vec<(Vec<u8>, String)> = Vec::new();
    let mut spaces: Vec<String> = Vec::new();
    for gm in &config.group_map {
        if !claims.groups.iter().any(|g| g == &gm.group) {
            continue;
        }
        let space_id = ids::unb64(&gm.space_id)?;
        // First mapping for a space wins its role (matches the prior insert-first-wins).
        if !desired.iter().any(|(s, _)| *s == space_id) {
            desired.push((space_id, gm.role.clone()));
        }
        if !spaces.contains(&gm.space_id) {
            spaces.push(gm.space_id.clone());
        }
    }
    for (space_id, role) in &desired {
        state
            .store
            .space_member_upsert_oidc(&mut tx, space_id, &account_id, role, now)
            .await?;
    }
    // De-provision: any prior oidc membership no longer mapped by this token is removed.
    for existing in state
        .store
        .list_oidc_member_spaces(&mut tx, &account_id)
        .await?
    {
        if !desired.iter().any(|(s, _)| *s == existing) {
            state
                .store
                .delete_oidc_member(&mut tx, &existing, &account_id)
                .await?;
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
    /// The token's expiry (validated present + in-future by `decode`). Bounds how long
    /// the replay-guard row must be kept.
    exp: i64,
    /// The token's `jti` (one-time id) claim, if present. Keys the replay guard; a
    /// token without a `jti` is keyed on a hash of the token instead.
    jti: Option<String>,
}

/// TTL of a POSITIVE cached JWK (bounds staleness when an IdP rotates a key *under the
/// same kid*; a rotation to a NEW kid is picked up on the next cache-miss refetch).
const JWKS_TTL_SECONDS: i64 = 3600;

/// TTL of a NEGATIVE cache entry (an unresolved kid, or a kid-less token against a
/// multi-key set). Short, so a genuinely new key is picked up within a minute, but
/// non-zero so a token with an absent/unknown `kid` does NOT trigger a JWKS refetch on
/// EVERY request (pre-verify outbound-fetch amplification). Without this, a stream of
/// kid-less or bogus-kid tokens would refetch the JWKS unboundedly before any signature
/// check even runs.
const JWKS_NEG_TTL_SECONDS: i64 = 60;

/// Cache-key suffix for a KID-LESS token (its header carried no `kid`). Resolution for
/// such a token is "the sole key iff the set has exactly one"; caching it under this
/// fixed sentinel means a kid-less login is served from cache like any kid'd one,
/// instead of refetching the JWKS every time. `\n` matches the `{url}\n{kid}` scheme
/// and the sentinel body can't collide with a real base64url/opaque kid.
const NOKID_SENTINEL: &str = "\u{0}__nokid__";

/// A cached JWKS resolution for one (jwks_url, kid|sentinel) key: either the selected
/// key, or a short-lived NEGATIVE result (no such key). Boxed `Jwk` keeps the enum
/// small (avoids `clippy::large_enum_variant`).
enum Resolution {
    Found(Box<Jwk>),
    Unresolved,
}

/// Cache-miss refetch keyed by `"{jwks_url}\n{kid|sentinel}"`. Storing the parsed `Jwk`
/// (not a `DecodingKey`) keeps the entry cheaply cloneable and rebuilds the key per
/// request. Keying by the full jwks_url isolates distinct issuers/mock-servers, and by
/// the kid (or the kid-less sentinel) lets BOTH positive and negative resolutions be
/// cached so no path refetches the JWKS on every request.
fn jwks_cache() -> &'static Mutex<HashMap<String, (Resolution, i64)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Resolution, i64)>>> = OnceLock::new();
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

/// The verify-time algorithm allowlist for `jwk`, pinned to the key's own family.
///
/// `jsonwebtoken`'s `decode` requires every algorithm in `Validation::algorithms` to
/// share the key's family (`decoding.rs`: `key.family != alg.family()` → `InvalidAlgorithm`),
/// so this is derived per key, never a fixed cross-family list. Only asymmetric families
/// are allowed; a symmetric (`OctetKey` / HMAC) JWK is refused — an id_token must be
/// verified against the IdP's *public* key, and permitting HMAC here would reopen the
/// RS256→HS256 key-confusion hole.
fn key_algorithms(jwk: &Jwk) -> AppResult<Vec<Algorithm>> {
    match &jwk.algorithm {
        // RSA: PKCS#1 v1.5 (RS*) and PSS (PS*) — all one family.
        AlgorithmParameters::RSA(_) => Ok(vec![
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ]),
        // EC (ECDSA): pin to the curve's algorithm. `jsonwebtoken` has no ES512, so a
        // P-521 JWK cannot be verified and is refused rather than silently mis-mapped.
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => Ok(vec![Algorithm::ES256]),
            EllipticCurve::P384 => Ok(vec![Algorithm::ES384]),
            // `jsonwebtoken` has no ES512, and Ed25519 is not an ECDSA curve, so neither
            // is verifiable via an `EC`-typed JWK; refuse rather than silently mis-map.
            EllipticCurve::P521 | EllipticCurve::Ed25519 => {
                Err(AppError::unauthenticated("invalid id_token"))
            }
        },
        // OKP (Ed25519/Ed448) → EdDSA.
        AlgorithmParameters::OctetKeyPair(_) => Ok(vec![Algorithm::EdDSA]),
        // Symmetric key: never valid for JWKS-backed id_token verification.
        AlgorithmParameters::OctetKey(_) => Err(AppError::unauthenticated("invalid id_token")),
    }
}

/// Resolve the signing `Jwk` for `kid` (or the sole key when the token carried no
/// `kid`): serve a fresh cache entry — POSITIVE *or* NEGATIVE — else fetch the JWKS
/// (over TLS, no redirects) exactly once, repopulate the cache, select the key, and
/// cache the resolution. Both the kid-less path and an unknown kid are cached, so
/// neither refetches the JWKS on every request. Never holds the cache mutex across the
/// network await.
async fn resolve_jwk(config: &OidcConfig, now: i64, kid: Option<&str>) -> AppResult<Jwk> {
    let jwks_url = resolve_jwks_url(config);
    // The concrete kid, or a fixed sentinel for a kid-less token — so the kid-less
    // resolution is cached under a stable key instead of refetching each time.
    let ck = match kid {
        Some(k) => format!("{jwks_url}\n{k}"),
        None => format!("{jwks_url}\n{NOKID_SENTINEL}"),
    };

    // 1. Serve a fresh cache entry (positive or negative) with NO network I/O.
    {
        let guard = jwks_cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some((entry, ts)) = guard.get(&ck) {
            let ttl = match entry {
                Resolution::Found(_) => JWKS_TTL_SECONDS,
                Resolution::Unresolved => JWKS_NEG_TTL_SECONDS,
            };
            if now.saturating_sub(*ts) < ttl {
                return match entry {
                    Resolution::Found(jwk) => Ok((**jwk).clone()),
                    Resolution::Unresolved => Err(AppError::unauthenticated("invalid id_token")),
                };
            }
        }
    }

    // 2. Cache miss/stale → fetch the JWKS once, then repopulate + cache this request's
    //    resolution (positive or negative) so a repeat is served from cache.
    let set = fetch_jwks(&jwks_url).await?;
    let selected = select_key(&set, kid).cloned();
    {
        let mut guard = jwks_cache().lock().unwrap_or_else(|e| e.into_inner());
        // Refresh every kid'd key present in the fetched set.
        for k in &set.keys {
            if let Some(id) = &k.common.key_id {
                guard.insert(
                    format!("{jwks_url}\n{id}"),
                    (Resolution::Found(Box::new(k.clone())), now),
                );
            }
        }
        // Cache THIS request's resolution under its (kid or sentinel) key. A negative
        // result is remembered under a short TTL so a repeat doesn't refetch.
        let entry = match &selected {
            Some(jwk) => Resolution::Found(Box::new(jwk.clone())),
            None => Resolution::Unresolved,
        };
        guard.insert(ck, (entry, now));
    }
    selected.ok_or_else(|| AppError::unauthenticated("invalid id_token"))
}

/// Hard cap on the JWKS response body. A real JWKS is a few keys (single-digit KiB);
/// 1 MiB is comfortably above any legitimate document while bounding a compromised-
/// but-config-trusted IdP that returns an enormous body. The request timeout is a TIME
/// bound, NOT a size bound — `resp.json()`/`resp.bytes()` would buffer the whole body.
const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// Fetch + parse the JWKS. Any transport/parse failure is logged server-side but
/// surfaced to the caller as the uniform "invalid id_token" (no detail leak). The body
/// is read with a MAX-byte limit before deserializing (DoS via an oversized body).
async fn fetch_jwks(url: &str) -> AppResult<JwkSet> {
    let mut resp = http_client().get(url).send().await.map_err(|e| {
        tracing::warn!(error = %e, "oidc: JWKS fetch failed");
        AppError::unauthenticated("invalid id_token")
    })?;
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "oidc: JWKS fetch non-success");
        return Err(AppError::unauthenticated("invalid id_token"));
    }
    // Fast reject on an advertised oversized length, then enforce the cap while reading
    // (a missing/lying Content-Length can't bypass the streamed byte-count check).
    if resp.content_length().is_some_and(|len| len > MAX_JWKS_BYTES as u64) {
        tracing::warn!("oidc: JWKS Content-Length exceeds cap");
        return Err(AppError::unauthenticated("invalid id_token"));
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(bytes) = resp.chunk().await.map_err(|e| {
        tracing::warn!(error = %e, "oidc: JWKS body read failed");
        AppError::unauthenticated("invalid id_token")
    })? {
        if body.len() + bytes.len() > MAX_JWKS_BYTES {
            tracing::warn!("oidc: JWKS body exceeds cap");
            return Err(AppError::unauthenticated("invalid id_token"));
        }
        body.extend_from_slice(&bytes);
    }
    serde_json::from_slice::<JwkSet>(&body).map_err(|e| {
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

    // Restrict to the asymmetric algorithms of the *resolved key's own family*. This —
    // combined with a public-key DecodingKey — defeats the classic RS256→HS256
    // key-confusion attack (an HMAC alg is neither derivable here nor constructible from
    // an asymmetric JWK) and rejects `alg:none`. It must be a single-family set:
    // `jsonwebtoken` rejects the whole verify with `InvalidAlgorithm` if *any* allowed
    // algorithm's family differs from the key's (decoding.rs: `key.family != alg.family()`),
    // so a cross-family list (RSA+EC+EdDSA) would reject *every* token. A symmetric JWK is
    // never valid for id_token verification and is refused outright.
    let algorithms = key_algorithms(&jwk)?;
    let mut validation = Validation::new(algorithms[0]);
    validation.algorithms = algorithms;
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
    // `exp` is required + validated in-future by `decode`; read it back to bound the
    // replay-guard row. `jti` is optional (keys the replay guard when present).
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
        .ok_or_else(|| AppError::unauthenticated("invalid id_token"))?;
    let jti = claims
        .get("jti")
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
        exp,
        jti,
    })
}
