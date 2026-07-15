//! Mocked-JWKS OIDC end-to-end (Phase 5): the correctness proof for
//! `POST /v1/oidc/callback`.
//!
//! A tiny in-test IdP is stood up: a fixed RSA (RS256) test keypair signs id_tokens,
//! and a second local axum server serves the matching JWKS (`{issuer}` JWK by `kid`).
//! `config.oidc.jwks_url` points the server at that endpoint, so the callback verifies
//! the id_token against a public key we control end-to-end. The `nonce` in every signed
//! token is the real key-binding `base64(sha256(ed25519_pub ‖ x25519_pub))` computed
//! from a genuine core registration (`make_identity`).
//!
//! Coverage: valid → account created (external = iss/sub) + group→space membership +
//! working session; wrong nonce → 403; bad signature / expired / wrong aud / wrong iss
//! → 401 (the callback returns a uniform, no-leak "invalid id_token"); idempotent
//! second callback (same iss/sub) reuses the account; and the OIDC reassertion gate
//! (advance the clock past `max_reassertion_age` → `session_refresh` is rejected, a
//! fresh callback mints a new session).
//!
//! Time note: the id_token `exp`/`iat` are validated by `jsonwebtoken` against the REAL
//! wall clock (not the server's TestClock — the handler only feeds TestClock time to the
//! JWKS cache), so token expiries here are computed from `SystemTime::now()`. The
//! reassertion deadline, by contrast, is a TestClock quantity and is driven by
//! `clock.advance`.

mod common;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use unissh_server::config::GroupMap;
use unissh_server::ids;

// ---- fixed test IdP keypair (RS256, 2048-bit). TEST-ONLY, never a real key. --------

/// The mock IdP's signing key (PKCS#8 PEM). Its public half is served as the JWKS JWK
/// below (`RSA_N` / e=AQAB), so tokens it signs verify against the callback's JWKS fetch.
const SIGNING_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC6yl51kqbC8Ban
mCF9aNFOnbvX9nGJyWpe6AZQwoMDsoFkLtj8sZkOyhTL0tiWxcRURgBYtgECz8/H
7ynFYpl/u66L+STfOB88OE0yFHAwdkPjHy0w9onYD33i7XJjcK9yhsjGHCI01IYV
Ko7GXoIxLcC7ZNDAKWC3DAmiaNx0Q3yjMZIKWPUSBp0Uvuy2HbacBDzZoe/9WVZI
bwu5R7mTr70m/DhvNVEteW7SLuoPPyk64XdxR+2vljVdyVZNHnu+d76kshzrjdDT
hTTRB52zaUiyExbsn9g6KfqoNwfTOQcglDbdA68M6SNfYF6spcYIC5vPEFShDs4P
61I6atoZAgMBAAECggEADdzIc1nRofx+9euqqpu9kuPOZcnupa7qw8Xc+B/jaMIV
67k1VdWZWhlhvzmz5MajGi0CyBKj0xFYpoonk7RMV4g2fUFdfOp1mPrFsd6F7/bK
9X9iE3TsiHon2dBM8bfScYGyw08hs8GE/OumYm7voxY17EJgYq5/dL5CNckp+T/L
FRfJzU2c+o2AJh+4PCEMfLA0vBcBrSUcmY9TyRleC0fuio556OQ76th/czqcSnSc
JaHNOwxUFFvR7DSRK918WxU8wlUvSTfTw76eEre7GHREOMEnqIj1ILYLNByyCq1t
UEq2efaqWKCZ7Xcp0KFfj4vxm2hujkpFq3KY0bTloQKBgQD/kC/pVidF2CCyW5LD
cOqErt9/Z57LYKXzrniZBfZMfbqPk022lHMyUk4Dc+ZI8OmXXFgZKuuBQivlHJUK
LX6NfXmCIg2uiYs4Pb3hQv23ON4SLCyem9WWK2dh88n3TlJV5DvXLIU5X1wKOAiM
U83k+jWFxwGOCMsWEYyLnY1NcQKBgQC7HBe7QK3wbmpBU5UEIbJGPm1QR4lwRBNj
7z9J88Yb2aB/szwpObCXGE8M53VoLYmiA+jeA1QCLN1YFS0eiFvSzS375eZ+fnq1
WI7YotpKDZJgCYguJNWXl7f7Ziaod8VBwgjvPXsJCdx+grl7pJZW4U6z3Pl5VEHF
+5fHIuMjKQKBgGElHhFEfok+Lq+dv5wrP/pPvwVfDi2g/3QxzgXdDlLlOBV7mP7e
TyvBvYXyeIchjKnMoHBwsDTiQm1FACJuSLzgBWBCMZE3F4S5c4Q9QtRy+XdO82cX
NYlv1kyVryAi1YlwyI5yjfHRHduEkTtGX+26br37d8vV69znrtUjfqMBAoGAbbc6
Xy29ENfd7HJzVdngbHocpU9dUvxIFnhqtxV/nEMPbvINm+rdFqxFZj6uxKi3JM6A
FPcEosXmAMliDJ5OoZx4k1Wqw4+sqnvEP1m3AGdW5oOQW+ZzbJGla3/puS2J+FYr
4QU/CPzEU1aaJttK4KT6/lLb4n46lzpBNJ7La4kCgYBFf2pxYiD0lJ7kHPzQ76Xl
QTzE/2OsSzFNE0qZz2JALGYl78gOjIIy0hL/HfXzZwLyvfX0uVNN16yNsYeUVIo9
SRnFFzOMFKc62ZtP6PCOFUTz+/XhHMyqABvcpUvIxjvbxu/TLTlfCtUWEiCCRi6C
mrelee9JQA6AVgHSsliffQ==
-----END PRIVATE KEY-----";

/// An UNRELATED RSA key (its public half is NOT in the JWKS). Signing an id_token with
/// this — under the same `kid` — proves the callback truly verifies the signature (not
/// merely the `kid`): the fetched JWK is the real key, so the check fails.
const ATTACKER_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCy0P4bD+aCdLgN
CULMy90G5rM0acs8U+6Fcd3Ciecnqos68WCafwz/Xg1VF93JtS5Q6j5oxp/nI958
hVCG+z6DZLHC9weYxg3l4bXTZ8iIw0+imx73JvVie6ABmf0NNAOhZXrTyi1hl8Iz
JVfGr5ZZBg9+MaPIHXb6HqqdXwLbGjzx65RYTR9nyOQSj8bSXu840/7sXAcIX2jb
DYkJ5TiHXxds6lPNTyfDelgRUA7FGSdnXEXQb92V0FQRI4k1/96Zt++afiwWhrQC
ElSXob9eMNrPTW0JP9WvIcRTNZKAM2h+nH1V9E+39PDNrfXmDg3ZCtVQUBCnPjxM
g7Bbf6Y7AgMBAAECggEACuLcqB1yh/GpfNMErT7MsM1duUH8PKrSxBlXtK68PbbN
GCRhdbZovlPlquRePRfvKb+WV2me4C2tBKwBvYimgyL1DCy0L9xVie+7p+hTFeRn
a5EBtG6Q6ih4PXC4WP6YKVIUxWJdxem9HxZVvtj/ZbcP6BEHQA5vKQYHQWJrOZcd
XfVMblkXF+6JblEDFBzJAb8tXFQFxc1aDxQRvGmWq47JPstsv7/tDg4ERt8OqThD
S3u6gpcJqjqpspfuwVvGQXzSUuSL8dkGNNDfZHFEoCf36umrpCCLXUGq8IBGCAkL
uA5rLyVyktvw+yk+i9MB/X/Rn1xJQ/1MQjdm1XyQpQKBgQDoDIvhszkV7d6gzU//
hFAMtV2WnN3TAF6aP57DOEV69i/iz3KdeuV4DJcKbetvzLUpQ1I800/EiDKMzour
EMUkaMsDsok2+IVO6PiN0g2bFIUhtjk6aKBd8YASgjv0QE5pgz1yQMVJRZFLHFL3
gqfD32d1I7ZH2KytiUwNOEB+TQKBgQDFReAKswLQH6wLSXSaKH/Y0qY78P+7OTKT
Dr82izoZ0wIBLCqFbd0INQyf2VqpteP0UZfuo9xbfNUqnyEiCxo4q/w8i5o4TX+y
S+bva5chtGkmLBDFs8OBrWrt9VeEzL+464OfSNvNYB+JpZ7asBTo9co6s8Fi5fOz
WGWbXBdKpwKBgQCAH/1Uf7rzasXUD8kuEoaIndOxB6hLixaxIJOuwvFKNYi3OUfV
wDfXk0wKjCrFLkiRIgTUZPDUWUdgC+N+buILenkt73RoD8y7h1NGK0cr66aeuJjc
sUxq0p+emJ41/RPOmpJg9XZ5QJo62MbOtyuesUnUmgVZoj+mCfseCYNCuQKBgQCg
ZKi9akC+QRIb9zRj5svT2ampENCMQ/wXzySuz1KFDqgRlfxYkjPlaWSDTzDEzYuy
6OhT8kzG4d9bkRhaWpaOP1+NRqA0aOaLa+UvAtZVZB8eFzPn2rn55KsNIK5w3hx/
2JUi3BVCjYX2338iJYpKwxUS13ZD191mE1hBkgWp/wKBgB+0NbhY2yBcMl9rEKAQ
e1em+Npsg2xgDcOzyNnhJ3Cd6LSquwy+U2Owqm4jp0xnl0XxLZOsS0EA4o6RYTPw
6iqWWvujxsgNPH3xK1Eq0dNEjTkVCX3V5s3yq71SeMVmnKxFHVLGX9mIlrIjTYqf
fh3k1TCALTNIqyibSH5E7e5A
-----END PRIVATE KEY-----";

/// base64url modulus of `SIGNING_PEM`'s public key (e = AQAB), served in the JWKS.
const RSA_N: &str = "uspedZKmwvAWp5ghfWjRTp271_ZxiclqXugGUMKDA7KBZC7Y_LGZDsoUy9LYlsXEVEYAWLYBAs_Px-8pxWKZf7uui_kk3zgfPDhNMhRwMHZD4x8tMPaJ2A994u1yY3CvcobIxhwiNNSGFSqOxl6CMS3Au2TQwClgtwwJomjcdEN8ozGSClj1EgadFL7sth22nAQ82aHv_VlWSG8LuUe5k6-9Jvw4bzVRLXlu0i7qDz8pOuF3cUftr5Y1XclWTR57vne-pLIc643Q04U00Qeds2lIshMW7J_YOin6qDcH0zkHIJQ23QOvDOkjX2BerKXGCAubzxBUoQ7OD-tSOmraGQ";

const KID: &str = "test-key-1";
const ISSUER: &str = "https://mock-idp.test";
const CLIENT_ID: &str = "unissh";
/// A deterministic space id the group→space mapping targets. The config's `group_map`
/// is set pre-boot, so the space is materialized in the store (with this id) post-boot.
const FIXED_SPACE_ID: [u8; 16] = [0x5a; 16];

// ---- mock IdP + config plumbing -----------------------------------------------------

/// Real wall-clock unix seconds — the reference `jsonwebtoken` validates `exp`/`iat`
/// against (the server's TestClock does not drive token expiry).
fn real_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Stand up a second local axum server serving the JWKS (one RSA JWK, `kid` = KID) for
/// `SIGNING_PEM`. Returns the absolute `jwks_url` to hand to `config.oidc.jwks_url`.
async fn spawn_jwks() -> String {
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": RSA_N,
            "e": "AQAB",
        }]
    });
    let app = axum::Router::new().route(
        "/jwks.json",
        axum::routing::get(move || {
            let j = jwks.clone();
            async move { axum::Json(j) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/jwks.json")
}

/// The key-binding nonce for an identity: `base64(sha256(ed25519_pub ‖ x25519_pub))`,
/// exactly what the callback recomputes from the presented registration.
fn nonce_for(id: &common::Identity) -> String {
    let mut bind = Vec::with_capacity(64);
    bind.extend_from_slice(&id.ed);
    bind.extend_from_slice(&id.x);
    ids::b64(&ids::sha256(&bind))
}

/// Sign an id_token with `pem` under `kid = KID`, `alg = RS256`, over `claims`.
fn sign_token(pem: &str, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("load RSA signing PEM");
    encode(&header, claims, &key).expect("sign id_token")
}

/// A well-formed claim set: valid `exp` (real-now + 1h), the given `nonce`, groups
/// `["eng"]`, `aud = CLIENT_ID`, `iss = ISSUER`, and a UNIQUE `jti`. Individual tests
/// override fields.
///
/// The unique `jti` matters because RS256 (PKCS#1 v1.5) is deterministic, so two tokens
/// with identical claims are byte-identical — and the callback's one-time / replay guard
/// keys on `jti` (or a hash of the token). A distinct `jti` per token keeps the normal
/// two-callback flows (reuse-account, reassertion) from tripping the replay guard; the
/// dedicated replay test posts the SAME token twice on purpose.
fn base_claims(nonce: &str) -> serde_json::Value {
    let now = real_now();
    serde_json::json!({
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-123",
        "exp": now + 3600,
        "iat": now,
        "name": "Alice Example",
        "nonce": nonce,
        "groups": ["eng"],
        "jti": ids::b64(&ids::random_bytes32()),
    })
}

/// Boot a server wired for OIDC against a fresh mock JWKS, and materialize the
/// group→space target space (`FIXED_SPACE_ID`) so the membership FK resolves.
async fn boot() -> common::TestApp {
    let jwks_url = spawn_jwks().await;
    let space_b64 = ids::b64(&FIXED_SPACE_ID);
    let app = common::spawn_with(move |c| {
        c.oidc.enabled = true;
        c.oidc.issuer = ISSUER.into();
        c.oidc.client_id = CLIENT_ID.into();
        c.oidc.audience = String::new(); // → falls back to client_id
        c.oidc.jwks_url = jwks_url;
        c.oidc.groups_claim = "groups".into();
        c.oidc.group_map = vec![GroupMap {
            group: "eng".into(),
            space_id: space_b64,
            role: "member".into(),
        }];
        c.oidc.max_reassertion_age_seconds = 604_800;
    })
    .await;

    let now = app.now();
    let mut tx = app.state.store.begin().await.unwrap();
    app.state
        .store
        .create_space(&mut tx, &FIXED_SPACE_ID, "Backend", None, now)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    app
}

/// POST an id_token + a registration to the callback; return the raw response.
async fn post_callback(
    app: &common::TestApp,
    id_token: &str,
    id: &common::Identity,
) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/oidc/callback", app.base))
        .json(&serde_json::json!({
            "id_token": id_token,
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
        }))
        .send()
        .await
        .unwrap()
}

// ---- (a) valid: account created, group→space, session works ------------------------

#[tokio::test]
async fn valid_callback_creates_account_maps_group_and_mints_session() {
    let app = boot().await;
    let id = common::make_identity();
    let token = sign_token(SIGNING_PEM, &base_claims(&nonce_for(&id)));

    let resp = post_callback(&app, &token, &id).await;
    assert_eq!(resp.status(), 201, "a fresh SSO identity is created (201)");
    let body: serde_json::Value = resp.json().await.unwrap();

    // group "eng" → the FIXED_SPACE_ID membership is reported.
    let space_b64 = ids::b64(&FIXED_SPACE_ID);
    let spaces = body["spaces"].as_array().unwrap();
    assert!(
        spaces
            .iter()
            .any(|s| s.as_str() == Some(space_b64.as_str())),
        "callback provisioned the group→space membership: {body}"
    );

    // The account is bound to the external (iss, sub) identity.
    let account_id = ids::unb64(body["account_id"].as_str().unwrap()).unwrap();
    let acct = app
        .state
        .store
        .get_account_by_external(ISSUER, "user-123")
        .await
        .unwrap()
        .expect("account resolvable by (iss, sub)");
    assert_eq!(acct.account_id, account_id);
    assert_eq!(acct.external_issuer.as_deref(), Some(ISSUER));
    assert_eq!(acct.external_subject.as_deref(), Some("user-123"));

    // The minted session actually authenticates: GET /v1/spaces lists the mapped space.
    let access = body["access_token"].as_str().unwrap();
    let spaces_resp = app
        .client
        .get(format!("{}/v1/spaces", app.base))
        .bearer_auth(access)
        .send()
        .await
        .unwrap();
    assert_eq!(spaces_resp.status(), 200, "oidc session authenticates");
    let listed: serde_json::Value = spaces_resp.json().await.unwrap();
    let member_of = listed["spaces"].as_array().unwrap();
    assert!(
        member_of
            .iter()
            .any(|s| s["space_id"].as_str() == Some(space_b64.as_str())
                && s["role"].as_str() == Some("member")),
        "session sees the group→space membership as a member: {listed}"
    );
}

// ---- (b) wrong nonce → 403 (the key-binding is enforced) ---------------------------

#[tokio::test]
async fn wrong_nonce_is_rejected() {
    let app = boot().await;
    let id = common::make_identity();
    // A token whose nonce does NOT match this registration's keyset binding.
    let bogus = ids::b64(&ids::sha256(b"not-the-binding"));
    let token = sign_token(SIGNING_PEM, &base_claims(&bogus));

    let resp = post_callback(&app, &token, &id).await;
    assert_eq!(
        resp.status(),
        403,
        "nonce key-binding mismatch is forbidden"
    );
    // No account leaked in on the rejected path.
    assert!(
        app.state
            .store
            .get_account_by_external(ISSUER, "user-123")
            .await
            .unwrap()
            .is_none()
    );
}

// ---- (c) bad signature (attacker key, same kid) → 401 ------------------------------

#[tokio::test]
async fn bad_signature_is_rejected() {
    let app = boot().await;
    let id = common::make_identity();
    // Correct claims, correct kid — but signed by a key that is NOT in the JWKS.
    let token = sign_token(ATTACKER_PEM, &base_claims(&nonce_for(&id)));

    let resp = post_callback(&app, &token, &id).await;
    assert_eq!(
        resp.status(),
        401,
        "an id_token not signed by the JWKS key is unauthenticated"
    );
}

// ---- (d) expired id_token → 401 ----------------------------------------------------

#[tokio::test]
async fn expired_token_is_rejected() {
    let app = boot().await;
    let id = common::make_identity();
    let now = real_now();
    let mut claims = base_claims(&nonce_for(&id));
    claims["iat"] = serde_json::json!(now - 7200);
    claims["exp"] = serde_json::json!(now - 3600); // an hour in the past
    let token = sign_token(SIGNING_PEM, &claims);

    let resp = post_callback(&app, &token, &id).await;
    assert_eq!(resp.status(), 401, "an expired id_token is unauthenticated");
}

// ---- (e) wrong audience → 401 ------------------------------------------------------

#[tokio::test]
async fn wrong_audience_is_rejected() {
    let app = boot().await;
    let id = common::make_identity();
    let mut claims = base_claims(&nonce_for(&id));
    claims["aud"] = serde_json::json!("some-other-client");
    let token = sign_token(SIGNING_PEM, &claims);

    let resp = post_callback(&app, &token, &id).await;
    assert_eq!(
        resp.status(),
        401,
        "a wrong-aud id_token is unauthenticated"
    );
}

// ---- wrong issuer → 401 (extra; iss is pinned) -------------------------------------

#[tokio::test]
async fn wrong_issuer_is_rejected() {
    let app = boot().await;
    let id = common::make_identity();
    let mut claims = base_claims(&nonce_for(&id));
    claims["iss"] = serde_json::json!("https://evil-idp.test");
    let token = sign_token(SIGNING_PEM, &claims);

    let resp = post_callback(&app, &token, &id).await;
    assert_eq!(
        resp.status(),
        401,
        "a wrong-iss id_token is unauthenticated"
    );
}

// ---- (f) second callback (same iss/sub) reuses the account -------------------------

#[tokio::test]
async fn second_callback_reuses_account() {
    let app = boot().await;
    let id = common::make_identity();

    let r1 = post_callback(
        &app,
        &sign_token(SIGNING_PEM, &base_claims(&nonce_for(&id))),
        &id,
    )
    .await;
    assert_eq!(r1.status(), 201, "first callback creates the account");
    let b1: serde_json::Value = r1.json().await.unwrap();
    let account_1 = b1["account_id"].as_str().unwrap().to_string();
    let device_1 = b1["device_id"].as_str().unwrap().to_string();

    // Same (iss, sub), a freshly signed token (new nonce is still this identity's).
    let r2 = post_callback(
        &app,
        &sign_token(SIGNING_PEM, &base_claims(&nonce_for(&id))),
        &id,
    )
    .await;
    assert_eq!(
        r2.status(),
        200,
        "a returning SSO identity reuses the account (200)"
    );
    let b2: serde_json::Value = r2.json().await.unwrap();
    assert_eq!(
        b2["account_id"].as_str().unwrap(),
        account_1,
        "same (iss, sub) resolves to the same account_id"
    );
    // A fresh device is minted each login (mirrors the join reattach path).
    assert_ne!(
        b2["device_id"].as_str().unwrap(),
        device_1,
        "each login mints a new device"
    );

    // Exactly one account carries this external identity (no duplicate).
    let acct = app
        .state
        .store
        .get_account_by_external(ISSUER, "user-123")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ids::b64(&acct.account_id), account_1);
}

// ---- (g) reassertion gate ----------------------------------------------------------

#[tokio::test]
async fn reassertion_gate_blocks_stale_refresh_then_fresh_callback_works() {
    let app = boot().await;
    let id = common::make_identity();

    let r1 = post_callback(
        &app,
        &sign_token(SIGNING_PEM, &base_claims(&nonce_for(&id))),
        &id,
    )
    .await;
    assert_eq!(r1.status(), 201);
    let b1: serde_json::Value = r1.json().await.unwrap();
    let refresh = b1["refresh_token"].as_str().unwrap().to_string();

    // Within the reassertion window, refresh rotates fine.
    let ok = app
        .client
        .post(format!("{}/v1/session/refresh", app.base))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200, "oidc session refreshes inside its window");
    let rotated = ok.json::<serde_json::Value>().await.unwrap();
    let refresh2 = rotated["refresh_token"].as_str().unwrap().to_string();

    // Advance past max_reassertion_age (TestClock) → the OIDC reassertion gate trips.
    app.clock.advance(604_800 + 10);
    let stale = app
        .client
        .post(format!("{}/v1/session/refresh", app.base))
        .json(&serde_json::json!({ "refresh_token": refresh2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        stale.status(),
        401,
        "past the reassertion deadline, refresh is rejected"
    );

    // A fresh OIDC callback re-authenticates and mints a new, working session.
    let r2 = post_callback(
        &app,
        &sign_token(SIGNING_PEM, &base_claims(&nonce_for(&id))),
        &id,
    )
    .await;
    assert_eq!(
        r2.status(),
        200,
        "re-running the OIDC dance mints a fresh session"
    );
    let b2 = r2.json::<serde_json::Value>().await.unwrap();
    let access2 = b2["access_token"].as_str().unwrap();
    let who = app
        .client
        .get(format!("{}/v1/spaces", app.base))
        .bearer_auth(access2)
        .send()
        .await
        .unwrap();
    assert_eq!(who.status(), 200, "the re-minted session authenticates");
}

// ---- (h) group→space de-provisioning + manual survival + role update ---------------

/// Boot with a THREE-entry group_map over two spaces (A mapped at both `member` and
/// `admin` via distinct groups, B at `member`) and materialize spaces A/B/C so a manual
/// membership can be seeded in C.
async fn boot_reconcile() -> (common::TestApp, [u8; 16], [u8; 16], [u8; 16]) {
    let jwks_url = spawn_jwks().await;
    let space_a = [0xa1u8; 16];
    let space_b = [0xb2u8; 16];
    let space_c = [0xc3u8; 16];
    let (a_b64, b_b64) = (ids::b64(&space_a), ids::b64(&space_b));
    let app = common::spawn_with(move |cfg| {
        cfg.oidc.enabled = true;
        cfg.oidc.issuer = ISSUER.into();
        cfg.oidc.client_id = CLIENT_ID.into();
        cfg.oidc.audience = String::new();
        cfg.oidc.jwks_url = jwks_url;
        cfg.oidc.groups_claim = "groups".into();
        cfg.oidc.group_map = vec![
            GroupMap {
                group: "a".into(),
                space_id: a_b64.clone(),
                role: "member".into(),
            },
            GroupMap {
                group: "a-admin".into(),
                space_id: a_b64,
                role: "admin".into(),
            },
            GroupMap {
                group: "b".into(),
                space_id: b_b64,
                role: "member".into(),
            },
        ];
        cfg.oidc.max_reassertion_age_seconds = 604_800;
    })
    .await;

    let now = app.now();
    let mut tx = app.state.store.begin().await.unwrap();
    for (id, name) in [(&space_a, "A"), (&space_b, "B"), (&space_c, "C")] {
        app.state
            .store
            .create_space(&mut tx, id, name, None, now)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    (app, space_a, space_b, space_c)
}

#[tokio::test]
async fn oidc_deprovisions_dropped_groups_updates_role_and_keeps_manual() {
    let (app, space_a, space_b, space_c) = boot_reconcile().await;
    let id = common::make_identity();

    // 1. Token groups {a, b} → oidc member of A and B.
    let mut claims = base_claims(&nonce_for(&id));
    claims["groups"] = serde_json::json!(["a", "b"]);
    let r1 = post_callback(&app, &sign_token(SIGNING_PEM, &claims), &id).await;
    assert_eq!(r1.status(), 201, "first callback creates the SSO account");
    let b1: serde_json::Value = r1.json().await.unwrap();
    let account_id = ids::unb64(b1["account_id"].as_str().unwrap()).unwrap();

    async fn role(app: &common::TestApp, space: &[u8], account_id: &[u8]) -> Option<String> {
        app.state
            .store
            .space_member_role(space, account_id)
            .await
            .unwrap()
    }
    assert_eq!(
        role(&app, &space_a, &account_id).await.as_deref(),
        Some("member"),
        "member of A"
    );
    assert_eq!(
        role(&app, &space_b, &account_id).await.as_deref(),
        Some("member"),
        "member of B"
    );

    // 2. A pre-existing MANUAL membership in C (invite / direct-add) must survive both
    //    callbacks — the oidc reconciler only ever touches source='oidc' rows.
    let now = app.now();
    let mut tx = app.state.store.begin().await.unwrap();
    app.state
        .store
        .space_member_add(&mut tx, &space_c, &account_id, "member", None, now)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // 3. Re-callback with groups {a-admin} only → B dropped, A kept + role bumped to
    //    admin, C (manual) untouched.
    let mut claims2 = base_claims(&nonce_for(&id));
    claims2["groups"] = serde_json::json!(["a-admin"]);
    let r2 = post_callback(&app, &sign_token(SIGNING_PEM, &claims2), &id).await;
    assert_eq!(r2.status(), 200, "returning identity reuses the account");

    assert_eq!(
        role(&app, &space_a, &account_id).await.as_deref(),
        Some("admin"),
        "A kept, its oidc role updated member→admin on reassertion"
    );
    assert!(
        role(&app, &space_b, &account_id).await.is_none(),
        "B (oidc) de-provisioned once its group was dropped from the token"
    );
    assert_eq!(
        role(&app, &space_c, &account_id).await.as_deref(),
        Some("member"),
        "the manual membership in C survives both callbacks"
    );
}

// ---- (i) id_token replay guard -----------------------------------------------------

#[tokio::test]
async fn replayed_id_token_is_rejected() {
    let app = boot().await;
    let id = common::make_identity();
    let token = sign_token(SIGNING_PEM, &base_claims(&nonce_for(&id)));

    let r1 = post_callback(&app, &token, &id).await;
    assert_eq!(
        r1.status(),
        201,
        "first use of the id_token creates the account"
    );

    // The SAME token replayed (a captured callback body) → 401: the id_token is
    // one-time, so a stolen-then-replayed body cannot re-authenticate.
    let r2 = post_callback(&app, &token, &id).await;
    assert_eq!(r2.status(), 401, "a replayed id_token is rejected");
}

// ---- oidc disabled → the surface does not exist (404) ------------------------------

#[tokio::test]
async fn callback_is_absent_when_oidc_disabled() {
    // Default config has oidc.enabled = false.
    let app = common::spawn().await;
    let id = common::make_identity();
    let token = sign_token(SIGNING_PEM, &base_claims(&nonce_for(&id)));
    let resp = post_callback(&app, &token, &id).await;
    assert_eq!(
        resp.status(),
        404,
        "with OIDC disabled the callback surface is not found"
    );
}
