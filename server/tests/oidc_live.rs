//! LIVE integration: the REAL packaged `unissh-server` binary (a separate process) doing
//! the full OIDC callback over real HTTP against a mock IdP JWKS.
//!
//! Unlike `oidc_http.rs` (which drives an in-process app), this spawns the shipped binary,
//! so it also exercises TOML `[oidc]` config loading, migrations, the real HTTP stack, and
//! a genuine outbound JWKS fetch from the server process to the mock IdP process. Run with:
//!   cargo build -p unissh-server && \
//!   cargo test -p unissh-server --test oidc_live -- --ignored --nocapture

mod common;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use unissh_server::ids;

// Reuse the same TEST-ONLY mock IdP keypair as `oidc_http.rs` (never a real key). The
// public half is served as the JWKS below, so tokens signed with SIGNING_PEM verify.
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

// An UNRELATED RSA key (its public half is NOT in the JWKS): signing under the same `kid`
// proves the callback truly verifies the SIGNATURE, not merely the kid.
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

const RSA_N: &str = "uspedZKmwvAWp5ghfWjRTp271_ZxiclqXugGUMKDA7KBZC7Y_LGZDsoUy9LYlsXEVEYAWLYBAs_Px-8pxWKZf7uui_kk3zgfPDhNMhRwMHZD4x8tMPaJ2A994u1yY3CvcobIxhwiNNSGFSqOxl6CMS3Au2TQwClgtwwJomjcdEN8ozGSClj1EgadFL7sth22nAQ82aHv_VlWSG8LuUe5k6-9Jvw4bzVRLXlu0i7qDz8pOuF3cUftr5Y1XclWTR57vne-pLIc643Q04U00Qeds2lIshMW7J_YOin6qDcH0zkHIJQ23QOvDOkjX2BerKXGCAubzxBUoQ7OD-tSOmraGQ";
const KID: &str = "test-key-1";
const ISSUER: &str = "https://mock-idp.test";
const CLIENT_ID: &str = "unissh";
const SETUP_CODE: &str = "live-oidc-setup";

fn real_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A second local HTTP server serving the JWKS (one RSA JWK, `kid = KID`) that the REAL
/// server binary fetches over the network to verify id_token signatures.
async fn spawn_jwks() -> String {
    let jwks = serde_json::json!({
        "keys": [{ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": RSA_N, "e": "AQAB" }]
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

/// `base64(sha256(ed25519_pub ‖ x25519_pub))` — the key-binding nonce the callback recomputes.
fn nonce_for(id: &common::Identity) -> String {
    let mut bind = Vec::with_capacity(64);
    bind.extend_from_slice(&id.ed);
    bind.extend_from_slice(&id.x);
    ids::b64(&ids::sha256(&bind))
}

fn sign_token(pem: &str, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    encode(&header, claims, &key).unwrap()
}

fn base_claims(nonce: &str) -> serde_json::Value {
    let now = real_now();
    serde_json::json!({
        "iss": ISSUER, "aud": CLIENT_ID, "sub": "user-123", "exp": now + 3600, "iat": now,
        "name": "Alice Example", "nonce": nonce, "groups": ["eng"],
        "jti": ids::b64(&ids::random_bytes32()),
    })
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn server_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/debug/unissh-server")
}

struct ServerProc {
    child: Child,
    base: String,
    _dir: tempfile::TempDir,
}
impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the real binary with an `[oidc]` config pointing at `jwks_url`; wait for `/readyz`.
async fn spawn_server(jwks_url: &str) -> Option<ServerProc> {
    let bin = server_binary();
    if !bin.exists() {
        eprintln!(
            "SKIP: server binary not found at {} — run `cargo build -p unissh-server` first",
            bin.display()
        );
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let mport = free_port();
    let db = dir.path().join("unissh.db");
    let cfg = format!(
        "[server]\n\
         bind = \"127.0.0.1:{port}\"\n\
         tls_cert = \"\"\n\
         tls_key = \"\"\n\
         trust_proxy = true\n\n\
         [db]\n\
         backend = \"sqlite\"\n\
         url = \"{db}\"\n\n\
         [setup]\n\
         code = \"{SETUP_CODE}\"\n\n\
         [obs]\n\
         metrics_bind = \"127.0.0.1:{mport}\"\n\
         log_format = \"text\"\n\n\
         [oidc]\n\
         enabled = true\n\
         issuer = \"{ISSUER}\"\n\
         client_id = \"{CLIENT_ID}\"\n\
         audience = \"\"\n\
         jwks_url = \"{jwks_url}\"\n\
         groups_claim = \"groups\"\n\
         max_reassertion_age_seconds = 604800\n",
        db = db.to_string_lossy(),
    );
    let cfg_path = dir.path().join("config.toml");
    std::fs::File::create(&cfg_path)
        .unwrap()
        .write_all(cfg.as_bytes())
        .unwrap();
    // CWD = the server crate dir so the binary resolves `./migrations/sqlite`.
    let child = Command::new(&bin)
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")))
        .arg("--config")
        .arg(&cfg_path)
        .spawn()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    // Own the child immediately so a readiness timeout still kills+reaps it (its Drop
    // waits — a bare Child dropped on the timeout path would leak a zombie).
    let proc = ServerProc {
        child,
        base: base.clone(),
        _dir: dir,
    };
    let http = reqwest::Client::new();
    for _ in 0..80 {
        if let Ok(r) = http.get(format!("{base}/readyz")).send().await {
            if r.status().is_success() {
                return Some(proc);
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None // `proc` drops here → kill + wait
}

/// The REAL binary verifies a mock-IdP id_token (fetching the JWKS over the network),
/// checks the key-binding nonce against the presented registration, creates the account,
/// and mints an OIDC session — all over real HTTP. A token signed by an unrelated key is
/// rejected, proving the signature check (not just the kid) is real.
#[tokio::test]
#[ignore = "needs `cargo build -p unissh-server` + free TCP ports"]
async fn live_oidc_callback_against_real_binary_with_mock_idp() {
    let jwks_url = spawn_jwks().await;
    let srv = match spawn_server(&jwks_url).await {
        Some(s) => s,
        None => return, // skipped (binary not built)
    };
    let http = reqwest::Client::new();

    // (1) A valid id_token + a key-binding registration → 200 + a session.
    let id = common::make_identity();
    let token = sign_token(SIGNING_PEM, &base_claims(&nonce_for(&id)));
    let resp = http
        .post(format!("{}/v1/oidc/callback", srv.base))
        .json(&serde_json::json!({
            "id_token": token,
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    // A first-time SSO login creates the account → 201 Created (a returning login is 200).
    assert_eq!(
        status, 201,
        "valid first-time OIDC callback should create the account + mint a session, got {status}: {body}"
    );
    assert!(
        body["access_token"].as_str().is_some_and(|s| !s.is_empty()),
        "response must carry a session access_token: {body}"
    );
    assert!(
        body["account_id"].as_str().is_some_and(|s| !s.is_empty()),
        "response must carry an account_id: {body}"
    );
    eprintln!(
        "LIVE OIDC ok — real binary minted a session: account_id={} device_id={} spaces={}",
        body["account_id"], body["device_id"], body["spaces"]
    );

    // (2) An id_token signed by an UNRELATED key (not in the JWKS) → rejected (401).
    let id2 = common::make_identity();
    let bad = sign_token(ATTACKER_PEM, &base_claims(&nonce_for(&id2)));
    let resp2 = http
        .post(format!("{}/v1/oidc/callback", srv.base))
        .json(&serde_json::json!({
            "id_token": bad,
            "registration_payload": id2.payload_b64,
            "registration_signature": id2.sig_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        401,
        "an id_token signed by a key absent from the JWKS must be rejected"
    );
    eprintln!("LIVE OIDC ok — attacker-signed id_token rejected: 401");
}
