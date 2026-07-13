//! Common test harness (v2, instance-scoped): bring up the server on a random port
//! (sqlite :memory:, controllable clock, fixed setup code), a reqwest client, and
//! helpers to claim the instance / seed accounts / log in.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use unissh_server::store::Val;
use unissh_server::time::{Clock, SharedClock, TestClock};
use unissh_server::{AppState, Config, app, build_state, ids};

pub struct TestApp {
    pub base: String,
    pub state: AppState,
    pub clock: Arc<TestClock>,
    pub client: reqwest::Client,
    /// This instance's id (base64), fetched from GET /v1/instance after boot.
    pub instance_id: String,
}

pub const START_TS: i64 = 1_700_000_000;

/// The fixed setup code every test instance boots with.
pub const SETUP_CODE: &str = "TEST-CODE-1234";

pub async fn spawn() -> TestApp {
    spawn_with(|_| {}).await
}

pub async fn spawn_with(f: impl FnOnce(&mut Config)) -> TestApp {
    let mut config = Config::default();
    config.db.backend = "sqlite".into();
    config.db.url = ":memory:".into();
    config.obs.log_format = "text".into();
    // A deterministic setup code so the harness can claim the instance.
    config.setup.code = SETUP_CODE.into();
    // The harness default is passthrough: most tests push synthetic
    // objects with dummy signatures. §2.4 tests enable validate_signatures explicitly.
    config.sync.validate_signatures = false;
    f(&mut config);

    let clock = Arc::new(TestClock::new(START_TS));
    let shared: SharedClock = clock.clone();
    let state = build_state(config, shared, None).await.unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app(state.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let base = format!("http://{addr}");
    // Read the instance id straight from state (not over HTTP) so booting the harness
    // does not consume a per-IP rate-limit token — `GET /v1/instance` is under the
    // rate-limited /v1 router and would perturb the rate-limit test.
    let instance_id = ids::b64(&state.instance_id);

    TestApp {
        base,
        state,
        clock,
        client: reqwest::Client::new(),
        instance_id,
    }
}

/// Credentials of a seeded device + access token.
pub struct Seeded {
    pub account_id: Vec<u8>,
    pub device_id: Vec<u8>,
    pub ed25519_pub: Vec<u8>,
    pub x25519_pub: Vec<u8>,
    pub access_token_b64: String,
}

impl TestApp {
    pub fn now(&self) -> i64 {
        self.clock.now_unix()
    }

    /// Create account+device+session directly in the store; return the credentials +
    /// bearer token. Instance-scoped: `_tier` is ignored (kept for call-site parity).
    pub async fn seed_session(&self, _tier: &str) -> Seeded {
        let account_id = ids::random_id16().to_vec();
        let device_id = ids::random_id16().to_vec();
        let ed = ids::random_bytes32().to_vec();
        let x = ids::random_bytes32().to_vec();
        let now = self.now();
        let s = &self.state.store;
        s.create_account(&account_id, &ed, &x, None, None, false, &[], &[], now)
            .await
            .unwrap();
        s.create_device(&account_id, &device_id, &ed, &x, now)
            .await
            .unwrap();

        let raw = ids::random_bytes32();
        let refresh = ids::random_bytes32();
        let session_id = ids::random_id16();
        s.create_session(
            &session_id,
            &account_id,
            &device_id,
            &ids::sha256(&raw),
            &ids::sha256(&refresh),
            now + 900,
            now + 1_000_000,
            now,
        )
        .await
        .unwrap();

        Seeded {
            account_id,
            device_id,
            ed25519_pub: ed,
            x25519_pub: x,
            access_token_b64: ids::b64(&raw),
        }
    }

    /// Seed a device with a specific ed/x key (a new account), return
    /// (account_id, device_id, bearer). `make_owner` sets is_owner=1 and binds the
    /// instance owner (anti-lockout) if none is bound yet.
    pub async fn seed_device(
        &self,
        ed: &[u8],
        x: &[u8],
        _tier: &str,
        make_owner: bool,
    ) -> (Vec<u8>, Vec<u8>, String) {
        let now = self.now();
        let s = &self.state.store;
        let account_id = ids::random_id16().to_vec();
        let device_id = ids::random_id16().to_vec();
        s.create_account(&account_id, ed, x, None, None, make_owner, &[], &[], now)
            .await
            .unwrap();
        s.create_device(&account_id, &device_id, ed, x, now)
            .await
            .unwrap();
        if make_owner {
            let _ = s
                .exec(
                    "UPDATE instance SET claimed = 1, owner_account_id = ? \
                     WHERE id = 1 AND owner_account_id IS NULL",
                    vec![Val::b(&account_id[..])],
                )
                .await;
        }
        let raw = ids::random_bytes32();
        let session_id = ids::random_id16();
        s.create_session(
            &session_id,
            &account_id,
            &device_id,
            &ids::sha256(&raw),
            &ids::sha256(&ids::random_bytes32()),
            now + 900,
            now + 1_000_000,
            now,
        )
        .await
        .unwrap();
        (account_id, device_id, ids::b64(&raw))
    }
}

// ---- real-crypto claim/login helpers (shared by identity-ish tests) ----

use unissh_crypto::{
    Ed25519Keypair, RegistrationPayload as CoreReg, ServerAuthChallenge as CoreChal, X25519Keypair,
    sign_registration, sign_server_auth,
};
use unissh_server::crypto::RegistrationPayload as SrvReg;

pub struct Identity {
    pub kp: Ed25519Keypair,
    pub ed: [u8; 32],
    pub x: [u8; 32],
    pub payload_b64: String,
    pub sig_b64: String,
}

pub fn make_identity() -> Identity {
    let kp = Ed25519Keypair::generate();
    let xk = X25519Keypair::generate();
    let ed = kp.verifying.to_bytes();
    let x = xk.public.to_bytes();
    let candidate = vec![0u8; 16];
    let core = CoreReg {
        account_id: candidate.clone(),
        x25519_pub: x,
        ed25519_pub: ed,
    };
    let sig = sign_registration(&kp.signing, &core).unwrap();
    let srv = SrvReg {
        account_id: candidate,
        x25519_pub: x,
        ed25519_pub: ed,
    };
    Identity {
        kp,
        ed,
        x,
        payload_b64: ids::b64(&srv.canonical().unwrap()),
        sig_b64: ids::b64(&sig),
    }
}

/// Claim the instance as the given identity → the claim response (account_id,
/// device_id, space_id, instance_id).
pub async fn claim_owner(app: &TestApp, payload_b64: &str, sig_b64: &str) -> serde_json::Value {
    let r = app
        .client
        .post(format!("{}/v1/claim", app.base))
        .json(&serde_json::json!({
            "setup_code": SETUP_CODE,
            "registration_payload": payload_b64,
            "registration_signature": sig_b64,
            "handle": "owner",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "claim failed");
    r.json().await.unwrap()
}

/// Full v2 auth flow: challenge → sign with the keyset key → verify → the WHOLE token
/// set. The challenge `host` is the instance id (echoed back and signed).
pub async fn login_tokens_v2(
    app: &TestApp,
    id: &Identity,
    account_id: &str,
    device_id: &str,
) -> serde_json::Value {
    let chal: serde_json::Value = app
        .client
        .post(format!("{}/v1/auth/challenge", app.base))
        .json(&serde_json::json!({
            "account_id": account_id, "device_id": device_id, "key_id": ids::b64(b"k1")
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        chal["host"], app.instance_id,
        "challenge host must be the instance id"
    );
    let g = |k: &str| ids::unb64(chal[k].as_str().unwrap()).unwrap();
    let core_chal = CoreChal {
        host: g("host"),
        account_id: g("account_id"),
        device_id: g("device_id"),
        key_id: g("key_id"),
        nonce: g("nonce"),
        expiry: chal["expiry"].as_u64().unwrap(),
    };
    let sig = sign_server_auth(&id.kp.signing, &core_chal).unwrap();
    let resp = app
        .client
        .post(format!("{}/v1/auth/verify", app.base))
        .json(&serde_json::json!({ "challenge": chal, "signature": ids::b64(&sig) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "auth/verify should succeed");
    resp.json().await.unwrap()
}

/// Convenience: v2 login returning just the access token.
pub async fn login_v2(app: &TestApp, id: &Identity, account_id: &str, device_id: &str) -> String {
    login_tokens_v2(app, id, account_id, device_id).await["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

impl TestApp {
    /// Method form of [`login_v2`] (access token only).
    pub async fn login(&self, id: &Identity, account_id: &str, device_id: &str) -> String {
        login_v2(self, id, account_id, device_id).await
    }
}
