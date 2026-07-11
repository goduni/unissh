//! Common test harness: bring up the server on a random port (sqlite :memory:,
//! controllable clock), a reqwest client, seeding tenant/account/device/session.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use unissh_server::time::{Clock, SharedClock, TestClock};
use unissh_server::{AppState, Config, app, build_state, ids};

pub struct TestApp {
    pub base: String,
    pub state: AppState,
    pub clock: Arc<TestClock>,
    pub client: reqwest::Client,
}

pub const START_TS: i64 = 1_700_000_000;

pub async fn spawn() -> TestApp {
    spawn_with(|_| {}).await
}

pub async fn spawn_with(f: impl FnOnce(&mut Config)) -> TestApp {
    let mut config = Config::default();
    config.db.backend = "sqlite".into();
    config.db.url = ":memory:".into();
    config.obs.log_format = "text".into();
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

    TestApp {
        base: format!("http://{addr}"),
        state,
        clock,
        client: reqwest::Client::new(),
    }
}

/// Credentials of a seeded device + access token.
pub struct Seeded {
    pub tenant_id: Vec<u8>,
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

    pub fn tenant_hdr(&self, tid: &[u8]) -> String {
        ids::b64(tid)
    }

    /// Create tenant+account+device+session; return the credentials + bearer token.
    pub async fn seed_session(&self, tenant_id: &[u8], tier: &str) -> Seeded {
        let account_id = ids::random_id16().to_vec();
        let device_id = ids::random_id16().to_vec();
        let ed = ids::random_bytes32().to_vec();
        let x = ids::random_bytes32().to_vec();
        let now = self.now();
        let s = &self.state.store;
        s.create_tenant(tenant_id, tier, now).await.unwrap();
        s.create_account(
            tenant_id,
            &account_id,
            &ed,
            &x,
            None,
            None,
            false,
            &[],
            &[],
            now,
        )
        .await
        .unwrap();
        s.create_device(tenant_id, &account_id, &device_id, &ed, &x, now)
            .await
            .unwrap();

        let raw = ids::random_bytes32();
        let refresh = ids::random_bytes32();
        let session_id = ids::random_id16();
        s.create_session(
            tenant_id,
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
            tenant_id: tenant_id.to_vec(),
            account_id,
            device_id,
            ed25519_pub: ed,
            x25519_pub: x,
            access_token_b64: ids::b64(&raw),
        }
    }

    /// Seed a device with a specific ed/x key (a new account), return
    /// (account_id, bearer). `make_genesis` fixes genesis_owner = ed (admin).
    pub async fn seed_device(
        &self,
        tenant_id: &[u8],
        ed: &[u8],
        x: &[u8],
        tier: &str,
        make_genesis: bool,
    ) -> (Vec<u8>, Vec<u8>, String) {
        let now = self.now();
        let s = &self.state.store;
        s.create_tenant(tenant_id, tier, now).await.unwrap();
        let account_id = ids::random_id16().to_vec();
        let device_id = ids::random_id16().to_vec();
        s.create_account(
            tenant_id,
            &account_id,
            ed,
            x,
            None,
            None,
            make_genesis,
            &[],
            &[],
            now,
        )
        .await
        .unwrap();
        s.create_device(tenant_id, &account_id, &device_id, ed, x, now)
            .await
            .unwrap();
        if make_genesis {
            let _ = s.set_genesis_owner_if_unset(tenant_id, ed).await;
        }
        let raw = ids::random_bytes32();
        let session_id = ids::random_id16();
        s.create_session(
            tenant_id,
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

// ---- real-crypto bootstrap/login helpers (shared by identity-ish tests) ----

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

impl TestApp {
    /// Full auth flow: challenge → sign with the keyset key → verify → access token.
    pub async fn login(
        &self,
        tid: &[u8],
        id: &Identity,
        account_id: &str,
        device_id: &str,
    ) -> String {
        let chal: serde_json::Value = self
            .client
            .post(format!("{}/v1/auth/challenge", self.base))
            .header("UniSSH-Tenant", ids::b64(tid))
            .json(&serde_json::json!({
                "account_id": account_id, "device_id": device_id, "key_id": ids::b64(b"k1")
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
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
        let resp = self
            .client
            .post(format!("{}/v1/auth/verify", self.base))
            .header("UniSSH-Tenant", ids::b64(tid))
            .json(&serde_json::json!({ "challenge": chal, "signature": ids::b64(&sig) }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "auth/verify should succeed");
        let t: serde_json::Value = resp.json().await.unwrap();
        t["access_token"].as_str().unwrap().to_string()
    }
}
