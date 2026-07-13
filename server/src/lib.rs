//! UniSSH Server — a self-hosted zero-knowledge control-plane.
//!
//! An untrusted ciphertext store + device/member sync + membership/sharing/
//! revocation + audit. SSH traffic does NOT pass through the server. The server sees only
//! encrypted blobs and open metadata (spec §1, ARCH §2).

pub mod codec;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod http;
pub mod ids;
pub mod modules;
pub mod obs;
pub mod state;
pub mod store;
pub mod time;

pub use config::Config;
pub use error::{AppError, AppResult, ErrorCode};
pub use state::{AppState, AppStateInner};
pub use store::Store;

use axum::Router;

/// Build the application state: connect to the DB, apply migrations,
/// bring up the clock and the metrics handle.
pub async fn build_state(
    config: Config,
    clock: time::SharedClock,
    metrics: Option<metrics_exporter_prometheus::PrometheusHandle>,
) -> AppResult<AppState> {
    let store = Store::connect(&config.db).await?;
    store.migrate().await?;
    // v2 boot order (Task-2 review finding): the singleton `instance` row MUST
    // exist before anything reads it — `Store::instance()` panics otherwise.
    let now = clock.now_unix();
    let instance_row = store.ensure_instance(now).await?;
    // Load the server-PRIVATE escrow-decoy secret (set once by `ensure_instance`,
    // just above). Kept off `InstanceRow` so it never rides along on the widely
    // read instance row — the decoy in `GET /v1/escrow/params` is keyed from THIS,
    // never from the PUBLIC `instance_id`.
    let escrow_decoy_secret = store.escrow_decoy_secret().await?;
    // Unclaimed: publish a setup code so a client can claim this instance. The code
    // is the config-fixed one (IaC/tests) if set, else a fresh random one. We store
    // only sha256(code); the human code is printed to logs (never persisted).
    if instance_row.claimed == 0 {
        let code = if config.setup.code.is_empty() {
            let mut rnd = [0u8; 6];
            ids::fill_random(&mut rnd);
            ids::generate_setup_code(&rnd)
        } else {
            config.setup.code.clone()
        };
        store
            .set_setup_code_hash(&ids::sha256(code.as_bytes()))
            .await?;
        tracing::warn!(%code, "server unclaimed — claim it from a client with this setup code");
        println!("SETUP CODE: {code}");
    }
    // Whole-DB-snapshot anti-rollback (§16): refuse to come up if
    // the instance-generation (instance.next_seq) has fallen below the
    // operator-anchored floor. Checked HERE (not only in `main`) so that
    // in-process/embedded deployments also get a fatal refusal when a stale
    // snapshot is restored — otherwise anti-rollback degrades to "not checked".
    let generation = store.instance_generation().await?;
    let floor = config.sync.min_instance_generation;
    rollback_guard(generation, floor)?;
    tracing::info!(generation, floor, "anti-rollback check passed");
    Ok(AppStateInner::new(
        store,
        config,
        instance_row.instance_id,
        escrow_decoy_secret,
        clock,
        metrics,
    ))
}

/// Build the router from a ready state.
pub fn app(state: AppState) -> Router {
    http::build_router(state)
}

/// Whole-DB-snapshot anti-rollback guard (§16). `generation` = instance-generation
/// (`Store::instance_generation`); `floor` = `[sync] min_instance_generation`,
/// anchored by the operator outside the DB. If `floor > 0` and `generation < floor` —
/// a stale snapshot was restored; the server must refuse to come up.
pub fn rollback_guard(generation: i64, floor: i64) -> AppResult<()> {
    if floor > 0 && generation < floor {
        return Err(AppError::rollback_detected(format!(
            "instance generation {generation} is below the anti-rollback floor {floor} \
             (a stale DB snapshot may have been restored); raise it with seq-bump \
             or correct min_instance_generation"
        )));
    }
    Ok(())
}

/// TLS decision at startup. `acme=true` is NOT supported in-process (§13 seam):
/// terminate TLS at a reverse-proxy (Caddy/nginx) or set `tls_cert`/`tls_key`.
/// Previously `acme` was silently ignored → the server served plain HTTP (footgun); now
/// it is an explicit startup error.
pub enum TlsPlan {
    Rustls { cert: String, key: String },
    Plain,
}

pub fn tls_plan(server: &config::ServerConfig) -> Result<TlsPlan, String> {
    if server.acme {
        return Err(
            "server.acme=true: in-process ACME is not built in — terminate TLS at a \
             reverse proxy (Caddy/nginx/Traefik) or set server.tls_cert + server.tls_key"
                .to_string(),
        );
    }
    if !server.tls_cert.is_empty() && !server.tls_key.is_empty() {
        Ok(TlsPlan::Rustls {
            cert: server.tls_cert.clone(),
            key: server.tls_key.clone(),
        })
    } else {
        Ok(TlsPlan::Plain)
    }
}

#[cfg(test)]
mod tls_plan_tests {
    use super::{TlsPlan, tls_plan};
    use crate::config::ServerConfig;

    #[test]
    fn acme_is_rejected() {
        let s = ServerConfig {
            acme: true,
            ..Default::default()
        };
        assert!(tls_plan(&s).is_err());
    }

    #[test]
    fn cert_and_key_select_rustls() {
        let s = ServerConfig {
            tls_cert: "/c.pem".into(),
            tls_key: "/k.pem".into(),
            ..Default::default()
        };
        assert!(matches!(tls_plan(&s), Ok(TlsPlan::Rustls { .. })));
    }

    #[test]
    fn empty_tls_is_plain() {
        let s = ServerConfig::default();
        assert!(matches!(tls_plan(&s), Ok(TlsPlan::Plain)));
    }
}

#[cfg(test)]
mod rollback_guard_tests {
    use super::rollback_guard;

    #[test]
    fn floor_zero_always_ok() {
        assert!(rollback_guard(0, 0).is_ok());
        assert!(rollback_guard(5, 0).is_ok());
    }

    #[test]
    fn below_floor_rejected() {
        assert!(rollback_guard(9, 10).is_err());
    }

    #[test]
    fn at_or_above_floor_ok() {
        assert!(rollback_guard(10, 10).is_ok());
        assert!(rollback_guard(11, 10).is_ok());
    }
}
