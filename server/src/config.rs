//! Config (figment: defaults → TOML → env). Hierarchy and keys — spec §14.2.
//! Env-override: `UNISSH__SERVER__BIND=...` (double-underscore nesting).

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub db: DbConfig,
    pub limits: LimitsConfig,
    pub sync: SyncConfig,
    pub session: SessionConfig,
    pub obs: ObsConfig,
    pub ops: OpsConfig,
    pub setup: SetupConfig,
    pub oidc: OidcConfig,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
    /// PEM certificate for in-process rustls (TLS 1.3). Empty → no TLS inside.
    pub tls_cert: String,
    pub tls_key: String,
    /// TLS-termination behind a reverse-proxy: trust `X-Forwarded-For`.
    pub trust_proxy: bool,
    /// ACME (rustls-acme) — config-gated seam; not implemented in v1.
    pub acme: bool,
    /// CORS allowlist of origins for an admin panel on a DIFFERENT origin (e.g.
    /// `https://admin.example.com`). Empty → the CORS layer is not attached (the panel
    /// is served from the same origin / behind the same proxy — headers not needed).
    pub cors_allowed_origins: Vec<String>,
    /// Public base URL used to render invite URLs (`{public_url}/join#<token>`).
    /// Empty → the server returns `url: null` and clients compose it themselves.
    pub public_url: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DbConfig {
    /// "sqlite" | "postgres".
    pub backend: String,
    /// SQLite: path to file (or ":memory:"); Postgres: postgres://...
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_body_bytes: usize,
    pub max_object_bytes: usize,
    pub max_objects_per_push: usize,
    pub delta_page_size: u32,
    pub delta_max_page_size: u32,
    pub rate_limit_per_ip_rps: u32,
    pub rate_limit_burst: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncConfig {
    /// Freshness window W (sec) for online-only live grants (§9.7).
    pub freshness_window_seconds: i64,
    /// Defense-in-depth server-side signature validation (§2.4).
    pub validate_signatures: bool,
    /// Anti-rollback floor for the whole-DB snapshot (§16): the instance-generation
    /// (= Σ next_seq across tenants) MUST be ≥ this value at startup, otherwise
    /// the server refuses to come up (a stale snapshot was restored). The operator
    /// anchors this number outside the DB (like MAX(next_seq) in the backup runbook). 0 = off.
    pub min_instance_generation: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    pub access_ttl_seconds: i64,
    pub refresh_ttl_seconds: i64,
    pub nonce_ttl_seconds: i64,
    pub invite_default_ttl_seconds: i64,
    pub relay_ttl_seconds: i64,
    /// Interval of the background janitor (TTL-cleanup §13).
    pub janitor_interval_seconds: u64,
    /// TTL of idempotency keys (the client's retry window, §5.0).
    pub idempotency_ttl_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ObsConfig {
    /// "json" | "text".
    pub log_format: String,
    pub otel_endpoint: String,
    pub metrics_bind: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpsConfig {
    /// Operator token (server-trusted) for cross-tenant `/v1/ops/*` (the
    /// `X-UniSSH-Ops-Token` header). Empty → ops surface is DISABLED. This is NOT a keyset and does NOT
    /// grant decryption — only infrastructure operations (tenants/suspend/seq-bump).
    pub token: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SetupConfig {
    /// Optional fixed setup code (IaC/tests). Empty → generated at boot while unclaimed.
    pub code: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OidcConfig {
    /// SSO seam (Phase 5): disabled by default; issuer/client_id only for now.
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8443".into(),
            tls_cert: String::new(),
            tls_key: String::new(),
            trust_proxy: false,
            acme: false,
            cors_allowed_origins: Vec::new(),
            public_url: String::new(),
        }
    }
}
impl Default for DbConfig {
    fn default() -> Self {
        Self {
            backend: "sqlite".into(),
            url: "data/unissh.db".into(),
            max_connections: 16,
        }
    }
}
impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 16 * 1024 * 1024,
            max_object_bytes: 1024 * 1024,
            max_objects_per_push: 1000,
            delta_page_size: 500,
            delta_max_page_size: 1000,
            rate_limit_per_ip_rps: 20,
            rate_limit_burst: 40,
        }
    }
}
impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            freshness_window_seconds: 30,
            validate_signatures: true,
            min_instance_generation: 0,
        }
    }
}
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            access_ttl_seconds: 900,
            refresh_ttl_seconds: 2_592_000,
            nonce_ttl_seconds: 120,
            invite_default_ttl_seconds: 86_400,
            relay_ttl_seconds: 120,
            janitor_interval_seconds: 300,
            idempotency_ttl_seconds: 86_400,
        }
    }
}
impl Default for ObsConfig {
    fn default() -> Self {
        Self {
            log_format: "json".into(),
            otel_endpoint: String::new(),
            metrics_bind: "127.0.0.1:9090".into(),
        }
    }
}
// Manual `Debug` for secret-bearing sub-structs: even an accidental
// `tracing::debug!(?config)`, a panic message, or an error wrapper must NOT
// emit tokens / the TLS key / the db-URL (with pg creds) to the logs (obs rule §13).
impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("bind", &self.bind)
            .field("tls_cert", &self.tls_cert)
            .field("tls_key", &redacted(&self.tls_key))
            .field("trust_proxy", &self.trust_proxy)
            .field("acme", &self.acme)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("public_url", &self.public_url)
            .finish()
    }
}
impl std::fmt::Debug for DbConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbConfig")
            .field("backend", &self.backend)
            .field("url", &redacted(&self.url))
            .field("max_connections", &self.max_connections)
            .finish()
    }
}
impl std::fmt::Debug for OpsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpsConfig")
            .field("token", &redacted(&self.token))
            .finish()
    }
}
impl std::fmt::Debug for SetupConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupConfig")
            .field("code", &redacted(&self.code))
            .finish()
    }
}

/// `***` for a non-empty secret, `<unset>` for an empty one (presence is not a secret).
fn redacted(s: &str) -> &'static str {
    if s.is_empty() { "<unset>" } else { "***" }
}

impl Config {
    /// Load: defaults → TOML (if a path is given and exists) → env (`UNISSH__`).
    pub fn load(toml_path: Option<&Path>) -> Result<Self, Box<figment::Error>> {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));
        if let Some(p) = toml_path {
            if p.exists() {
                fig = fig.merge(Toml::file(p));
            }
        }
        fig = fig.merge(Env::prefixed("UNISSH__").split("__"));
        fig.extract().map_err(Box::new)
    }

    pub fn is_sqlite(&self) -> bool {
        self.db.backend.eq_ignore_ascii_case("sqlite")
    }
    pub fn is_postgres(&self) -> bool {
        self.db.backend.eq_ignore_ascii_case("postgres")
    }
}
