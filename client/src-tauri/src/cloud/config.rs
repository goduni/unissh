//! Persisted cloud identity + in-memory session state for one instance.
//!
//! An instance may be linked to MULTIPLE cloud servers at once. Each link is a
//! `ServerConfig` keyed by a stable, locally-generated `server_id`; one of them
//! is the *active* server that argument-less cloud commands resolve against. The
//! collection persists as a single `cloud.json` document `{ servers, active }`
//! (atomic whole-set write), with a migration shim that wraps a legacy single
//! object as one active server.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::cloud::{client, identity, tokens};
use crate::error::{ApiError, ApiResult};

/// Opaque, locally-generated id for a linked server (32 hex chars of a random
/// UUID). It namespaces the keychain refresh-token entry and selects the active
/// server; it never goes on the wire. Hex is deliberately path-safe — the id is
/// embedded in a keychain account name (`cloud-refresh-token/<id>`), so it must
/// not contain `/`, `+` or `=` (which base64 STANDARD would produce).
pub type ServerId = String;

/// Mint a fresh, stable, path-safe server id (32 lowercase hex chars).
pub fn new_server_id() -> ServerId {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Canonical form of a server base URL for *identity* comparison. Trims
/// surrounding whitespace, drops trailing `/`, and lowercases the scheme +
/// authority (the case-insensitive parts of an origin) while leaving any path
/// untouched. So `https://X.example/`, `https://x.example` and `HTTPS://x.example`
/// all collapse to one identity — re-linking the same server with a differently
/// typed URL can never mint an un-collapsible phantom duplicate link.
fn canonical_base_url(base_url: &str) -> String {
    let s = base_url.trim().trim_end_matches('/');
    match s.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
            let scheme = scheme.to_ascii_lowercase();
            let authority = authority.to_ascii_lowercase();
            if path.is_empty() {
                format!("{scheme}://{authority}")
            } else {
                format!("{scheme}://{authority}/{path}")
            }
        }
        None => s.to_ascii_lowercase(),
    }
}

/// Stable identity of a server link: the canonical base URL plus the wire
/// instance/account ids (both base64, server-assigned → compared verbatim). Two
/// links with the same identity ARE the same server and must collapse to one.
fn identity_key(base_url: &str, instance_id: &str, account_id: &str) -> (String, String, String) {
    (
        canonical_base_url(base_url),
        instance_id.to_owned(),
        account_id.to_owned(),
    )
}

/// Persisted, NON-secret cloud identity for one linked server (one entry in the
/// `cloud.json` `servers` array). Tokens are NOT stored here: the refresh token
/// lives in the OS keychain (namespaced by `server_id`), the access token in
/// memory only. The three wire ids are base64 STANDARD (the server's
/// header/body form), so they round-trip to the wire verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Local, stable id for this link (keychain namespace + active selector).
    /// `#[serde(default)]` so a legacy doc without it can still deserialize; the
    /// migration assigns one.
    #[serde(default = "new_server_id")]
    pub server_id: ServerId,
    /// Base URL of the server, e.g. `https://cloud.example.com` (no `/v1` suffix).
    pub base_url: String,
    /// base64(instance_id) — the opaque server-instance id (from claim/join). It
    /// keys the link identity for dedup; the instance is addressed by `base_url`
    /// on the wire (there is no tenant header any more).
    pub instance_id: String,
    /// base64(space_id) — the cloud-vault binding label. The claim owner's first
    /// space, or (for a join) the primary granted space. Cloud vaults created/bound
    /// on this link carry this label; sync scopes to it. `#[serde(default)]` = "".
    #[serde(default)]
    pub space_id: String,
    /// base64(account_id) — server-assigned at claim/join.
    pub account_id: String,
    /// base64(device_id) — server-assigned; this device's id for auth/revocation.
    pub device_id: String,
    /// Optional human handle on the server (server-visible open metadata).
    #[serde(default)]
    pub handle: Option<String>,
    /// True when THIS account claimed the instance and owns its first Space — vs
    /// joined via invite (`false`). Used to guard the personal vault to a Space you
    /// own. `#[serde(default)]` = false for legacy links.
    #[serde(default)]
    pub owned: bool,
}

/// The whole persisted set: every linked server plus the active selection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CloudDoc {
    #[serde(default)]
    servers: Vec<ServerConfig>,
    #[serde(default)]
    active: Option<ServerId>,
}

/// One space the caller belongs to on a server link (name + server-trusted role),
/// as surfaced inside [`ServerStatus`] for the frontend. Mirrors the wire
/// `GET /v1/spaces` row; serialized camelCase (`spaceId`, `name`, `role`) to match
/// the frontend `SpaceInfo`. Lets the UI name a cloud vault's bound space (a vault's
/// `sync_tenant` is a space id) without a separate round-trip.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceEntry {
    pub space_id: String,
    pub name: String,
    pub role: String,
}

/// Read-only snapshot of ONE server's state for the frontend (camelCase JSON).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    /// Local id of this server link.
    pub server_id: Option<String>,
    /// A server is linked (config entry present).
    pub connected: bool,
    /// This is the active server (argument-less commands resolve to it).
    pub active: bool,
    /// A live access token is held (this process can make authenticated calls).
    pub has_session: bool,
    pub base_url: Option<String>,
    pub instance_id: Option<String>,
    pub account_id: Option<String>,
    pub device_id: Option<String>,
    pub handle: Option<String>,
    /// This account owns (claimed) the Space — eligible to hold the personal vault.
    pub owned: bool,
    /// base64(space_id) — this link's cloud-vault binding label (the config's own
    /// `space_id`). A cloud vault's `sync_tenant` equals this when bound here, so the
    /// frontend can attribute a vault to its server WITHOUT a live session (unlike
    /// `spaces`, which needs `GET /v1/spaces`). None when the link has no space yet.
    pub space_id: Option<String>,
    /// The caller's spaces on this link (server-v2), cached in memory from the last
    /// `GET /v1/spaces` (populated on claim/join/login/refresh; needs a session).
    /// Empty when no session has fetched them yet.
    pub spaces: Vec<SpaceEntry>,
}

impl ServerStatus {
    const fn disconnected() -> Self {
        Self {
            server_id: None,
            connected: false,
            active: false,
            has_session: false,
            base_url: None,
            instance_id: None,
            account_id: None,
            device_id: None,
            handle: None,
            owned: false,
            space_id: None,
            spaces: Vec::new(),
        }
    }
}

/// The list of linked servers + the active id, for the frontend (camelCase).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerList {
    pub servers: Vec<ServerStatus>,
    pub active: Option<String>,
}

/// Cloud runtime state held in `AppState`. The blocking HTTP client is a process
/// global (see `client::http`) — it is NOT stored here, so this state can be
/// constructed in Tauri's `setup` without spinning a runtime inside a runtime.
pub struct CloudState {
    config_path: PathBuf,
    /// All linked servers, keyed by `server_id`.
    servers: Mutex<HashMap<ServerId, ServerConfig>>,
    /// In-memory base64(access_token) per server; never written to disk.
    access_tokens: Mutex<HashMap<ServerId, String>>,
    /// In-memory space list per server (server-v2), refreshed from `GET /v1/spaces`
    /// whenever a session is (re)established. Never persisted; a fresh boot re-fetches
    /// it on `server_login`. Feeds `ServerStatus.spaces`.
    spaces: Mutex<HashMap<ServerId, Vec<SpaceEntry>>>,
    /// The active server (argument-less commands resolve here).
    active: Mutex<Option<ServerId>>,
    /// Serialises token rotation. Refresh tokens are single-use — the server
    /// hands back a new one and burns the old — so two calls whose access token
    /// expires at the same moment must not each spend one, or the second gets
    /// "refresh token expired or revoked" and the session is gone.
    refresh_gate: Mutex<()>,
}

impl CloudState {
    /// Build cloud state, loading any persisted config sidecar next to the instance.
    pub fn new(config_path: PathBuf) -> Self {
        let (doc, migrated) = load_doc(&config_path);

        // Collapse duplicate links that share the same server identity
        // (base_url + instance_id + account_id). Re-registering a server used to
        // mint a fresh `server_id` each time (before idempotent registration),
        // leaving phantom duplicate entries that the UI renders N times. Keep one
        // survivor per identity, preferring the persisted-active entry.
        let active_hint = doc.active.clone();
        let mut survivor: HashMap<(String, String, String), ServerId> = HashMap::new();
        for cfg in &doc.servers {
            let ident = identity_key(&cfg.base_url, &cfg.instance_id, &cfg.account_id);
            let is_active = active_hint.as_deref() == Some(cfg.server_id.as_str());
            match survivor.get(&ident) {
                Some(_) if is_active => {
                    survivor.insert(ident, cfg.server_id.clone());
                }
                Some(_) => {}
                None => {
                    survivor.insert(ident, cfg.server_id.clone());
                }
            }
        }
        let survivor_ids: std::collections::HashSet<ServerId> = survivor.into_values().collect();

        let mut servers = HashMap::new();
        let mut dropped: Vec<ServerId> = Vec::new();
        for cfg in doc.servers {
            if survivor_ids.contains(&cfg.server_id) {
                servers.insert(cfg.server_id.clone(), cfg);
            } else {
                dropped.push(cfg.server_id);
            }
        }
        let deduped = !dropped.is_empty();

        // Keep `active` valid: fall back to an arbitrary linked server if the
        // persisted active id is stale/missing but servers exist.
        let active = match active_hint {
            Some(id) if servers.contains_key(&id) => Some(id),
            _ => servers.keys().next().cloned(),
        };
        let state = Self {
            config_path,
            servers: Mutex::new(servers),
            access_tokens: Mutex::new(HashMap::new()),
            spaces: Mutex::new(HashMap::new()),
            active: Mutex::new(active),
            refresh_gate: Mutex::new(()),
        };
        // Drop orphaned refresh tokens for the duplicate links we collapsed.
        //
        // On a THREAD, and that is not tidiness. This constructor runs inside
        // Tauri's `setup`, on the main thread, before there is a window: on Linux
        // a keychain call is a Secret Service round trip that can raise the
        // keyring's own unlock prompt, and doing that on the main thread before
        // the app has a UI is how a launch hangs. Nothing waits on this cleanup —
        // an orphan left behind is unreferenced, not harmful — so it is the one
        // keychain touch here that can simply be moved off the path.
        //
        // (The pre-multi-server global refresh token is NOT migrated here for the
        // same reason. `tokens::load_refresh` picks it up on first read instead,
        // which is both off the main thread and exactly where it is needed.)
        if !dropped.is_empty() {
            let orphans = dropped.clone();
            std::thread::spawn(move || {
                for id in &orphans {
                    if let Err(e) = tokens::delete_refresh(id) {
                        log::warn!(
                            "cloud: failed to drop refresh token for duplicate link {id}: {e}"
                        );
                    }
                }
            });
        }
        // A legacy/partial sidecar minted fresh ids on load. Persist immediately
        // so the id is STABLE across boots — otherwise every launch re-mints it
        // and `server_login` leaks a new keychain refresh-token entry.
        if migrated || deduped {
            if let Err(e) = state.persist() {
                log::warn!("cloud: failed to persist the migrated cloud.json: {e:?}");
            }
        }
        state
    }

    /// The active server id, if any.
    #[cfg(test)]
    pub fn active_id(&self) -> Option<ServerId> {
        self.active.lock().unwrap().clone()
    }

    /// Resolve a `ServerConfig` by id, defaulting to the active server when
    /// `id` is `None` (back-compat for argument-less commands).
    pub fn config_for(&self, id: Option<&str>) -> ApiResult<Option<ServerConfig>> {
        let servers = locked(&self.servers, "server")?;
        let key = match id {
            Some(id) => id.to_owned(),
            None => match locked(&self.active, "active-server")?.clone() {
                Some(k) => k,
                None => return Ok(None),
            },
        };
        Ok(servers.get(&key).cloned())
    }

    /// Find an already-linked server with the same canonical identity (normalized
    /// base URL plus instance/account). Registration reuses this id instead of
    /// minting a fresh one, so re-connecting the same server replaces its link
    /// rather than duplicating it (the `cloud.json` map is keyed by `server_id`).
    pub fn find_by_identity(
        &self,
        base_url: &str,
        instance_id: &str,
        account_id: &str,
    ) -> ApiResult<Option<ServerId>> {
        let want = identity_key(base_url, instance_id, account_id);
        Ok(locked(&self.servers, "server")?
            .values()
            .find(|c| identity_key(&c.base_url, &c.instance_id, &c.account_id) == want)
            .map(|c| c.server_id.clone()))
    }

    /// Insert/replace a server entry, persist the whole set, and make it active.
    /// Returns the server id.
    pub fn upsert_config(&self, cfg: ServerConfig) -> ApiResult<ServerId> {
        let id = cfg.server_id.clone();
        let want = identity_key(&cfg.base_url, &cfg.instance_id, &cfg.account_id);
        let mut dropped: Vec<ServerId> = Vec::new();
        {
            let mut servers = locked(&self.servers, "server")?;
            // Enforce "one link per server identity" at insert time, not only at
            // boot: drop any OTHER link that resolves to the same identity (a
            // phantom from a pre-idempotent registration, or the same server typed
            // with a different trailing slash / host casing). Otherwise the UI
            // renders the same server twice until the next restart's collapse.
            let dups: Vec<ServerId> = servers
                .values()
                .filter(|c| {
                    c.server_id != id
                        && identity_key(&c.base_url, &c.instance_id, &c.account_id) == want
                })
                .map(|c| c.server_id.clone())
                .collect();
            for sid in dups {
                servers.remove(&sid);
                dropped.push(sid);
            }
            servers.insert(id.clone(), cfg);
        }
        *locked(&self.active, "active-server")? = Some(id.clone());
        // Clear the collapsed phantoms' in-memory access + keychain refresh so they
        // don't linger as orphaned sessions. Best-effort (boot collapse does the same).
        if !dropped.is_empty() {
            let mut toks = locked(&self.access_tokens, "session-token")?;
            for sid in &dropped {
                toks.remove(sid);
            }
        }
        for sid in &dropped {
            if let Err(e) = tokens::delete_refresh(sid) {
                log::warn!("cloud: failed to drop refresh token for duplicate link {sid}: {e}");
            }
        }
        self.persist()?;
        Ok(id)
    }

    /// Forget every linked server: clear the in-memory maps, remove the persisted
    /// `cloud.json`, and best-effort drop each server's keychain refresh token.
    /// Used by the full instance reset ("can't unlock → start over") so the fresh
    /// onboarding doesn't inherit stale links pointing at the old account.
    pub fn clear_all(&self) -> ApiResult<()> {
        let ids: Vec<ServerId> = {
            let mut servers = locked(&self.servers, "server")?;
            let ids = servers.keys().cloned().collect();
            servers.clear();
            ids
        };
        locked(&self.access_tokens, "session-token")?.clear();
        locked(&self.spaces, "space")?.clear();
        *locked(&self.active, "active-server")? = None;
        remove_sidecar(&self.config_path);
        for id in &ids {
            if let Err(e) = tokens::delete_refresh(id) {
                log::warn!("cloud: failed to drop refresh token on reset for {id}: {e}");
            }
        }
        Ok(())
    }

    /// Persist an in-place edit of an existing server's config (no active change).
    pub fn set_config(&self, cfg: ServerConfig) -> ApiResult<()> {
        locked(&self.servers, "server")?.insert(cfg.server_id.clone(), cfg);
        self.persist()
    }

    /// Switch the active server. Errors if the id is not linked.
    pub fn set_active(&self, id: &str) -> ApiResult<()> {
        if !locked(&self.servers, "server")?.contains_key(id) {
            return Err(ApiError::Server {
                code: "not_connected".into(),
                message: "no such linked server".into(),
            });
        }
        *locked(&self.active, "active-server")? = Some(id.to_owned());
        self.persist()
    }

    /// The access token for a server (defaults to the active server).
    pub fn access_token_for(&self, id: Option<&str>) -> ApiResult<Option<String>> {
        let Some(key) = self.key_or_active(id)? else {
            return Ok(None);
        };
        Ok(locked(&self.access_tokens, "session-token")?
            .get(&key)
            .cloned())
    }

    /// Swaps an access token the server has just rejected for a fresh one.
    ///
    /// Keyed by the STALE TOKEN rather than a server id, because the only thing
    /// that sees the rejection is the HTTP layer, and all it knows is the bearer
    /// it sent. Tokens are per-server and unique, so that identifies the link.
    ///
    /// Single-flight, and that is the load-bearing part: a refresh token is
    /// spent by using it. Two calls that expire together would otherwise each
    /// spend one, and the second would come back "refresh token expired or
    /// revoked" — turning a routine rotation into a sign-out. The loser of the
    /// gate finds the token already replaced and takes that instead.
    ///
    /// Every failure returns None, which leaves the original 401 to surface
    /// exactly as it did before. Rotating is an optimisation on top of "ask the
    /// user to sign in again", never a replacement for it. A poisoned registry
    /// lock is one of those failures: it is logged and the 401 reaches the UI.
    pub fn rotate_expired_access(&self, stale: &str) -> Option<String> {
        match self.try_rotate_expired_access(stale) {
            Ok(fresh) => fresh,
            Err(e) => {
                log::warn!("cloud: token rotation skipped: {e:?}");
                None
            }
        }
    }

    /// Body of [`Self::rotate_expired_access`]; `Err` only for a poisoned lock.
    fn try_rotate_expired_access(&self, stale: &str) -> ApiResult<Option<String>> {
        let found = locked(&self.access_tokens, "session-token")?
            .iter()
            .find(|(_, v)| v.as_str() == stale)
            .map(|(k, _)| k.clone());
        let Some(sid) = found else {
            return Ok(None);
        };
        // The gate guards no data (it is `Mutex<()>`), so a poisoned gate still
        // serialises rotation correctly; recovering it is safe.
        let _gate = self
            .refresh_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cur) = locked(&self.access_tokens, "session-token")?.get(&sid) {
            if cur != stale {
                return Ok(Some(cur.clone()));
            }
        }
        let base_url = match locked(&self.servers, "server")?.get(&sid) {
            Some(cfg) => cfg.base_url.clone(),
            None => return Ok(None),
        };
        let Some(refresh_token) = tokens::load_refresh(&sid) else {
            return Ok(None);
        };
        // No Bearer on this request, so it cannot recurse back into here.
        let session = match identity::refresh(client::http(), &base_url, &refresh_token) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("cloud: token rotation failed for server {sid}: {e:?}");
                return Ok(None);
            }
        };
        locked(&self.access_tokens, "session-token")?
            .insert(sid.clone(), session.access_token.clone());
        if let Err(e) = tokens::save_refresh(&sid, &session.refresh_token) {
            // The new refresh token is live on the server either way; failing to
            // store it costs a re-login after restart, not this session.
            log::warn!("cloud: rotated refresh token not persisted (server {sid}): {e}");
        }
        Ok(Some(session.access_token))
    }

    /// Set/clear a server's in-memory access token (defaults to the active server).
    pub fn set_access_token_for(&self, id: Option<&str>, token: Option<String>) -> ApiResult<()> {
        let Some(key) = self.key_or_active(id)? else {
            return Ok(());
        };
        let mut toks = locked(&self.access_tokens, "session-token")?;
        match token {
            Some(t) => {
                toks.insert(key, t);
            }
            None => {
                toks.remove(&key);
            }
        }
        Ok(())
    }

    /// Set/replace a server's cached space list (defaults to the active server).
    /// `None` clears it. Populated by the session-establishing commands from
    /// `GET /v1/spaces`; read back into `ServerStatus.spaces`.
    pub fn set_spaces_for(
        &self,
        id: Option<&str>,
        spaces: Option<Vec<SpaceEntry>>,
    ) -> ApiResult<()> {
        let Some(key) = self.key_or_active(id)? else {
            return Ok(());
        };
        let mut map = locked(&self.spaces, "space")?;
        match spaces {
            Some(s) => {
                map.insert(key, s);
            }
            None => {
                map.remove(&key);
            }
        }
        Ok(())
    }

    /// Forget ONE server link entirely: its entry + in-memory access + keychain
    /// refresh. If it was active, the active selection moves to another linked
    /// server (or `None`). Other servers' configs/tokens are untouched.
    pub fn remove(&self, id: &str) -> ApiResult<()> {
        // Lock order is servers→active everywhere (see config_for/persist); never
        // hold `active` while taking `servers`. Compute the next active under the
        // servers lock, then assign it separately.
        let next_active = {
            let mut servers = locked(&self.servers, "server")?;
            servers.remove(id);
            servers.keys().next().cloned()
        };
        locked(&self.access_tokens, "session-token")?.remove(id);
        locked(&self.spaces, "space")?.remove(id);
        {
            let mut active = locked(&self.active, "active-server")?;
            if active.as_deref() == Some(id) {
                *active = next_active;
            }
        }
        if let Err(e) = tokens::delete_refresh(id) {
            log::warn!("cloud: failed to delete refresh token from keychain (server {id}): {e}");
        }
        self.persist()
    }

    /// Drop the live session (access + refresh) for one server but keep the link.
    pub fn drop_session(&self, id: Option<&str>) -> ApiResult<()> {
        let Some(key) = self.key_or_active(id)? else {
            return Ok(());
        };
        locked(&self.access_tokens, "session-token")?.remove(&key);
        // The cached spaces were session-scoped; a re-login refetches them.
        locked(&self.spaces, "space")?.remove(&key);
        if let Err(e) = tokens::delete_refresh(&key) {
            log::warn!("cloud: failed to delete refresh token from keychain (server {key}): {e}");
        }
        Ok(())
    }

    /// Snapshot of ONE server (defaults to the active server) for the frontend.
    pub fn status_for(&self, id: Option<&str>) -> ApiResult<ServerStatus> {
        let active_id = locked(&self.active, "active-server")?.clone();
        let Some(key) = id.map(str::to_owned).or_else(|| active_id.clone()) else {
            return Ok(ServerStatus::disconnected());
        };
        let cfg = locked(&self.servers, "server")?.get(&key).cloned();
        match cfg {
            Some(c) => self.status_of(&c, active_id.as_deref()),
            None => Ok(ServerStatus::disconnected()),
        }
    }

    /// The whole linked-server list + active id, for the frontend.
    pub fn list(&self) -> ApiResult<ServerList> {
        let active = locked(&self.active, "active-server")?.clone();
        let configs: Vec<ServerConfig> =
            locked(&self.servers, "server")?.values().cloned().collect();
        let mut out = configs
            .iter()
            .map(|c| self.status_of(c, active.as_deref()))
            .collect::<ApiResult<Vec<ServerStatus>>>()?;
        // Stable, deterministic order: by base_url then id (HashMap iteration
        // order is otherwise random across runs).
        out.sort_by(|a, b| {
            a.base_url
                .cmp(&b.base_url)
                .then_with(|| a.server_id.cmp(&b.server_id))
        });
        Ok(ServerList {
            servers: out,
            active,
        })
    }

    /// The explicit id, or the active server's id when `id` is `None`.
    fn key_or_active(&self, id: Option<&str>) -> ApiResult<Option<ServerId>> {
        match id {
            Some(id) => Ok(Some(id.to_owned())),
            None => Ok(locked(&self.active, "active-server")?.clone()),
        }
    }

    /// Build a `ServerStatus` for a config, marking active + session presence and
    /// attaching the last-fetched space list (empty until a session fetched it).
    fn status_of(&self, c: &ServerConfig, active_id: Option<&str>) -> ApiResult<ServerStatus> {
        let has_session = locked(&self.access_tokens, "session-token")?.contains_key(&c.server_id);
        let spaces = locked(&self.spaces, "space")?
            .get(&c.server_id)
            .cloned()
            .unwrap_or_default();
        Ok(ServerStatus {
            server_id: Some(c.server_id.clone()),
            connected: true,
            active: active_id == Some(c.server_id.as_str()),
            has_session,
            base_url: Some(c.base_url.clone()),
            instance_id: Some(c.instance_id.clone()),
            account_id: Some(c.account_id.clone()),
            device_id: Some(c.device_id.clone()),
            handle: c.handle.clone(),
            owned: c.owned,
            space_id: (!c.space_id.is_empty()).then(|| c.space_id.clone()),
            spaces,
        })
    }

    /// Atomically write the whole set ({ servers, active }) to the sidecar.
    fn persist(&self) -> ApiResult<()> {
        // Snapshot servers+active with both locks held (order servers→active) so
        // a concurrent mutation can't make us persist a torn { servers, active }.
        let (servers, active) = {
            let servers_g = locked(&self.servers, "server")?;
            let active_g = locked(&self.active, "active-server")?;
            (
                servers_g.values().cloned().collect::<Vec<ServerConfig>>(),
                active_g.clone(),
            )
        };
        // If nothing is linked, remove the sidecar entirely (matches the old
        // single-server `forget()` behavior of leaving no file behind).
        if servers.is_empty() {
            remove_sidecar(&self.config_path);
            return Ok(());
        }
        let doc = CloudDoc { servers, active };
        save_doc(&self.config_path, &doc)
    }
}

/// Lock one of the registry maps. A poisoned lock means an earlier panic left
/// the map possibly half-updated; it becomes an error the UI shows rather than
/// a panic or a silent recovery onto that state.
fn locked<'a, T>(m: &'a Mutex<T>, what: &str) -> ApiResult<MutexGuard<'a, T>> {
    m.lock().map_err(|e| {
        ApiError::other(format!(
            "internal error: the cloud {what} registry is unavailable ({e}); restart UniSSH"
        ))
    })
}

/// Best-effort removal of the `cloud.json` sidecar. Absence is the goal, so
/// `NotFound` is success; any other failure is logged (a stale file is re-read
/// on the next boot, which is the old behaviour).
fn remove_sidecar(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!("cloud: failed to remove {}: {e}", path.display());
        }
    }
}

/// Load the persisted doc, applying the legacy single-object migration shim.
/// Returns the loaded doc and whether it was migrated (fresh ids minted), which
/// the caller must persist to stabilize those ids.
fn load_doc(path: &Path) -> (CloudDoc, bool) {
    let Ok(bytes) = std::fs::read(path) else {
        return (CloudDoc::default(), false);
    };
    migrate_doc(&bytes).unwrap_or_default()
}

/// Parse `cloud.json` into a `CloudDoc`, accepting either the new
/// `{ servers, active }` shape or the legacy single `ServerConfig` object.
///
/// Migration: a legacy single object (no `servers` array) is wrapped as one
/// server. If it lacks a `server_id` (it always did in the old format), one is
/// minted via `#[serde(default)]`, and that server becomes active.
/// Returns `(doc, migrated)` where `migrated` is true when ids were freshly
/// minted (legacy/partial data) and the result must be persisted to stabilize.
fn migrate_doc(bytes: &[u8]) -> Option<(CloudDoc, bool)> {
    // The new shape has a top-level `servers` array; the legacy shape has
    // top-level `base_url`. Probe the JSON to decide, then deserialize.
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value.get("servers").is_some() {
        let mut doc: CloudDoc = serde_json::from_value(value).ok()?;
        // Defensively ensure every entry has a non-empty id (older partial data).
        let mut migrated = false;
        for cfg in &mut doc.servers {
            if cfg.server_id.is_empty() {
                cfg.server_id = new_server_id();
                migrated = true;
            }
        }
        if doc.active.is_none() {
            doc.active = doc.servers.first().map(|c| c.server_id.clone());
        }
        Some((doc, migrated))
    } else {
        // Legacy single-object form → wrap as one active server. `server_id` was
        // minted by `#[serde(default)]`, so this MUST be persisted (migrated=true)
        // to stabilize the id and avoid re-minting on every boot.
        let cfg: ServerConfig = serde_json::from_value(value).ok()?;
        let active = Some(cfg.server_id.clone());
        Some((
            CloudDoc {
                servers: vec![cfg],
                active,
            },
            true,
        ))
    }
}

fn save_doc(path: &Path, doc: &CloudDoc) -> ApiResult<()> {
    let json = serde_json::to_vec_pretty(doc).map_err(ApiError::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json).map_err(ApiError::other)?;
    std::fs::rename(&tmp, path).map_err(ApiError::other)?;
    Ok(())
}

#[cfg(test)]
mod config_tests {
    use super::*;

    fn cfg(id: &str, base: &str) -> ServerConfig {
        ServerConfig {
            server_id: id.to_owned(),
            base_url: base.to_owned(),
            instance_id: "dGVuYW50".to_owned(),
            space_id: "c3BhY2U=".to_owned(),
            account_id: "YWNjb3VudA==".to_owned(),
            device_id: "ZGV2aWNl".to_owned(),
            handle: Some("jane".to_owned()),
            owned: false,
        }
    }

    #[test]
    fn migrates_legacy_single_object_to_one_active_server() {
        // The exact legacy on-disk shape: a single ServerConfig object, no id.
        let legacy = br#"{
            "base_url": "https://cloud.example.com",
            "instance_id": "dGVuYW50",
            "account_id": "YWNjb3VudA==",
            "device_id": "ZGV2aWNl",
            "handle": "jane"
        }"#;
        let (doc, migrated) = migrate_doc(legacy).expect("legacy doc should migrate");
        assert!(
            migrated,
            "legacy migration must be flagged so it gets persisted"
        );
        assert_eq!(doc.servers.len(), 1, "one server after migration");
        let s = &doc.servers[0];
        assert_eq!(s.base_url, "https://cloud.example.com");
        assert!(!s.server_id.is_empty(), "migration mints a server_id");
        assert_eq!(
            doc.active.as_deref(),
            Some(s.server_id.as_str()),
            "the migrated server is active"
        );
    }

    #[test]
    fn parses_new_multi_server_shape() {
        let new = br#"{
            "servers": [
                {"server_id":"AAAA","base_url":"https://a.example","instance_id":"dA==","account_id":"YQ==","device_id":"ZA==","handle":null},
                {"server_id":"BBBB","base_url":"https://b.example","instance_id":"dA==","account_id":"YQ==","device_id":"ZA==","handle":null}
            ],
            "active": "BBBB"
        }"#;
        let (doc, migrated) = migrate_doc(new).expect("new doc should parse");
        assert!(!migrated, "a well-formed multi-server doc is not re-minted");
        assert_eq!(doc.servers.len(), 2);
        assert_eq!(doc.active.as_deref(), Some("BBBB"));
    }

    #[test]
    fn roundtrip_persist_and_reload_preserves_servers_and_active() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cloud.json");
        let state = CloudState::new(path.clone());
        let id_a = state
            .upsert_config(cfg("AAAA", "https://a.example"))
            .unwrap();
        let id_b = state
            .upsert_config(cfg("BBBB", "https://b.example"))
            .unwrap();
        assert_eq!(id_a, "AAAA");
        assert_eq!(id_b, "BBBB");
        // upsert sets active → last inserted wins.
        assert_eq!(state.active_id().as_deref(), Some("BBBB"));
        state.set_active("AAAA").unwrap();

        // Reload from disk: both servers present, active preserved.
        let reloaded = CloudState::new(path);
        let list = reloaded.list().unwrap();
        assert_eq!(list.servers.len(), 2);
        assert_eq!(list.active.as_deref(), Some("AAAA"));
    }

    #[test]
    fn remove_reassigns_active_and_keeps_other_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cloud.json");
        let state = CloudState::new(path);
        state
            .upsert_config(cfg("AAAA", "https://a.example"))
            .unwrap();
        state
            .upsert_config(cfg("BBBB", "https://b.example"))
            .unwrap();
        state.set_active("AAAA").unwrap();
        state.remove("AAAA").unwrap();
        // Active moved to the remaining server; B's config survives.
        assert_eq!(state.active_id().as_deref(), Some("BBBB"));
        assert!(state.config_for(Some("BBBB")).unwrap().is_some());
        assert!(state.config_for(Some("AAAA")).unwrap().is_none());
    }

    #[test]
    fn find_by_identity_matches_same_server_else_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cloud.json");
        let state = CloudState::new(path);
        state
            .upsert_config(cfg("AAAA", "https://a.example"))
            .unwrap();
        // `cfg` uses instance_id "dGVuYW50" / account_id "YWNjb3VudA==".
        assert_eq!(
            state
                .find_by_identity("https://a.example", "dGVuYW50", "YWNjb3VudA==")
                .unwrap()
                .as_deref(),
            Some("AAAA"),
            "same identity reuses the existing link id"
        );
        assert!(
            state
                .find_by_identity("https://b.example", "dGVuYW50", "YWNjb3VudA==")
                .unwrap()
                .is_none(),
            "a different base_url is a different server"
        );
    }

    #[test]
    fn dedups_duplicate_identity_links_on_load_keeping_active() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cloud.json");
        // Three links with the SAME identity but distinct ids — exactly the shape
        // that re-registering the same server produced before idempotent register.
        let doc = br#"{
            "servers": [
                {"server_id":"AAAA","base_url":"https://a.example","instance_id":"dA==","account_id":"YQ==","device_id":"ZA==","handle":null},
                {"server_id":"BBBB","base_url":"https://a.example","instance_id":"dA==","account_id":"YQ==","device_id":"ZA==","handle":null},
                {"server_id":"CCCC","base_url":"https://a.example","instance_id":"dA==","account_id":"YQ==","device_id":"ZA==","handle":null}
            ],
            "active": "BBBB"
        }"#;
        std::fs::write(&path, doc).unwrap();
        let state = CloudState::new(path);
        let list = state.list().unwrap();
        assert_eq!(
            list.servers.len(),
            1,
            "duplicate-identity links collapse to a single survivor"
        );
        assert_eq!(
            list.active.as_deref(),
            Some("BBBB"),
            "the active duplicate is kept as the survivor"
        );
    }

    #[test]
    fn distinct_servers_are_not_deduped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cloud.json");
        let doc = br#"{
            "servers": [
                {"server_id":"AAAA","base_url":"https://a.example","instance_id":"dA==","account_id":"YQ==","device_id":"ZA==","handle":null},
                {"server_id":"BBBB","base_url":"https://b.example","instance_id":"dA==","account_id":"YQ==","device_id":"ZA==","handle":null}
            ],
            "active": "AAAA"
        }"#;
        std::fs::write(&path, doc).unwrap();
        let state = CloudState::new(path);
        assert_eq!(
            state.list().unwrap().servers.len(),
            2,
            "different base_urls stay separate"
        );
    }

    #[test]
    fn canonical_base_url_normalizes_slash_and_case() {
        // Same origin, differently typed → one canonical identity.
        assert_eq!(canonical_base_url("https://x.example"), "https://x.example");
        assert_eq!(
            canonical_base_url("https://x.example/"),
            "https://x.example"
        );
        assert_eq!(
            canonical_base_url("HTTPS://X.Example/"),
            "https://x.example"
        );
        assert_eq!(
            canonical_base_url("  https://x.example  "),
            "https://x.example"
        );
        // Distinct origins stay distinct.
        assert_ne!(
            canonical_base_url("https://x.example"),
            canonical_base_url("https://y.example")
        );
    }

    #[test]
    fn find_by_identity_ignores_trailing_slash_and_case() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cloud.json");
        let state = CloudState::new(path);
        state
            .upsert_config(cfg("AAAA", "https://a.example"))
            .unwrap();
        // Re-typed with a trailing slash + different case → same server.
        assert_eq!(
            state
                .find_by_identity("HTTPS://A.example/", "dGVuYW50", "YWNjb3VudA==")
                .unwrap()
                .as_deref(),
            Some("AAAA"),
            "trailing slash / host casing must not mint a new identity"
        );
    }

    #[test]
    fn upsert_purges_same_identity_phantom_in_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cloud.json");
        let state = CloudState::new(path);
        // First link, then a SECOND link for the same server with a fresh id and a
        // differently typed URL — the exact transient duplicate a pre-idempotent
        // path could produce mid-session. It must collapse to one immediately,
        // without waiting for a restart.
        state
            .upsert_config(cfg("AAAA", "https://a.example"))
            .unwrap();
        state
            .upsert_config(cfg("CCCC", "https://a.example/"))
            .unwrap();
        let list = state.list().unwrap();
        assert_eq!(
            list.servers.len(),
            1,
            "the phantom duplicate is dropped at insert time"
        );
        assert_eq!(
            list.active.as_deref(),
            Some("CCCC"),
            "the freshly upserted link survives and is active"
        );
        assert!(
            state.config_for(Some("AAAA")).unwrap().is_none(),
            "phantom removed"
        );
    }

    #[test]
    fn clear_all_forgets_every_link_and_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cloud.json");
        let state = CloudState::new(path.clone());
        state
            .upsert_config(cfg("AAAA", "https://a.example"))
            .unwrap();
        state
            .upsert_config(cfg("BBBB", "https://b.example"))
            .unwrap();
        assert_eq!(state.list().unwrap().servers.len(), 2);
        state.clear_all().unwrap();
        assert_eq!(
            state.list().unwrap().servers.len(),
            0,
            "all links forgotten"
        );
        assert!(state.active_id().is_none(), "no active server after reset");
        assert!(!path.exists(), "cloud.json removed");
        // A reload from disk stays empty.
        assert_eq!(CloudState::new(path).list().unwrap().servers.len(), 0);
    }
}
