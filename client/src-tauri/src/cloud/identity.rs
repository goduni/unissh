//! Identity / session / device operations against the server `/v1` API.
//!
//! Every function is synchronous (`reqwest::blocking`) and must run inside a
//! blocking context. Signing is delegated to the core (`build_registration_request`,
//! `sign_server_challenge_raw`) — the private keyset never leaves the core.

use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::{json, Value};
use unissh_ffi as ffi;

use crate::cloud::client;
use crate::dto;
use crate::error::{ApiError, ApiResult};

/// Client-chosen key identifier echoed in the auth challenge. The server stores
/// and echoes it verbatim (it never interprets it), and the device signs over the
/// echoed value, so any stable value works.
const KEY_ID: &[u8] = b"unissh-keyset-v1";

/// Result of `claim` — the server-assigned identity for a freshly claimed instance.
/// The claimer becomes the instance owner and gets a first space.
pub struct ClaimOutcome {
    pub account_id: String,
    pub device_id: String,
    /// The first space created for the owner (cloud-vault binding label).
    pub space_id: String,
    /// Opaque server-instance id (echoed back on the auth challenge `host`).
    pub instance_id: String,
}

/// Result of `join` — the server-assigned identity plus the spaces the invite
/// granted (space ids, base64). May reuse an existing account (reattach).
pub struct JoinOutcome {
    pub account_id: String,
    pub device_id: String,
    /// Space ids (base64) this join was granted membership in.
    pub spaces: Vec<String>,
}

/// One space in a `join_preview` (read-only; does not consume the invite).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinPreviewSpace {
    pub space_id: String,
    pub name: String,
    pub role: String,
}

/// Read-only preview of an invite: the instance name + the spaces it grants.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinPreview {
    pub instance_name: Option<String>,
    pub spaces: Vec<JoinPreviewSpace>,
}

/// `GET /v1/instance` — public instance descriptor (before/after claim).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceInfo {
    /// True once the single-winner claim has happened.
    pub claimed: bool,
    /// Human name of the instance (set at claim), if any.
    pub name: Option<String>,
    /// Server version string.
    pub version: String,
    /// Opaque server-instance id (base64).
    pub instance_id: String,
    /// Supported auth methods (e.g. `["password", "oidc"]`).
    pub auth: Vec<String>,
}

/// Session tokens minted by `auth/verify` / `session/refresh`. (Token expiries are
/// also returned by the server and will be consumed by the Phase-5 auto-refresh.)
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
}

impl SessionTokens {
    fn from_value(v: &Value) -> ApiResult<Self> {
        Ok(SessionTokens {
            access_token: client::jstr(v, "access_token")?,
            refresh_token: client::jstr(v, "refresh_token")?,
        })
    }
}

fn claim_outcome(v: &Value) -> ApiResult<ClaimOutcome> {
    Ok(ClaimOutcome {
        account_id: client::jstr(v, "account_id")?,
        device_id: client::jstr(v, "device_id")?,
        space_id: client::jstr(v, "space_id")?,
        instance_id: client::jstr(v, "instance_id")?,
    })
}

fn join_outcome(v: &Value) -> ApiResult<JoinOutcome> {
    let spaces = v
        .get("spaces")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(JoinOutcome {
        account_id: client::jstr(v, "account_id")?,
        device_id: client::jstr(v, "device_id")?,
        spaces,
    })
}

/// `POST /v1/claim` — single-winner claim of an unclaimed instance. The `setup_code`
/// (printed by the server on first boot) authorizes it; the claimer becomes the
/// instance owner and is given a first space. A claimed instance returns 409.
#[allow(clippy::too_many_arguments)]
pub fn claim(
    http: &Client,
    base_url: &str,
    setup_code: &str,
    reg: ffi::RegistrationRequest,
    display_name: Option<String>,
    handle: Option<String>,
    space_name: Option<String>,
) -> ApiResult<ClaimOutcome> {
    let body = json!({
        "setup_code": setup_code,
        "registration_payload": client::b64(&reg.payload),
        "registration_signature": client::b64(&reg.signature),
        "display_name": display_name,
        "handle": handle,
        "space_name": space_name,
    });
    let v = client::send_json(
        client::headers(http.post(client::url(base_url, "/v1/claim")), None).json(&body),
    )?;
    claim_outcome(&v)
}

/// `POST /v1/join` — redeem an invite. A new keyset creates a fresh account+device;
/// an already-registered keyset reuses the account and mints a new device (reattach).
/// `binding_mac` is an optional invite-binding proof (pass `None` — the server
/// accepts a join without it; wiring the MAC is a later concern).
#[allow(clippy::too_many_arguments)]
pub fn join(
    http: &Client,
    base_url: &str,
    invite_token: &str,
    reg: ffi::RegistrationRequest,
    binding_mac: Option<&[u8]>,
    display_name: Option<String>,
    handle: Option<String>,
) -> ApiResult<JoinOutcome> {
    let body = json!({
        "invite_token": invite_token,
        "registration_payload": client::b64(&reg.payload),
        "registration_signature": client::b64(&reg.signature),
        "binding_mac": binding_mac.map(client::b64),
        "display_name": display_name,
        "handle": handle,
    });
    let v = client::send_json(
        client::headers(http.post(client::url(base_url, "/v1/join")), None).json(&body),
    )?;
    join_outcome(&v)
}

/// `POST /v1/join/preview` — resolve an invite's spaces (with names) WITHOUT
/// consuming it. POST (not GET) so the secret token never lands in a URL/query log.
pub fn join_preview(http: &Client, base_url: &str, token: &str) -> ApiResult<JoinPreview> {
    let body = json!({ "token": token });
    let v = client::send_json(
        client::headers(http.post(client::url(base_url, "/v1/join/preview")), None).json(&body),
    )?;
    let instance_name = v
        .get("instance_name")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut spaces = Vec::new();
    if let Some(arr) = v.get("spaces").and_then(Value::as_array) {
        for s in arr {
            spaces.push(JoinPreviewSpace {
                space_id: client::jstr(s, "space_id")?,
                name: s
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                role: client::jstr(s, "role")?,
            });
        }
    }
    Ok(JoinPreview {
        instance_name,
        spaces,
    })
}

/// `GET /v1/instance` — public instance descriptor (claimed?, name, version,
/// instance_id, auth methods). No auth. Used to learn the opaque `instance_id`
/// on a join (the join response carries only account/device/spaces).
pub fn instance_info(http: &Client, base_url: &str) -> ApiResult<InstanceInfo> {
    let v = client::send_json(client::headers(
        http.get(client::url(base_url, "/v1/instance")),
        None,
    ))?;
    let auth = v
        .get("auth")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(InstanceInfo {
        claimed: v.get("claimed").and_then(Value::as_bool).unwrap_or(false),
        name: v.get("name").and_then(Value::as_str).map(str::to_string),
        version: v
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        instance_id: client::jstr(&v, "instance_id")?,
        auth,
    })
}

/// Full auth handshake: `auth/challenge` → core `sign_server_challenge_raw` →
/// `auth/verify`. Returns the session tokens. `account_id_b64`/`device_id_b64` are
/// the server-assigned ids (base64). The challenge `host` (the opaque instance id)
/// is echoed by the server and signed verbatim — the client never supplies it.
pub fn login(
    http: &Client,
    base_url: &str,
    core: &ffi::Core,
    account_id_b64: &str,
    device_id_b64: &str,
) -> ApiResult<SessionTokens> {
    let chal_body = json!({
        "account_id": account_id_b64,
        "device_id": device_id_b64,
        "key_id": client::b64(KEY_ID),
    });
    let chal = client::send_json(
        client::headers(http.post(client::url(base_url, "/v1/auth/challenge")), None)
            .json(&chal_body),
    )?;

    // Sign over the RAW bytes of every field (the server reconstructs the
    // challenge from base64-decoded fields and verifies over those raw bytes).
    let host = client::unb64(&client::jstr(&chal, "host")?)?;
    let account_id = client::unb64(&client::jstr(&chal, "account_id")?)?;
    let device_id = client::unb64(&client::jstr(&chal, "device_id")?)?;
    let key_id = client::unb64(&client::jstr(&chal, "key_id")?)?;
    let nonce = client::unb64(&client::jstr(&chal, "nonce")?)?;
    let expiry = client::ju64(&chal, "expiry")?;
    let sig = core
        .sign_server_challenge_raw(host, account_id, device_id, key_id, nonce, expiry)
        .map_err(ApiError::from)?;

    // Echo the challenge object verbatim — its field names/values must match what
    // the server issued, byte-for-byte, or verification fails.
    let verify_body = json!({ "challenge": chal, "signature": client::b64(&sig) });
    let tokens = client::send_json(
        client::headers(http.post(client::url(base_url, "/v1/auth/verify")), None)
            .json(&verify_body),
    )?;
    SessionTokens::from_value(&tokens)
}

/// `POST /v1/session/refresh` — rotate access+refresh (same session). No Bearer.
pub fn refresh(http: &Client, base_url: &str, refresh_token: &str) -> ApiResult<SessionTokens> {
    let body = json!({ "refresh_token": refresh_token });
    let v = client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/session/refresh")),
            None,
        )
        .json(&body),
    )?;
    SessionTokens::from_value(&v)
}

/// `POST /v1/session/logout` (Bearer) — revoke the calling session. 204.
pub fn logout(http: &Client, base_url: &str, access: &str) -> ApiResult<()> {
    client::send_json(client::headers(
        http.post(client::url(base_url, "/v1/session/logout")),
        Some(access),
    ))?;
    Ok(())
}

/// `POST /v1/session/device-revoke` (Bearer). Own device, or another's if admin. 204.
pub fn device_revoke(
    http: &Client,
    base_url: &str,
    access: &str,
    device_id_b64: &str,
) -> ApiResult<()> {
    let body = json!({ "device_id": device_id_b64 });
    client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/session/device-revoke")),
            Some(access),
        )
        .json(&body),
    )?;
    Ok(())
}

/// `POST /v1/devices/add` (Bearer) — add a sibling device under the caller's
/// account (shared keyset). Returns the new `device_id` (base64).
pub fn device_add(http: &Client, base_url: &str, access: &str) -> ApiResult<String> {
    let v = client::send_json(client::headers(
        http.post(client::url(base_url, "/v1/devices/add")),
        Some(access),
    ))?;
    client::jstr(&v, "device_id")
}

/// `GET /v1/devices` (Bearer) — list the caller's own account devices.
pub fn device_list(http: &Client, base_url: &str, access: &str) -> ApiResult<Vec<dto::DeviceInfo>> {
    let v = client::send_json(client::headers(
        http.get(client::url(base_url, "/v1/devices")),
        Some(access),
    ))?;
    let devices = v["devices"].as_array().ok_or_else(|| ApiError::Server {
        code: "malformed".into(),
        message: "devices response missing 'devices'".into(),
    })?;
    let mut out = Vec::with_capacity(devices.len());
    for d in devices {
        out.push(dto::DeviceInfo {
            device_id: client::jstr(d, "device_id")?,
            status: d
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            registered_at: d.get("registered_at").and_then(|x| x.as_i64()).unwrap_or(0),
            active_sessions: d
                .get("active_sessions")
                .and_then(|x| x.as_i64())
                .unwrap_or(0),
        });
    }
    Ok(out)
}

/// `POST /v1/account/profile` (Bearer) — set display_name / handle. 204.
pub fn account_profile(
    http: &Client,
    base_url: &str,
    access: &str,
    display_name: Option<String>,
    handle: Option<String>,
) -> ApiResult<()> {
    let body = json!({ "display_name": display_name, "handle": handle });
    client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/account/profile")),
            Some(access),
        )
        .json(&body),
    )?;
    Ok(())
}

/// `GET /v1/accounts` (Bearer-admin) — list accounts with their member-id pubkeys
/// (Ed25519 + X25519), converted from the server's base64 to the hex form the
/// core's `add_member`/`rotate_vk` expect. Non-admin callers get `forbidden`.
pub fn list_accounts(
    http: &Client,
    base_url: &str,
    access: &str,
) -> ApiResult<Vec<dto::AccountInfo>> {
    let v = client::send_json(client::headers(
        http.get(client::url(base_url, "/v1/accounts")),
        Some(access),
    ))?;
    let accounts = v["accounts"].as_array().ok_or_else(|| ApiError::Server {
        code: "malformed".into(),
        message: "accounts response missing 'accounts'".into(),
    })?;
    let to_hex_field = |a: &Value, key: &str| -> Option<String> {
        a.get(key)
            .and_then(|x| x.as_str())
            .and_then(|s| client::unb64(s).ok())
            .map(|b| client::to_hex(&b))
    };
    let mut out = Vec::with_capacity(accounts.len());
    for a in accounts {
        out.push(dto::AccountInfo {
            account_id: client::jstr(a, "account_id")?,
            display_name: a
                .get("display_name")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            handle: a.get("handle").and_then(|x| x.as_str()).map(str::to_string),
            is_admin: a.get("is_admin").and_then(|x| x.as_bool()).unwrap_or(false),
            ed25519_pub_hex: to_hex_field(a, "member_pubkey"),
            x25519_pub_hex: to_hex_field(a, "x25519_pub"),
            status: a
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            device_count: a.get("device_count").and_then(|x| x.as_i64()).unwrap_or(0),
        });
    }
    Ok(out)
}

// ---- keyset escrow (Path A) ----

/// `PUT /v1/keyset` (Bearer) — escrow this device's already-encrypted keyset blob
/// (no-downgrade on generation). Returns the stored generation.
pub fn keyset_put(
    http: &Client,
    base_url: &str,
    access: &str,
    keyset_blob: &[u8],
) -> ApiResult<i64> {
    let body = json!({ "keyset_blob": client::b64(keyset_blob) });
    let v = client::send_json(
        client::headers(http.put(client::url(base_url, "/v1/keyset")), Some(access)).json(&body),
    )?;
    client::ji64(&v, "generation")
}

/// `GET /v1/keyset` (Bearer) — pull the escrowed keyset blob. Returns `(blob, generation)`.
pub fn keyset_get(http: &Client, base_url: &str, access: &str) -> ApiResult<(Vec<u8>, i64)> {
    let v = client::send_json(client::headers(
        http.get(client::url(base_url, "/v1/keyset")),
        Some(access),
    ))?;
    let blob = client::unb64(&client::jstr(&v, "keyset_blob")?)?;
    let generation = client::ji64(&v, "generation")?;
    Ok((blob, generation))
}

// ---- PAKE relay (Path B) ----

/// `POST /v1/relay/open` (Bearer) — open a device-to-device PAKE relay channel.
/// Returns the channel id (base64).
pub fn relay_open(http: &Client, base_url: &str, access: &str) -> ApiResult<String> {
    let v = client::send_json(client::headers(
        http.post(client::url(base_url, "/v1/relay/open")),
        Some(access),
    ))?;
    client::jstr(&v, "channel_id")
}

/// `POST /v1/relay/{slot}` (NO bearer) — put a PAKE message into a slot
/// (`msg1`/`msg2`/`msg3`). The slot name is also the body field name.
pub fn relay_post(
    http: &Client,
    base_url: &str,
    channel_id_b64: &str,
    slot: &str,
    msg: &[u8],
) -> ApiResult<()> {
    let mut body = serde_json::Map::new();
    body.insert(
        "channel_id".to_string(),
        Value::String(channel_id_b64.to_string()),
    );
    body.insert(slot.to_string(), Value::String(client::b64(msg)));
    client::send_json(
        client::headers(
            http.post(client::url(base_url, &format!("/v1/relay/{slot}"))),
            None,
        )
        .json(&Value::Object(body)),
    )?;
    Ok(())
}

/// `GET /v1/relay/poll` — fetch a slot. `Some(bytes)` if present, `None` on 204
/// (not posted yet).
pub fn relay_poll(
    http: &Client,
    base_url: &str,
    channel_id_b64: &str,
    want: &str,
) -> ApiResult<Option<Vec<u8>>> {
    let path = format!(
        "/v1/relay/poll?channel_id={}&want={}",
        client::enc_query(channel_id_b64),
        client::enc_query(want)
    );
    let rb = client::headers(http.get(client::url(base_url, &path)), None);
    let v = client::send_json(rb)?;
    if v.is_null() {
        return Ok(None);
    }
    match v.get(want).and_then(|x| x.as_str()) {
        Some(s) => Ok(Some(client::unb64(s)?)),
        None => Ok(None),
    }
}

// ---- audit (read-only) ----

/// `GET /v1/audit` (Bearer-admin) — read the server's audit log of observed events
/// (logins, etc.). The opaque blobs are dropped; the UI-useful fields are surfaced.
pub fn audit_query(
    http: &Client,
    base_url: &str,
    access: &str,
    since_seq: Option<i64>,
) -> ApiResult<Vec<dto::AuditEntry>> {
    let path = match since_seq {
        Some(s) => format!("/v1/audit?since_seq={s}"),
        None => "/v1/audit".to_string(),
    };
    let v = client::send_json(client::headers(
        http.get(client::url(base_url, &path)),
        Some(access),
    ))?;
    let entries = v["entries"].as_array().ok_or_else(|| ApiError::Server {
        code: "malformed".into(),
        message: "audit response missing 'entries'".into(),
    })?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        out.push(dto::AuditEntry {
            seq: client::ji64(e, "seq")?,
            source: e
                .get("source")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            recorded_at: e.get("recorded_at").and_then(|x| x.as_i64()).unwrap_or(0),
            author_pubkey: e
                .get("author_pubkey")
                .and_then(|x| x.as_str())
                .map(str::to_string),
        });
    }
    Ok(out)
}
