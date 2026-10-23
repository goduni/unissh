//! Server answers, shaped for a client.
//!
//! The server sends base64 everywhere; these records keep its ids as it sent
//! them and turn public keys into the hex form the core's membership calls take.
//! They serialize as `camelCase` because the desktop app hands them to its UI
//! verbatim — a rename here is a rename of that IPC contract.

use serde::Serialize;

/// An account as seen by an instance-admin via `/v1/accounts`. Pubkeys are hex
/// (converted from the server's base64) so they feed `add_member` directly.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    /// Server account id (base64).
    pub account_id: String,
    /// Display name the account set for itself, if any.
    pub display_name: Option<String>,
    /// Handle the account set for itself, if any.
    pub handle: Option<String>,
    /// Instance admin.
    pub is_admin: bool,
    /// Member-identity Ed25519 public key (hex).
    pub ed25519_pub_hex: Option<String>,
    /// Member-identity X25519 public key (hex).
    pub x25519_pub_hex: Option<String>,
    /// Account status as the server reports it (`active`, …).
    pub status: String,
    /// Registered devices.
    pub device_count: i64,
}

/// A device under the caller's own account, from `GET /v1/devices`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    /// Server device id (base64).
    pub device_id: String,
    /// Device status as the server reports it (`active`, `revoked`, …).
    pub status: String,
    /// Registration time, Unix seconds.
    pub registered_at: i64,
    /// Sessions currently open on the device.
    pub active_sessions: i64,
}

/// One space the caller is a member of, from `GET /v1/spaces`. `role` is the
/// caller's server-trusted role in that space (`admin`|`member`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceInfo {
    /// Space id (base64) — the cloud-vault binding label.
    pub space_id: String,
    /// Human name of the space.
    pub name: String,
    /// The caller's role in it.
    pub role: String,
}

/// A freshly-minted invite from `POST /v1/invite`. `token` is returned exactly
/// once (only its hash is stored server-side); `url` is the shareable join link
/// when the server has a `public_url` configured, else `None`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteInfo {
    /// Invite id (base64), for revoking it.
    pub invite_id: String,
    /// The single-use secret the invitee redeems.
    pub token: String,
    /// Shareable join link, when the server knows its public URL.
    pub url: Option<String>,
    /// Expiry, Unix seconds.
    pub expires_at: i64,
}

/// One person in the shared directory (`GET /v1/directory`). Pubkeys are hex
/// (converted from the server's base64) so they feed `server_add_member` /
/// `server_add_space_member` directly, matching [`AccountInfo`]'s convention.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryEntry {
    /// Server account id (base64).
    pub account_id: String,
    /// Handle, if set.
    pub handle: Option<String>,
    /// Display name, if set.
    pub display_name: Option<String>,
    /// Member-identity Ed25519 public key (hex).
    pub ed25519_pub_hex: String,
    /// Member-identity X25519 public key (hex).
    pub x25519_pub_hex: String,
    /// Account status as the server reports it.
    pub status: String,
}

/// One outstanding crypto action a vault-admin must fulfil (`GET /v1/pending`):
/// a `grant` or `revoke` for `account_id` on `vault_id`. `vault_id_hex` and the
/// target pubkeys are hex (from the server's base64) so they feed `server_add_member`
/// / `server_rotate_vk`; the server ids (`action_id`, `account_id`) and the opaque
/// binding `proof` stay base64 as the server sends them.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAction {
    /// Action id (base64).
    pub action_id: String,
    /// `grant` or `revoke`.
    pub kind: String,
    /// The vault the action is about (hex).
    pub vault_id_hex: String,
    /// The account the action is about (base64).
    pub account_id: String,
    /// That account's Ed25519 public key (hex).
    pub ed25519_pub_hex: Option<String>,
    /// That account's X25519 public key (hex).
    pub x25519_pub_hex: Option<String>,
    /// The vault role to grant (the core's numeric role), when the action carries one.
    pub crypto_role: Option<i64>,
    /// Where the action came from, as the server labels it.
    pub source: String,
    /// Opaque binding MAC (base64), when there is one.
    pub proof: Option<String>,
    /// Creation time, Unix seconds.
    pub created_at: i64,
}

/// One key-binding attestation about an account (`GET /v1/attestations`). The
/// `blob` + `signature` are opaque base64 the CLIENT verifies (the server never
/// interprets them); `attestor_pubkey` is the attesting device's Ed25519 (base64).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationInfo {
    /// The attesting device's Ed25519 public key (base64).
    pub attestor_pubkey: String,
    /// The attested statement (base64).
    pub blob: String,
    /// Signature over `blob` (base64).
    pub signature: String,
    /// Creation time, Unix seconds.
    pub created_at: i64,
}

/// Everything a new device needs to join, produced by the existing device. It is
/// transferred over a TRUSTED side channel (QR / read-aloud) — the `oob_code` is
/// the PAKE secret, so the relay never sees it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingPayload {
    /// Server base URL.
    pub base_url: String,
    /// Opaque server-instance id (base64) — used to key the new device's link.
    pub instance_id: String,
    /// Cloud-vault binding label (space id, base64) the new device inherits.
    pub space_id: String,
    /// The account being joined (base64).
    pub account_id: String,
    /// The new device's id, pre-created on the server by the existing device.
    pub device_id: String,
    /// Relay channel for the PAKE message exchange.
    pub channel_id: String,
    /// PAKE OOB secret (base64). Transferred only over the trusted side channel.
    pub oob_code: String,
}

impl PairingPayload {
    /// Reads the `key: value` text an existing device's "Add device" card copies
    /// (one line per field, camelCase keys). Lenient the way the app's own paste
    /// box is: order, blank lines and surrounding whitespace do not matter, and a
    /// line is split on its FIRST colon so a URL's own `:` survives. `None` until
    /// every field is present with a value.
    pub fn parse_text(text: &str) -> Option<Self> {
        let mut base_url = None;
        let mut instance_id = None;
        let mut space_id = None;
        let mut account_id = None;
        let mut device_id = None;
        let mut channel_id = None;
        let mut oob_code = None;
        for line in text.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let slot = match key.trim() {
                "baseUrl" => &mut base_url,
                "instanceId" => &mut instance_id,
                "spaceId" => &mut space_id,
                "accountId" => &mut account_id,
                "deviceId" => &mut device_id,
                "channelId" => &mut channel_id,
                "oobCode" => &mut oob_code,
                _ => continue,
            };
            *slot = Some(value.to_owned());
        }
        Some(Self {
            base_url: base_url?,
            instance_id: instance_id?,
            space_id: space_id?,
            account_id: account_id?,
            device_id: device_id?,
            channel_id: channel_id?,
            oob_code: oob_code?,
        })
    }
}

/// A server audit-log entry (observed event). Opaque blobs are omitted.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    /// Position in the audit log.
    pub seq: i64,
    /// The event's source label, as the server records it.
    pub source: String,
    /// Record time, Unix seconds.
    pub recorded_at: i64,
    /// The author's public key (base64), when the event names one.
    pub author_pubkey: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::PairingPayload;

    /// The text the app's "Add device" card copies, pasted the way people paste:
    /// shuffled, with blank lines and padding. A URL's own colons must survive.
    #[test]
    fn pairing_text_parses_in_any_order_and_keeps_url_colons() {
        let text = "\n  oobCode: b29i\nbaseUrl: https://unissh.example:8443\n\n\
                    instanceId: aW5z\nspaceId: c3Bj\naccountId: YWNj\n\
                    deviceId: ZGV2\nchannelId: Y2hu  \n";
        let p = PairingPayload::parse_text(text).expect("every field is present");
        assert_eq!(p.base_url, "https://unissh.example:8443");
        assert_eq!(p.channel_id, "Y2hu");
        assert_eq!(p.oob_code, "b29i");
    }

    /// A paste cut short (the terminal swallowed the last line) must not yield a
    /// payload with an empty secret — it is incomplete, and says so with `None`.
    #[test]
    fn pairing_text_with_a_missing_or_empty_field_is_incomplete() {
        let full = "baseUrl: https://u\ninstanceId: a\nspaceId: b\naccountId: c\n\
                    deviceId: d\nchannelId: e\n";
        assert!(
            PairingPayload::parse_text(full).is_none(),
            "no oobCode line"
        );
        let empty = format!("{full}oobCode:   \n");
        assert!(
            PairingPayload::parse_text(&empty).is_none(),
            "an empty oobCode"
        );
    }
}
