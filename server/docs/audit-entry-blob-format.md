# Audit `entry_blob` format (for UI rendering)

Reference for rendering `GET /v1/audit` entries in the admin panel. Resolves
handoff **P3.9**.

**This log records server events only. SSH sessions never pass through the server and are not recorded here.** The server is a control plane: SSH connections, commands and file transfers go directly from the client to the host and leave no trace in this log.

`GET /v1/audit?since_seq&limit` returns:

```json
{
  "entries": [
    {
      "seq": 42,
      "entry_blob": "<base64>",
      "signature": "<base64|null>",
      "author_pubkey": "<base64|null>",
      "recorded_at": 1700000000,
      "source": "server-observed"
    }
  ],
  "has_more": false,
  "next_since": 43
}
```

The shape of the **decoded** `entry_blob` depends entirely on `source`. Branch on
`source` first.

---

## 1. `source: "server-observed"`

`entry_blob` is **UTF-8 JSON** — `JSON.parse(atob(entry_blob))` yields an object.
The server writes these for lifecycle actions it performs itself; there is no
client signature, so `signature` and `author_pubkey` are `null`.

Every server-observed event has:

| Field   | Type             | Notes                                  |
|---------|------------------|----------------------------------------|
| `event` | string (enum)    | Discriminator — see table below.       |
| `ts`    | int (unix secs)  | Server clock at the time of the action. Equals `recorded_at`. |

Additional fields per `event`:

| `event`              | Extra fields                                  | Emitted when                                        |
|----------------------|-----------------------------------------------|-----------------------------------------------------|
| `login`              | `account_id`, `device_id`                     | `POST /v1/auth/verify` succeeds.                    |
| `logout`             | `account_id`, `device_id`                     | `POST /v1/session/logout`.                          |
| `join`               | `account_id`, `device_id`                     | `POST /v1/join` redeems an invite → new account.    |
| `oidc_login`         | `account_id`, `device_id`                     | `POST /v1/oidc/callback` (SSO).                     |
| `device_add`         | `account_id`, `device_id`                     | A new sibling device is registered (`POST /v1/devices/add`). |
| `device_self_enroll` | `account_id`, `device_id`                     | An account self-enrolls a further device (`POST /v1/devices/self-enroll`). |
| `device_remove`      | `account_id`, `device_id`                     | `POST /v1/session/device-revoke`.                   |
| `keyset_publish`     | `account_id`, `device_id`                     | A keyset generation is published (`PUT /v1/keyset`).|
| `key_attest`         | `account_id`, `attestor_pubkey`               | A space-admin attests a member's key.               |
| `owner_grant`        | `account_id`                                  | `POST /v1/owner/set {is_owner:true}`.               |
| `owner_revoke`       | `account_id`                                  | `POST /v1/owner/set {is_owner:false}`.              |
| `account_disable`    | `account_id`                                  | `POST /v1/admin/account/status {disabled:true}`.    |
| `account_enable`     | `account_id`                                  | `POST /v1/admin/account/status {disabled:false}`.   |
| `space_create`       | `space_id`, `account_id`                      | `POST /v1/spaces`.                                  |
| `space_member_add`   | `space_id`, `account_id`                      | `POST /v1/spaces/members`.                          |
| `space_member_remove`| `space_id`, `account_id`                      | `POST /v1/spaces/members/remove`.                   |
| `space_member_role`  | `space_id`, `account_id`                      | `POST /v1/spaces/members/role`.                     |
| `invite_create`      | `invite_id`, `account_id`                     | `POST /v1/invite`.                                 |
| `invite_revoke`      | `invite_id`, `account_id`                     | `POST /v1/invite/revoke`.                           |
| `access_grant`       | `vault_id`, `new_epoch`, `revoke_epoch` (int\|null) | `POST /v1/grants/publish` (membership publish / rotation / revoke). The entry's top-level `vault_id` column is also set. |

`account_id`, `device_id`, `space_id`, `invite_id`, `vault_id`, and
`attestor_pubkey` values are **base64** (same encoding as the rest of the API).
The instance **owner** is established at claim (a server-side lifecycle event,
not one of the rows above); subsequent changes surface as `owner_grant` /
`owner_revoke`. Treat the `event` set as **open** — render unknown `event`
strings generically (show `event` + remaining keys) rather than failing.

Example decoded blob:

```json
{ "event": "login", "account_id": "Ym9i...", "device_id": "ZGV2...", "ts": 1700000000 }
```

---

## 2. `source: "client-signed"`

`entry_blob` is **opaque canonical bytes** produced and signed by the client
(rust-core), submitted via `POST /v1/audit` or a sync push. The server stores
it verbatim and **does not parse it** — it only enforces that `author_pubkey`
equals the instance **owner** and that `signature` verifies.

For these entries:

- `signature` and `author_pubkey` are **present** (non-null, base64).
- The internal structure of `entry_blob` is **not defined by the server**. A
  dedicated `audit` crate (rust-core, milestone 2) will fix the canonical
  domain/format; until then it is application-defined and may not be JSON.

**UI guidance:** do **not** assume JSON. Render client-signed entries from the
envelope metadata the server does expose — `seq`, `recorded_at`,
`author_pubkey`, "signed ✓" — and show `entry_blob` as hex/base64 (collapsible),
not as parsed fields. Attempting `JSON.parse` will throw for most client-signed
blobs.

---

## 3. Tamper-evidence (context)

Independent of `entry_blob` content, the whole log is a hash chain
(`prev_hash[n] = SHA-256(prev_hash[n-1] ‖ record_bytes(n))`, domain
`unissh-audit-chain-v2`). The UI verifies integrity via
`GET /v1/admin/audit/verify` → `{ok, count, broken_at, head_hash}` — it does
**not** need to recompute the chain itself, and `prev_hash` is not exposed on the
`/v1/audit` listing.

---

## 4. Export (JSON Lines)

`GET /v1/audit/export?from_seq&to_seq` streams the log as [JSON Lines](https://jsonlines.org/) (`Content-Type: application/jsonl`), one entry per line in `seq` order. It is **owner only** (the same gate as `/v1/admin/*`); the admin panel's audit screen has an **Export** control for it.

- `from_seq` and `to_seq` are optional, inclusive, and must be positive integers with `to_seq >= from_seq` (otherwise `400`). Omitted, the export starts at `1` and ends at the newest entry.
- The upper bound is pinned to the newest entry at request time, so a download is a consistent slice even while the server keeps appending.
- The body is streamed in pages; an error part-way through ends the download early. The chain cannot detect a missing tail, so compare the last line's `seq` with the pinned upper bound in the `Content-Disposition` file name (`unissh-audit-<from>-<to>.jsonl`): they must be equal. A cut-off final line fails to parse.

Each line:

```json
{
  "seq": 42,
  "server_seq": null,
  "source": "server-observed",
  "recorded_at": 1700000000,
  "author_pubkey": null,
  "vault_id": null,
  "space_id": null,
  "prev_hash": "<base64>",
  "signature": null,
  "entry": { "event": "login", "account_id": "Ym9i...", "device_id": "ZGV2...", "ts": 1700000000 },
  "entry_blob": "<base64>"
}
```

Binary fields are base64 or `null`. `entry` is the decoded JSON for a `server-observed` entry and the base64 string for a `client-signed` one (the same value as `entry_blob`). `entry_blob` is always the exact stored bytes: verify against it, not a re-serialised `entry`.

### Verifying an export offline

Recompute the chain from the first exported line. For an export from `seq` 1 the running hash starts at 32 zero bytes; for a range, start from the `prev_hash` of the line before it (in an earlier export). For each line, in order:

```text
record_bytes = "unissh-audit-chain-v2"            (ASCII, no length prefix)
             ‖ seq                                 (i64, big-endian)
             ‖ lp(source)                          (UTF-8)
             ‖ lp(entry_blob)
             ‖ opt(signature)
             ‖ opt(author_pubkey)
             ‖ opt(vault_id)
             ‖ recorded_at                         (i64, big-endian)
             ‖ server_seq                          (i64, big-endian; -1 when null)

lp(x)  = len(x) as u32 big-endian ‖ x
opt(x) = 0x00 when null, else 0x01 ‖ lp(x)

chain = SHA-256( chain ‖ record_bytes )   and it must equal the line's prev_hash
```

`space_id` is exported for context but is not part of `record_bytes`. The last line's `prev_hash` of a whole-log export equals the `head_hash` returned by `GET /v1/admin/audit/verify` at that point. A matching chain proves the file was not edited, reordered or cut in the middle; as with the server-side check, it does not by itself prove that no entries were dropped from the tail, so keep the head hash of each export to compare with the next.

---

## Rendering decision tree (pseudocode)

```ts
const blob = atob(entry.entry_blob);
if (entry.source === "server-observed") {
  const ev = JSON.parse(blob);            // always valid JSON
  renderEvent(ev.event, ev);              // unknown ev.event → generic row
} else {
  // "client-signed": opaque, signed
  renderSigned({
    author: entry.author_pubkey,
    recordedAt: entry.recorded_at,
    rawHex: toHex(blob),                  // do NOT JSON.parse
  });
}
```
