---
title: Audit webhook integration
description: How to receive the UniSSH audit log over the webhook sink — the request body, the HMAC-SHA256 signature with a worked example, the at-least-once contract and dedupe on seq, retries, and how to watch a sink's status.
---

The server can push its [audit log](../server-audit/) to a receiver you run, such as a SIEM ingest endpoint or a small service that archives it. This page is for whoever writes that receiver. How to switch the sink on is covered under [`[audit]` in the server configuration](../../operations/configuration/#audit).

**This log records server events only. SSH sessions never pass through the server and are not recorded here.**

## The request

Each delivery is one HTTP request:

```http
POST /your/path HTTP/1.1
Content-Type: application/json
X-UniSSH-Signature: sha256=<64 lowercase hex chars>
X-UniSSH-Delivery: <first seq>-<last seq>

{"instance":"<instance id, base64>","entries":[ ... ]}
```

- `instance` is this server's instance id (base64). It lets one receiver tell several UniSSH servers apart.
- `entries` holds 1 to `batch_size` (default 100) entries in ascending `seq` order. Each entry object has exactly the fields of a line of the [JSON Lines export](../server-audit/#export-json-lines): `seq`, `server_seq`, `source`, `recorded_at`, `author_pubkey`, `vault_id`, `space_id`, `prev_hash`, `signature`, `entry` and `entry_blob`.
- `entry` is the decoded event for a `server-observed` entry, and the base64 string for a `client-signed` one. The per-event fields (`event`, `account_id`, `device_id`, …) are listed in [the entry format](../server-audit/#source-1--server-observed). Treat the event set as open.
- `entry_blob` is the base64 of the exact stored bytes. The hash chain covers these bytes and not a re-serialised `entry`, so verify the chain from `entry_blob` as described in [Verifying an export offline](../server-audit/#verifying-an-export-offline).
- `X-UniSSH-Delivery` is the `seq` range of the batch, for example `42-57`. It is for logging and quick dedupe. The authoritative values are the `seq` fields in the body.

## Answering

- **Any `2xx` acknowledges the whole batch.** The server then records the batch's last `seq` as delivered and sends what follows.
- **Anything else fails the batch.** That includes any other status, a redirect (redirects are never followed), a connection error, or no answer within `timeout_secs` (default 10 s). The server then sends the **same** batch again, with the same entries, after a backoff. The backoff starts at 1 s, doubles on each failure up to 5 minutes, and is shortened by a random amount of up to 25 % so that many servers do not retry in lockstep. A success resets it.
- Only one batch per sink is in flight at a time, so batches arrive in `seq` order.

Acknowledge only after the entries are stored durably on your side. If you answer `2xx` first and lose the data afterwards, the server will not send it again.

## At-least-once: dedupe on `seq`

Delivery is **at-least-once**. A batch can arrive more than once, for example when the server crashes or loses its database write after you answered `2xx`, or when your `2xx` never reached it. Nothing is ever skipped: the server resumes after the last `seq` it recorded as delivered, including after a restart.

**Receivers dedupe on `seq`.** `seq` is unique per instance and never reused, so `(instance, seq)` identifies an entry. Because batches arrive in order, the simplest rule is to keep the highest `seq` stored per `instance` and drop any entry at or below it. A unique key on `(instance, seq)` works as well.

:::caution[After a database restore]
`seq` is assigned as one more than the newest entry and is never reused while the database lives. If the server's database is restored from an older backup, its log and its sink cursor go back together, and new entries get `seq` values your receiver has already stored, with different content. A receiver that only drops "seen" `seq`s would then silently discard them. Compare the `prev_hash` of a re-sent `seq` with the one you stored: equal means a duplicate; different means the log was rolled back, which is worth an alert.
:::

## Verifying the signature

`X-UniSSH-Signature` is `sha256=` followed by the lowercase hex HMAC-SHA256 of the **raw request body**:

```text
X-UniSSH-Signature = "sha256=" + hex( HMAC-SHA256( key = secret, message = body ) )
```

- **The key is the secret's literal string**, as its UTF-8 bytes, exactly as stored in the variable or file the server reads (`secret_env` / `secret_file`; a trailing newline in the file is ignored). Do not hex- or base64-decode it, even if it looks encoded.
- **The message is the body exactly as received**, before any JSON parsing. Re-serialised JSON will not match.
- Compare in constant time (`hmac.compare_digest`, `crypto.timingSafeEqual`, `hmac.Equal`), and reject the request with a non-`2xx` status if the signature does not match.
- The HMAC proves the batch came from a server that knows the secret and was not altered. It does not encrypt anything, so use an `https://` URL.

### Worked example

With the secret `example-secret` and this body (one line, no trailing newline, 502 bytes):

```json
{"instance":"aW5zdGFuY2UtaWQ=","entries":[{"seq":42,"server_seq":null,"source":"server-observed","recorded_at":1700000000,"author_pubkey":null,"vault_id":null,"space_id":null,"prev_hash":"UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw=","signature":null,"entry":{"account_id":"Ym9iLWFjY291bnQ=","device_id":"Ym9iLWRldmljZQ==","event":"login","ts":1700000000},"entry_blob":"eyJhY2NvdW50X2lkIjoiWW05aUxXRmpZMjkxYm5RPSIsImRldmljZV9pZCI6IlltOWlMV1JsZG1salpRPT0iLCJldmVudCI6ImxvZ2luIiwidHMiOjE3MDAwMDAwMDB9"}]}
```

the header is:

```text
X-UniSSH-Signature: sha256=8006caf6788f2bc1e15ea2c1075275b230f3b3c28110f1ab4bad5d5d936e1f04
```

Check it yourself, with the body saved to `body.json` without a trailing newline:

```bash
openssl dgst -sha256 -hmac 'example-secret' body.json
# HMAC-SHA2-256(body.json)= 8006caf6788f2bc1e15ea2c1075275b230f3b3c28110f1ab4bad5d5d936e1f04
```

A minimal receiver check in Python:

```python
import hashlib, hmac

def verified(secret: str, body: bytes, header: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)
```

The server's own test suite checks this exact example, so the page and the code cannot drift apart.

## Watching the sink

- **Admin panel.** The audit screen shows each configured sink with its last delivered `seq`, its lag behind the newest entry, its last success time and its last error, marked **healthy**, **lagging** or **failing**.
- **API.** `GET /v1/admin/audit/sinks` (instance owner only) returns `{ "sinks": [ { "sink", "last_seq", "lag", "last_success_at", "last_error", "last_error_at" } ] }`. `last_seq` is the persisted cursor, and `lag` is the newest audit `seq` minus `last_seq`. The timestamps and the error are what the running process has seen since it started. `last_error` is a short code such as `http_500`, `timeout` or `connect`, never a URL, a secret or entry contents. The list is empty when no sink is configured.
- **Prometheus.** `unissh_audit_sink_delivered_seq{sink}` is a gauge of the last delivered `seq`, and `unissh_audit_sink_failures_total{sink}` counts failed attempts. `sink` is `webhook` or `syslog`. Alert on a failure rate that stays up, or on the gauge standing still while the log grows.

## Syslog instead

The server can also send each entry as an RFC 5424 syslog message over UDP or TCP. Those messages carry `seq` and the event kind in structured data, with the entry JSON as the body, but not the hash fields. Its format, the UDP and TCP delivery contracts, and the advice to use a local forwarder for TLS are in [`[audit]` in the server configuration](../../operations/configuration/#audit). Both sinks can run at once, each with its own cursor.
