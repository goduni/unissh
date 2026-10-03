---
title: Server configuration
description: The layered configuration for the UniSSH server — the config.toml sections, environment-variable overrides, the TLS strategy, the setup code, SSO, and the optional ops break-glass token.
---

The UniSSH server is configured in layers: **defaults → `config.toml` → environment**. Environment keys use the form `UNISSH__SECTION__KEY=...` (double-underscore nesting). Secrets (TLS key, Postgres URL, and the optional ops token) should come from the environment or Docker secrets, never the committed file.

Start from the shipped template:

```bash
cp config.example.toml config.toml
```

## Sections

### `[server]`

```toml
[server]
bind = "0.0.0.0:8443"
public_url = ""                  # external base URL for links/redirects;
                                 # empty → derived from the request
tls_cert = "/secrets/cert.pem"   # in-process TLS 1.3 (rustls)
tls_key  = "/secrets/key.pem"
trust_proxy = false
acme = false
```

Set `tls_cert`/`tls_key` for in-process **rustls (TLS 1.3 only)**, or leave them empty and terminate TLS at a reverse proxy with `trust_proxy = true`. `public_url` is the externally reachable base URL (used when the server builds links); leave it empty to derive it from the request. A `cors_allowed_origins` key (a list, empty by default) adds extra browser origins for CORS — unneeded in the same-origin Compose deployment, where CORS stays off.

:::caution[No in-process ACME]
`acme = true` is a **hard startup error** — the server never does ACME itself. Use a reverse proxy (Caddy/nginx) or supply `tls_cert` + `tls_key`. The recommended [Docker Compose deployment](../deploy/) terminates TLS in Caddy and runs the server as plain HTTP behind it with `trust_proxy = true`.
:::

### `[db]`

```toml
[db]
backend = "sqlite"               # "sqlite" | "postgres"
url = "/app/data/unissh.db"      # sqlite: file path (or ":memory:")
                                 # postgres: postgres://user:pass@host/db
max_connections = 16
```

### `[limits]`

Request and object bounds, plus a per-IP rate limit.

```toml
[limits]
max_body_bytes = 16777216        # 16 MiB
max_object_bytes = 1048576       # 1 MiB
max_objects_per_push = 1000
delta_page_size = 500
delta_max_page_size = 1000
rate_limit_per_ip_rps = 20
rate_limit_burst = 40
```

### `[sync]`

```toml
[sync]
freshness_window_seconds = 30    # window for online-only live-grants
validate_signatures = true       # defense-in-depth record-signature checks
min_instance_generation = 0      # anti-rollback floor (Σ next_seq); 0 = off
```

- **`validate_signatures`** (on by default) re-verifies each Vault/Item/Manifest/Grant record's Ed25519 signature on write, byte-exact with the core, dropping forged/tampered objects early. This is **defense-in-depth, not the security boundary** — the client still re-verifies on read.
- **`min_instance_generation`** is an **operator-anchored, out-of-band** floor for the instance-wide sequence (`next_seq`). The server **refuses to boot** if a restored snapshot is below it, closing the new-client/TOFU rollback gap. Anchor this value outside the database. See [Backups & anti-rollback restore](../backups/) and the [sync model](../../architecture/sync-model/).

### `[session]`

Token and lifecycle TTLs (seconds):

```toml
[session]
access_ttl_seconds = 900
refresh_ttl_seconds = 2592000
nonce_ttl_seconds = 120
invite_default_ttl_seconds = 86400
relay_ttl_seconds = 120
janitor_interval_seconds = 300
idempotency_ttl_seconds = 86400
```

### `[obs]`

```toml
[obs]
log_format = "json"              # "json" | "text"
otel_endpoint = ""               # OTLP export is NOT compiled in: a value here
                                 # only warns at startup. Metrics: /metrics.
metrics_bind = "127.0.0.1:9090"
```

### `[setup]`

Controls the one-time **setup code** that the first user presents to **claim** the instance and become its **owner**. There is **no bootstrap token**.

```toml
[setup]
code = ""                        # empty → a random setup code is printed to the
                                 # server log on first boot (while unclaimed);
                                 # set a value to pin a deterministic code for IaC.
                                 # Env: UNISSH__SETUP__CODE
```

The server stores only `sha256(code)`, and the code is valid **only while the instance is unclaimed** — a second claim is refused. Read the printed code with `docker compose logs server 2>&1 | grep -i "setup code"`. Because only the hash is kept, a generated code cannot be printed a second time; if the log is gone, `unissh-server setup-code --rotate --config <your config>` issues a new one without touching any data (point it at the config you serve with — the default database path is relative, so a different working directory silently creates an empty one) (a *pinned* code is never printed at all — it came from you). See the [Docker Compose deployment](../deploy/).

### `[oidc]`

Optional **SSO** (OpenID Connect). Disabled by default; when enabled, the login screen offers "Sign in with SSO", and IdP groups map to space memberships (reconciled on every login).

```toml
[oidc]
enabled = false
issuer = ""                          # IdP issuer URL
client_id = ""
audience = ""                        # expected id_token `aud`; empty → client_id
jwks_url = ""                        # empty → {issuer}/.well-known/jwks.json
groups_claim = "groups"              # id_token claim holding the group list
max_reassertion_age_seconds = 604800 # 7 days before a full OIDC re-auth
# [[oidc.group_map]]                 # repeat per mapping: IdP group → space membership
# group = "engineering"
# space_id = "<space-id>"
# role = "member"
```

SSO asserts **identity + space memberships only — never vault keys**: the id_token is verified against the issuer JWKS and bound to the presented keyset via an OIDC nonce, and dropping an IdP group removes that space on the next login.

### `[ops]`

An **optional break-glass** operator surface (`/v1/ops/*`, header `X-UniSSH-Ops-Token`), **off by default**:

```toml
[ops]
token = ""                       # empty → ops surface DISABLED (the default)
                                 # set via UNISSH__OPS__TOKEN
```

This is **server-trusted infrastructure access** (overview / instance / `seq-bump`), **not** a keyset and never decryption. It is not how the [admin panel](../../components/server-ui/) normally signs in — the panel authenticates by escrow or SSO; the ops token is a last-resort infrastructure lever.

### `[audit]`

Optional **audit export sinks**. Absent means the server exports nothing; sinks are configured here only, never through the API. The log holds server events only: SSH sessions never pass through the server and are not recorded here (see [the audit log](../../components/server-audit/)).

```toml
[audit.webhook]
url = "https://siem.example.com/unissh"
secret_env = "UNISSH_AUDIT_WEBHOOK_SECRET"   # or: secret_file = "/run/secrets/audit_webhook"
batch_size = 100                             # entries per POST
timeout_secs = 10                            # a timeout fails the batch
```

The webhook POSTs batches of entries as JSON, each entry shaped like a line of the [JSON Lines export](../../components/server-audit/#export-json-lines), with `X-UniSSH-Signature: sha256=<hex HMAC-SHA256 of the body>` and `X-UniSSH-Delivery: <first seq>-<last seq>`. A `2xx` acknowledges the batch; anything else, a redirect or a timeout retries the **same** batch with exponential backoff (1 s up to 5 min, with jitter).

- **The secret never goes in the TOML.** `secret_env` names an environment variable that holds it; `secret_file` is a path to a file that holds it (a trailing newline is ignored). Set exactly one. A webhook without a readable secret is a **startup error**.
- **The HMAC key is the secret's literal bytes**, exactly as written. A hex- or base64-looking secret is not decoded, so receivers must not decode it either.
- **Use `https://`.** Batches carry audit entries and metadata; a plain `http://` URL to a non-loopback host is accepted but warned about at boot.
- A section whose `url`, `secret_env` and `secret_file` are all empty counts as absent (so a deployment can pass empty variables through); a partly set one fails startup.
- **At-least-once.** The server records the last acknowledged `seq` and resumes after it on restart. A batch can arrive twice (for example, a crash right after the receiver answered), so **receivers dedupe on `seq`**.
- Every key also works from the environment: `UNISSH__AUDIT__WEBHOOK__URL`, `UNISSH__AUDIT__WEBHOOK__SECRET_ENV`, and so on.
- Writing the receiver: the body, the signature recipe with a worked example, and the dedupe rule are in [Audit webhook integration](../../components/audit-webhook/).

```toml
[audit.syslog]
address = "127.0.0.1:514"   # host:port of the collector; IPv6 in brackets: "[::1]:514"
protocol = "tcp"            # "tcp" (default) or "udp"
facility = "auth"           # kern, user, ..., auth, authpriv, ..., local0..local7
app_name = "unissh"         # RFC 5424 APP-NAME
```

The syslog sink sends one [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424) message per entry, at severity `notice`:

```text
<37>1 2026-10-03T09:12:44Z unissh.example.com unissh - login [unissh@32473 seq="42" event="login" space_id="" vault_id=""] {"event":"login",...}
```

- **Header.** The timestamp is the entry's `recorded_at` (UTC). The hostname is the host of `server.public_url`, or `-` when it is unset. MSGID is the event kind, or `-` when there is none.
- **Structured data.** `unissh@32473` carries `seq`, `event`, `space_id` and `vault_id` (base64; empty when the entry has none, and `event` is empty for a client-signed entry). UniSSH has no IANA Private Enterprise Number of its own, by design; 32473 is the number [RFC 5612](https://www.rfc-editor.org/rfc/rfc5612) reserves for documentation. `unissh@32473` is a frozen wire identifier: collector parsers key on it, so changing it would be a breaking change.
- **Body.** The entry exactly as in the JSON Lines export's `entry`: compact JSON for a server event, the base64 of the blob for a client-signed entry. It is UTF-8 sent as RFC 5424 MSG-ANY **without a BOM**, so collectors should not expect one. For chain verification use the export or the webhook, which carry `entry_blob` and the hash fields.
- **UDP vs TCP.** **UDP sends and forgets:** the cursor advances once every datagram of a batch is sent, so a datagram lost on the way is lost. An entry too large for one datagram (65,507 bytes over IPv4, 65,527 over IPv6) is skipped with a `udp_oversize` warning naming its `seq`, so it never holds back later entries; use TCP if entries can be that large. **TCP** uses octet counting ([RFC 6587](https://www.rfc-editor.org/rfc/rfc6587)) on one persistent connection, re-opened after an error, and advances the cursor only after the write succeeds; otherwise the same batch is retried with backoff.
- **No TLS.** Syslog goes out in plaintext; a non-loopback collector is warned about at boot. Use a forwarder on the same host (rsyslog, syslog-ng, Vector) to carry it further over TLS.
- Both sinks can be configured at once; each keeps its own cursor, so one sink's outage does not hold back the other.
- Each sink's last delivered `seq`, lag and last error show on the admin panel's audit screen and at `GET /v1/admin/audit/sinks`; Prometheus gets `unissh_audit_sink_delivered_seq{sink}` and `unissh_audit_sink_failures_total{sink}` (see [watching the sink](../../components/audit-webhook/#watching-the-sink)).
- An empty `address` with every other key empty or default counts as absent; an empty `protocol`, `facility` or `app_name` takes its default. A bad address, protocol, facility or app name is a **startup error**. From the environment: `UNISSH__AUDIT__SYSLOG__ADDRESS`, `UNISSH__AUDIT__SYSLOG__PROTOCOL`, and so on.

## Environment overrides

Any key maps to an environment variable by uppercasing and joining with double underscores:

```bash
UNISSH__SERVER__BIND=0.0.0.0:8443
UNISSH__SERVER__TRUST_PROXY=true
UNISSH__DB__BACKEND=postgres
UNISSH__DB__URL=postgres://unissh:secret@postgres:5432/unissh
UNISSH__SETUP__CODE=my-pinned-setup-code       # optional — pin instead of a random one
UNISSH__OPS__TOKEN=$(openssl rand -hex 32)      # optional — only if you enable break-glass ops
```

Generate strong tokens with `openssl rand -hex 32`. In the Compose stack these live in a gitignored `.env`; nothing secret is baked into images. See [Docker Compose deployment](../deploy/).
