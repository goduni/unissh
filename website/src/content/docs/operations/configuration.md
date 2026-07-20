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

The server stores only `sha256(code)`, and the code is valid **only while the instance is unclaimed** — a second claim is refused. Read the printed code with `docker compose logs server 2>&1 | grep -i "setup code"`. See the [Docker Compose deployment](../deploy/).

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
