---
title: Docker Compose deployment
description: Deploy the UniSSH self-hosted server with Docker Compose — a Caddy front door for TLS and the SPA, with SQLite, Postgres, and monitoring profiles.
---

The production deployment is a single **Caddy** front door (TLS + the admin SPA + an API reverse proxy) in front of the **UniSSH server** (plain HTTP on an internal network), with **SQLite** by default and optional **Postgres** / **Prometheus** profiles.

```
            :80 / :443                internal compose network "unissh"
  client ───────────────►  caddy  ──────────────────►  server  (:8443 HTTP)
                            │ TLS                        │
                            │ SPA (same-origin)          └─ :9090 /metrics
                            └─ proxy /v1 /healthz /readyz    (internal only)
```

## Quick start

The production stack is the **`compose.yml` at the repository root** (build context `.`, so `rust-core/`, `server/`, and `server-ui/` are all in one context).

```bash
cp deploy/.env.example .env      # at the repo root, next to compose.yml
$EDITOR .env                     # set domain, email, and secrets
docker compose up -d --build
```

- Only **Caddy** publishes host ports: **80** and **443** (443/udp for HTTP/3).
- The server is **never** host-published; Caddy reaches it as `http://server:8443`.
- Migrations auto-apply on boot (SQLite). The SPA is served same-origin, so the admin panel and its API share one origin and **CORS stays off**.

Then open `https://<UNISSH_DOMAIN>/`.

### Prebuilt images instead of building

`compose.yml` **builds from source** — it needs the Rust and Node toolchains and a cold compile. Operators who just want to run the server can use `compose.prod.yml` at the repository root, which pulls **prebuilt multi-arch images** from GHCR (`ghcr.io/goduni/unissh-server` and `ghcr.io/goduni/unissh-caddy`, published by the [`publish-images.yml`](../ci-cd/) workflow):

```bash
docker compose -f compose.prod.yml up -d      # pull + run, no build toolchain
```

Everything else — the `.env`, TLS, profiles, and volumes — is identical to the from-source stack.

## First run: claim the instance

A fresh instance is **unclaimed** and holds no data. On first boot it prints a one-time **setup code** to the server log; the first person to present it becomes the **owner**.

```bash
docker compose logs server 2>&1 | grep -i "setup code"
```

Enter that code on the admin panel's **Claim** screen (or in the desktop client) to take ownership — it is valid only while the instance is unclaimed. See [Server configuration → `[setup]`](../configuration/) and [Admin panel](../../components/server-ui/).

## TLS strategy

Caddy is the **only** TLS terminator and the only host-exposed service. The UniSSH server always runs **plain HTTP** behind it (`UNISSH__SERVER__TLS_CERT`/`TLS_KEY` empty → plain, `UNISSH__SERVER__TRUST_PROXY=true`). The server **never** does ACME — `acme=true` is a hard startup error — so all certificate management lives in Caddy, and switching TLS modes is a Caddy/env change with no server rebuild.

TLS is controlled by one env knob, `UNISSH_TLS_DIRECTIVE`:

- **Public domain (automatic ACME):** set `UNISSH_DOMAIN` to your real domain and `UNISSH_TLS_DIRECTIVE="tls you@example.com"` (the email enables expiry notices; leave it empty for ACME without an account email). Caddy gets a public cert (Let's Encrypt / ZeroSSL via HTTP-01 or TLS-ALPN-01). Port 80 must be reachable for the challenge and the HTTP→HTTPS redirect.
- **LAN / air-gapped (self-signed internal CA):** set `UNISSH_DOMAIN` to a local host (e.g. `unissh.local`) or an IP and `UNISSH_TLS_DIRECTIVE="tls internal"`. Caddy issues a cert from its own internal CA — trust Caddy's root CA on clients (export it from the `caddy-data` volume at `/data/caddy/pki/authorities/local/root.crt`) or accept the self-signed cert.

:::tip[Keep the `caddy-data` volume]
The `caddy-data` volume persists issued certs and the internal CA root. Keep it.
:::

## Content Security Policy / wasm

The admin panel uses `crypto-wasm` (wasm-bindgen), which requires `script-src 'self' 'wasm-unsafe-eval'`. Because the SPA is served same-origin and its API client uses a relative base, all fetches hit `/v1` and `/readyz` on the page origin, so `connect-src 'self'` suffices and CORS stays disabled. The full CSP is set in `deploy/Caddyfile`. See [Admin panel](../../components/server-ui/).

## Health checks

The server image is `gcr.io/distroless/cc-debian12:nonroot` — **no shell, no curl/wget**, and the binary has no `health` subcommand (only `serve` / `migrate` / `seq-bump` / `reclaim`). So the `server` service has **no Docker `HEALTHCHECK`** by design. Health is observed at the proxy instead:

- Caddy reverse-proxies `/healthz` and `/readyz`, so external probes hit `https://<domain>/readyz`.
- Caddy's `reverse_proxy ... health_uri /readyz` actively health-checks the upstream and stops routing to it when unhealthy.
- The **Postgres** profile has a real container healthcheck (`pg_isready`) that gates the migrate init container.

## Database

### SQLite (default)

A single named volume `unissh-data` mounted at `/app/data` (owned by uid 65532, the distroless nonroot user). The rootfs is read-only with a `tmpfs` `/tmp`. Migrations auto-apply on boot. **The default SQLite path needs no database secrets** — `POSTGRES_PASSWORD` is not required, and `docker compose config` resolves with only `UNISSH_DOMAIN` set.

### Postgres (profile `postgres`)

Adds a `postgres:16-alpine` service (with a `pg_isready` healthcheck) and a one-shot `unissh-server-migrate` init container that runs migrations **after** Postgres is healthy and **before** the server connects.

:::caution[Two things the Postgres profile requires]
**1. `POSTGRES_PASSWORD` is mandatory** — there is no safe default (the `postgres:16` image refuses to start with an empty password). The migrate init container composes its DSN from `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB`, so set credentials there.

**2. Profiles cannot rewrite the default service env** — starting the profile only *adds* services. To make the `server` actually use Postgres you must also set, in `.env`:

```bash
POSTGRES_PASSWORD=<password>
UNISSH__DB__BACKEND=postgres
UNISSH__DB__URL=postgres://unissh:<password>@postgres:5432/unissh
```
:::

```bash
docker compose --profile postgres up -d --build
```

## Monitoring (profile `monitoring`)

Adds Prometheus scraping `server:9090` (`deploy/prometheus.yml`) over the internal network. The metrics listener (`UNISSH__OBS__METRICS_BIND=0.0.0.0:9090`) is **never** host-published. Prometheus itself is internal by default; uncomment its `ports` in `compose.yml` for local UI access.

```bash
docker compose --profile monitoring up -d
```

## Secrets

All secrets come from the gitignored `.env` (template: `deploy/.env.example`); nothing secret is baked into images. Config uses figment env keys `UNISSH__SECTION__KEY`. Generate strong tokens with `openssl rand -hex 32`. See [Server configuration](../configuration/).

## Maintenance

- **Rollback / sequence floor:** `docker compose run --rm server seq-bump ...` — see [Backups & anti-rollback restore](../backups/).
- **Backup (SQLite):** stop the stack or snapshot the `unissh-data` volume (`/app/data/unissh.db`).
- **Backup (Postgres):** `pg_dump` the `postgres` service or snapshot the `unissh-pg` volume.

Backups contain **only ciphertext** — zero-knowledge is preserved.

## Dev variant (single service, no Caddy)

`server/docker-compose.yml` is a **minimal single-service dev variant**: it builds only the server and publishes `8443` as **plain HTTP** bound to `127.0.0.1` only — **no TLS, no Caddy, no SPA** — running with `trust_proxy=false`. Use it only for local development, never in production:

```bash
docker compose -f server/docker-compose.yml up --build
# curl http://localhost:8443/readyz
```

The production path is always the root `compose.yml`.
