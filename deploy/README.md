# UniSSH — Deployment

Production deployment of the UniSSH self-hosted server: a single **Caddy** front
door (TLS + SPA + API reverse proxy) in front of the **UniSSH server** (plain
HTTP on an internal network), with **SQLite** by default and optional
**Postgres** / **Prometheus** profiles.

```
            :80 / :443                internal compose network "unissh"
  client ───────────────►  caddy  ──────────────────►  server  (:8443 HTTP)
                            │ TLS                        │
                            │ SPA (/srv, same-origin)    └─ :9090 /metrics
                            └─ proxy /v1 /healthz /readyz    (internal only)
```

## Quick start (production)

The production stack is the **`compose.yml` at the repo root** (build context
`.` so `rust-core/`, `server/`, and `server-ui/` are all in one context).

```bash
cp deploy/.env.example .env      # at the repo root, next to compose.yml
$EDITOR .env                     # set UNISSH_DOMAIN (+ a TLS directive); rest is optional
docker compose up -d --build
```

- Only **Caddy** publishes host ports: **80** and **443** (443/udp for HTTP/3).
- The server is **never** host-published; Caddy reaches it as `http://server:8443`.
- Migrations auto-apply on boot (SQLite). The SPA is served same-origin, so the
  admin panel and its API share one origin (CORS stays off).

Open `https://<UNISSH_DOMAIN>/`.

### First-run: claim the instance

There is **no bootstrap token**. On first boot, while the instance is still
unclaimed, the server prints a one-time **SETUP CODE** to its log. Read it, then
claim the instance from the client or the admin panel — the first user to claim
becomes the **owner**:

```bash
docker compose logs server 2>&1 | grep -i "setup code"
```

Open `https://<UNISSH_DOMAIN>/`, enter the setup code to claim, and you're the
owner. From there teammates join via a space-scoped **invite link** or **SSO**
(if `[oidc]` is enabled) — no code needed. For IaC/automation, pin a
deterministic code with `UNISSH__SETUP__CODE=…` instead of the random one.

**Admin-panel sign-in.** After claiming, the panel logs in by **escrow**
(handle + password + Secret Key — the keyset is recovered and unlocked
in-browser, never on the server) or by **SSO**. There is no `.keyset` file to
import and no ops-token to enter first. The optional server-trusted **ops**
break-glass token (`UNISSH__OPS__TOKEN`, `X-UniSSH-Ops-Token` header) unlocks
only the `/v1/ops/*` infrastructure surface (overview / instance / `seq-bump`)
and grants **no** decryption.

## TLS strategy

Caddy is the **only** TLS terminator and the only host-exposed service. The
UniSSH server always runs **plain HTTP** behind it:
`UNISSH__SERVER__TLS_CERT`/`TLS_KEY` are empty (→ `TlsPlan::Plain`) and
`UNISSH__SERVER__TRUST_PROXY=true`. The server **never** does ACME —
`server.acme=true` is a hard startup error — so all certificate management lives
in Caddy. Switching TLS modes is purely a Caddy/env change; no server rebuild.

TLS is controlled by a single env knob, `UNISSH_TLS_DIRECTIVE`:

- **Public domain (automatic ACME):** set `UNISSH_DOMAIN` to your real domain and
  `UNISSH_TLS_DIRECTIVE="tls you@example.com"` (the email enables expiry notices;
  leave it empty for ACME without an account email). Caddy gets a public cert
  (Let's Encrypt / ZeroSSL via HTTP-01 or TLS-ALPN-01). Port 80 must be reachable
  for the challenge + HTTP→HTTPS redirect.
- **LAN / air-gapped (self-signed internal CA):** set `UNISSH_DOMAIN` to a local
  host (e.g. `unissh.local`) or an IP and set `UNISSH_TLS_DIRECTIVE="tls internal"`
  in `.env`. Caddy issues a cert from its own internal CA. Trust Caddy's root CA
  on clients (export it from the `caddy-data` volume at
  `/data/caddy/pki/authorities/local/root.crt`) or accept the self-signed cert.

The `caddy-data` volume persists issued certs / the internal CA root — keep it.

## Content Security Policy / wasm

The admin panel uses `crypto-wasm` (wasm-bindgen), which requires
`script-src 'self' 'wasm-unsafe-eval'`. Because the SPA is served same-origin and
its API client uses a relative base (`instanceUrl` defaults to `""`), all fetches
hit `/v1` and `/readyz` on the page origin, so `connect-src 'self'` suffices and
CORS stays disabled. The full CSP is set in `deploy/Caddyfile`.

## Health checks & the distroless no-shell limitation

The server image is `gcr.io/distroless/cc-debian12:nonroot` — it has **no shell
and no curl/wget**, and the binary has **no `health` subcommand** (only
`serve` / `migrate` / `seq-bump`). Therefore the `server` service has **no Docker
`HEALTHCHECK`** by design.

Health is observed at the proxy instead:
- Caddy reverse-proxies `/healthz` and `/readyz` to the server, so external
  health probes hit `https://<domain>/readyz`.
- Caddy's `reverse_proxy ... health_uri /readyz` actively health-checks the
  upstream and stops routing to it when unhealthy.
- **Postgres** (profile) has a real container healthcheck (`pg_isready`), which
  gates the migrate init container.

## Database

**SQLite (default).** Single named volume `unissh-data` mounted at `/app/data`
(owned by uid 65532, the distroless nonroot user). Rootfs is read-only with a
`tmpfs` `/tmp`. Migrations auto-apply on boot. **The default SQLite path needs
no database secrets** — `POSTGRES_PASSWORD` is **not** required, and
`docker compose config` resolves with only `UNISSH_DOMAIN` set (no `.env`).

**Postgres (profile `postgres`).** Adds a `postgres:16-alpine` service (with a
`pg_isready` healthcheck) and a one-shot `unissh-server-migrate` init container
that runs `unissh-server migrate` **after** Postgres is healthy and **before**
the server connects.

> **Important — the `postgres` profile REQUIRES `POSTGRES_PASSWORD`.** There is
> no safe default (the `postgres:16` image refuses to start with an empty
> password, so an unset password fails loud at container start). The migrate
> init container composes its DSN from `POSTGRES_USER` / `POSTGRES_PASSWORD` /
> `POSTGRES_DB` (single source of truth), so those vars are the one place to set
> Postgres credentials.

> **Important — profiles cannot rewrite the default service env.** Starting the
> `postgres` profile only *adds* the Postgres service + migrate container. To
> actually make the `server` use Postgres you must also set, in `.env`:
>
> ```
> POSTGRES_PASSWORD=<POSTGRES_PASSWORD>          # REQUIRED for this profile
> UNISSH__DB__BACKEND=postgres
> UNISSH__DB__URL=postgres://unissh:<POSTGRES_PASSWORD>@postgres:5432/unissh
> ```
>
> then:
>
> ```bash
> docker compose --profile postgres up -d --build
> ```

## Monitoring (profile `monitoring`)

Adds Prometheus scraping `server:9090` (`deploy/prometheus.yml`) over the
internal network. The metrics listener (`UNISSH__OBS__METRICS_BIND=0.0.0.0:9090`)
is **never** host-published. Prometheus itself is internal by default; uncomment
its `ports` in `compose.yml` for local UI access.

```bash
docker compose --profile monitoring up -d
```

## Secrets

All secrets come from the gitignored `.env` (template: `deploy/.env.example`);
nothing secret is baked into images. Config uses figment env keys
`UNISSH__SECTION__KEY` (double underscore). Generate strong tokens with
`openssl rand -hex 32`.

## Maintenance

- **Rollback / sequence floor:** `docker compose run --rm server seq-bump ...`
  (see `server/src/main.rs` for `seq-bump` usage).
- **Backup (SQLite):** stop the stack or snapshot the `unissh-data` volume
  (`/app/data/unissh.db`). **Backup (Postgres):** `pg_dump` the `postgres`
  service / snapshot the `unissh-pg` volume.

## Dev variant (single service, no Caddy)

`server/docker-compose.yml` is a **minimal single-service dev variant**: it
builds only the server (context = repo root) and publishes `8443` as **plain
HTTP** bound to `127.0.0.1` only (localhost) for local API poking — **no TLS, no
Caddy, no SPA**. Because there is no proxy in front of it, it runs with
`UNISSH__SERVER__TRUST_PROXY=false`. Use it only for local development, never in
production:

```bash
docker compose -f server/docker-compose.yml up --build
# curl http://localhost:8443/readyz
```

The production path is always the root `compose.yml`.
