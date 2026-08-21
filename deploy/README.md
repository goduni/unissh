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
  One of them already taken? See [Port 80 or 443 already in use](#port-80-or-443-already-in-use).
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

Restarted the container before copying that line? Only `sha256(code)` is stored,
so it cannot be printed again — issue a new one instead of re-creating the stack:

```bash
docker compose exec server /usr/local/bin/unissh-server setup-code --rotate --config /app/config.toml
```

The old code stops working, the new one is live immediately (no restart), and the
database is untouched. Run it without `--rotate` to just report where the code
stands. The image is distroless — no shell — so the binary must be named in full.

If the server container is not running (a port conflict, a certificate it cannot
get — the usual reasons you are here), `exec` has nothing to attach to. Use the
stopped-stack form, which mounts the same volume:

```bash
docker compose run --rm server setup-code --rotate --config /app/config.toml
```

Outside Docker, pass the config you serve with: the default database path is
relative, so a different working directory silently creates an empty database and
hands you a confident code for it.

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
- **Certificates you already have:** set
  `UNISSH_TLS_DIRECTIVE="tls /certs/fullchain.pem /certs/privkey.pem"` and mount
  the directory with the `compose.tls-files.yml` override in this folder:
  `docker compose -f compose.prod.yml -f deploy/compose.tls-files.yml up -d`.
  Renewal is NOT picked up on its own — after replacing the files run
  `docker compose exec caddy caddy reload --force --config /etc/caddy/Caddyfile`
  (or `docker compose restart caddy`).
- **LAN / air-gapped (self-signed internal CA):** set `UNISSH_DOMAIN` to a local
  host (e.g. `unissh.local`) or an IP and set `UNISSH_TLS_DIRECTIVE="tls internal"`
  in `.env`. Caddy issues a cert from its own internal CA — and every client
  machine must then TRUST that root (export it from the `caddy-data` volume at
  `/data/caddy/pki/authorities/local/root.crt` and install it in the OS trust
  store). The client verifies against the OS store, has no "accept anyway"
  prompt, and refuses plain `http://` to a non-loopback host. The
  `"certutil" is not available` line older images logged was about trusting the
  root *inside the container* — unrelated to clients, and suppressed now via
  `skip_install_trust` in the Caddyfile.

The `caddy-data` volume persists issued certs / the internal CA root — keep it.

## Port 80 or 443 already in use

The published ports are variables, so a host that already serves something on
80 or 443 is a two-line `.env` change rather than a fork of a tracked compose
file:

```bash
# .env
UNISSH_HTTP_PORT=8080
UNISSH_HTTPS_PORT=8443
```

```bash
docker compose config | grep -B1 -A2 published   # resolved mapping, nothing started
docker compose up -d
curl -kI https://<UNISSH_DOMAIN>:8443/readyz
```

Both default to today's values, so a stack that sets neither publishes exactly
what it always did. They work the same in `compose.yml` and `compose.prod.yml`,
take a **port number** (not an interface prefix — for loopback-only use
`compose.behind-proxy.yml` below), and `UNISSH_HTTPS_PORT` carries the HTTP/3
(QUIC) UDP mapping with it, so HTTPS and HTTP/3 can never land on different
ports. Only the host side moves: inside the container Caddy still listens on
80/443, so the Caddyfile and every override in this folder are untouched. (One
visible consequence of that: Caddy advertises HTTP/3 as `alt-svc: h3=":443"`,
the port it listens on inside. `Alt-Svc` is an optional hint — a client that
cannot reach h3 there just keeps the connection it already has
([RFC 7838](https://www.rfc-editor.org/rfc/rfc7838.html)) — so a browser on a
moved HTTPS port stays on HTTP/2. The UDP mapping is published either way.)

Set `UNISSH__SERVER__PUBLIC_URL=https://<domain>:8443` to match, or invite links
come out pointing at the port you no longer serve. Caddy's HTTP→HTTPS redirect
targets the site address with no port, so browse the HTTPS port directly.

> **Moving the HTTP port breaks automatic ACME.** The challenge GET "MUST be
> sent to TCP port 80"
> ([RFC 8555 §8.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-8.3)),
> and Let's Encrypt follows redirects "only to ports 80 or 443"
> ([Challenge Types](https://letsencrypt.org/docs/challenge-types/)) — so the
> obvious fix, a 301 from the busy port to the one you picked, does **not**
> work either. What does depends on *what* owns port 80:
> - **Nothing on this host** — the host is not the edge, or the conflict is
>   elsewhere. Forward public `:80` to your chosen port upstream (router, NAT
>   rule, cloud load balancer). The challenge arrives on the moved port and
>   succeeds.
> - **Another HTTP server on this host** (nginx, Apache, another Caddy — the
>   usual reason you are here). Have it **proxy** `/.well-known/acme-challenge/*`
>   to your chosen HTTP port — a proxy_pass, not a redirect, per the port rule
>   above. Do not NAT-redirect all of `:80` either: that hijacks the traffic of
>   the service that owns the port. And weigh `compose.behind-proxy.yml` first —
>   a proxy already terminating TLS for other sites can do it for this one, and
>   then no port has to move at all.
> - **Neither is workable** — use a TLS mode that needs no challenge:
>   `UNISSH_TLS_DIRECTIVE="tls internal"` for a LAN host, or certificate files
>   obtained some other way (DNS-01, a commercial cert) via
>   `compose.tls-files.yml`.
>
> Moving **only** `UNISSH_HTTPS_PORT` is safe for ACME — HTTP-01 still runs on
> 80. (TLS-ALPN-01, which would need 443, simply stops being an option.)

The nginx form of the second case, on the server that holds `:80`:

```nginx
location /.well-known/acme-challenge/ {
    proxy_pass http://127.0.0.1:8080;   # your UNISSH_HTTP_PORT
    proxy_set_header Host $host;
}
```

The `Host` line is load-bearing. Drop it and the request reaches Caddy as
`Host: 127.0.0.1:8080`, which matches no site it serves, so it answers the
challenge with a redirect elsewhere and validation fails — with a connection
error that says nothing about the header. Both outcomes were reproduced against
a local ACME server before this was written.

If the reason 443 is busy is that **you already run a proxy there**, these
variables are the wrong tool: use `compose.behind-proxy.yml` and let that proxy
terminate TLS in front of the stack — see *Other front doors* just below.

## Other front doors

- `compose.tls-files.yml` — Caddy, but with certificate files you supply.
- `compose.behind-proxy.yml` — Caddy stays as a PLAIN-HTTP front on
  `127.0.0.1:8080` (SPA + API), for a proxy you already run to terminate TLS in
  front of. Recommended: the panel keeps travelling with the image, so upgrades
  need no file syncing.
- `compose.traefik.yml` — the same, published through an existing Traefik by
  labels over a shared Docker network; nothing host-published.
- `compose.reverse-proxy.yml` — no bundled Caddy at all; publishes the API on
  `127.0.0.1:8443` for a proxy that will also serve the SPA itself.
- `nginx/unissh.conf` — TLS + one proxy_pass to the stack (pairs with
  compose.behind-proxy.yml).
- `nginx/unissh-static-spa.conf` — nginx doing the Caddyfile's whole job: TLS,
  the SPA from disk, the API proxied straight to the server (pairs with
  compose.reverse-proxy.yml). One hop, so the server sees real client IPs.

Full write-up, including client-side CA trust and a no-proxy variant:
<https://unissh.dev/operations/deploy-scenarios/>.

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
