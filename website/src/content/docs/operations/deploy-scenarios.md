---
title: Deployment scenarios
description: Five ways to put TLS in front of a self-hosted UniSSH server — automatic certificates, certificates you already have, a proxy you already run, a LAN with no public DNS, and no proxy at all.
---

The [Docker Compose deployment](../deploy/) ships one path: Caddy in front, an automatic Let's Encrypt certificate, panel and API on one origin. This page covers what to do when your situation is different.

## Find your situation

| | Scenario |
| --- | --- |
| Public domain, let it handle certificates | **[1 — automatic](#1--automatic-certificates)** |
| You already hold a certificate | **[2 — your own certificate](#2--your-own-certificate)** |
| Something already owns ports 80/443 here | **[3 — behind a proxy you run](#3--behind-a-proxy-you-run)** |
| LAN, air-gapped, IP only — no public DNS | **[4 — private CA](#4--private-ca-lan--air-gapped)** |
| One admin, no panel, no proxy | **[5 — no proxy at all](#5--no-proxy-at-all)** |

In every one of them the UniSSH server itself is identical — plain HTTP on an internal network, `trust_proxy = true`, never any ACME. Only the front door changes.

## Two rules the client enforces

Neither is configurable, and a deployment that ignores them fails at the last step rather than the first.

1. **`https://` only.** Plain `http://` is accepted for loopback (`localhost`, `127.x`, `[::1]`) and nothing else — that connection carries bearer tokens. The refusal reads:

   ```
   refusing plaintext http:// to non-loopback host "10.0.0.5:8443":
   use https:// so tokens and data are encrypted in transit
   ```

2. **The certificate must verify against the machine's OS trust store.** The client uses the platform verifier — the same roots `curl` uses on that machine — and has no "continue anyway" button. A public CA just works; a private CA works after [scenario 4](#4--private-ca-lan--air-gapped).

---

## 1 — Automatic certificates

**Use when** the instance has a public DNS name and port 80 is reachable.

```bash
# .env
UNISSH_DOMAIN=unissh.example.com
UNISSH_TLS_DIRECTIVE=tls you@example.com     # the email is optional; it enables expiry notices
```

```bash
docker compose -f compose.prod.yml up -d
```

Caddy obtains and renews the certificate on its own. The full walkthrough — profiles, first-run claim, backups — is on the [Docker Compose deployment](../deploy/) page.

---

## 2 — Your own certificate

**Use when** the certificate comes from somewhere else: a corporate CA, a commercial wildcard, a DNS-01 issuance, certbot/acme.sh on the host.

Caddy stays the front door; only the source of the certificate changes.

**1.** Put the pair on the host (default location is `./certs` at the repository root):

```bash
mkdir -p certs
cp /path/to/fullchain.pem certs/fullchain.pem   # leaf FIRST, then intermediates
cp /path/to/privkey.pem   certs/privkey.pem     # unencrypted PEM
chmod 600 certs/privkey.pem
```

**2.** Point the TLS knob at them:

```bash
# .env
UNISSH_DOMAIN=unissh.example.com
UNISSH_TLS_DIRECTIVE=tls /certs/fullchain.pem /certs/privkey.pem
# UNISSH_CERTS_DIR=./certs      # optional: some other host directory
```

**3.** Start with the cert-mount override, which bind-mounts that directory read-only at `/certs`:

```bash
docker compose -f compose.prod.yml -f deploy/compose.tls-files.yml up -d
```

:::danger[Renewal is not automatic — wire up the reload]
Caddy loads these files **once**. Rewriting them on disk changes nothing, and plain `caddy reload` is a no-op because the config is unchanged. Verified by swapping the files under a running container: the original certificate was still on the wire 75 seconds later.

Every renewal must be followed by one of:

```bash
docker compose exec caddy caddy reload --force --config /etc/caddy/Caddyfile
docker compose restart caddy
```

Put it in your certbot/acme.sh **deploy hook**. Skip it and the instance serves an expired certificate — which, with no "accept anyway" in the client, is an outage rather than a warning.
:::

:::note[Ship the full chain]
A leaf-only file often works in a browser (which caches intermediates from other sites) and then fails in the client, which does not. Check with `openssl s_client -connect host:443 -showcerts </dev/null`.
:::

Relative paths in the override resolve against the **first** `-f` file's directory — the repository root — which is why the default is `./certs` and not `../certs`.

---

## 3 — Behind a proxy you run

**Use when** nginx, Traefik, HAProxy, an appliance or a tunnel already owns 80/443 on this host.

### 3a — Your proxy does TLS only (start here)

Set the bundled Caddy's site address to `:80` and it becomes a plain-HTTP internal front: no ACME, no internal CA, still serving the panel and proxying the API. Your proxy terminates TLS and forwards everything to it.

```
client ──TLS──► your proxy ──HTTP──► 127.0.0.1:8080 (caddy) ──► server:8443
```

```bash
docker compose -f compose.prod.yml -f deploy/compose.behind-proxy.yml up -d
curl -i http://127.0.0.1:8080/readyz          # 200, empty body
```

Then install [`deploy/nginx/unissh.conf`](https://github.com/goduni/unissh/blob/main/deploy/nginx/unissh.conf) — TLS plus a single `proxy_pass`, because the routing, the panel and the security headers all arrive from inside the stack:

```bash
sudo cp deploy/nginx/unissh.conf /etc/nginx/conf.d/unissh.conf
sudo $EDITOR /etc/nginx/conf.d/unissh.conf    # server_name + the two cert paths
sudo nginx -t && sudo systemctl reload nginx
```

**Why start here:** the panel is versioned with the server and travels inside the image, so `docker compose pull && up -d` upgrades both. Nothing on your disk to re-sync.

**Forward every path,** not just `/v1` — the panel and the API must share one origin, which is what keeps CORS off and the CSP tight.

:::caution[The cost: the server stops seeing client IPs]
The server takes the **rightmost** `X-Forwarded-For` element, and the last hop to write that header is the stack's Caddy, which — trusting no upstream — replaces whatever your proxy sent with its own peer. Every request then looks like it came from one address, so the per-IP rate limit (`limits.rate_limit_per_ip_rps`, 20/s) applies **instance-wide**.

Usually fine for a team; raise the limit if it isn't, or use [3b](#3b--your-proxy-replaces-caddy). Configuring Caddy's `trusted_proxies` does **not** fix it — tested: the chain is preserved, but the rightmost element is still the inner proxy. The upside of the same behaviour is that a client-forged `X-Forwarded-For` never reaches the server either.
:::

### 3b — Your proxy replaces Caddy

**Use when** the server must see real client addresses (per-IP rate limiting, access logs, fail2ban).

```
client ──TLS──► nginx ──plain HTTP──► 127.0.0.1:8443 (unissh-server)
                  └─ panel from /var/www/unissh
```

**1.** Start without the bundled Caddy — the override parks it and publishes the API on loopback:

```bash
docker compose -f compose.prod.yml -f deploy/compose.reverse-proxy.yml up -d
```

**2.** Put the panel on disk (its files live in the caddy image at `/srv`):

```bash
cid=$(docker create ghcr.io/goduni/unissh-caddy:latest)
sudo mkdir -p /var/www/unissh
sudo docker cp "$cid:/srv/." /var/www/unissh/
docker rm "$cid"
```

**Repeat that on every upgrade** — panel and server ship as one version, and a stale copy surfaces as odd API errors rather than a version banner. (Building it instead: `just build-wasm && cd server-ui && npm ci && npm run build`. See [Build from source](../build/).)

**3.** Install [`deploy/nginx/unissh-static-spa.conf`](https://github.com/goduni/unissh/blob/main/deploy/nginx/unissh-static-spa.conf), edit `server_name`, the certificate paths and `root`, then `nginx -t && systemctl reload nginx`.

<details>
<summary>Four details in that file are load-bearing for any proxy</summary>

- **One origin for panel and API.** The panel calls the API with a relative base. Two hostnames means enabling `cors_allowed_origins` and a weaker CSP.
- **`application/wasm`.** The panel's crypto module is loaded with `WebAssembly.instantiateStreaming`, which rejects any other content type. Older `mime.types` files have no `wasm` entry, and the only symptom is a panel that never unlocks.
- **`client_max_body_size 16m`.** At least the server's `limits.max_body_bytes`, or a legal push is 413'd before the server sees it.
- **`X-Forwarded-For`.** The server reads the rightmost element; `$proxy_add_x_forwarded_for` appends the real peer there, so a client-supplied header cannot displace it. A proxy that *overwrites* XFF with a client-controlled value hands every user a way past the rate limit.

</details>

### 3c — Traefik

Traefik cannot serve static files, so the bundled Caddy stays as the origin (as in 3a) and Traefik routes to it over a shared Docker network — nothing is host-published.

```bash
# .env
TRAEFIK_NETWORK=traefik              # the network your traefik container is on
UNISSH_HOST=unissh.example.com
UNISSH_CERTRESOLVER=letsencrypt      # your Traefik's resolver name
```

```bash
docker compose -f compose.prod.yml -f deploy/compose.traefik.yml up -d
```

The integration is four labels — router rule, entrypoint, TLS, and the container-internal port 80. Rename the `websecure` entrypoint to match your Traefik, and delete the `certresolver` label if it gets certificates another way. The client-IP caveat from 3a applies.

### 3d — Behind a CDN, WAF or tunnel

Cloudflare with proxied DNS, or a `cloudflared` tunnel with no inbound ports at all, is often the easiest answer for a host with no public IP. Route it exactly like 3a — forward everything to `127.0.0.1:8080` — and be deliberate about two things:

- **Whoever terminates TLS sees session tokens.** Not vault contents: those are ciphertext the server itself cannot read, so the zero-knowledge guarantee is unaffected. But an access token is enough to act as a device, so terminating TLS at a third party is a real trust decision. Terminating at your own edge keeps it to yourself.
- **Allow a 16 MiB request body, and do not cache `/v1`.** The panel's hashed assets are safe to cache.

---

## 4 — Private CA (LAN / air-gapped)

**Use when** there is no public DNS: a `.local` name or a bare IP.

```bash
# .env
UNISSH_DOMAIN=unissh.local      # or 10.0.0.5
UNISSH_TLS_DIRECTIVE=tls internal
```

Caddy issues from its own internal CA. That is half the job — **every client machine must trust that root**, or the client refuses the certificate and (per the [two rules](#two-rules-the-client-enforces)) will not fall back to `http://`. Skipping this half is the most common failed self-hosted deployment.

**Export the root** (it lives in the `caddy-data` volume, which is why that volume must persist):

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./unissh-root.crt
```

**Install it on every client machine:**

```bash
# Debian / Ubuntu
sudo cp unissh-root.crt /usr/local/share/ca-certificates/unissh-root.crt
sudo update-ca-certificates

# Fedora / RHEL
sudo cp unissh-root.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust

# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain unissh-root.crt

# Windows (elevated PowerShell)
Import-Certificate -FilePath unissh-root.crt -CertStoreLocation Cert:\LocalMachine\Root
```

The Linux paths are verified against a clean Debian and Fedora; the macOS and Windows lines are the vendor-documented ones. Confirm from the client before opening the app — `curl` reads the same store:

```bash
curl -v https://unissh.local/readyz     # must succeed with NO -k
```

:::note[`certutil is not available` in the Caddy log is a red herring]
That is Caddy trying to install its root into the trust store **inside its own container**, where nothing consumes it. Installing `certutil` there fixes nothing and has no bearing on whether clients trust the certificate.
:::

:::caution[Mobile clients cannot use a private CA]
Android does not let apps trust user-installed CAs by default, and iOS needs the profile installed *and* enabled under Certificate Trust Settings. If phones are part of the plan, get a real certificate for a real name and use [scenario 2](#2--your-own-certificate). A public CA will issue one for a host that is unreachable from the internet via the **DNS-01** challenge — obtain it out of band with certbot/lego/acme.sh. The shipped Caddy image cannot do DNS-01 itself: those challenges need a provider plugin compiled in with `xcaddy`, and this image has none.
:::

If the root cannot be distributed at all, the remaining option is **loopback**: reach the server through an SSH tunnel and point the client at `http://127.0.0.1:<port>`, which is allowed precisely because it never touches a network.

---

## 5 — No proxy at all

**Use when** one admin runs one instance and wants the smallest possible deployment. The server has in-process rustls and can serve `/v1` directly.

```yaml
services:
  server:
    image: ghcr.io/goduni/unissh-server:latest
    ports:
      - "8443:8443"
    volumes:
      - unissh-data:/app/data
      - ./certs:/certs:ro
    environment:
      UNISSH__SERVER__BIND: "0.0.0.0:8443"
      UNISSH__SERVER__TLS_CERT: "/certs/fullchain.pem"
      UNISSH__SERVER__TLS_KEY: "/certs/privkey.pem"
      UNISSH__SERVER__TRUST_PROXY: "false"    # nothing in front; XFF is forgeable
```

The container runs as the distroless nonroot user, so the key must be readable by **uid 65532**:

```bash
sudo chown 65532:65532 certs/privkey.pem
```

A root-owned `chmod 600` key — what a certbot copy leaves behind — makes the server exit at startup with `load TLS cert/key: … Permission denied (os error 13)`.

Clients then use `https://host:8443`.

:::caution[What you give up]
**No admin panel** — it is served by the front door, which no longer exists; claim and administer the instance from the desktop client instead. **No ACME** either (`acme = true` is a hard startup error), so renewal is replace-the-files-and-restart. Anything beyond a single admin is better served by scenario 2 or 3.
:::

<details>
<summary>Without Docker at all</summary>

No server binaries are published — the release artifacts are the client apps and the two container images — so bare metal means [building from source](../build/) (`cargo build --release -p unissh-server`) and running it under an init system. Configuration is the same `config.toml` or `UNISSH__*` environment keys; a missing config file is fine, the environment alone is enough.

```ini
# /etc/systemd/system/unissh-server.service
[Unit]
Description=UniSSH server
After=network-online.target

[Service]
ExecStart=/usr/local/bin/unissh-server serve --config /etc/unissh/config.toml
User=unissh
Environment=UNISSH__SERVER__TLS_CERT=/etc/unissh/fullchain.pem
Environment=UNISSH__SERVER__TLS_KEY=/etc/unissh/privkey.pem
Environment=UNISSH__DB__URL=/var/lib/unissh/unissh.db
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=unissh

[Install]
WantedBy=multi-user.target
```

Create the user first (`sudo useradd -r -s /usr/sbin/nologin unissh`) and make the key readable by it. Upgrades are yours to drive: rebuild, replace the binary, restart. The container images exist so that most operators don't have to.

</details>

---

## Before you commit

- **Give the instance its own hostname.** `https://unissh.example.com/` — a subpath like `https://example.com/unissh/` is not a tested layout.
- **A non-standard port is fine** (`https://host:8443`); set `UNISSH__SERVER__PUBLIC_URL` to match so invite links carry it. ACME's HTTP-01 challenge still needs port 80, so where 80 is taken, use scenario 2.
- **One trusted hop.** The server assumes a single proxy when it reads `X-Forwarded-For`. Two hops work and are common; they just cost per-client rate limiting.
- **Only 443 has to be reachable** (plus 80 for ACME and the redirect). The server's own port and the metrics port stay internal in every scenario here.
- **The panel is versioned with the server.** Any layout that copies it onto your disk has to re-copy it on upgrade.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `refusing plaintext http:// to non-loopback host` | Working as designed — tokens ride that connection. Serve HTTPS; there is no override. |
| `the server's TLS certificate is not trusted by this machine` | A private CA whose root is not installed ([4](#4--private-ca-lan--air-gapped)), or a chain served without its intermediates ([2](#2--your-own-certificate)). `curl -v https://<host>/readyz` reproduces it outside the app. |
| `certificate is not valid for this hostname` | The certificate's names don't include the address you typed. Certificates for a bare IP are rare; issue for a hostname. |
| A renewed certificate still shows as the old one | File-based certificates load once. `caddy reload --force` or restart ([2](#2--your-own-certificate)). |
| Server exits with `Permission denied (os error 13)` on the key | The key is not readable by uid 65532 ([5](#5--no-proxy-at-all)). `chown 65532:65532`. |
| Caddy logs `"certutil" is not available` | Harmless, and unrelated to client trust ([4](#4--private-ca-lan--air-gapped)). |
| Caddy cannot get an ACME certificate | Port 80 must be reachable and public DNS must resolve here. On a private network use scenario 2 or 4. |
| The panel loads but never unlocks | The `.wasm` file is served with the wrong content type. `curl -I …/assets/*.wasm` must show `application/wasm` ([3b](#3b--your-proxy-replaces-caddy)). |
| The panel is a version behind the server | A docroot copy that wasn't refreshed after an upgrade ([3b](#3b--your-proxy-replaces-caddy)). |
| Everything 404s through your proxy | The proxy forwards only `/v1`, or `UNISSH_DOMAIN` is still a hostname instead of `:80` in [3a](#3a--your-proxy-does-tls-only-start-here). Forward every path; check `docker compose logs caddy`. |
| Pushes fail with 413 | The proxy's body limit is below `limits.max_body_bytes` (16 MiB). |
| Rate limiting hits the wrong client | Either `trust_proxy` is true with nothing in front, or you are two hops deep ([3a](#3a--your-proxy-does-tls-only-start-here)). |

## See also

- [Docker Compose deployment](../deploy/) — the full stack, profiles, first-run claim, backups.
- [Server configuration](../configuration/) — every `config.toml` key and its environment override.
- [Backups & anti-rollback restore](../backups/).
