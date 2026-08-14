---
title: Deployment scenarios
description: Four ways to put TLS in front of a self-hosted UniSSH server — Caddy with automatic ACME, Caddy with certificates you already have, your own nginx, and a LAN deployment behind a self-signed internal CA.
---

The [Docker Compose deployment](../deploy/) ships one opinionated path: Caddy in front, a certificate from Let's Encrypt, the admin panel and the API on one origin. This page covers the situations operators land in instead — a certificate you already hold, a proxy you already run (nginx, Traefik, Cloudflare), a LAN with no public DNS, and no proxy at all.

Every configuration file referenced here lives in the repository and was verified against live nginx, Traefik and Caddy containers rather than written from memory.

Everything below changes **only the front door**. The UniSSH server itself is unchanged: plain HTTP on an internal network, `trust_proxy = true`, no ACME (`acme = true` is a hard startup error). Whatever terminates TLS is the only piece that differs.

## What the client requires

Before picking a scenario, know the two rules the desktop and mobile clients enforce. They are what make a "quick" deployment fail later.

1. **The server URL must be `https://`.** Plain `http://` is accepted only for loopback (`localhost`, `127.x`, `[::1]`) — the connection carries bearer tokens, so a plaintext hop to a real host would hand an on-path attacker a working session. The client fails with:

   ```
   refusing plaintext http:// to non-loopback host "10.0.0.5:8443":
   use https:// so tokens and data are encrypted in transit
   ```

   This is not a setting. There is no flag to turn it off.

2. **The certificate must verify against the machine's OS trust store.** The client uses the platform verifier — the same roots your browser and `curl` use on that machine — and offers no "continue anyway" prompt. A public CA works out of the box; a private or self-signed CA works once its **root** is installed on each client machine ([scenario 4](#scenario-4--lan--air-gapped-self-signed-internal-ca)).

Everything else — port, path, hostname — is yours to choose.

## Pick a scenario

| Your situation | Scenario | TLS lives in |
| --- | --- | --- |
| Public DNS name, want certificates handled for you | [1 — Caddy + ACME](#scenario-1--caddy--automatic-acme-default) | Caddy (automatic) |
| You already hold a certificate (corporate CA, wildcard, DNS-01, certbot) | [2 — Caddy + your files](#scenario-2--caddy-with-certificates-you-already-have) | Caddy (files) |
| A proxy already terminates TLS on this host (nginx, HAProxy, a tunnel) | [3a — TLS-only proxy in front](#scenario-3a--a-proxy-in-front-of-the-bundled-stack-recommended) | your proxy |
| …and the server must see real client IPs | [3b — the proxy replaces Caddy](#scenario-3b--the-proxy-replaces-caddy-one-hop) | your proxy |
| Traefik with Docker labels | [3c — Traefik](#scenario-3c--traefik) | Traefik |
| No public DNS at all: LAN, air-gapped, IP-only | [4 — self-signed internal CA](#scenario-4--lan--air-gapped-self-signed-internal-ca) | Caddy (internal CA) |
| No proxy wanted; API only, no admin panel | [5 — the server terminates TLS](#scenario-5--no-proxy-the-server-terminates-tls-itself) | the server (rustls) |

Scenarios 1, 2 and 4 differ by one line in `.env`. Scenarios 3a and 3c keep the bundled Caddy but move TLS to a proxy you already run; 3b and 5 replace the front door outright.

---

## Scenario 1 — Caddy + automatic ACME (default)

The shipped path, covered in full on the [Docker Compose deployment](../deploy/) page. `.env`:

```bash
UNISSH_DOMAIN=unissh.example.com
UNISSH_TLS_DIRECTIVE=tls you@example.com    # empty is also valid (no expiry notices)
```

Requires public DNS pointing at the host and port **80** reachable for the challenge and the HTTP→HTTPS redirect. Renewal is automatic and needs no operator action.

---

## Scenario 2 — Caddy with certificates you already have

For a certificate that does not come from Caddy's own ACME: a corporate/internal CA, a commercial wildcard, a DNS-01 issuance, or a cert renewed on the host by certbot/acme.sh. Caddy still serves the SPA and proxies the API — only where the certificate comes from changes.

**1. Put the two files on the host.** Default location is `./certs` at the repository root:

```bash
mkdir -p certs
cp /path/to/fullchain.pem certs/fullchain.pem   # leaf FIRST, then intermediates
cp /path/to/privkey.pem   certs/privkey.pem     # unencrypted PEM
chmod 600 certs/privkey.pem
```

:::caution[Ship the full chain, not just the leaf]
A leaf-only `cert.pem` frequently works in a browser (which caches intermediates from other sites) and then fails in the UniSSH client, which does not. If in doubt, check with
`openssl s_client -connect host:443 -showcerts </dev/null` — you should see the leaf **and** every intermediate up to a root your machine trusts.
:::

**2. Point the TLS knob at them** in `.env`:

```bash
UNISSH_DOMAIN=unissh.example.com
UNISSH_TLS_DIRECTIVE=tls /certs/fullchain.pem /certs/privkey.pem
# UNISSH_CERTS_DIR=./certs        # optional: mount some other host directory
```

**3. Start with the cert-mount override** (`deploy/compose.tls-files.yml`, which bind-mounts that directory read-only at `/certs`):

```bash
docker compose -f compose.prod.yml -f deploy/compose.tls-files.yml up -d
# or, building from source:
docker compose -f compose.yml -f deploy/compose.tls-files.yml up -d --build
```

Relative host paths in the override resolve against the **first** `-f` file's directory (the repository root), which is why the default is `./certs` and not `../certs`.

:::danger[Renewal does not happen by itself]
Caddy loads these files **once**. Rewriting them on disk changes nothing — the old certificate keeps being served, and plain `caddy reload` is a no-op because the config is unchanged. (Both verified against a running container: after swapping the files, the original certificate was still on the wire.) Every renewal must be followed by:

```bash
docker compose exec caddy caddy reload --force --config /etc/caddy/Caddyfile
# or: docker compose restart caddy
```

Put that in the certbot/acme.sh **deploy hook**. Otherwise the instance serves an expired certificate — and because the client has no "accept anyway", that is a full outage, not a warning.
:::

---

## Scenario 3a — a proxy in front of the bundled stack (recommended)

The layout to reach for when something already owns ports 80/443 on the host. Your proxy does exactly one job — terminate TLS with your certificate and forward **everything** — and the stack's own front door keeps doing the rest:

```
client ──TLS──► your proxy ──HTTP──► 127.0.0.1:8080 (caddy) ──► server:8443
```

Setting Caddy's site address to `:80` turns it into a plain-HTTP internal front: no ACME, no internal CA, still serving the admin SPA and still proxying `/v1`, `/healthz`, `/readyz`. That is what `deploy/compose.behind-proxy.yml` does:

```bash
docker compose -f compose.prod.yml -f deploy/compose.behind-proxy.yml up -d
curl -i http://127.0.0.1:8080/           # the SPA
curl -i http://127.0.0.1:8080/readyz     # proxied to the server
```

Then install [`deploy/nginx/unissh.conf`](https://github.com/goduni/unissh/blob/main/deploy/nginx/unissh.conf) — TLS plus a single `proxy_pass`, because the security headers, the SPA routing and the API proxying all arrive from inside the stack:

```bash
sudo cp deploy/nginx/unissh.conf /etc/nginx/conf.d/unissh.conf
sudo $EDITOR /etc/nginx/conf.d/unissh.conf     # server_name + the two cert paths
sudo nginx -t && sudo systemctl reload nginx
```

**Why this one and not 3b.** The admin panel is versioned with the server and travels inside the image, so `docker compose pull && up -d` upgrades both together. Nothing on your disk to re-sync, nothing to skew.

**Forward every path, not just `/v1`.** The SPA and the API must share one origin — that is what keeps CORS off server-side and the CSP tight.

:::caution[The trade-off: the server stops seeing client IPs]
The server takes the **rightmost** `X-Forwarded-For` element as the client address, and the last hop to write that header is the stack's Caddy, which — not being configured to trust an upstream — replaces whatever your proxy sent with its own peer. Every request then looks like it came from one address, so the per-IP rate limit (`limits.rate_limit_per_ip_rps`, 20/s) applies **instance-wide** rather than per client.

For a small team that is usually fine; raise the limit if it isn't. If you need real client addresses (rate limiting, access logs, fail2ban), use [3b](#scenario-3b--the-proxy-replaces-caddy-one-hop). The upside of the same behaviour: a client-forged `X-Forwarded-For` never reaches the server either.
:::

---

## Scenario 3b — the proxy replaces Caddy (one hop)

nginx does the whole job the Caddyfile does: TLS, the SPA from its own docroot, the API proxied straight to the server. One hop, so the server sees real client addresses.

```
client ──TLS──► nginx ──plain HTTP──► 127.0.0.1:8443 (unissh-server)
                  └─ SPA from /var/www/unissh
```

**1. Start the stack without the bundled Caddy.** `deploy/compose.reverse-proxy.yml` parks it behind a profile nobody enables (so 80/443 stay free) and publishes the API on loopback only:

```bash
docker compose -f compose.prod.yml -f deploy/compose.reverse-proxy.yml up -d
curl -i http://127.0.0.1:8443/readyz     # HTTP/1.1 200 OK (empty body)
```

**2. Put the admin SPA on disk.** Its files live inside the caddy image at `/srv`:

```bash
cid=$(docker create ghcr.io/goduni/unissh-caddy:latest)
sudo mkdir -p /var/www/unissh
sudo docker cp "$cid:/srv/." /var/www/unissh/
docker rm "$cid"
```

**Repeat this on every upgrade.** The panel and the server ship as one version; a stale docroot is the failure mode this scenario buys, and it shows up as odd API errors rather than an obvious version banner. (Building it yourself instead: the panel needs its wasm package first — `just build-wasm && cd server-ui && npm ci && npm run build` → `dist/`. See [Build from source](../build/).)

**3. Install the server block.** [`deploy/nginx/unissh-static-spa.conf`](https://github.com/goduni/unissh/blob/main/deploy/nginx/unissh-static-spa.conf) is complete; edit `server_name`, the two `ssl_certificate` paths and `root`, then `nginx -t && systemctl reload nginx`.

Four details in it are load-bearing, whichever proxy you actually use:

- **Same origin for SPA and API.** The panel calls the API with a relative base, so one hostname is what keeps CORS off. Splitting them across two names means enabling `cors_allowed_origins` and weakening the CSP.
- **`application/wasm`.** The panel's crypto module is loaded with `WebAssembly.instantiateStreaming`, which rejects any other content type. Older `mime.types` files have no `wasm` entry, and the only symptom is a panel that never unlocks.
- **`client_max_body_size 16m`.** At least the server's `limits.max_body_bytes` (16 MiB default), or nginx returns 413 for a legal push before the server sees it.
- **`X-Forwarded-For`.** With `trust_proxy = true` the server reads the **rightmost** element. nginx's `$proxy_add_x_forwarded_for` appends the real peer on the right, so a client-supplied header cannot displace it. A proxy that *overwrites* XFF with a client-controlled value would hand every user a way past the rate limit.

---

## Scenario 3c — Traefik

Traefik cannot serve static files, so the bundled Caddy stays as the origin (as in [3a](#scenario-3a--a-proxy-in-front-of-the-bundled-stack-recommended)) and Traefik routes to it over a shared Docker network — nothing is host-published at all:

```
client ──TLS──► traefik ──HTTP──► caddy:80 ──► server:8443
```

`deploy/compose.traefik.yml` carries the labels. In `.env`:

```bash
TRAEFIK_NETWORK=traefik              # the network your traefik container is on
UNISSH_HOST=unissh.example.com
UNISSH_CERTRESOLVER=letsencrypt      # your Traefik's resolver name
```

```bash
docker compose -f compose.prod.yml -f deploy/compose.traefik.yml up -d
```

The integration is four labels — router rule, entrypoint, TLS, and the container-internal port `80`. Adjust the `websecure` entrypoint name to match your Traefik, and delete the `certresolver` label if it gets certificates another way. The two-hop client-IP caveat from 3a applies here too.

HAProxy, Caddy-you-already-run, nginx-proxy-manager, or an appliance follow the same shape as 3a: terminate TLS, forward every path to the stack's front door, keep one origin, allow a 16 MiB body.

---

## Behind a CDN, WAF or tunnel (Cloudflare & co.)

Putting the instance behind Cloudflare — proxied DNS, or a `cloudflared` tunnel with no inbound ports at all — works, and is often the easiest answer when the host has no public IP. Route it exactly like 3a: the tunnel or CDN forwards everything to `127.0.0.1:8080`.

Two things to be deliberate about:

- **The TLS terminator sees your bearer tokens.** Whoever terminates TLS — Cloudflare, your company's WAF, a shared proxy — sees the API traffic in the clear: session tokens and metadata. It does **not** see vault contents: those are ciphertext the server itself cannot read, so the zero-knowledge guarantee is unaffected either way. But an access token is enough to act as a device against the server, so terminating TLS at a third party is a real trust decision, not a formality. Terminating at your own edge (3a/3b) keeps that to yourself.
- **Body limits and caching.** The proxy must allow a 16 MiB request body (Cloudflare's free plan caps at 100 MB — fine), and must not cache `/v1` responses. Leave `/v1` uncached; the SPA's hashed assets are safe to cache.

If the CDN also injects `X-Forwarded-For`, the note in 3a still applies: with the bundled Caddy in the chain, the server sees one address regardless.

---

## Scenario 4 — LAN / air-gapped (self-signed internal CA)

No public DNS means no ACME. Caddy can issue from its own internal CA:

```bash
UNISSH_DOMAIN=unissh.local          # or an IP: 10.0.0.5
UNISSH_TLS_DIRECTIVE=tls internal
```

This works — but it is only half the job, and skipping the other half is the single most common failed self-hosted deployment. **Every client machine must trust that CA root.** The client verifies against the OS trust store and has no "accept anyway" prompt, and (per [What the client requires](#what-the-client-requires)) falling back to `http://` is refused.

:::note[The `certutil` warning in the Caddy log is a red herring]
```
warning: "certutil" is not available, install "certutil" with "apt install libnss3-tools" …
```
That is Caddy trying to install its root into the trust store **inside its own container**, where nothing consumes it. It is harmless, installing `certutil` there fixes nothing, and it is unrelated to whether clients trust the certificate.
:::

**Export the root** (once — it lives in the `caddy-data` volume, which is why that volume must persist):

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

Verify from a client before opening the app — `curl` uses the same store:

```bash
curl -v https://unissh.local/readyz     # must succeed with NO -k
```

:::caution[Mobile clients cannot use a private CA]
Android does not let apps trust user-installed CAs by default, and iOS requires the profile to be installed *and* enabled under Certificate Trust Settings. If phones or tablets are part of the plan, do not rely on an internal CA — get a real certificate for a real name and use [scenario 2](#scenario-2--caddy-with-certificates-you-already-have). A public CA issues one for a host that is not reachable from the internet via the **DNS-01** challenge — obtain it out of band with certbot/lego/acme.sh and drop the files in. The shipped Caddy image cannot do DNS-01 itself: those challenges need a provider plugin compiled in with `xcaddy`, and this image has none.
:::

If the CA root cannot be distributed at all, the remaining supported option is **loopback**: reach the server through an SSH tunnel and point the client at `http://127.0.0.1:<port>` — loopback plaintext is allowed precisely because it never touches a network.

---

## Scenario 5 — no proxy: the server terminates TLS itself

The smallest possible deployment. The server has in-process rustls; give it a certificate and key and it serves `/v1` directly, with no proxy in the picture:

```bash
UNISSH__SERVER__BIND=0.0.0.0:8443
UNISSH__SERVER__TLS_CERT=/certs/fullchain.pem
UNISSH__SERVER__TLS_KEY=/certs/privkey.pem
UNISSH__SERVER__TRUST_PROXY=false        # nothing in front; XFF must not be trusted
```

In Docker, mount the files and publish the port. The container runs as the distroless nonroot user, uid **65532**, so the key has to be readable by that uid — a root-owned `chmod 600` key (what a certbot copy leaves you with) makes the server exit at startup with:

```
Error: load TLS cert/key: failed to read from file `/certs/privkey.pem`: Permission denied (os error 13)
```

```bash
sudo chown 65532:65532 certs/privkey.pem
sudo chmod 600 certs/privkey.pem
```


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
      UNISSH__SERVER__TRUST_PROXY: "false"
```

Clients then use `https://host:8443`.

:::caution[What you give up]
There is **no admin panel** — the SPA is served by the front door, which no longer exists. Claim the instance and administer it from the desktop client instead. There is also no ACME (`acme = true` is a hard startup error), so renewal is entirely yours: replace the files and restart the container. Anything more than a single-admin instance is better served by scenario 2 or 3.
:::

Setting `trust_proxy = false` matters here: with nothing in front, an `X-Forwarded-For` header can only have come from the client, so trusting it would let anyone forge their own IP and evade rate limiting.

### Without Docker at all

No server binaries are published — the release artifacts are the client apps and the two container images — so a bare-metal install means [building from source](../build/) (`cargo build --release -p unissh-server` → `target/release/unissh-server`) and running it under an init system. The config above applies unchanged, via `config.toml` or the same `UNISSH__*` environment keys:

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
Restart=on-failure
# The key must be readable by User= and nothing else.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=unissh

[Install]
WantedBy=multi-user.target
```

Point `[db].url` at `/var/lib/unissh/unissh.db` (the `StateDirectory`), and remember there is no admin panel on this path either — the SPA needs a web server. Upgrades are yours to drive: rebuild, replace the binary, restart. The container images exist so that most operators don't have to.

---

## Constraints worth knowing before you commit

- **The site must live at the root of its hostname.** `https://unissh.example.com/` works; `https://example.com/unissh/` is not a tested layout. Give the instance its own hostname (or a subdomain) rather than a path on a shared one.
- **A non-standard port is fine, everywhere except ACME.** `https://unissh.example.com:8443` works — clients accept the port, just set `UNISSH__SERVER__PUBLIC_URL` to match so invite links carry it. But Caddy's HTTP-01 challenge needs port 80 reachable, so on a host where 80 is taken, use [scenario 2](#scenario-2--caddy-with-certificates-you-already-have) or DNS-01 out of band.
- **The panel is versioned with the server.** They ship as one image pair. Any layout that copies the SPA onto your own disk ([3b](#scenario-3b--the-proxy-replaces-caddy-one-hop)) has to re-copy it on every upgrade.
- **One trusted hop.** The server assumes exactly one proxy between it and the client when it reads `X-Forwarded-For`. Two hops is supported and common ([3a](#scenario-3a--a-proxy-in-front-of-the-bundled-stack-recommended)), it just costs you per-client rate limiting.
- **Whoever terminates TLS sees session tokens** — not vault contents, which are ciphertext end to end. Relevant when that terminator is someone else's infrastructure.
- **Mobile clients need a publicly-rooted certificate.** A private CA is a desktop-only answer.
- **What must be reachable:** 443 (and 80 only for ACME HTTP-01 and the redirect). The server's own port and the metrics port stay on the internal network in every scenario above; publishing them is never required.

## Troubleshooting

**`refusing plaintext http:// to non-loopback host "…"`** — the client will not send bearer tokens in the clear. Serve HTTPS (any scenario above); there is no override.

**`the server's TLS certificate is not trusted by this machine`** — the certificate chains to a CA this machine does not know: a self-signed/internal CA whose root is not installed ([scenario 4](#scenario-4--lan--air-gapped-self-signed-internal-ca)), or a chain served without its intermediates ([scenario 2](#scenario-2--caddy-with-certificates-you-already-have)). `curl -v https://<host>/readyz` from the same machine reproduces it without the app.

**`certificate is not valid for this hostname`** — the certificate's names do not include the address you typed. Certificates for a bare IP are rare; issue for a hostname and use that hostname.

**Caddy logs `"certutil" is not available`** — harmless, unrelated to client trust. See [scenario 4](#scenario-4--lan--air-gapped-self-signed-internal-ca).

**Caddy cannot get an ACME certificate** — port 80 must be reachable from the internet for HTTP-01, and public DNS must resolve to this host. On a private network, use scenario 2 or 4 instead.

**The admin panel loads but never unlocks** — the `.wasm` file is being served with the wrong content type. Check `curl -I https://<host>/assets/*.wasm | grep content-type`; it must be `application/wasm` ([scenario 3b](#scenario-3b--the-proxy-replaces-caddy-one-hop)).

**A renewed certificate is still showing as the old one** — the file-based Caddy modes load the certificate once; `caddy reload --force` or a container restart is required after every renewal ([scenario 2](#scenario-2--caddy-with-certificates-you-already-have)).

**The server exits with `Permission denied (os error 13)` on the key** — the key is not readable by uid 65532 in [scenario 5](#scenario-5--no-proxy-the-server-terminates-tls-itself). `chown 65532:65532` it.

**Pushes fail with 413** — the proxy's body limit is below the server's `limits.max_body_bytes` (16 MiB default). Raise `client_max_body_size` (nginx) to match.

**The panel shows an older version than the server** — a docroot copy of the SPA that was not refreshed after an upgrade ([3b](#scenario-3b--the-proxy-replaces-caddy-one-hop)). Re-copy `/srv` out of the current caddy image.

**Everything 404s through your proxy** — the proxy is forwarding only `/v1` and not the SPA paths, or (in [3a](#scenario-3a--a-proxy-in-front-of-the-bundled-stack-recommended)) `UNISSH_DOMAIN` is still a hostname rather than `:80`, so the bundled Caddy is matching on a name your proxy doesn't send. Forward every path, and check `docker compose logs caddy`.

**Rate limiting hits the wrong client** — either `trust_proxy` is true with nothing in front of the server, or the proxy is not appending the real peer to `X-Forwarded-For`. The server reads the rightmost element.

## See also

- [Docker Compose deployment](../deploy/) — the full stack, profiles, first-run claim, backups.
- [Server configuration](../configuration/) — every `config.toml` key and its env override.
- [Backups & anti-rollback restore](../backups/).
