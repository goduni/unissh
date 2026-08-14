---
title: Deployment scenarios
description: Four ways to put TLS in front of a self-hosted UniSSH server — Caddy with automatic ACME, Caddy with certificates you already have, your own nginx, and a LAN deployment behind a self-signed internal CA.
---

The [Docker Compose deployment](../deploy/) ships one opinionated path: Caddy in front, a certificate from Let's Encrypt, the admin panel and the API on one origin. This page covers the other four situations operators actually land in — an existing certificate, an existing nginx, no proxy at all, and a LAN with no public DNS.

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
| nginx already runs on this host and terminates TLS | [3 — your own nginx](#scenario-3--your-own-nginx-in-front) | nginx |
| No public DNS at all: LAN, air-gapped, IP-only | [4 — self-signed internal CA](#scenario-4--lan--air-gapped-self-signed-internal-ca) | Caddy (internal CA) |
| No proxy wanted; API only, no admin panel | [5 — the server terminates TLS](#scenario-5--no-proxy-the-server-terminates-tls-itself) | the server (rustls) |

Scenarios 1, 2 and 4 keep the bundled Caddy and differ by one line in `.env`. Scenarios 3 and 5 replace the front door.

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

**Renewal.** Caddy watches the files: rewrite `fullchain.pem` / `privkey.pem` in place and it picks up the new certificate without a restart. A certbot deploy hook only has to `cp` the files — no `docker compose` command is needed.

---

## Scenario 3 — your own nginx in front

For hosts where nginx already terminates TLS for other sites. The job is the same one Caddy does: **terminate TLS, serve the admin SPA from disk, reverse-proxy the API to the server.**

```
client ──TLS──► nginx ──plain HTTP──► 127.0.0.1:8443 (unissh-server)
                  └─ SPA from /var/www/unissh
```

**1. Start the stack without the bundled Caddy.** The `deploy/compose.reverse-proxy.yml` override parks Caddy behind a profile nobody enables (so ports 80/443 stay free) and publishes the API on loopback only:

```bash
docker compose -f compose.prod.yml -f deploy/compose.reverse-proxy.yml up -d
curl -i http://127.0.0.1:8443/readyz     # HTTP/1.1 200 OK (empty body)
```

**2. Put the admin SPA on disk.** Its files live inside the caddy image at `/srv`; copy them out once per upgrade:

```bash
cid=$(docker create ghcr.io/goduni/unissh-caddy:latest)
sudo mkdir -p /var/www/unissh
sudo docker cp "$cid:/srv/." /var/www/unissh/
docker rm "$cid"
```

(Or build them yourself — the panel needs its wasm package built first: `just build-wasm && cd server-ui && npm ci && npm run build` → `dist/`. See [Build from source](../build/).)

**3. Install the server block.** [`deploy/nginx/unissh.conf`](https://github.com/goduni/unissh/blob/main/deploy/nginx/unissh.conf) is a complete, tested one — copy it to `/etc/nginx/conf.d/`, edit `server_name` and the two `ssl_certificate` paths, then `nginx -t && systemctl reload nginx`.

Four details in it are load-bearing, whichever proxy you actually use:

- **Same origin for SPA and API.** The panel calls the API with a relative base, so serving both from one hostname is what keeps CORS off server-side. Splitting them across two names means enabling `cors_allowed_origins` and weakening the CSP.
- **`application/wasm`.** The panel's crypto module is loaded with `WebAssembly.instantiateStreaming`, which rejects any other content type. Older `mime.types` files have no `wasm` entry, and the only symptom is a panel that never unlocks.
- **`client_max_body_size 16m`.** It must be at least the server's `limits.max_body_bytes` (16 MiB by default) or nginx returns 413 for a legal push before the server sees it.
- **`X-Forwarded-For`.** With `trust_proxy = true` the server reads the **rightmost** element as the client IP for per-IP rate limiting. nginx's `$proxy_add_x_forwarded_for` appends the real peer on the right, so a client-supplied header cannot displace it. A proxy that *overwrites* XFF with a client-controlled value would hand every user a way past the rate limit.

**If your proxy runs in a container**, drop the `ports:` block from the override, attach the proxy to the `unissh` network, and forward to `http://server:8443` by service name — then nothing is host-published at all.

**Invite links.** Nothing derives your public address for you; set it so invites come back with a usable URL:

```bash
UNISSH__SERVER__PUBLIC_URL=https://unissh.example.com
```

The same recipe transfers to HAProxy, Traefik or an appliance: TLS in front, one origin, correct `X-Forwarded-For`, a body limit ≥ 16 MiB, `application/wasm` for the SPA.

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
Android does not let apps trust user-installed CAs by default, and iOS requires the profile to be installed *and* enabled under Certificate Trust Settings. If phones or tablets are part of the plan, do not rely on an internal CA — get a real certificate for a real name (a public CA with DNS-01 works fine for a host that is not reachable from the internet) and use [scenario 2](#scenario-2--caddy-with-certificates-you-already-have).
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

In Docker, mount the files and publish the port (the container runs as the distroless nonroot user, uid **65532** — the key must be readable by it):

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

---

## Troubleshooting

**`refusing plaintext http:// to non-loopback host "…"`** — the client will not send bearer tokens in the clear. Serve HTTPS (any scenario above); there is no override.

**`the server's TLS certificate is not trusted by this machine`** — the certificate chains to a CA this machine does not know: a self-signed/internal CA whose root is not installed ([scenario 4](#scenario-4--lan--air-gapped-self-signed-internal-ca)), or a chain served without its intermediates ([scenario 2](#scenario-2--caddy-with-certificates-you-already-have)). `curl -v https://<host>/readyz` from the same machine reproduces it without the app.

**`certificate is not valid for this hostname`** — the certificate's names do not include the address you typed. Certificates for a bare IP are rare; issue for a hostname and use that hostname.

**Caddy logs `"certutil" is not available`** — harmless, unrelated to client trust. See [scenario 4](#scenario-4--lan--air-gapped-self-signed-internal-ca).

**Caddy cannot get an ACME certificate** — port 80 must be reachable from the internet for HTTP-01, and public DNS must resolve to this host. On a private network, use scenario 2 or 4 instead.

**The admin panel loads but never unlocks** — the `.wasm` file is being served with the wrong content type. Check `curl -I https://<host>/assets/*.wasm | grep content-type`; it must be `application/wasm` ([scenario 3](#scenario-3--your-own-nginx-in-front)).

**Pushes fail with 413** — the proxy's body limit is below the server's `limits.max_body_bytes` (16 MiB default). Raise `client_max_body_size` (nginx) to match.

**Rate limiting hits the wrong client** — either `trust_proxy` is true with nothing in front of the server, or the proxy is not appending the real peer to `X-Forwarded-For`. The server reads the rightmost element.

## See also

- [Docker Compose deployment](../deploy/) — the full stack, profiles, first-run claim, backups.
- [Server configuration](../configuration/) — every `config.toml` key and its env override.
- [Backups & anti-rollback restore](../backups/).
