# UniSSH Server

Self-hostable, **zero-knowledge control plane** for UniSSH: an untrusted ciphertext
store + device/team sync + membership/sharing/revocation + audit. **SSH traffic does
not flow through the server** — it sees only encrypted blobs and open metadata
(ARCH §2). Positioned as a private, self-hosted sync backend ("self-hosted Termius").

**Byte-compatible** with the UniSSH client core (`rust-core`) — every wire format in §4–6 mirrors
the core 1:1 and is mechanically verified against it (see Testing).

## Stack

tokio · axum 0.8 · sqlx 0.9 (**SQLite** default, **Postgres** for scale) · rustls
(TLS 1.3) · ed25519-dalek (`verify_strict`, same lib as the core) · figment · tracing
+ Prometheus metrics. The server performs **no payload crypto** by design — only TLS
and Ed25519 signature verification for auth/registration.

## Build & run

```bash
cargo build --release
# config: copy and edit
cp config.example.toml config.toml
# apply migrations (also auto-applied on serve)
./target/release/unissh-server migrate --config config.toml
# serve
./target/release/unissh-server --config config.toml
```

Config is layered: defaults → `config.toml` → env (`UNISSH__SECTION__KEY=...`,
double-underscore nesting). See `config.example.toml`.

**TLS:** set `[server] tls_cert`/`tls_key` for in-process rustls (TLS 1.3 only), or
leave empty and terminate TLS at a reverse proxy with `trust_proxy = true`.

### Docker

The build context is the **parent** directory (so `rust-core/` is reachable for the
byte-compat oracle dev-deps):

```bash
docker compose -f server/docker-compose.yml up --build
```

Multi-stage → distroless `cc`, non-root (uid 65532), read-only rootfs. SQLite data on
a named volume; uncomment the `postgres` service for the Postgres backend.

## API (`/v1`, JSON over TLS)

All crypto blobs are base64 (STANDARD). One server = one **instance** (no tenant
header). `Authorization: Bearer` gates private routes; the setup/onboarding routes
(`/v1/claim`, `/v1/join`, `/v1/escrow/*`, `/v1/oidc/callback`) are **public** — the
credential is in the body (setup code / invite token / password proof / id_token).
`/v1/ops/*` is gated by the `X-UniSSH-Ops-Token` header. Mutating routes accept
`Idempotency-Key`.

- **instance / setup:** `GET /v1/instance` (public: claimed-flag, instance-id, the
  enabled auth methods, and — when OIDC is on — the issuer + client_id a browser
  needs to start SSO), `POST /v1/claim` (public: the **first user** claims the
  unclaimed instance with the **setup code** printed to the server log → becomes the
  **owner**, and optionally names the first space).
- **onboarding:** `POST /v1/invite` (owner / space admin: mint a one-time,
  space-scoped invite link with role intents), `POST /v1/invite/revoke` (the
  minting admin / owner: cancel a still-pending invite so a leaked token can no
  longer be redeemed), `POST /v1/join/preview` +
  `POST /v1/join` (public: redeem an invite → a new account bound to the invited
  spaces), `POST /v1/oidc/callback` (public: **SSO** — the server verifies the
  IdP id_token against the JWKS, maps IdP groups → spaces via `[[oidc.group_map]]`,
  and binds the account's pubkeys via the OIDC nonce; SSO never yields vault keys).
  Group→space mappings are **reconciled on every SSO login**: a space the user
  is no longer in the mapped group for is removed (manual grants are untouched).
- **auth / escrow:** `POST /v1/auth/{challenge,verify}` (Ed25519 challenge-response),
  `POST /v1/session/{refresh,logout,device-revoke}`, `GET|PUT /v1/keyset`,
  `GET /v1/escrow/params` + `POST /v1/escrow/fetch` (public: a fresh device/browser
  re-derives `K_auth` from handle + password and pulls its **encrypted** keyset blob —
  no `.keyset` file), `/v1/relay/{open,msg1,msg2,msg3}` + `GET /v1/relay/poll`
  (QR-approve device add).
- **accounts / devices:** `POST /v1/devices/add` (sibling device, shared keyset),
  `GET /v1/devices`, `GET /v1/accounts` (admin: handles / display names / member-ids /
  device counts), `POST /v1/account/profile`, `POST /v1/owner/set` (owner
  grant/revoke, server-trusted). Identity model + client flows: see
  [`CLIENT.md`](CLIENT.md). **One account, many spaces:** an **account = one keyset
  identity** (its Ed25519 = canonical member-id) that a person keeps across every
  space; devices share it; optional `display_name`/`handle` are **server-visible**
  human labels. Server-trusted **owner** (instance) + space **admin/member** roles are
  decoupled from the cryptographic per-vault role (viewer/editor/admin).
- **spaces / directory:** `POST|GET /v1/spaces` (create / list-my-memberships),
  `POST|GET /v1/spaces/members` (add / roster), `POST /v1/spaces/members/remove`,
  `POST /v1/spaces/members/role`, `GET /v1/directory` (the member-visible roster).
- **sync:** `POST /v1/sync/push`, `GET /v1/sync/delta`, `GET /v1/sync/version`.
- **vaults / policy:** `POST /v1/vaults/claim` (claim a vault namespace),
  `POST /v1/grants/publish`, `GET /v1/grants`, `GET /v1/pending` (a vault-admin's
  crypto to-do queue: the grant/revoke bindings the calling keyset must fulfil).
- **audit:** `POST /v1/audit`, `GET /v1/audit` (admin).
- **admin** (Bearer, owner / space admin, **suspended-gate-exempt** so a suspended
  account stays recoverable): `GET /v1/admin/{overview,devices,sessions,invites,
  vaults,vault,objects,relay,keysets,config,metrics,metrics/summary,health,
  migrations,instance}`, `GET /v1/admin/audit/verify`, and
  `POST /v1/admin/{account/status,session/revoke,seq-bump}`; `config` reads the
  effective config (secrets masked) and `PUT`s the live-editable subset. These are
  read-projections of **open metadata** + lifecycle controls for the self-hosted
  admin panel; they never expose ciphertext (object_bytes / keyset_bytes / relay
  messages). Account-disable is enforced in the auth path (existing sessions stop)
  with owner / last-admin anti-lockout.
- **ops** (break-glass, `X-UniSSH-Ops-Token`; empty token → disabled): `GET
  /v1/ops/{overview,instance}`, `POST /v1/ops/seq-bump`. Server-trusted infrastructure
  access only — **not a keyset**, grants no decryption.
- **service:** `GET /healthz`, `/readyz`, `/metrics`, `/v1/version`.

## Testing

```bash
cargo test                      # SQLite + byte-compat oracle vs rust-core
# Postgres integration (needs a live PG):
docker run -d --name pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=unissh -p 55433:5432 postgres:16-alpine
UNISSH_TEST_PG=postgres://postgres:test@127.0.0.1:55433/unissh \
  cargo test --test pg_integration -- --test-threads=1
```

The **oracle** tests implement the core's `SyncTransport` trait over HTTP and run the
real core `sync_pull` engine against a live server, asserting identical observable
results to the reference `InMemoryTransport` and verbatim byte round-trips. Codec and
crypto are parity-gated against the actual `rust-core` source.

## Backups & restore (read carefully)

`server_seq` is a single **instance-wide** monotonic counter; each client keeps a
trusted last-seen cursor **outside** the server. The anti-rollback invariant requires
`report_version()` (= `next_seq`) to never drop below a cursor a client has seen —
else the client treats it as a snapshot-replay **attack** and refuses to sync
(fatal `TransportRollback`). So a restore that *lowers* `next_seq` looks like a
rollback and breaks sync until corrected. Here's what that means in practice — **no
WAL/PITR setup required for self-host**:

**Crash / power loss → do nothing.** SQLite WAL recovers the live DB to the last
committed write on restart. No corruption, no `next_seq` regression. This is the
common failure and it needs no backup at all.

**Disk dies / file deleted / bad `rm` → restore your nightly snapshot, then run
`seq-bump`.** A plain nightly `cp data/unissh.db …` (or volume snapshot, or
`VACUUM INTO`) is **fine** for homelab. The snapshot is stale, so after restoring:

```bash
unissh-server seq-bump --config config.toml --by 100000000      # raise by a delta
# or raise the instance counter to an exact floor:
unissh-server seq-bump --config config.toml --to <N>
```

`seq-bump` only ever **raises** `next_seq` (never lowers). Once `report_version` is
above every client's cursor, clients stop seeing a rollback and **resume**, and
because each client does a **full re-push** on sync (§7.6) it re-uploads its whole
vault state — so anything that still lives on ≥1 client is **re-populated
automatically**. One command, then it heals itself.

**Is full re-push safe — can a client corrupt the data?** No. The server never
merges; clients resolve deterministically by **signed monotonic version (LWW)**
with verify-before-apply (`engine.rs`):
- Re-pushing an object the server already has (same version + content) is an
  **idempotent no-op**.
- A **lower-or-equal** version can **never overwrite** a newer one (`skipped_stale`);
  the highest signed version always wins, re-propagated from whichever device holds
  it. An offline device coming back with stale data converges up on its next pull.
- **Equal version, different content** surfaces as an explicit **Conflict** — the
  local copy is **not** overwritten (no silent corruption).
- A client can only push objects it can **sign**; it cannot forge another author's
  record. With `validate_signatures` on, the server also re-verifies signatures.
- **Membership / revocation / key-rotation are not undone** by a stale restore: the
  epoch-floor and keyset-gen-floor are **client-side** and don't regress, so clients
  reject down-epoch objects (`EpochBelowFloor`) regardless of what the restored
  server serves; the admin's re-push heals the server's manifests/grants.

**The one honest data hazard of a *stale* restore:** the most-recent server-only
changes are lost — specifically a **deletion (tombstone) or newer edit that no
surviving client still holds** (e.g. made by a device that's now gone). Since the
old version is validly signed and no higher version exists anywhere anymore, LWW
accepts it → a deleted item can **reappear**, or a since-superseded edit can come
back. That's loss-of-latest-state, not corruption, and it's exactly the window
between your snapshot and the failure. Tighten that window by backing up more often;
the instance **`next_seq`** snapshotted to a tiny out-of-band durable key (more
often than the full backup) lets you `seq-bump --to` precisely.

**Postgres operators** get the zero-touch upgrade if they want it (WAL archiving +
PITR or a streaming replica → restore with ~0 loss and no `seq-bump`), but that's
an *option*, not a requirement. Backups contain only ciphertext (ZK preserved).

## Honest limitations (read this)

The server is **honest-but-curious**; a malicious server can deny/withhold/replay but
**cannot decrypt or mint access**. Enforced honestly (not cryptographically):

- **Revocation does not retrieve already-synced plaintext.** It protects the future,
  not the past. The only revocation effective against a forked/untrusted client is
  **cryptographic VK rotation + epoch-floor** (client-side); the server's read-deny /
  write-deny are server-trusted.
- **Access enforcement is server-trusted; confidentiality is not.** A malicious server
  can keep serving a revoked member, but they still cannot read plaintext.
- **Metadata leaks by design** (ARCH §5.4): vault/item ids, versions, tombstones,
  author/member pubkeys, roles, key_epoch, sync_target, cache_policy, server_seq, the
  full signed (unencrypted) manifest member-set, blob sizes, push/pull timings.
  Instance-scoped identity is likewise open: account handles / display names, **space
  memberships** (which account is in which space, at which role), and — for accounts
  created via **SSO** — the OIDC **issuer + subject** the account is bound to. The
  server **never** sees names/content, VK, per-item keys, audit bodies, or private keys.
- **Live-grant `not_after` (§9.7)** is unauthenticated server metadata — an
  availability-revoke under server-trust, **not** cryptographic enforcement.
- **SSH-key offboarding requires host-side rotation (§9.6).** VK rotation does not
  invalidate an exfiltrated private SSH key still in `authorized_keys`/a CA.
- **Path A keyset freshness gap (§6.5):** an onboarding device has no prior
  `keyset_gen_floor`, so a malicious server could serve a stale generation (TOFU gap).
  PUT rejects downgrades best-effort; real protection is the client's floor.
- **Audit v1: authenticity + tamper-evidence (§11.2).** Client-signed entries are
  authentic (owner signature). The audit log is now a **server-side hash-chain**
  (`prev_hash` = SHA-256(prev ‖ canonical(record)), computed under the instance write
  lock); `GET /v1/admin/audit/verify` recomputes it and reports `{ok, broken_at}`,
  detecting any edit/reorder/deletion. Caveats remain: a malicious operator can still
  withhold/refuse-to-serve the log wholesale, and server-observed entries are unsigned
  (authentic *origin* not provable, only *integrity* of the recorded sequence).
- **Whole-DB-snapshot anti-rollback (§7.3/§16).** Per-record `report_version`
  monotonicity catches lowering. Additionally, an **instance generation** (Σ next_seq)
  is checked at startup against `[sync] min_instance_generation` — an operator-anchored
  out-of-band floor; the server refuses to boot if a restored snapshot is below it,
  closing the new-client/TOFU gap. Surfaced via `GET /v1/admin/instance`.
- **Server-side record-signature verification (§2.4) is implemented** behind
  `validate_signatures` (on by default). When enabled, the server re-verifies each
  Vault/Item/Manifest/Grant record's Ed25519 signature on write (byte-exact with
  the core `sign_version`: `"unissh-sig-v1" ‖ AAD.canonical ‖ SHA-256(content)`)
  and drops forged/tampered objects early. This is **defense-in-depth, not the
  security boundary** — the client still re-verifies on read. Audit-record bodies
  are not signature-checked here (their payload format is design-time, §11) but
  are gated by `author == owner`; Keyset blobs are AEAD-authenticated.

## License

MIT OR Apache-2.0.
