---
title: Server & API surface
description: The UniSSH zero-knowledge control plane — its stack, the /v1 API endpoint groups, the identity/account/device model, and how it is verified byte-compatible with the core.
---

The UniSSH server is a **self-hostable, zero-knowledge control plane**: an untrusted ciphertext store plus device/team sync, membership/sharing/revocation, and audit. **SSH traffic does not flow through the server** — it sees only encrypted blobs and open metadata. Think of it as a private, self-hosted sync backend ("self-hosted Termius").

## Stack

tokio · **axum 0.8** · **sqlx 0.9** (**SQLite** default, **Postgres** for scale) · rustls (**TLS 1.3**) · `ed25519-dalek` (`verify_strict`, the same library as the core) · figment (layered config) · tracing + **Prometheus** metrics.

By design the server performs **no payload crypto** — only TLS and Ed25519 signature verification for auth, registration, and (defense-in-depth) record validation.

## Identity, accounts, and devices — one account, many spaces

One server is a single **instance** that hosts many **spaces** (teams). A person has **one account** across every space they belong to — spaces are groupings, **not** identity boundaries — and a shared **directory** spans the spaces.

```
instance ─┬─ space "Backend"   ─┬─ member: Alice, John
          │                     └─ …
          ├─ space "Security"   ─┬─ member: Alice, Igor
          │                     └─ …
          └─ directory: every account on the instance

account "Alice" ── canonical keyset (ed25519 = MEMBER-ID, x25519)
      ├─ device A (laptop)   ┐ share the same keyset
      └─ device B (phone)    ┘ (one identity, many devices, many spaces)
```

- An **account = one keyset identity.** Its **Ed25519 public key is the canonical member-id** — the thing vault grants and membership are keyed on. The server holds only the two **public** keys; the private keyset never leaves the device.
- **Devices of an account share that keyset** (so granting "Alice" once works on all her devices, in every space). Each device has its own `device_id` for sessions and revocation.
- **Human identifiers** (`display_name`, `handle`) live on the account and are **server-visible metadata**. For privacy-sensitive deployments, use a pseudonym.

Keep the **two authority planes** distinct:

- **Server-trusted roles** — **owner** (the first user to *claim* the instance with its one-time setup code; runs ops and appoints space admins), **space-admin**, and **member**. This is *server-trusted* authority over invites, spaces, audit, device-revoke, and publishing grants. The owner cannot be removed while last; the last space-admin cannot be removed (anti-lockout).
- **Vault role** (viewer / editor / **admin**) — *cryptographic*, living in the signed manifest + grant; controls who can decrypt/write a vault. Being an instance owner grants no vault key; holding a vault-admin grant confers no server-side privilege.

Onboarding is by a space-scoped, revocable **invite link** (`/v1/join`) or **SSO (OIDC)**; a fresh device recovers its keyset by **escrow sign-in** (handle + password + Secret Key) or **QR-approve** from an already-trusted device. The full client flows (claim, first device, add a sibling device, team management) are in the repository's `server/CLIENT.md`.

## API surface (`/v1`, JSON over TLS)

All crypto blobs are base64 (STANDARD). **One server = one instance — there is no tenant header.** `Authorization: Bearer` gates private routes; the setup/onboarding routes (`/v1/claim`, `/v1/join`, `/v1/escrow/*`, `/v1/oidc/callback`) are **public** (the credential — setup code / invite token / password proof / id_token — is in the body); mutating routes accept an `Idempotency-Key`.

### Instance / setup / onboarding

`GET /v1/instance` (public: claimed-flag, instance-id, enabled auth methods, and — when OIDC is on — the issuer + client_id a browser needs), `POST /v1/claim` (public: the **first user** claims the unclaimed instance with the **setup code** printed to the log → becomes the **owner**). Onboarding: `POST /v1/invite` (owner / space-admin mints a one-time, space-scoped invite link), `POST /v1/invite/revoke` (cancel a still-pending invite), `POST /v1/join/preview` + `POST /v1/join` (public: redeem an invite → a new account bound to the invited spaces), `POST /v1/oidc/callback` (public: **SSO** — verify the IdP id_token against the JWKS, map IdP groups → spaces, bind the account's pubkeys via the OIDC nonce; SSO never yields vault keys, and group→space is reconciled on every login).

### Auth / escrow

`POST /v1/auth/{challenge,verify}` (Ed25519 challenge-response), `POST /v1/session/{refresh,logout,device-revoke}`, `GET|PUT /v1/keyset`, `GET /v1/escrow/params` + `POST /v1/escrow/fetch` (public: a fresh device re-derives `K_auth` from handle + password and pulls its **encrypted** keyset blob — the server stores only `sha256(K_auth)`, never the decryption key; **no `.keyset` file**), and the device-to-device relay `/v1/relay/{open,msg1,msg2,msg3}` + `GET /v1/relay/poll` (QR-approve device add).

### Accounts / devices

`POST /v1/devices/add` (a sibling device sharing the keyset), `GET /v1/devices`, `GET /v1/accounts` (admin: handles, display names, member-ids, device counts), `POST /v1/owner/set` (owner grant/revoke, server-trusted, anti-lockout), `POST /v1/account/profile`.

### Spaces / directory

`POST|GET /v1/spaces` (create / list-my-memberships), `POST|GET /v1/spaces/members` (add / roster), `POST /v1/spaces/members/remove`, `POST /v1/spaces/members/role`, `GET /v1/directory` (the member-visible roster).

### Sync

`POST /v1/sync/push`, `GET /v1/sync/delta`, `GET /v1/sync/version`. These implement the server side of the core's untrusted-transport sync — see [Sync & anti-rollback](../../architecture/sync-model/).

### Vaults / policy

`POST /v1/vaults/claim`, `POST /v1/grants/publish` (publish a new-epoch manifest + per-member grants — membership, rotation, or revoke), `GET /v1/grants`, `GET /v1/pending` (a vault-admin's crypto to-do queue: the grant/revoke bindings the calling keyset must fulfil).

### Audit

`POST /v1/audit`, `GET /v1/audit` (admin). The log is a server-side hash chain; `GET /v1/admin/audit/verify` recomputes it. Entry formats: [Audit log & entry format](../server-audit/).

### Admin / ops (for the admin panel)

A Bearer-admin (owner / space-admin), per-instance read surface plus lifecycle controls, deliberately **suspended-gate-exempt** so a suspended account stays recoverable:

`GET /v1/admin/{overview,devices,sessions,invites,vaults,vault,objects,relay,keysets,config,metrics,health,migrations,instance}`, `GET /v1/admin/audit/verify`, and `POST /v1/admin/{account/status,session/revoke,seq-bump}`.

These are **read-projections of open metadata** plus lifecycle controls; they **never** expose ciphertext (object bytes, keyset bytes, or relay messages). `config` reads the effective config with secrets masked (and `PUT`s the live-editable subset). Account-disable is enforced in the auth path (existing sessions stop) with owner / last-admin anti-lockout.

### Service

`GET /healthz`, `/readyz`, `/metrics`, `/v1/version`.

:::note[Ops vs. admin]
An **optional break-glass** infrastructure surface (`GET /v1/ops/{overview,instance}`, `POST /v1/ops/seq-bump`) sits behind a static `X-UniSSH-Ops-Token` and is **off by default** (an empty token disables it). That is server-trusted infrastructure access — **not** a keyset, and never decryption. It is *not* how the admin panel normally signs in (the panel authenticates by escrow or SSO). See [Server configuration](../../operations/configuration/) and [Admin panel](../server-ui/).
:::

## Build, run, and verification

```bash
cargo build --release
cp config.example.toml config.toml
./target/release/unissh-server migrate --config config.toml   # also auto-applied on serve
./target/release/unissh-server --config config.toml
```

The server is **byte-compatible** with the Milestone-2 core: every wire format mirrors the core 1:1 and is mechanically verified. The test suite includes an **oracle** that implements the core's `SyncTransport` trait over HTTP and runs the real core `sync_pull` engine against a live server, asserting identical results to the reference in-memory transport plus verbatim byte round-trips. Codec and crypto are parity-gated against the actual `rust-core` source.

See also: [Server configuration](../../operations/configuration/), [Docker Compose deployment](../../operations/deploy/), and [Backups & anti-rollback restore](../../operations/backups/).

## License

MIT OR Apache-2.0.
