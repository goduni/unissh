# Client integration guide — accounts, spaces, devices

How the identity model works and the flows a client app implements against this server.

## Identity model (the mental model)

One server is a single **instance** that hosts many **spaces** (teams). A person has
**one account** across every space they belong to — spaces are groupings, **not**
identity boundaries — and a shared **directory** spans the spaces.

```
instance ─┬─ space "Backend"   ── members: Alice, John …
          ├─ space "Security"  ── members: Alice, Bob …
          └─ directory: every account on the instance

account "Alice" ── canonical keyset (ed25519 = MEMBER-ID, x25519)
      ├─ device A (laptop)   ┐ share the same keyset
      └─ device B (phone)    ┘ (one identity, many devices, many spaces)
```

- An **account = one keyset identity**. Its **Ed25519 public key is the canonical
  member-id** — the thing vault grants and membership are keyed on. The server holds
  only the two **public** keys; the private keyset never leaves the device.
- **Devices of an account share that keyset** (so granting "Alice" once works on all
  her devices, in every space). Each device has its own `device_id` for
  sessions/revocation.
- **Human identifiers** live on the account: `display_name` ("Alice Smith") and a
  unique `handle` ("alice"). ⚠️ **These are server-visible metadata** (like the member
  set already is). For privacy-sensitive deployments, put a pseudonym, not real PII.

There are **two distinct authority planes** — keep them separate in the UI:
- **Server-trusted roles** — **owner** (the first user to *claim* the instance;
  appoints space admins, runs ops), **space-admin**, and **member**. *Server-trusted*
  authority over invites, spaces, audit, device-revoke, and publishing grants. Set via
  `/v1/owner/set` and the `/v1/spaces/*` endpoints.
- **Vault role** (viewer/editor/**admin**) — *cryptographic*, lives in the signed
  manifest+grant. Controls who can decrypt/write a vault. Set via `/v1/grants/publish`.

Being an instance owner grants no vault key; holding a vault-admin grant confers no
server-side privilege. The planes are decoupled on purpose.

## Flow 1 — first device (create the account)

There is **no bootstrap token**. The first user **claims** the instance with the
one-time **setup code** the server prints to its log while unclaimed, and becomes the
**owner** (and admin of the first space). Everyone else joins later via an invite or
SSO.

1. Client generates the keyset locally (`keychain::create_account`) and a Secret Key.
2. Build the registration payload + `unissh-registration-v1` signature.
3. **Claim** the unclaimed instance (→ owner), or **join** with an invite, or arrive
   via **SSO**:
   ```http
   POST /v1/claim
   { "setup_code": "...", "registration_payload": "...",
     "registration_signature": "...", "display_name": "Alice",
     "handle": "alice", "space_name": "Backend" }
   → 201 { "account_id", "device_id", "space_id", "instance_id" }
   ```
   - **Join an invite:** `POST /v1/join` with `{ "invite_token", "registration_payload",
     "registration_signature", "display_name"?, "handle"? }` (preview first with
     `POST /v1/join/preview`). The new account is bound to the invited spaces.
   - **SSO:** `POST /v1/oidc/callback` verifies an IdP `id_token`, binds the keyset via
     the OIDC nonce, and maps IdP groups → spaces. SSO never yields vault keys.
4. Authenticate to get a session:
   ```http
   POST /v1/auth/challenge { account_id, device_id, key_id } → ServerAuthChallenge
   # sign challenge.canonical with the keyset → signature
   POST /v1/auth/verify { challenge, signature } → { access_token, refresh_token, … }
   ```

## Flow 2 — add another device (shared keyset)

1. On the **existing** (authenticated) device:
   ```http
   POST /v1/devices/add          (Bearer)
   → 201 { "device_id" }         # a new device_id under the same account
   ```
2. Bring the keyset to the **new** device out-of-band — no `.keyset` file to copy:
   - **QR-approve (recommended):** the device-to-device relay (`/v1/relay/*`) with an
     OOB code; the new device receives the sealed keyset. Pass it the `device_id` too.
   - **Escrow sign-in (keyless recovery):** the new device re-derives `K_auth` from
     `handle + password + Secret Key`, pulls its **encrypted** keyset
     (`GET /v1/escrow/params` → `POST /v1/escrow/fetch`), and unlocks it locally with
     `K_unlock`. The server stores only `sha256(K_auth)` and never sees `K_unlock`.
3. The new device authenticates with that `device_id`, signing the challenge with the
   **shared keyset**. It now has the same member-id → **all of the account's vault
   grants already apply**. No re-granting.

Revoke a single device with `POST /v1/session/device-revoke { device_id }` — kills its
sessions without touching siblings.

## Flow 3 — owner / space-admin: manage spaces and the team

```http
GET /v1/accounts              (Bearer-admin)
→ { "accounts": [
     { "account_id", "display_name": "Alice", "handle": "alice",
       "is_owner": true, "member_pubkey": "<b64 ed25519>", "status": "active",
       "device_count": 2 }, … ] }
```
Use `member_pubkey` when you build a manifest/grant for someone (that's their member-id).
`GET /v1/directory` returns the member-visible roster.

- **Create / staff a space** (server-trusted):
  ```http
  POST /v1/spaces                 { "name": "Backend" }              (Bearer-owner)
  POST /v1/spaces/members         { space_id, account_id, role }     (Bearer space-admin)
  POST /v1/spaces/members/role    { space_id, account_id, role }
  POST /v1/spaces/members/remove  { space_id, account_id }
  ```
  `GET /v1/spaces` lists the caller's own memberships; `GET /v1/spaces/members` is the
  space roster.
- **Invite a new person** (space-scoped, revocable):
  ```http
  POST /v1/invite         { space_intents:[…], vault_intents?:[…], ttl_seconds? }
  → { invite_id, token, url, expires_at }        # url = {public_url}/join#<token>
  POST /v1/invite/revoke  { invite_id }           # cancel a still-pending invite
  ```
- **Grant/revoke instance-owner** (server-trusted, anti-lockout — the claim owner can't
  be demoted, and you can't remove the last owner):
  ```http
  POST /v1/owner/set { "account_id": "...", "is_owner": true }   (Bearer-owner)
  ```
- **Give vault access / make a vault-admin** (cryptographic): build a new-epoch
  `manifest` listing the member with their role + a per-member `grant` (VK wrapped to
  their x25519), sign, and:
  ```http
  POST /v1/grants/publish { manifest, grants:[…], new_epoch, revoke_epoch? }
  ```
  A vault-admin's outstanding crypto to-do (bindings the caller must fulfil) is at
  `GET /v1/pending`.
- **Update your own profile:** `POST /v1/account/profile { display_name?, handle? }`.

## Endpoint quick-reference

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/claim` | public (setup code) | first user claims the instance → **owner** + first space |
| `POST /v1/join` (`/preview`) | public (invite token) | redeem an invite → new account bound to the invited spaces |
| `POST /v1/oidc/callback` | public (id_token) | SSO: verify IdP token, bind keyset, map groups → spaces |
| `POST /v1/invite` | Bearer (space-admin) | mint a one-link, space-scoped invite |
| `POST /v1/invite/revoke` | Bearer | cancel a still-pending invite |
| `GET /v1/escrow/params` + `POST /v1/escrow/fetch` | public (password proof) | fetch the encrypted keyset for a keyless device (no `.keyset` file) |
| `POST /v1/devices/add` | Bearer | add a device under the caller's account (shared keyset) |
| `GET /v1/accounts` | Bearer-admin | list accounts (handle, display_name, is_owner, member_pubkey, device_count) |
| `POST /v1/owner/set` | Bearer-owner | grant/revoke instance-owner (anti-lockout) |
| `POST\|GET /v1/spaces` | Bearer | create a space / list my memberships |
| `POST\|GET /v1/spaces/members` (`/remove`, `/role`) | Bearer (space-admin) | staff a space |
| `GET /v1/directory` | Bearer | the member-visible roster |
| `POST /v1/account/profile` | Bearer | set your own display_name / handle |

`claim`/`join` also accept optional `display_name` and `handle`.
