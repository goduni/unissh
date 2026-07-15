# Security Policy

UniSSH is a self-hosted, end-to-end-encrypted SSH client. Its core security
property is **zero-knowledge sync**: the server you host stores ciphertext and a
bit of routing metadata, and **cannot decrypt your vaults, mint access, or forge
records**. Because of that, security bugs in the cryptographic core and the sync
verify-before-apply path matter more than almost anything else in this repo — we
take reports about them seriously and want to make them easy to send.

The deeper model lives in [`THREAT_MODEL.md`](THREAT_MODEL.md) and in the
[zero-knowledge model docs](https://goduni.github.io/unissh/architecture/zero-knowledge-model/).

## Supported versions

UniSSH is **pre-1.0**. There are no stable releases and no long-term support
branches yet — APIs, formats, and the server protocol can still change.

Security fixes land on **`main`** and in the **latest tagged release**. There is
no back-porting to older tags. If you run UniSSH today, track `main` (or the most
recent release) to stay current on fixes.

| Version            | Supported                          |
| ------------------ | ---------------------------------- |
| `main` (latest)    | ✅ fixes land here first            |
| latest release tag | ✅                                  |
| any older tag      | ❌ no back-ports (pre-1.0)          |

## Reporting a vulnerability

**Please report security issues privately. Do not open a public GitHub issue,
pull request, or discussion for a suspected vulnerability** — that discloses it
before a fix exists.

Email **`uni@goduni.me`**. You can also use GitHub's private
**["Report a vulnerability"](https://github.com/goduni/unissh/security/advisories/new)**
advisory form, which routes to the same maintainer.

Please include, as far as you can:

- **Affected component** — e.g. `rust-core/crates/crypto`, `rust-core/crates/sync`,
  `server/`, `server-ui/`, or `client/`, and the commit/tag you tested.
- **Reproduction** — minimal steps, a script, or a failing test. For crypto/sync
  issues, the exact inputs and the property you believe is violated.
- **Impact** — what an attacker gains (e.g. read plaintext, forge a record,
  bypass an epoch floor, roll back state) and under which adversary (see
  [`THREAT_MODEL.md`](THREAT_MODEL.md) for the adversaries we consider).
- Any suggested fix or mitigation, if you have one.

**What to expect.** This is an anonymously-maintained indie project, not a vendor
with an on-call team, so please set expectations accordingly:

- **Acknowledgement** of your report within **7 days**. If you don't hear back,
  re-send — mail can be lost.
- A **coordinated-disclosure** request: please give a reasonable window for a fix
  before public disclosure (we suggest up to **90 days**, shorter for issues
  under active exploitation). We'll keep you updated and credit you in the fix /
  advisory if you want credit (and only if you want it).
- If a report turns out to be a known limitation rather than a bug, we'll point
  you to where it's documented in [`THREAT_MODEL.md`](THREAT_MODEL.md) rather than
  silently closing it.

### PGP / encrypted reports

For especially sensitive reports you may want to encrypt the contents.

> **TODO (maintainer): publish an encrypted-report public key.**
> A dedicated **age / minisign / PGP** public key for `uni@goduni.me` has **not
> been generated yet**, so there is no key to fingerprint here. Until one is
> published, email plain text (omit the actual exploit payload and offer to send
> details over an encrypted channel), or use the private GitHub advisory form.
> When a key exists it will be committed here and pinned in this section:
>
> ```text
> -----BEGIN PLACEHOLDER PUBLIC KEY-----
>   (not yet generated — do NOT trust any key claiming to be this one
>    until it appears in this file on the main branch)
> -----END PLACEHOLDER PUBLIC KEY-----
> ```

## Release integrity / unsigned builds

**UniSSH release binaries are intentionally unsigned.** There is no Apple
Developer-ID / notarization and no Windows Authenticode certificate, because
obtaining one would tie the project to a verifiable legal identity, and UniSSH is
anonymously maintained. This is a deliberate privacy trade-off, **not** a request
to ignore integrity — we replace certificate-based trust with verifiability:

- **Open source.** The whole client, core, and server are public; nothing in a
  release is built from code you can't read.
- **Checksums.** Each release is meant to ship a `SHA256SUMS` file. Verify your
  download against it — see the README's
  [Verifying release integrity](https://github.com/goduni/unissh#verifying-release-integrity)
  steps (`shasum -a 256` / `Get-FileHash`).
- **Build provenance (SLSA attestations).** Releases are meant to carry GitHub
  build-provenance attestations, so you can prove the public CI built exactly
  that artifact from exactly that commit:

  ```bash
  gh attestation verify <artifact> --repo goduni/unissh
  ```

- **Reproducible builds + optional pseudonymous minisign signature.** You can
  rebuild from source and compare, and (once published) verify a detached
  `minisign` signature over `SHA256SUMS`.
- **Build it yourself.** If you'd rather trust only your own toolchain, see
  [Build from source](https://github.com/goduni/unissh#build-from-source). A
  locally-built app is the strongest trust check.

> Some of the above (the `SHA256SUMS` / provenance / signature release pipeline)
> is still being wired up — the README and [`THREAT_MODEL.md`](THREAT_MODEL.md)
> track current status honestly. Do **not** suggest, or wait for, Apple/Windows
> code-signing: it's out of scope by design.

A captured warning ("developer cannot be verified" / SmartScreen) on first launch
is expected for unsigned builds and is **not** a security finding — see
[Installing unsigned builds](https://github.com/goduni/unissh#installing-unsigned-builds).

## Logging and redaction

UniSSH logs to help diagnose problems (stdout, a rotating file in the per-OS app
log dir, and the webview console on the client; structured `tracing` on the
server). Logs are held to a **hard redaction rule** — mirrored across the server
(`server/src/obs.rs`), the client core, and the frontend (`client/src/bridge/log.ts`):

> **Never** log private keys, passphrases, the master password, the Secret Key,
> refresh/access tokens, decrypted vault contents, or full public keys / crypto
> blobs. Log **metadata only** — host/port/user, key fingerprints, server/vault/item
> ids, error kinds, generation counters, and sync counts.

A log line that leaks any of the secret material above is a **security bug** —
please report it. (The intent at each instrumented call site is documented inline,
and CI runs `scripts/check-log-redaction.py` to fail the build if a log/print call
interpolates a secret-bearing identifier.)

The client log file rotates at ~5 MB and keeps one rotated copy (≈10 MB on disk).
Verbosity is `info` by default; set `UNISSH_LOG` (or `RUST_LOG`) to raise it without
a rebuild — e.g. `UNISSH_LOG=debug` or `UNISSH_LOG=info,unissh_sync=debug,russh=info`.

## On-disk format changes (migration discipline)

Persisted crypto artifacts (the personal `EncryptedKeyset` sidecar, wrapped vault
keys, grants, manifests, backups) carry a **scheme version** that covers the *whole
recipe* — byte layout **plus** key derivation, IKM construction, AAD recipe,
domain-separation strings, and combine order — not only the algorithm id. The
3-byte crypto header (`format_version || alg_id`) versions the *primitive*; it does
**not** version the *construction*. A change to how a key is derived or what goes
into the AAD is a **format change even when the algorithm is unchanged**.

> **Rule:** if a change would make a previously-written blob decode, decrypt, or
> verify differently, it MUST move an explicit per-type scheme version. Never a
> silent semantic change under a stable tag.

Invariants:

- **Read many, write one.** Readers dispatch on the stored version and support
  every version ever shipped; writers only ever emit the current one.
- **Freeze old schemes.** Once a scheme ships, its derivation/serialization code is
  immutable — add `…_v{n+1}`, never edit `…_v{n}`. Each frozen scheme is pinned by
  a **golden byte vector** (a captured blob that must keep decoding). A change that
  breaks a frozen vector is a format break that needs a new version, not an edit.
- **Migrate lazily on open, atomically, verify-before-replace.** On opening an
  artifact below the current version, re-wrap under the current scheme and persist
  atomically; only then raise the anti-rollback floor (persist-before-raise, so a
  failed write can't brick the next launch). See `keychain::unlock_account_migrating`
  and the FFI `unlock` / `unlock_from_server_blob` call sites.
- **Refuse the future loudly.** A version newer than the reader knows → a clear
  "written by a newer app" error, never a misparse.

Checklist when touching any derivation / AAD / KDF-combine / domain string:

1. Bump the affected type's scheme version (write the new one; keep reading old).
2. Freeze the old derivation/codec as a `…_legacy_v{n}` function — do not mutate it.
3. Add a golden byte vector for the old scheme (captured once).
4. Add migrate-on-open: open old → re-wrap current → persist atomically → raise floor.
5. Add a round-trip test that an old-scheme artifact opens and migrates forward.

Two reference instances, with deliberately different strategies by risk profile:

- **keyset** (`keychain/src/keyset.rs`) — a single local, unsigned, unsynced record:
  full **migrate-on-open** (re-wrap to v3, generation+1, persist atomically before
  raising the floor). Cheap and safe to re-write, so it converges to one format.
- **vault** (`vault/src/vault.rs`) — Ed25519-signed, sync-replicated, multi-record
  (owner-VK + name + every item): **read-fallback** via frozen legacy codecs instead
  of re-writing. The owner-VK `info`, item-key keywrap, and content/name AEAD each try
  the current scheme then the pre-round-2 codec (`open_owner_vk` / `unwrap_key_compat`
  / `aead_decrypt_compat`). No re-sign, no version bump, no sync churn — so there is no
  way for the migration itself to brick a vault. New writes (`put_item`, `set_name`,
  `rotate_vk`) are current, so any modification upgrades that record naturally; pure
  reads of old data stay readable indefinitely. The signature mechanism never changed,
  so old records still verify. (No grant read-fallback is needed: the member
  `build_grant`/`open_grant` path has bound `vk_wrap_info(vault_id, member_ed, epoch)`
  since the initial commit — round 8 only unified the *dormant* `seal_vk_to_recipient`
  extension point, which has no opener and never stored data. Adding a raw-`vault_id`
  fallback there would re-introduce the weak binding round 8 removed.)

The frozen codecs (`aead_*_pre_agility`, `derive_unlock_key_legacy_v1`,
`*_key_pre_agility`) are pinned by golden vectors; `pre_agility.rs::*_incompatible`
are the canaries that catch a construction change masquerading as a no-op.

## Authentication & onboarding surface

A server is one **instance** hosting many **spaces**. Accounts, sessions, and
roles are **server-trusted** — they gate what the server lets you *do*; the
zero-knowledge crypto boundary above is what actually protects vault *contents*.
The current onboarding / sign-in entry points all verify a **self-attested keyset
registration** and never see plaintext keys:

- **Claim** (`POST /v1/claim`) — a first-boot **setup code** (printed to the log
  while the instance is unclaimed, stored only as `sha256`) plus a keyset
  registration wins a single-winner claim of the empty instance, creating the
  owner and first space. The code is valid only while unclaimed.
- **Invite / join** (`POST /v1/invite`, `POST /v1/join`) — a space admin issues a
  single-use invite; a joiner self-attests a keyset and is added at the invited
  role.
- **Escrow sign-in** (`GET /v1/escrow/params`, `POST /v1/escrow/fetch`) — a
  keyless device recovers its encrypted keyset from `(password, Secret Key)`. The
  server stores only `sha256(K_auth)`, never the decryption key `K_unlock`; both
  endpoints are enumeration-resistant (a deterministic per-handle decoy under a
  server-private secret; a constant-time `403` on the fetch).
- **SSO / OIDC** (`POST /v1/oidc/callback`, when `[oidc]` is enabled) — an
  IdP-signed `id_token` is verified against the issuer JWKS and bound to the
  keyset by a **nonce key-binding**, asserting identity + space memberships
  **only** — never vault keys.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full treatment (the two authority
planes, the escrow decoy secret, the nonce binding, and the admin-panel
web-crypto boundary).

Relevant config (server TOML, override with `UNISSH__` env): `[setup].code` pins a
fixed setup code (empty → one is generated at boot while unclaimed); the `[oidc]`
block sets issuer / client_id / audience / jwks_url / group_map / reassertion age
(disabled by default); and the optional `[ops].token` is a **server-trusted**
infrastructure token that grants **no** decryption — empty disables the
`/v1/ops/*` surface entirely.

## Scope

Reports are welcome anywhere in the repo, but the **highest-value review targets**
— where a bug most directly breaks the security promise — are:

- **`rust-core/crates/crypto`** — the cryptographic core (AEAD + associated-data
  binding, Ed25519 `verify_strict` signatures, HPKE/X25519 envelope encryption,
  Argon2id, zeroization). UniSSH does **not** roll its own primitives, but the
  composition and byte formats live here.
- **The sync verify-before-apply path (`rust-core/crates/sync`)** — the client
  treats the transport as **untrusted**. Anything that lets a malicious server
  get an unverified, rolled-back, foreign-signed, below-epoch-floor, or
  equivocating object **applied** to local state is a high-severity bug.

Also in scope: the server's defense-in-depth signature re-verification, the
admin-panel wasm crypto, anti-rollback floors, and any path that could route
plaintext private keys across the FFI/UI boundary (which must never happen). The
onboarding / sign-in surface counts here too — the escrow endpoints'
enumeration-resistance and constant-time behavior, the OIDC `id_token`
verification (JWKS, asymmetric-only algorithms, `iss`/`aud`/`exp`) and nonce
key-binding, and the single-winner claim CAS.

Out of scope: the unsigned-build OS warnings above, and the documented
**server-trusted** (not cryptographic) limitations — revocation/live-grant expiry,
SSH-key offboarding, the TOFU onboarding gap, audit origin-vs-integrity, and the
server-trusted authority plane itself (instance owner / space roles, invites, and
OIDC-asserted identity + memberships assert what the server *permits*, not what
you can *decrypt*). These are known and explained in
[`THREAT_MODEL.md`](THREAT_MODEL.md); a report that one of them is server-trusted
isn't a vulnerability, but a way to make a documented limitation *worse* than
documented is — including anything that lets the SSO/escrow surface **yield a
decryption key**, which it must never do.
