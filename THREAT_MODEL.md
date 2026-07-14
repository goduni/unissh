# UniSSH threat model

This is the canonical, top-level threat model for UniSSH. It states what the
system protects, which adversaries it is designed against, the metadata that is
visible **by design**, and — just as importantly — what it does **not** protect.
It is deliberately honest: some properties are cryptographic, others are merely
**server-trusted**, and the difference is spelled out below.

This file promotes the model out of the docs subpage so reviewers find it at the
repo root. The deeper, primitive-level write-up (byte formats, key hierarchy) lives
in the
[zero-knowledge model docs](https://goduni.github.io/unissh/architecture/zero-knowledge-model/).
To report something that breaks these guarantees, see [`SECURITY.md`](SECURITY.md).

## What UniSSH protects

UniSSH's core property is **zero-knowledge (end-to-end encryption)**: a server
instance is an **untrusted ciphertext store**. It routes blobs and applies policy,
but never holds anything in the clear.

- **Zero-knowledge vaults.** All vault content is encrypted on the client before
  it leaves the device. The server stores ciphertext blobs plus open metadata and
  performs **no payload crypto** — it cannot decrypt vaults, mint access, or forge
  records.
- **Keys never cross the FFI / UI boundary.** The private keyset never leaves the
  device; the server holds only the **public** halves. The UI never receives
  plaintext private keys — the core won't hand them out. The only revealable
  secrets are user passwords/notes, strictly type-gated. Secrets are zeroized,
  private-key plaintext is never written to disk, and key pages are `mlock`'d where
  possible.
- **Signed, monotonic versions + associated-data binding.** Every item is
  encrypted with its `vault_id + item_id + version` bound into the AEAD associated
  data, so the server cannot silently swap or reorder blobs (a misplaced blob fails
  authentication). Each object change carries a monotonic version counter **signed
  by its author (Ed25519, `verify_strict`)**; a client detects a rolled-back
  version or a foreign signature. Vault keys are envelope-encrypted under each
  member's public key (HPKE/X25519) and bound to `(vault_id, recipient, key_epoch)`,
  so the server only ever sees wrappers and cannot pass off a stale wrapper as a
  current-epoch one. These same signed-version primitives underpin both sync and
  the local integrity audit (`verify_chain`).
- **Transport.** TLS 1.3 only — via the bundled Caddy, in-process rustls, or a
  reverse proxy you control. SSH traffic always goes **straight from your device to
  your hosts** and never tunnels through the sync server.
- **Honest-but-curious server, stated plainly.** A malicious server can **deny,
  withhold, delay, or replay** — but it **cannot decrypt, mint access, or forge
  records**.

UniSSH does **not** roll its own crypto: it builds on RustCrypto, `hpke`,
SQLCipher, and Argon2id, with Ed25519 for signatures.

## Instance model and the two authority planes

A server is a single **instance** that hosts many **spaces** (teams). Two kinds
of authority run over that instance, and keeping them apart is central to the
model:

- **Server-trusted authority (who the server lets act).** The **owner**
  (server-trusted, established at claim) and **space admins / members** drive
  operational surfaces: invites, spaces, the pending crypto-action queue, member
  attestations, devices, and account labels. The server enforces these roles; a
  malicious server could ignore them. This is the same *server-trusted* class as
  revocation below — not a cryptographic guarantee.
- **Cryptographic authority (who can decrypt).** Vault membership, HPKE-wrapped
  Vault Keys, signed manifests/grants, and the cryptographic vault roles
  (viewer/editor/admin) decide who can actually read plaintext. The server only
  ever routes wrappers; it cannot mint this authority.

These planes are **decoupled on purpose**: being an instance owner grants no
vault key, and holding a vault-admin grant confers no server-side privilege.
Collapsing them would let a server compromise escalate into decryption — which
must never happen.

### First-boot claim window

An unclaimed instance prints a one-time **setup code** to its log on first boot
and stores only its `sha256`. The first caller to present that code together with
a self-attested keyset registration wins a **single-winner CAS claim**, becoming
the instance owner and admin of its first space. The code is valid **only while
the instance is unclaimed**; a second claim is refused. The exposure in that
window is bounded: a fresh instance holds no vaults and no ciphertext, so all
that is at stake is who first claims an empty server. (`[setup].code` can pin a
fixed code for IaC/tests; a `reclaim` admin command re-opens the window if an
owner loses every device, leaving existing data intact.)

## Onboarding & sign-in surfaces

The instance model adds unauthenticated, security-critical entry points. None of
them ever yields decryption material — keys arrive only via device pairing or
escrow, never from the server's say-so.

### Escrow sign-in (keyless-device recovery)

A device holding only the **password + Secret Key** — no session, no enrolled
device — can recover its encrypted keyset by handle:

- **Split credentials.** The retrieval credential `K_auth` is a domain-separated
  HKDF over `(Argon2id(password), Secret Key)` under a distinct `info` label,
  independent of the Unlock Key `K_unlock` that actually decrypts. The server
  stores **only `sha256(K_auth)`** and **never sees `K_unlock`**; `K_auth` cannot
  recover `K_unlock`.
- **Enumeration resistance.** `GET /v1/escrow/params` always answers `200`: a
  real, escrow-enabled handle returns its stored Argon salt/params, and anything
  else returns a **deterministic per-handle decoy** of identical shape. The decoy
  salt is HMAC'd under a **server-private `escrow_decoy_secret`** that no endpoint
  ever returns, so a probe cannot tell an enrolled handle from an unenrolled one —
  and, critically, the decoy is **not** keyed from the public `instance_id`, which
  would have let an attacker recompute it and distinguish the two. `POST
  /v1/escrow/fetch` runs a constant-time compare against either the real hash or a
  fixed dummy and returns `403` on every failure, so unknown-handle, not-enrolled,
  and wrong-credential are timing-indistinguishable.
- **Anti-DoS on the fetch path.** The `argon_*` params arrive from an untrusted
  server, so the client **clamps them before deriving** (ceilings well above the
  recommended 64 MiB / t=3 / p=1), refusing a params response that would force a
  memory-exhausting derivation on a recovering device.
- Passwordless (SSO / Secret-Key-only) accounts derive `K_auth` from the Secret
  Key alone; their escrow fetch is authorized by the session, not a password.

### SSO / OIDC (a server-trusted plane, never a key plane)

`POST /v1/oidc/callback` turns an IdP-signed `id_token` plus a self-attested
keyset registration into an account, device, and session:

- **Token verification.** The id_token is verified against the issuer **JWKS**,
  with the algorithm allowlist pinned to the resolved key's own **asymmetric**
  family; a symmetric/HMAC JWK is refused and `alg:none` rejected, closing the
  classic RS256→HS256 key-confusion hole. `iss`/`aud`/`exp` are enforced and
  every failure returns a uniform "invalid id_token". The JWKS fetch is
  **redirect-disabled and host-pinned** with a short timeout (SSRF-hardened).
- **Nonce key-binding.** The id_token's `nonce` MUST equal
  `base64(sha256(ed25519_pub ‖ x25519_pub))` of the presented keyset. Because the
  nonce sits inside the IdP's signature, a **stolen id_token cannot be re-bound to
  an attacker's keyset**. A new SSO identity's Ed25519 key must also be
  instance-wide unique, so SSO cannot silently take over a non-SSO account.
- **SSO asserts identity + memberships, never keys.** A successful callback finds
  or provisions the account by `(issuer, subject)` and maps IdP groups → space
  memberships. It **never** touches keyset / escrow / vault-key material;
  decryption keys arrive only via pairing or escrow. A compromised IdP can
  impersonate a *server-trusted* identity — it **cannot decrypt vaults**.
- **Reassertion gate.** `oidc` sessions carry a reassertion deadline (default
  7 days); past it the client must re-run the OIDC dance rather than silently
  refresh, bounding how long a deprovisioned SSO user keeps server access.

(**Invite / join** — a space admin issues a single-use invite; a joiner
self-attests a keyset and is added to the space at the invited role. As with
claim and OIDC, the server verifies the self-attestation but never sees plaintext
keys.)

## Admin panel: a web-crypto trust boundary

The admin panel runs the **real rust-core crypto compiled to wasm** (account
unlock, challenge signing, registration, grant rotation, manifest/binding
verification) — it is not a thin client that hands the server plaintext. But it
trusts the **wasm/JS bundle the server serves at page load**: a compromised server
could ship a backdoored bundle that exfiltrates a password or Secret Key the
moment they are typed. This is the **same web-vault compromise as the 1Password /
Bitwarden web apps**, and it is inherent to browser-delivered crypto.

Consequently the **desktop client remains the highest-trust surface** for
cryptographic operations; the panel is an operational tool for owners and
space-admins. Panel (`web`) devices auto-expire and are revocable, so a panel
session is ephemeral by construction, unlike a long-lived app device.

## Adversaries considered

In decreasing order of importance:

1. **Backend compromise / an honest-but-curious instance operator.** A database
   dump yields only ciphertext. This is exactly what zero-knowledge addresses.
2. **A malicious insider at the operator, or legal compulsion.** The operator
   physically cannot hand over what it cannot decrypt.
3. **A malicious team member** with legitimate vault access. Cryptography does not
   help here — least-privilege (cryptographic vault roles: viewer/editor/admin) and
   audit do.
4. **A compromised client device.** Mitigated by auto-lock, OS keychain / Secure
   Enclave storage of the Secret Key, biometric unlock, and a minimal
   plaintext lifetime — but a fully compromised, unlocked device sees what its user
   sees.
5. **An active MITM during public-key distribution.** Arises when sharing /
   onboarding, where a member's public key is first learned (see the TOFU gap
   below).
6. **A server serving a backdoored admin-panel bundle.** The panel runs real
   crypto in the browser but trusts the wasm/JS the server delivers at page load;
   a hostile server can replace it. Mitigated by keeping the panel an operational
   tool and the desktop client the highest-trust crypto surface (see *Admin
   panel: a web-crypto trust boundary*).
7. **A compromised or hostile IdP (OIDC deployments).** It can assert a
   *server-trusted* identity and space memberships for accounts it controls, but
   the nonce key-binding and the ZK boundary mean it **cannot** decrypt vaults or
   re-bind a stolen id_token to another keyset (see *SSO / OIDC*).

## Metadata visible by design

A UniSSH server is, by definition, a store of opaque ciphertext **plus open
metadata**. Confidentiality is cryptographic; access enforcement is server-trusted.
The operator can see — and this is an accepted, documented trade-off:

- vault and item **ids**, **versions**, and **tombstones**;
- author / member **public keys**, **roles**, and `key_epoch`;
- `sync_target`, `cache_policy`, and `server_seq` (sequence numbers);
- the full **signed (unencrypted) member-set** manifest — the social graph of
  who shares with whom;
- each account's **space memberships** and **server-trusted roles** (instance
  owner, space admin/member), and — for SSO accounts — the external identity
  binding `(issuer, subject)` the operator's IdP assigned;
- **blob sizes** and **push/pull timings**.

For privacy-sensitive deployments, an account's human labels (`display_name`,
`handle`) are also server-visible metadata — **use a pseudonym, not real PII.**

The server **never** sees: item/vault **names** or **content**, Vault Keys (VK),
per-item keys, audit bodies, or private keys. Content — **including item names** —
is always encrypted. But membership, the social graph, sizes, and timings are
visible to the operator by definition; this is documented to the user rather than
hidden.

## Honest limitations / NOT protected

**Confidentiality is cryptographic; access enforcement is server-trusted.** The
following are enforced by the server's good behavior, **not** by cryptography —
overclaiming them would be dishonest:

- **Server-trusted authority is not cryptographic.** Instance ownership, space
  admin/member roles, invites, memberships, and OIDC-asserted identity gate what
  the server *lets you do*; they do not gate what you can *decrypt*. A malicious
  server (or a compromised IdP, for the SSO plane) can misrepresent them. Only the
  cryptographic plane — VK wrapping, signed manifests/grants, the vault roles — is
  enforced against an untrusted server.
- **Revocation is server-trusted and protects the future, not the past.**
  Revocation does not retrieve already-synced plaintext. The server's
  read-deny/write-deny can be ignored by a malicious server, which could keep
  serving a revoked member. The only revocation effective against a forked or
  untrusted client is **cryptographic VK rotation + a client-side epoch floor** —
  after which the revoked member still cannot read *new* plaintext.
- **Live-grant expiry (`not_after`) is unauthenticated server metadata** — an
  availability-revoke under server trust, not cryptographic enforcement.
- **SSH-key offboarding requires host-side rotation.** Rotating the VK does **not**
  invalidate an exfiltrated private SSH key still sitting in a host's
  `authorized_keys` or a CA. Rotate it on the host.
- **TOFU onboarding keyset-freshness gap.** A freshly onboarding device has no
  prior generation floor, so a malicious server could serve a **stale generation**
  — a trust-on-first-use gap. The server rejects downgrades best-effort; the real
  protection is the client's floor once it's established.
- **Whole-DB snapshot rollback is bounded, not eliminated.** Per-record version
  monotonicity catches lowering of any single object. Across the whole DB, an
  **instance generation** (the sum of per-space sequences) is checked at startup
  against an operator-anchored, out-of-band floor (`min_instance_generation`); the
  server refuses to boot below it. The client's trusted **anti-rollback cursor**
  (a last-seen `server_seq` held locally, never replicated back from the server)
  refuses any delta or reported cursor below what it has already seen. Together
  these bound a stale restore — but a restore *within* the bound can still
  resurrect a deleted item, which is why a full re-push is safe and expected.
- **Audit: integrity is provable, origin is not.** Client-signed entries are
  authentic (genesis-owner Ed25519 signature, verified with associated data
  `(vault_id, "__audit__", 0)`). The log is a server-side **hash chain**, and a
  verify endpoint detects any edit, reorder, or deletion. But a malicious operator
  can still refuse to serve the log wholesale, and server-observed entries are
  unsigned — their **integrity in the recorded sequence** is provable, their
  **origin** is not.

There is also **no "reset password via email"** for zero-knowledge vaults — that
would nullify the property. Lose every device **and** the Emergency Kit (Secret
Key), and that instance's data is gone. An optional, opt-in, audited M-of-N org
escrow is a planned future capability, not a default.

---

For the primitives and key hierarchy, see the
[zero-knowledge model docs](https://goduni.github.io/unissh/architecture/zero-knowledge-model/)
and [`rust-core/crates/sync/README.md`](rust-core/crates/sync/README.md) for the
verify-before-apply pipeline. To report a vulnerability, see
[`SECURITY.md`](SECURITY.md).
