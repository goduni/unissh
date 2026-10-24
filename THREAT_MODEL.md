# UniSSH threat model

This is the canonical, top-level threat model for UniSSH. It states what the
system protects, which adversaries it is designed against, the metadata that is
visible **by design**, and — just as importantly — what it does **not** protect.
It is deliberately honest: some properties are cryptographic, others are merely
**server-trusted**, and the difference is spelled out below.

This file promotes the model out of the docs subpage so reviewers find it at the
repo root. The deeper, primitive-level write-up (byte formats, key hierarchy) lives
in the
[zero-knowledge model docs](https://unissh.dev/architecture/zero-knowledge-model/).
To report something that breaks these guarantees, see [`SECURITY.md`](SECURITY.md).

## What UniSSH protects

UniSSH's core property is **zero-knowledge (end-to-end encryption)**: a server
instance is an **untrusted ciphertext store**. It routes blobs and applies policy,
but never holds anything in the clear.

- **Zero-knowledge vaults.** All vault content is encrypted on the client before
  it leaves the device. The server stores ciphertext blobs plus open metadata and
  performs **no payload crypto** — it cannot decrypt vaults, mint access, or forge
  records.
- **A host may deliberately use a key we do not hold.** Choosing *System agent*
  for a host delegates signing to the operating system's ssh-agent — which is how
  a FIDO/U2F token, a PKCS#11 smart card, a Secure Enclave key, 1Password or
  gpg-agent becomes usable at all. For such a host the guarantee below does not
  apply, because the key was never ours: it lives in the agent, and whoever can
  reach that agent socket can ask it to sign. That is the same trust the tool
  providing the key already asks for, and it is opt-in per host — the default
  remains a key inside the vault. What UniSSH stores is the public key, which is
  a handle, not a secret. UniSSH's own system agent (below) is refused as that
  agent, so such a host never ends up asking UniSSH itself.
- **The keyset never crosses the FFI / UI boundary.** The private keyset never
  leaves the device; the server holds only the **public** halves. No operation
  hands the UI a private SSH key as a side effect either — authentication signs
  inside the agent. The single exception is `export_ssh_key`, an explicit
  user-initiated export of the user's own key; it is allowlisted in the boundary
  test rather than hidden by it. Everything else revealable is a password or a
  note, strictly type-gated. Secrets are zeroized,
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
SQLCipher, and Argon2id, with Ed25519 for signatures. It does compose them —
the associated-data binding, envelope layout, and key hierarchy are this
project's own, and **no third party has reviewed them**. What that leaves
verifiable, and what it leaves open, is set out in
[Independent review status](SECURITY.md#independent-review-status).

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

**Personal and space vaults.** The server registers a cloud vault either as a
*personal* vault of one account or as a vault *of a space*. The difference lives
entirely on the server-trusted plane: invitations that carry access to a
personal vault can be issued only by its owning account, and to a space vault by
any admin of that space — including admins other than the vault's creator, and
the creator only for as long as they remain one. It does not touch the
cryptographic plane: either way, reading needs a grant wrapped to the reader's
key, which only a device holding the Vault Key can publish. Clients up to 0.5
created personal vaults only; from 0.6 a vault is placed in a space only when
the user picks one explicitly, and personal stays the default. Existing vaults
are not migrated, so an instance holds both kinds. Which kind a vault is, is
server state: a malicious server could misreport it, with the consequences of
the server-trusted class above (the wrong account could queue an invitation) and
no more (it still cannot mint a grant).

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
4. **A compromised client device.** Mitigated by auto-lock (also on screen lock
   and sleep), OS-keychain storage of the Secret Key, and a minimal plaintext
   lifetime — but a fully compromised, unlocked device sees what its user sees.
   Optional desktop biometric unlock is a convenience with stated limits, not a
   stronger lock (see *Biometric unlock*).
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

## The local terminal: a process on your machine, not a new trust boundary

The desktop client can open a shell on the machine it is running on. That is a
code-execution surface, so it is stated plainly rather than left implicit.

- **It runs as you, and only on your action.** The shell is an ordinary child
  process of the app with the app's own environment, privileges and user. There
  is no privilege escalation, no setuid path, and no way to run it as another
  account. Nothing that arrives over the network — not a synced vault item, not a
  server response, not a remote host's output — can open one; the only trigger is
  a click or a keystroke in the UI.
- **It is gated on unlock, like every session.** A locked instance has no
  terminal view to open one from, and auto-lock closes local tabs along with SSH
  ones, terminating the processes in them. Settings says so in as many words.
- **The shell path is client-side configuration, which does not widen anything.**
  It lives in the webview's `localStorage`, so "whoever can write `localStorage`
  can choose what gets executed" is true — and already true of the same webview,
  which can call `ssh_exec` and `session_write` directly. An attacker with script
  execution in the webview has code execution regardless; this setting adds no
  capability they did not already have. It is deliberately **not** vault content:
  a shell path is a fact about one machine, and syncing it would let a
  compromised server influence what a client starts.
- **Recordings of local sessions are encrypted like any other**, in the vault,
  through the same recorder. They default to the *personal* vault where one is
  configured, because a recording of your own machine synced into a shared team
  vault is a disclosure the toggle never asked for; when there is no personal
  vault, Settings names the shared vault it would go to instead.

Not protected, and not claimed to be: the local terminal does not sandbox,
restrict or audit what you type into your own shell. It is your machine.

## The command-line client: a device wherever it runs

`unissh` (crate `unissh-cli`) runs the same core without a GUI, typically on a
server reached over plain SSH. An unlocked `unissh` is a **device of the
account**: for as long as a command runs, or the interactive host list stays
unlocked, its process holds the keyset and the vault keys it opened. Whoever
controls that machine — its root user, or whoever compromises it — can read that
memory, record the master password as it is typed, or ride the SSH connections it
opens. That is equally true of a laptop. What is new is where people will put it:
machines they share with others.

What the design does about it:

- **Scope by account.** `unissh login join` creates a separate account on that
  machine, and it can decrypt exactly the vaults whose keys a vault admin wraps to
  it. Pairing (`login pair`) or escrow (`login escrow`) instead gives the machine
  your whole account. The documentation tells people to use `join` for shared
  and production servers.
- **No secret on the command line or in the environment.** Secrets are asked on
  the controlling terminal (`/dev/tty`), with echo off — the invite of
  `login join` included, since a single-use invite in argv is readable by every
  user of the machine until it is redeemed, and the pasted pairing text, which
  carries the pairing secret. Such a prompt reads a key at a time with the
  terminal's own signals off, so Ctrl-C cancels it and puts the terminal back
  rather than killing the process with echo still off. For unattended use,
  `--password-file` / `UNISSH_PASSWORD_FILE` names a file — never the password
  itself — and a file anyone but its owner can read is refused, as is a device
  directory that is not the user's alone.
- **Untrusted text stays text.** Instance and space names, server errors, host
  labels and keyboard-interactive prompts come from the server, vault members
  or the remote host; they reach the terminal without control characters, so
  none of them can move the cursor, rewrite the line naming who asks, or fake
  a prompt.
- **No session at rest.** No access or refresh token is written to disk. Each
  command that needs the server signs a fresh server challenge with the unlocked
  keyset and signs out when it ends. A copy of the device directory without the
  master password (and the Secret Key, when that is not kept there) yields neither
  vault contents nor a session.
- **The kept Secret Key is the keychain's equivalent.** By default the Secret Key
  is kept in an owner-only file, like the app keeps it in the OS keychain. It is
  refused if its permissions loosen, and `--no-remember` keeps it off the disk
  altogether. A copy without a master password (`--no-password`) makes that file
  the whole credential, and the help text says so.
- **Short-lived unlocks.** A command unlocks for its own run. The interactive host
  list locks after 15 minutes without input, which zeroizes the keys, and asks
  for the master password again — on the terminal, even when a password file is
  set, since that file would unlock for whoever sits down at it. A copy without
  a master password unlocks again with its kept Secret Key alone: the lock
  means nothing there.
- **Revocation.** `unissh logout` revokes the device on the server, then deletes
  its local data, after a last sync so that nothing made there is lost with it.
  It warns first when a joined account has no other device, since deleting that
  data loses the account; `--yes` skips the question, not the warning. Revoking the device from elsewhere stops
  its sync and sessions; that is server-trusted and protects the future only (see
  the limitations below). A machine that may have been compromised calls for
  rotating the keys of the vaults it could open.
- **Host keys stay per machine.** Trust on first use is announced with the
  fingerprint. A changed key stops the connection and prints the presented
  fingerprint, and accepting it takes an explicit `unissh known-hosts trust`.
  The exception is a host reached through a jump host, whose key the core
  cannot pin ahead of a connection: there it takes `unissh known-hosts forget`,
  and the next connection trusts on first use again, announced the same way.
- **No agent forwarding.** The CLI never forwards an agent. Approving each
  signature needs a prompt that a raw terminal cannot show safely.

Not protected, and not claimed: the CLI cannot keep a machine's own
administrator out of what runs on that machine.

## Saved password at interactive prompts

When a host was logged into with a saved vault password, the terminal can offer
to type that password at a later prompt for it — `sudo` and `doas` by default,
a bare `Password:` only with a second opt-in. A password typed into the wrong
place is a disclosure, so the feature is built around one invariant:

> A session can type exactly one secret — the vault password item it
> authenticated with — into exactly that session, only while the core itself
> sees a recognised password prompt at the end of the output, at most once per
> prompt, never followed by Enter. The plaintext never crosses the FFI/IPC
> boundary and never reaches the UI, the clipboard, the scrollback or a
> recording.

- **The UI cannot choose the secret.** The fill call takes no item and returns
  nothing; the item is bound when the session opens, and the core re-reads it
  from the vault at fill time (a locked core refuses). The webview only learns
  that an offer exists, its kind and its id. Other logins (keys, inline
  passwords, the OS agent), local shells, auto-reconnecting sessions, broadcast
  and MCP have no fill at all, and neither has a session opened with fill off.
  The client opens with fill off when the setting is off and for any host with
  a username template: that password authenticates to a gateway, and the
  prompts the session shows belong to the machines behind it. An SSH-terminating
  proxy has the same property and must be opened with fill off too. That
  exclusion is the caller's: the core cannot see a profile's template or what
  the endpoint terminates, and does what `open_session` is told — the same
  limit as a compromised webview, below.
- **Consent is to one prompt.** Each offer has an id, and the fill must name
  the live one; a fill for an offer that has since been replaced — the `sudo`
  timed out and a different prompt took its place — is refused.
- **Only prompts that ask for this account's password.** The core classifies
  the last line of output against an allow-list. `[sudo] … for USER:` and
  `doas (USER@…)` count only when USER is the login user; a nested
  `user@other-host's password:`, key passphrases, `git`/HTTPS credentials,
  `Enter password:` (database and archive tools) and `New password:` are never
  offered. A line where a carriage return draws the prompt over other text
  (`(bob@evil) \rPassword: `) is not a prompt. Bare `Password:` prompts are off
  unless the user turns them on.
- **A rejected password is not typed again.** Any keystroke withdraws the
  offer, and a fill consumes it. If a prompt of the same kind comes back within
  15 seconds of a fill with nothing but Enter typed in between, the saved
  password was refused: the UI says so, and the core remembers it (by a keyed
  digest, never the password) and refuses to type it again on that session
  until it has been changed in the vault. This is language-agnostic; it does
  not parse "Sorry, try again". It catches a program that asks again by itself
  within the window — `sudo`'s retry. It does not catch one that exits on a
  wrong password (`doas`, `su`, `sudo` with `passwd_tries=1`), nor a re-prompt
  more than 15 seconds later: those are new prompts, offered again. The other
  way round, a genuinely new prompt of the same kind inside the window with
  only Enter typed — `sudo a; sudo -k; sudo b` on one line — is taken for a
  rejection: the second prompt is not offered, the user types it by hand, and
  the saved password stays refused on that session (a new session forgets
  it). Against PAM
  faillock or fail2ban the remaining guard is that every attempt is an
  explicit click; nothing is ever retried by itself. A rejected password that
  was then edited in the vault is typed again even if the edit restored the
  same password — the digest only remembers what was rejected on this session.
- **A mis-detected prompt that echoes is contained.** After a fill — for 30
  seconds, cut to 3 seconds after the next keystroke — the password is masked
  out of the output (one `*` per character, in place) before the recorder or
  the UI sees it, also when it is split across reads, wrapped at the margin or
  interleaved with colour and cursor sequences. An occurrence that completes
  before the user's next keystroke is the fill's own echo: the core then sends
  Ctrl-U so the line is not run on Enter, and the UI warns. One after it — a
  short password turning up in a command's output — is masked without either,
  since a Ctrl-U then would go into whatever program now runs. A possible start
  of an echo held back at the end of a read is shown after 150 ms if nothing
  follows, and when the session closes. Recordings capture output
  only, so the typed password is not in them either way.

Not protected, and not claimed to be:

- **Which machine is asking.** Anything printing into this session — a nested
  `ssh` (including another server's keyboard-interactive prompt), `telnet`,
  `ftp`, `su` on another host — can draw an offer, and a nested host can print
  `[sudo] password for USER:` with the same login name. The core sees bytes, not
  machines: it cannot tell which machine or program prints the prompt, and an
  accepted offer sends the outer host's password there. The offer says so and
  never names a host.
- **A transformed echo.** A program that echoes the password changed — readline
  showing a non-ASCII byte as `\303\244` in the C locale, `^X` or `M-x` for
  control and meta characters — is not masked, nor is the part of an echo
  that arrives more than 150 ms before the rest of it. Ctrl-U is readline's and zle's
  kill-line: the text stays in their kill ring, and a program reading the
  terminal raw may take it as just another byte.
- **Copies the core does not own.** The password is handed to the SSH
  library in a buffer the core wipes; the library's own packet buffers are not
  ours to wipe.
- **A compromised webview.** The defence is against accidents and a buggy UI.
  A webview running hostile code already has the ungated password-reveal call
  and does not need this one.

## Biometric unlock (desktop: Touch ID, Windows Hello)

Opt-in, per device, macOS and Windows only. On macOS, Touch ID unlock works
only in a build the user signs themselves with an Apple certificate and the
keychain entitlement; the official release is unsigned and reports it
unavailable (see the last item below). Linux is not offered: its
fingerprint stack answers yes/no and protects no secret. The key hierarchy is
unchanged — the password alone always unlocks, and nothing biometric is bound
into the Unlock Key.

**What is stored.** For a password vault, after a password unlock the user may
let the device remember the **master password**, sealed (device-wrap v1, see
`SECURITY.md`) in `biometric-unlock.bin` beside the keyset. The sealing key is
derived (HKDF) from a **device secret** that is never written to disk:

- *macOS:* 32 random bytes in a data-protection Keychain item created with
  `biometryCurrentSet` and `WhenPasscodeSetThisDeviceOnly` — readable only after
  a Touch ID match by a finger enrolled when it was made, excluded from backups
  and iCloud Keychain.
- *Windows:* the signature of a Windows Hello key credential over a random
  challenge. The Hello private key stays in the Hello container (TPM-backed
  where the machine has one) and every signature shows the Hello prompt. The
  challenge sits in Credential Manager and is not secret. On a machine without
  a TPM the Hello key is protected by software only, and the PIN that releases
  it is not guarded by the TPM's anti-hammering: whoever copies that container
  offline can brute-force the PIN without a lockout.

The Secret Key is not part of the sealed material; it is the one the device
already remembers in the OS keychain, without which biometric unlock is
neither offered nor attempted.

**Protects against:**

- **Offline theft of the disk, a backup or a roaming profile.** The blob (and on
  Windows the challenge) are useless without the device secret, which is only
  reproduced on that device, behind the biometric prompt.
- **A finger enrolled later (macOS).** The item is bound to the enrolled set;
  the set's domain-state hash is also recorded and compared. A changed set
  reads as invalidated and the user must re-enable with the password.
- **Stale material outliving the password.** Changing, adding or removing the
  master password wipes the material, as does any path that replaces this
  device's keyset (Emergency-Kit or escrow recovery, device pairing, a keyset
  pulled from a server, a new account) and resetting the instance — also when
  such a change fails after the keyset on disk was already rewritten, and also
  when the change lands while biometric unlock is being turned on: the setting
  is then not turned on, and nothing stays stored. A password
  the keyset no longer accepts is also wiped when it is next tried. Turning the
  setting off wipes both halves at once. A wipe that leaves the sealed password
  on disk is not passed over: the app says so, and Settings offers to forget
  whatever is still stored, including on a vault that no longer has a password
  (which never tries the biometric again, so nothing else would remove it). If
  only the device secret could not be deleted, the sealed password is gone and
  the leftover secret opens nothing.
- **A prompt answered after you moved on.** A biometric result counts only for
  the attempt that asked for it. Choosing the password instead, a typed unlock,
  a lock, a reset and a newer prompt each end the attempt before them. Whatever
  its prompt answers afterwards is discarded: nothing is unlocked, nothing is
  wiped, and a secret the prompt released is zeroized unused — so a Touch ID or
  Hello confirmation that arrives late cannot replace a session opened with the
  password. Choosing the password also holds for a prompt that had not come up
  yet: the screen names the attempt it gives up on, and no prompt is shown for
  it afterwards. That a lock wins is enforced in the core, for every kind of unlock
  (typed, remembered-key and biometric alike): an unlock that began before a
  lock installs nothing, however long its prompt or its key derivation took, so
  it cannot reopen a vault you have locked again. On macOS the abandoned
  evaluation is cancelled, which closes its sheet; on Windows the request is
  cancelled too, but Windows does not promise to close the Hello dialog. One
  left on screen cannot unlock anything — its answer is discarded as above —
  but it can get in the way: it may sit in front of the next Hello dialog, or
  keep that one from appearing until it is dismissed.

**Does not protect against:**

- **Anyone who can pass the platform check today.** Every finger enrolled on
  the Mac now is a way in. On Windows, every face or finger enrolled in Hello
  *and the Hello PIN* are ways in; adding a face or finger does **not**
  invalidate anything — only resetting Hello or removing its PIN does.
- **Offline PIN guessing on a TPM-less Windows machine.** Without a TPM the
  Hello key is software-protected and its PIN has no hardware anti-hammering;
  an attacker with a copy of the disk can brute-force a short PIN offline and
  then, with the blob and challenge from the same disk, the master password.
  Use a long Hello PIN, or keep biometric unlock off, on such a machine.
- **Code running as you on the unlocked OS session.** Malware can trigger the
  prompt, or socially engineer you into approving a prompt it timed, and
  receives what the unlock releases. It could already read the remembered
  Secret Key and wait for a typed password; biometric unlock adds no defence
  here.
- **Wider exposure of a reused password.** Before, a compromised session
  exposed the vault; now one biometric approval in it also releases the master
  password itself into the app's memory. If that password is used anywhere
  else, it is exposed there too. Use a unique master password.
- **Windows roaming profiles.** The blob (Roaming AppData) and the challenge
  (Credential Manager) roam; the Hello key does not. Enabling on a second
  machine overwrites the first machine's material, which then reads as
  invalidated and is wiped there: the machines take turns. Nothing leaks, but
  only one of them works at a time.
- **Two instances under one OS user.** The Keychain item, Hello credential and
  challenge are named per OS user, not per instance — and the name is the
  fixed service `me.goduni.unissh`, so a development build and the release
  build collide the same way. A second instance enabling biometric unlock
  replaces the first one's device secret; the first then asks to be
  re-enabled. Wiping is shared too: when one instance wipes (turned off, its
  password changed, its keyset replaced, an invalidation), the shared device
  secret goes, and the other instance's material goes dead with it. As with
  roaming profiles, the instances take turns; only one works at a time.
- **A change in Windows' signature scheme.** The Windows construction assumes
  Hello signs deterministically (RSA PKCS#1 v1.5 today). Were that to change,
  the signature would no longer open the blob: the material is wiped as
  invalidated and must be re-enabled. It fails safe, never into a wrong unlock.
- **Availability on unsigned macOS builds.** Biometry-protected Keychain items
  require the data-protection Keychain, which macOS ties to a signed app with a
  keychain-access-group entitlement. An unsigned or ad-hoc build is refused
  (`errSecMissingEntitlement`) and reports Touch ID unlock as unavailable; it
  is then not offered at all rather than offered weaker. The official UniSSH
  release is such a build: Touch ID unlock is for a build you sign yourself
  with an Apple certificate and that entitlement. There is no plan to sign the
  official builds. The presence gate below needs no Keychain item and is not
  affected.

When the platform stops offering biometrics after material was stored (Hello
turned off or its PIN removed, Touch ID gone, a closed lid), the material is
not wiped on its own — "not now" and "not any more" look the same — but
Settings shows the feature off, says why, and offers to forget it.

**Secret-Key-only vaults: the presence gate.** A Secret-Key-only vault on a
device that remembers the Secret Key opens at startup with no check at all.
The optional *Require Touch ID / Windows Hello at startup* asks for the
platform's presence prompt first (`LAContext` on macOS, `UserConsentVerifier`
on Windows) and, while it is on, the unlock screen does not fill in the
remembered key either; a dismissed prompt leaves the vault locked, with the
Secret Key from the Emergency Kit as the manual way in. It is switched on only
after the prompt has succeeded once on that device, so a prompt that never
works there cannot be the only way in. Nothing is stored for it. It is a **presence check, not a protection of the key**: the setting is
device-local app state (the webview's `localStorage`, beside the startup
setting), and the Secret Key stays readable without a prompt by any process
running as you, exactly as before. It stops someone at your unlocked session
from opening the vault through the app's own UI; it does not stop code running
as you, or anyone who can edit the app's local state.

Instances whose server sign-in is SSO or escrow behave the same: sign-in is a
server-plane matter, and the local unlock is password-based or Secret-Key-only
on every instance alike.

## The system agent: vault keys for local programs, one approval at a time

The desktop client can act as an ssh-agent for other programs on the same
machine (`ssh`, `git`, `ssh-add -l`, an IDE's remote window). It is a new local
boundary, so what crosses it is spelled out here.

- **Off by default, and per key.** Nothing listens until the user turns the
  system agent on in Settings, and it offers only the keys the user shared with
  it one by one. That choice is device-local metadata inside the SQLCipher
  database. It is never synced or exported, and it is pinned to the public key
  it was made for, so a key rotated, re-imported or replaced by sync under the
  same id is not offered until it is shared again. macOS, Linux and Windows.
- **The endpoint's permissions are the access control.** On macOS and Linux it
  is a Unix socket in a `0700` directory, itself `0600`. On Windows it is the
  named pipe `\\.\pipe\unissh-agent-<SID>`, named after the user's own SID so
  that each Windows account has its own, with a protected DACL holding a single
  entry: the current user's own SID (read from the process token, not the
  owner-rights alias, which under an elevated token would mean the
  Administrators group). Remote pipe clients are rejected, and the default
  integrity label keeps lower-integrity processes of the same user out. Either
  way only processes running as the same OS user can connect; nothing else
  authenticates a caller. The two differ in who can claim the address: on
  Unix the `0700` directory keeps other users from placing anything there,
  while a pipe name is machine-wide and predictable, and the DACL guards only
  the instances UniSSH created. The pipe is therefore created as its first
  instance, so if anything already holds the name the agent reports it in use
  instead of joining it. OpenSSH's own `openssh-ssh-agent` pipe is never taken
  over.
- **What a connected process can do without asking:** list the shared keys'
  public halves (and, for a key with an attached certificate, that certificate
  as a second identity), with the key's item id as the comment. That is
  metadata (which keys this user shares and what they are called), the same
  disclosure any ssh-agent makes to whoever can reach it.
- **What needs an approval: every signature, one by one.** The request is shown
  in UniSSH with the key and its vault, the user name the SSH login payload
  would log in as, and the calling process as the OS reported it. It is denied
  by default and on a 60-second timeout, and every exit but *Approve* refuses.
  The prompt cannot name the server: an agent sign request carries the user
  and the session hash, not the destination host (OpenSSH's `session-bind`
  extension is refused along with every other extension). A payload that is
  not an SSH login (for example a git commit signature) is shown as such. A
  signature asked for a certificate is approved and made as its key. The agent
  does not check a certificate's validity (expiry, principals); like OpenSSH's
  agent, it leaves that to the server. The
  private key stays in the core's embedded agent; only the signature leaves.
- **What it cannot do at all:** add, remove, lock or unlock keys, or call any
  extension (all refused outright); get a signature with a key that was not
  shared; get a SHA-1 `ssh-rsa` signature (an RSA request must ask for
  `rsa-sha2-256` or `rsa-sha2-512`; one asking for neither is refused before
  any prompt); or read private key material.
- **The caller's identity is advisory.** The pid comes from the kernel when the
  connection is accepted (`SO_PEERCRED` on Linux, `LOCAL_PEEREPID` on macOS,
  `GetNamedPipeClientProcessId` on Windows) and the executable path is looked
  up from it. Neither is verified, and the
  prompt says so. A pid can be reused after its process exits. A process can
  exec something else after connecting, or hand the connected socket to
  another process, in which case the prompt names whoever connected, not
  whoever is asking. For an interpreter the executable is the interpreter
  (`python3`), not the script. The identity helps a person judge a request;
  it is not what grants access.
- **One prompt at a time, for every agent; connections are bounded.** The
  core puts one signature request to the window at a time, whether it came
  through the system agent or through a forwarded agent of an SSH session;
  the others wait in a single line. The 60-second timeout of a request starts
  when its prompt is shown, not while it waits, so none expires unseen; the
  prompt says how many were waiting behind it when it appeared. Waiting itself
  is not timed: a request waits at most 60 seconds for each request ahead of
  it. The line holds at most one request per system-agent connection (64, see
  below) and 64 forwarded requests, beyond which a forwarded request is
  refused immediately, so the worst case is a little over two hours, reached
  only if 127 requests ahead are each left to time out. A new prompt ignores
  input for its first half second, so a click meant for the previous one
  cannot answer it. A client that disconnects withdraws its open prompt or
  gives up its place in line, and so does a connection the listener cuts. A
  forwarded request does the same when the remote host closes the agent
  channel it came in on, or when its SSH session ends. A client that only half-closes its side
  (`shutdown(SHUT_WR)` after sending) counts as gone too, so its prompt is
  withdrawn. OpenSSH's own clients keep the stream open and are unaffected.
  At most 64 connections are served at once (one beyond that is closed
  unanswered), and a connection that sends no request for ten minutes is
  closed. The identity list is resolved from the vaults once and reused only
  while nothing it was resolved from has changed (the set of shared keys, and
  any vault, item or certificate, a sync pull included; a lock discards it); a
  signature never relies on that list, it resolves the key again.
- **No unlocked vault, no agent.** A locked vault lists no identities and signs
  nothing. The listener stops on vault lock, screen lock, sleep and exit,
  cutting open connections, withdrawing the open prompt and refusing every
  request still waiting in line, so none of them is shown afterwards. It comes back after
  the next unlock, however it is made (password, Secret Key, or the biometric
  unlock above), or wake if the vault is still unlocked, when the setting is
  on. A vault lock does the same to forwarded agents' requests, in the core
  itself and so on every platform: the open prompt is withdrawn and every
  request in line is refused, whichever agent it came through, and a request
  arriving while the vault is locked (on an SSH session that outlived the
  lock) is refused without a prompt, so nothing asked before or during a lock
  is shown after the unlock that follows. A screen lock or
  sleep that leaves the vault unlocked (the "lock with the screen" setting off,
  or its grace period still running) stops only the system agent: SSH sessions
  stay up, and a forwarded request is still put to the window, which the
  operating system's lock screen covers; unanswered, it is refused after its
  60 seconds. A prompt answered in the instant before it is withdrawn still yields
  nothing. After the approval the core re-checks that it is unlocked and that
  the key is still shared and unchanged, and an answer for a connection that
  was cut is discarded.
- **It does not loop into itself.** A host profile using *System agent* auth is
  meant to reach the operating system's agent. If `SSH_AUTH_SOCK` points at
  UniSSH's own socket instead (compared as canonical paths), the connection
  fails with an error saying so, rather than UniSSH prompting itself for a
  vault key. The OS-agent key picker refuses it the same way. On Windows the
  loop cannot arise: *System agent* auth always dials OpenSSH's own pipe,
  whose name differs from UniSSH's.
- **Nothing sensitive is logged.** Neither the data to be signed, the key, nor
  the caller's identity is written to the log.

Not protected, and not claimed to be: a process running as the same user can
connect, list the shared public keys and raise approval prompts (one at a time,
up to the line's length) as often as it likes, and by holding every connection
slot or filling the line it can keep the user's own tools from being served,
or make them wait behind its prompts. A remote host given agent forwarding can
fill its share of the same line and delay local requests the same way; its
prompts name that host; refusing them, and closing the session so that no more
arrive, is the remedy.
Any signature the user approves is that process's to use,
including a login signature for a server other than the one the user had in
mind, since the prompt can name only the user, not the host. A process running
as the same user can also attack the app directly (debugging it, reading its
memory, driving its UI) without going through the agent at all. Root or an
administrator is outside this boundary entirely. The system agent assumes a
trusted desktop session, as the MCP listener does.

On Windows, another user's process can create the user's pipe (the name is
per user but not secret: a SID can be looked up)
while UniSSH's agent is not listening (locked, disabled, or not started yet),
since the name disappears with the last instance. The user's tools then talk
to that process: it receives their agent requests and can offer its own
identities, though it gets no UniSSH keys or signatures. The first-instance
check protects the agent, not the clients; "in use" in Settings is the
signal.

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

### The update check (visible to GitHub, not to your server operator)

Desktop builds make one outbound request that does **not** go to your server or to
a host you configured: at most once an hour, UniSSH fetches the release manifest
from `github.com` to see whether a newer version exists. It is a plain GET of a
public file.

- **Sent:** nothing about you, your account, your hosts, or your vaults. No
  identifier, no telemetry, no version-specific path — the URL is the same for
  every user.
- **Inferable by GitHub:** your IP address, and the timing pattern of a UniSSH
  install starting up. That is enough to say "someone at this IP runs UniSSH".
- **Downloaded updates** are verified against a signing key compiled into the app
  before anything executes, so a hostile network cannot substitute a payload.

This is on by default: builds are unsigned, there are no back-ports (see
[`SECURITY.md`](SECURITY.md)), and a user who never updates runs known-vulnerable
code — a worse outcome for most people than the IP exposure. If that trade is
wrong for your threat model, turn it off in **Settings → About**; nothing else in
the app depends on it. Mobile sideloads never check — no updater is compiled
into them.

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
  **instance generation** (the instance-wide `next_seq`) is checked at startup
  against an operator-anchored, out-of-band floor (`min_instance_generation`); the
  server refuses to boot below it. The client's trusted **anti-rollback cursor**
  (a last-seen `server_seq` held locally, never replicated back from the server)
  refuses any delta or reported cursor below what it has already seen. Together
  these bound a stale restore — but a restore *within* the bound can still
  resurrect a deleted item, which is why a full re-push is safe and expected.
- **Audit: integrity is provable, origin is not.** Client-signed entries are
  authentic (owner Ed25519 signature, verified with associated data
  `(vault_id, "__audit__", 0)`). The log is a server-side **hash chain**, and a
  verify endpoint detects any edit, reorder, or deletion. But a malicious operator
  can still refuse to serve the log wholesale, and server-observed entries are
  unsigned — their **integrity in the recorded sequence** is provable, their
  **origin** is not.
- **Audit webhook: a new outbound channel.** When `[audit.webhook]` is configured,
  the server POSTs audit entries and their metadata (account/device ids, vault ids,
  timestamps) to that URL, HMAC-signed for integrity but not encrypted by the
  server. Use an `https://` URL; plain `http://` to a non-loopback host is warned
  about at boot. The sink is set in config only, never through the API.
  `[audit.syslog]` sends the same entries (minus the hash fields) in plaintext over
  UDP or TCP with no TLS and no authentication; a non-loopback collector is warned
  about at boot, and the documented setup is a local forwarder.

There is also **no "reset password via email"** for zero-knowledge vaults — that
would nullify the property. Lose every device **and** the Emergency Kit (Secret
Key), and that instance's data is gone. An optional, opt-in, audited M-of-N org
escrow is a planned future capability, not a default.

---

For the primitives and key hierarchy, see the
[zero-knowledge model docs](https://unissh.dev/architecture/zero-knowledge-model/)
and [`rust-core/crates/sync/README.md`](rust-core/crates/sync/README.md) for the
verify-before-apply pipeline. To report a vulnerability, see
[`SECURITY.md`](SECURITY.md).

## Local AI automation (desktop MCP)

The opt-in MCP listener adds a local plaintext boundary from an authenticated AI
application to a native authorization broker. It binds IPv4 loopback only,
validates exact Host, rejects Origin/query credentials, and authenticates every
request. The caller receives only granted opaque target IDs and aliases, owned
session/task metadata and approved command output. Its connection parameters
cannot override credentials or destinations. No approval, signing, vault-export
or terminal-tab attachment tool is exposed. Host trust, Personal destination binding and complete jump
routes remain Core responsibilities; MCP forbids TOFU for every hop.

An integration token and native consent are separate authorities. Live grants
require an unlocked native Core and are invalidated by
security-relevant storage revisions, including synced changes. Final command
admission is serialized with revocation and Core mutation. Output access is checked
on every read. A late authentication/output callback cannot restore revoked
records. Tokens persist locally as digests. Native consent is separately saved in
versioned local SQLCipher metadata, with an absolute expiry or no expiry. Native
unlock/restart restores consent only after checking current security records;
changed records require consent again. Connections and tasks never survive restart.
An OS lock/suspend prevents restoration until a native unlock/wake; a wake does not
resume while an observed screen lock remains active. Explicit revoke deletes saved
consent. Token rotation creates a new integration identity
and revokes the previous identity so already-authenticated requests cannot inherit
new permissions. Sharing one token intentionally shares one integration's scope.

A malicious model can request a dangerous command or return misleading output.
In manual mode, the native UI displays the immutable command and optional cwd
with escaped controls and requires a separate decision. The explicitly selected
trusted-application mode bypasses per-command native confirmation for the granted
targets; it trusts the token holder to apply its own approval policy. An agent's
claim of user approval is not verified and never enables this mode. Grant edits
replace the old scope and revoke its runs/sessions. No shell safety classifier or
output-redaction claim is made. Authorized remote shell authority can read secrets
or cause irreversible effects in either mode. Output can leave the device through the chosen AI provider. Closing an
SSH channel cannot recall those effects or guarantee remote child termination.

Local malware, a hostile OS administrator, and port impersonation are not isolated
by localhost. Bearer authentication authenticates the caller, not the server; an
impostor listener can capture tokens. Browser requests are rejected, but an
arbitrary local process can forge headers. The feature assumes a trusted desktop
environment and offers no cross-user sandbox guarantee. Only observed native OS
lock/suspend events can revoke immediately; desktops without those signals still
have manual vault lock and native grant/runtime deadlines. Separate loopback
namespaces (remote IDEs/containers/WSL) are unsupported, not exposed through LAN.

This feature changes neither ciphertext sync nor vault/AAD formats. Its separately
versioned local digest configuration is not synced. Temporary SQLite revision
triggers observe security-relevant writes without a persistent schema migration.

Opt-in host recording also persists MCP command transcripts in encrypted vault
items. This deliberately extends command/output lifetime beyond the ephemeral
broker buffer; normal vault sharing, sync and explicit export apply. Recordings
are bounded operational history, not tamper-proof or crash-durable audit logs.
Their versioned optional MCP content extension preserves raw stream bytes while
the standard asciicast preview escapes terminal controls. Lock saves partial
captures while Core still has keys; late callbacks cannot reopen a saved capture.
Recording-only local item writes do not change authorization snapshots. Changes
into or out of recording type still do, and external SQLite commits conservatively
invalidate snapshots regardless of item type. The cryptographic envelope and AAD
encodings are unchanged.

Command stdin and environment values follow the same untrusted-agent boundary as
command text: native review/deduplication binds them, input sizes are bounded,
values are quoted rather than interpolated, and optional host recordings persist
them encrypted. Caller-owned task discovery excludes those inputs and foreign
integrations. Native command limits cannot be increased through MCP. Native-only
retention is off by default and never removes interactive terminal recordings;
when enabled, its deletion tombstones sync like explicit recording deletions.
