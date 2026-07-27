# Changelog

All notable changes to UniSSH are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

GitHub also generates release notes per tag from commit titles. This file exists
because those cannot answer the one question that actually matters here: **will
upgrading break the data I already have, or the server I already run?**

## Compatibility policy

UniSSH is pre-1.0, and [`README.md`](README.md) says plainly that the vault
format and the server protocol may still change. That is a licence to change
them, not a licence to change them quietly. So, for as long as the version
starts with `0.`:

- Every release states its **vault format** and **server protocol** status. If
  both are unchanged, this file says so — silence is not the signal, the
  explicit line is.
- A change to an on-disk or wire format arrives as a **new versioned scheme**,
  never as an edit to an existing one. Old data stays readable through frozen
  legacy codecs pinned by golden byte vectors; the discipline is specified in
  [`SECURITY.md`](SECURITY.md#on-disk-format-changes-migration-discipline) and
  enforced by CI, not by memory.
- Anything that *does* break — a format that stops being readable, a server that
  stops serving an older client, a setting that resets — appears under a
  **`Breaking changes`** heading at the very top of that release's entry, with
  what to do about it. If a release has no such heading, it broke nothing.
- **Server and client are versioned together but deploy separately.** Upgrade the
  server first; a newer server serves older clients, the reverse is not promised.

## [Unreleased]

### Added

- **Two-factor logins work.** A `keyboard-interactive` prompt that no stored
  secret can answer — a one-time code, a push confirmation, a forced password
  change — is now put to you instead of being answered with your password. That
  was the actual defect: a two-factor login sends two rounds, and both were
  answered from storage, so the second was always wrong and the failure looked
  like a bad password. The stored password still answers a plain PAM round by
  itself, so nothing prompts needlessly.
- **Hardware keys, through the system ssh-agent.** A per-host auth kind that
  delegates signing to the operating system's agent — which is how a FIDO/U2F
  token, a PKCS#11 smart card, a Secure Enclave key, 1Password or gpg-agent
  becomes usable at all. For such a host the key lives outside the vault, by
  definition; [`THREAT_MODEL.md`](THREAT_MODEL.md) states that plainly. What is
  stored is the public key, which is a handle.
- **Snippets** — a command library that is vault content, so it is encrypted at
  rest and syncs. Reachable from ⌘K, where selecting one types it into the
  active pane without running it, and linkable per host as startup commands,
  where they do run, in the order you picked them.
- **Session recording** as [asciicast v2], encrypted in the vault, per host.
  Exportable to a file that plays in `asciinema`, because a recording only its
  own tool can read is not evidence anyone else can check. Capped at 8 MB per
  session; a recording that reaches the cap says so instead of ending quietly.
- A **modern-only algorithm policy**: post-quantum key exchange required with no
  classical fallback, Ed25519 host keys, AEAD ciphers. Off by default, because a
  server without ML-KEM then stops connecting.
- **Post-quantum key exchange is now documented.** It is not new — the transport
  has negotiated the hybrid `mlkem768x25519-sha256` ahead of classical
  curve25519 since the first release. It had simply never been written down.
- **Shell integration (OSC 133)**: jump between prompts, and a gutter mark on a
  prompt whose command failed. Nothing is inferred — a shell that emits no marks
  produces none.
- **GPU terminal rendering on desktop**, opt-in. Phones already had it.
- `~/.ssh/config` import now applies `LocalForward`, `RemoteForward`,
  `DynamicForward`, `SetEnv`, `ServerAliveInterval`, `ConnectTimeout` and
  `Compression`, follows `Include`, and — the point — **reports every directive
  it cannot apply**, with its line. A real config is mostly directives UniSSH
  does not implement, and importing in silence left people believing their
  `ProxyCommand` came across.

[asciicast v2]: https://docs.asciinema.org/manual/asciicast/v2/

- Desktop builds for macOS now ship as a **universal binary** — one `.dmg` that
  runs on both Apple Silicon and Intel. Previously the release carried an
  arm64-only build, because GitHub's `macos-latest` runner is Apple Silicon, so
  Intel Macs silently had no artifact at all. Existing installs keep updating
  normally: the updater manifest still advertises `darwin-aarch64`, now alongside
  `darwin-x86_64`.
- Android builds now cover **every ABI**. The release carries a universal APK
  that installs on any device, plus smaller per-ABI APKs (`arm64`, `armv7`,
  `x86_64`, `x86`) for people who want them. Previously only `arm64` was built,
  which left x86-64 emulators and armv7 devices with nothing.
- **Linux builds for ARM64** (`.deb`, `.rpm`, `.AppImage`), alongside the existing
  x86-64 ones. This was the last remaining platform gap: an SSH client is used on
  Asahi, on ARM laptops and on a Raspberry Pi that has a screen attached, and none
  of those had an artifact. ARM *servers* are a different question and were already
  answered — the container images are multi-arch. Windows remains x86-64 only.
- Sideloading instructions for **Android and iOS** in
  [Installing unsigned builds](README.md#installing-unsigned-builds), including
  the Play Protect warning and what re-signing an unsigned `.ipa` with your own
  Apple ID does and does not cost you.
- `.github/dependabot.yml` covering all seven ecosystems (three Cargo
  workspaces, three npm projects, GitHub Actions), grouped so routine updates
  arrive as one pull request per ecosystem per month while security updates are
  not held back by that schedule.
- [Independent review status](SECURITY.md#independent-review-status) in
  `SECURITY.md` — an explicit statement that no third-party audit exists, what
  a stranger can verify without trusting the maintainer, and what remains
  unreviewed.
- This file.

### Changed

- Release notes and the README download table now name the **architecture** of
  every artifact, and name the architectures that are deliberately not built
  (Windows is x86-64 only; nothing ships 32-bit for desktop).

### Fixed

- Android ships a real two-layer adaptive icon instead of Tauri's placeholder,
  with a CI check that proves the replacement happened.
- Release notes describe the release they are attached to.
- The docs site's internal links are checked in CI, as are the frontends.
- Documentation claimed `.deb` and `.rpm` installs do not auto-update. They do.
- Removed an unsupported claim that the shared core is "audited" — it is not.
  See [Independent review status](SECURITY.md#independent-review-status).
- **`Match` blocks in `~/.ssh/config` rewrote the host above them.** The
  directive was not recognised, so everything inside a `Match` was merged into
  the preceding `Host` — a config with `Host prod` followed by `Match user root`
  imported prod with the wrong user and the wrong address. Silent, and in the
  one place nobody rereads.
- **`Include` was appended instead of spliced.** Resolution is
  first-match-wins, so a config opening with `Include conf.d/*` and then a
  catch-all `Host *` handed every host the catch-all's user.
- **A FIDO/U2F (`sk-*`) key imported cleanly and then failed at
  authentication.** The file holds a key handle, not a private scalar, so it
  parsed; the opaque signing error that followed read as a broken client. It is
  now refused at import, with the reason.
- **Returning from the background is treated as a reconnect, not a retry.** A
  suspended phone spends its retry budget against a machine that was never going
  to answer, then makes you wait out a backoff computed for a flaky link.
- Unsolicited agent-forwarding channels are refused. russh accepts them by
  default and we inherited that; nothing leaked, since no agent protocol is
  served over such a channel, but accepting a channel whose purpose is to ask us
  to sign was the wrong answer.
- A session recording could deadlock the app. The write ran on a runtime worker
  and needed a lock a concurrent connect held across the network phase.
- The core lock is no longer held across a handshake at all, so a connection —
  30 seconds, or minutes while you type a one-time code or touch a token — stops
  freezing every other operation.

### Compatibility

**Vault format extended, additively. Server protocol unchanged.** Two new item
types — snippets and session recordings — and four new connection-profile fields
(startup snippets, session recording, agent forwarding, system-agent identity).

Nothing breaks, and the discipline that makes that true is worth stating rather
than asserting: an older client filters items by type, so it ignores the two new
ones instead of choking on them; and profile fields it does not know round-trip
through the record's `extra` map, so re-saving a host on an old device does not
strip settings made on a new one. New fields are omitted from the encoding
entirely when unset, so existing signed items keep their exact bytes.

## [0.1.3] — 2026-07-25

Version bump only, cutting a release that carries the `v0.1.2` fixes to the
updater signing path (see below) in correctly-versioned artifacts.

### Compatibility

Vault format unchanged. Server protocol unchanged.

## [0.1.2] — 2026-07-25

### Added

- **Desktop auto-update**, verified against a minisign key compiled into the
  app. This is what makes an unsigned distributable safe to keep current: the
  client checks the release feed, verifies the payload's signature before
  executing anything, and installs on your click — never silently. Turn it off
  in Settings → About. The updater key is deliberately **separate** from the key
  that signs `SHA256SUMS`; one authorizes code execution, the other authorizes
  nothing.
- **Terminal appearance settings** — font, cursor, spacing, text colour and
  contrast — with eight built-in themes behind a contrast gate, a live preview
  built from the same options real panes use, and preferences applied to already
  open panes.
- A **Support** settings tab and a `/support` page on the site, with donation QR
  codes rendered offline.

### Fixed

- Updater artifacts were not actually signed on tag builds: an inverted
  GitHub Actions expression (`a && b || c` returns a *value*, and the empty
  string is falsy) resolved to `--no-sign` on exactly the builds that needed
  signing.
- The tag/manifest agreement guard ran under PowerShell on the Windows runner,
  where bash parameter expansion silently yields an empty string — so it had been
  "passing" without checking anything.
- Connection settings moved out of Appearance into General.

### Compatibility

Vault format unchanged. Server protocol unchanged. The first release whose
desktop artifacts carry updater metadata — 0.1.0 and 0.1.1 installs do not
auto-update and must be replaced by hand once.

## [0.1.1] — 2026-07-23

### Added

- **Mobile builds in the release pipeline** — a sideload Android APK signed by
  an identity-free self-signed key, and an unsigned iOS `.ipa`. Both get the same
  `SHA256SUMS` and SLSA provenance treatment as desktop.
- The **age public key** for encrypted vulnerability reports is published in
  `SECURITY.md`, along with the shipped integrity pipeline.
- Server-side **member vault catalog** and targeted delta sync; a client can pull
  or push one specific server vault instead of everything.

### Fixed

- **A vault could fail to bind.** An unbound cloud vault can now be bound from
  Settings, a re-pull binds a vault that landed unbound, pulled vaults are born
  bound, and Bind pushes immediately rather than waiting for the next sync.
- **Vault tombstones are version-gated on the server.** Without this, a delete
  could resurrect or duplicate vault state.
- **SQLCipher first-open is serialized** — the global crypto initialization
  raced, which could fail an open on a cold start.
- The mobile client no longer carries a 780-line fork of the hosts view; the
  shell is a shell. Layouts now collapse on *content* width rather than window
  width, which is what was overflowing on Russian text in narrow windows.

### Compatibility

Vault format unchanged. **Server protocol changed additively** — new catalog and
targeted-delta endpoints, plus version-gating on vault tombstones. Upgrade the
server before clients; older clients keep working against the newer server.

## [0.1.0] — 2026-07-15

First public release: 179 commits, no prior tag. Everything below is "added" by
definition, so it is summarized rather than enumerated.

### Added

- **Zero-knowledge vaults** — secrets encrypted client-side with a key the server
  never sees, built on RustCrypto, `hpke` (RFC 9180), Argon2id, SQLCipher, and
  Ed25519 with `verify_strict`.
- **A shared Rust core** of nine crates (`crypto`, `keychain`, `storage`,
  `vault`, `ssh-agent`, `ssh-transport`, `ffi`, `cli`, `sync`) behind a UniFFI
  boundary. Crypto, blob formats, storage, SSH, and agent logic exist only here —
  every client calls the same implementation.
- **Desktop clients** for macOS, Windows, and Linux (Tauri), with an embedded
  in-memory SSH agent whose keys never leave the core process.
- **An optional self-hosted sync server** (axum) and a **WASM admin panel**.
  Local-only operation is the default and needs no server.
- **Release integrity without a code-signing certificate** — `SHA256SUMS`, a
  `minisign` signature over it, and GitHub build provenance (SLSA attestations)
  proving the public CI built the exact artifacts from the exact public commit.

### Compatibility

The baseline everything below is measured against: local storage schema
version 9, server HTTP surface `/v1`. Both are unchanged as of 0.1.3 — no
release so far has broken a vault or a deployed server.

[Unreleased]: https://github.com/goduni/unissh/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/goduni/unissh/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/goduni/unissh/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/goduni/unissh/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/goduni/unissh/releases/tag/v0.1.0
