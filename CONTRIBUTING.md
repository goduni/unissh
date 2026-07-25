# Contributing to UniSSH

Thanks for taking an interest in UniSSH. It's an anonymously-maintained, fully open-source, self-hosted SSH client with zero-knowledge encrypted vaults — and it's honest, in-progress software. Contributions of all sizes are welcome: a typo fix, a translated doc, a fuzz harness, or a deep security review all move the project forward.

This guide is meant to be practical and skimmable. If anything here is wrong or unclear, that's a bug too — open an issue or a PR.

## Ways to contribute

You don't have to write Rust to help.

- **Code** — fix bugs or build features in any component. Stay inside the component you're touching and respect the [invariants](#critical-invariants).
- **Docs** — improve the top-level `README.md`, component READMEs, or the [docs site](https://goduni.github.io/unissh/) (`website/`).
- **Translating the core docs** — the Rust core's `rust-core/README.md` and `rust-core/ARCH.md` (the architecture spec) are currently in **Russian**. Translating them to English is one of the most useful non-code contributions right now — it's on the roadmap. Keep technical decisions and the ✅/⏳ status markers intact.
- **Reproducible-build verification** — build the unsigned releases from source and confirm the artifacts match. Releases are intentionally unsigned; the trust story is open source + `SHA256SUMS` + GitHub build provenance + reproducible builds. Independent verification is real, valuable work — report mismatches.
- **Fuzzing the length-prefixed parsers** — the blob formats, the SSH wire/agent protocols, and the sync envelopes are all length-prefixed binary. Fuzz harnesses (and the crashing inputs they find) are very welcome.
- **Security review** — read the crypto, FFI boundary, and storage code and tell us what's wrong. See [Security](#security) — please report vulnerabilities **privately**, never in a public issue or PR.

## Project layout

It's a monorepo. One root virtual Cargo workspace covers the core crates plus the server; the frontends and the wasm crypto bundle are separate, excluded Cargo roots.

| Path | What it is |
| --- | --- |
| `rust-core/` | The Rust core — 9 crates (`crypto`, `keychain`, `storage`, `vault`, `ssh-agent`, `ssh-transport`, `ffi`, `cli`, `sync`). All crypto, blob formats, storage, SSH, and agent logic lives **only** here. Architecture truth: `rust-core/ARCH.md`. |
| `server/` | The self-hosted server (axum). Control plane only — metadata, encrypted blobs, access policy, audit, sync. SSH traffic never flows through it. |
| `server-ui/` | The web admin panel — a zero-knowledge React SPA with real in-browser crypto via a wasm bundle (`server-ui/crypto-wasm/`). |
| `client/` | The Tauri v2 + React desktop/mobile client (macOS, Windows, Linux, iOS, Android). |
| `website/` | The Astro docs site published to the docs URL. |
| `deploy/` | Caddy reverse proxy + Docker Compose deployment (TLS, profiles, backups). |

The task runner is [`just`](https://github.com/casey/just) (see `justfile`); run `just` with no args to list every target.

## Dev setup

**Toolchain:**

- **Rust 1.94** — pinned by `rust-toolchain.toml` (with `rustfmt` + `clippy`), so `rustup` picks it up automatically.
- **A C toolchain + system OpenSSL** — needed for the bundled SQLCipher in the dev/test path.
- **Node 20.19+ / 22.12+** — for the frontends (`server-ui/`, `client/`).
- **`wasm-pack` + the `wasm32-unknown-unknown` target** — only for the admin panel's wasm crypto bundle:
  ```bash
  rustup target add wasm32-unknown-unknown
  cargo install wasm-pack
  ```

Component-specific platform notes (e.g. the Linux desktop WebKitGTK stack for the Tauri client) live in each component's README and in the top-level `README.md` Quick Start.

**`just` targets you'll use most:**

```bash
just build          # cargo build --workspace  (core crates + server)
just test           # core unit/bin tests + server integration tests
just lint           # cargo fmt --all --check  +  cargo clippy ... -D warnings
just fmt            # cargo fmt --all
just build-ui       # wasm-pack build + server-ui production build → server-ui/dist/
just dev-client     # run the Tauri client in dev (Vite + the Rust app)
```

Prefer raw cargo? `cargo build --workspace` / `cargo test --workspace` from the repo root do the core+server build directly.

## Before you open a PR

Run these from the repo root and make sure they're green:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

(`just lint` covers the first two.) Notes:

- The `ssh-transport` / `ffi` **integration tests spin up a local sshd**, so you need **`sshd` and `ssh-keygen` on your `PATH`** to run them.
- If you touched the admin panel, also run `just build-ui` to confirm the wasm bundle and SPA still build.
- Keep PRs focused on one component / one concern where you can — it makes review (and the security story) much easier.

### Changelog entries

Add a line to the `## [Unreleased]` section of [`CHANGELOG.md`](CHANGELOG.md) if
your change is one a user or a server operator would notice — a feature, a
behaviour change, a fixed bug. Refactors, tests, and internal cleanups don't
need one; GitHub's generated release notes already list every commit.

Two cases where the entry is **required**, not optional:

- **You changed an on-disk or wire format.** Say what changed, and confirm the
  old data still reads. The migration rules are in
  [`SECURITY.md`](SECURITY.md#on-disk-format-changes-migration-discipline) —
  formats get a new version, they never get edited in place.
- **You broke something.** A format that no longer reads, a server that no
  longer serves an older client, a setting that resets. Put it under a
  `Breaking changes` heading at the top of `## [Unreleased]`, and say what a
  user has to do about it.

Every released version carries an explicit **Compatibility** line stating whether
the vault format and server protocol moved. Keep the `## [Unreleased]` one
current as you go — reconstructing it at release time is how a break ships
undocumented.

## Critical invariants

These are non-negotiable. A PR that breaks either of them cannot be merged as-is:

1. **Never duplicate core logic.** Crypto, blob/wire formats, storage, SSH, and the agent live **only** in `rust-core`. The server, the wasm panel, and the client must call into the core (or the documented contract) — they must not reimplement it. Diverging copies are how zero-knowledge guarantees silently rot.
2. **Never route plaintext private keys across the FFI boundary.** Private key material stays inside the core's in-memory agent and never crosses the core↔UI boundary. Authentication happens via a signer over the agent. The only sanctioned exception is the strictly type-gated *reveal* of user passwords / notes (which are user secrets, not key material) — and even that can never be used to extract a private key.

When in doubt, read `rust-core/ARCH.md` and the relevant crate README before changing anything in or near the trust boundary.

## Commit style

This repo uses [Conventional Commits](https://www.conventionalcommits.org/). Match the prefixes already in the history:

```
feat(client): integrate the Tauri client with the self-hosted server
fix(...):  ...
docs: ...
ci: ...
deps: ...
```

Scope is optional but appreciated (e.g. `feat(server)`, `fix(crypto)`). Keep the subject imperative and concise.

## Licensing of contributions

UniSSH is dual-licensed **MIT OR Apache-2.0** (see `LICENSE-MIT` and `LICENSE-APACHE` at the repo root). By submitting a contribution, you agree that your work is licensed under the same dual license, with no additional terms — i.e. inbound = outbound, per **Apache-2.0 §5**. Please don't add files under incompatible licenses.

## Code of conduct

Be respectful and constructive. Participation in this project is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Security

**Do not report security vulnerabilities in public issues or pull requests.** Email **uni@goduni.me** privately instead — see [`SECURITY.md`](SECURITY.md) for the disclosure policy. Security review of the crypto, FFI boundary, and storage is one of the most valuable things you can do here; just route anything sensitive through private disclosure first.
