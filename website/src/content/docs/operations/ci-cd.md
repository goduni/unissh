---
title: CI/CD & releases
description: The UniSSH GitHub Actions pipelines — core/server CI, the docs site deploy, and the desktop client build/release flow, plus the core release artifacts.
---

UniSSH ships four GitHub Actions workflows: continuous integration for the Rust workspace, the desktop client build/release, container-image publishing, and this documentation site's deploy.

## Core & server CI (`ci.yml`)

Runs on every push to `main`, every pull request, and weekly on a schedule (to surface new advisories via cargo-deny). Three jobs:

- **`lint`** — a log-redaction guard (`scripts/check-log-redaction.py`), then `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings`. The toolchain (channel 1.94 + rustfmt/clippy) comes from `rust-toolchain.toml`.
- **`test`** — `cargo test --workspace` inside a `rust:bookworm` **root container**. The sshd-backed integration tests are designed to run as root against a self-spawned `sshd`, so the container provides a privileged, reproducible environment; it installs `openssh-server`/`openssh-client` plus the OpenSSL headers and C toolchain for bundled SQLCipher.
- **`deny`** — `cargo-deny check advisories bans sources licenses`, reading `deny.toml` from the repo root and, separately, from the two excluded workspaces (`client/src-tauri`, `server-ui/crypto-wasm`) — a supply-chain gate over all three lockfiles.

## Container images (`publish-images.yml`)

On every push to `main`, on `v*` tags, and on manual dispatch, this workflow builds two **multi-arch** (linux/amd64 + linux/arm64) images and pushes them to the GitHub Container Registry with SLSA build-provenance attestations:

- `ghcr.io/goduni/unissh-server` — the server (`server/Dockerfile`).
- `ghcr.io/goduni/unissh-caddy` — the Caddy front door + admin SPA (`deploy/Caddy.Dockerfile`).

A push to `main` publishes the `latest` tag; a `v*` tag publishes the matching semver tags. These images back the prebuilt [`compose.prod.yml`](../deploy/) deployment, so operators can run the stack without a local compile. The Rust core itself is **not** released as a standalone artifact — it is a path dependency of the server and client.

## Desktop client (`client.yml`)

One file carries two flows:

- **CI** — on pull requests and pushes to `main`: build the desktop bundles to validate they compile and bundle. No GitHub Release is created.
- **Release** — on a `v*` tag: build release bundles and attach them to a GitHub Release.

It builds on a five-way matrix: `ubuntu-22.04` and `ubuntu-22.04-arm` (the version is pinned for webkit2gtk-4.1 availability and broad AppImage glibc compatibility → `.deb`/`.rpm`/`.AppImage`), `windows-latest` and `windows-11-arm` (`.msi` via WiX + NSIS `.exe`), and `macos-latest` building `--target universal-apple-darwin` (`.dmg`/`.app` for Apple Silicon and Intel in one bundle). Both ARM legs build natively rather than cross-compiling, which is what keeps the vendored-OpenSSL and webkit dependencies straightforward. Node 22 + the repo-root pinned Rust toolchain are used; the client's path dependency on `../../rust-core/crates/ffi` resolves inside the single checkout (no cross-repo checkout, no PAT).

Each tagged release also gets a **`SHA256SUMS`** file, a **`SHA256SUMS.minisig`** detached signature over it, and a **build-provenance attestation** (`actions/attest-build-provenance`) for the bundles — verifiable with `gh attestation verify <file> --repo goduni/unissh`, which needs GitHub CLI 2.49 or newer (see [Install from a release](../../overview/install/)).

:::caution[Unsigned by design (privacy)]
The client builds ship **unsigned** — no Apple cert/notarization, no Windows code-signing. This is a deliberate privacy choice: no developer identity is attached.

- **macOS** (`.dmg`/`.app`): Gatekeeper will quarantine the app. After moving it to `/Applications`, run `xattr -dr com.apple.quarantine /Applications/UniSSH.app`.
- **Windows** (`.msi`/`.exe`): SmartScreen may warn — choose "More info" → "Run anyway".
- **Linux** (`.deb`/`.rpm`/`.AppImage`): unsigned.
:::

### Signing keys (not code-signing certificates)

The workflow holds two bare Ed25519 (`minisign`) keypairs. Neither carries a name, email, or keyserver presence, which is exactly why they are compatible with an anonymously maintained project where a code-signing certificate is not.

| Secret | Signs | Purpose |
| --- | --- | --- |
| `MINISIGN_SECRET_KEY` | `SHA256SUMS` | Proves the checksum file itself wasn't swapped on the release page. |
| `TAURI_SIGNING_PRIVATE_KEY` | Desktop updater artifacts | Lets an already-installed client verify an update before executing it. |

They are kept separate on purpose: the first authorizes nothing, the second authorizes code execution on every desktop install. The updater's public half is compiled into the app (`client/src-tauri/tauri.conf.json`), so **losing that private key permanently ends auto-update for everyone already installed** — a new key would be rejected by every existing client.

Because `bundle.createUpdaterArtifacts` makes the bundler *require* the signing key, and GitHub withholds secrets from fork pull requests, non-release builds pass `--no-sign`. Only tag builds produce signed updater artifacts and the `latest.json` manifest clients poll.

Mobile (iOS/Android) is intentionally **out of scope** for the workflow: there is no privacy-preserving unsigned distributable for those stores/runtimes.

## Documentation site (`docs.yml`)

This site deploys to **GitHub Pages** and is served at the custom domain **[unissh.dev](https://unissh.dev)** (pinned by `website/public/CNAME`; the old `goduni.github.io/unissh` project URL now redirects there). The workflow runs on pushes to `main` that touch `website/**` (or the workflow itself), and on manual dispatch:

- **build** — Astro build via `withastro/action@v6` (path `website`, Node 22).
- **deploy** — `actions/deploy-pages@v5` to the `github-pages` environment, with `pages: write` and `id-token: write` permissions and a single-concurrency `pages` group.

To build the site locally, see [Build from source](../build/) and the site's own `package.json` (`npm run build`).
