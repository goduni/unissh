---
title: Install & prerequisites
description: Install the UniSSH desktop client from a release, or build any component from source — core, server, client, and admin panel.
---

There are two ways in: download a desktop build from a release, or compile from source. Most people want the release. Building from source is for the server, the admin panel, mobile, an unlisted platform, or hacking on the code — and the rest of this page covers the prerequisites for that.

## Install from a release

The [latest release](https://github.com/goduni/unissh/releases/latest) carries desktop bundles built and published by CI ([`client.yml`](https://github.com/goduni/unissh/blob/main/.github/workflows/client.yml)):

| Platform | Download |
| --- | --- |
| **macOS** (Apple Silicon *and* Intel) | `.dmg` — one universal bundle for both |
| **Windows** (x64 *and* ARM64) | `.msi`, or the `.exe` (NSIS) installer |
| **Linux** (x64 *and* ARM64) | `.deb`, `.rpm`, or `.AppImage` |
| **Android / iOS** (sideload) | `.apk` / unsigned `.ipa` |

The `.AppImage` is self-contained: `chmod +x` it and run.

:::caution
**Builds are unsigned.** The release workflow ships no Apple Developer identity and no Windows code-signing certificate, so macOS Gatekeeper and Windows SmartScreen will warn on first launch. This is deliberate — see the workflow's own note — but it means the binaries are not notarized. If that is a dealbreaker, build from source.
:::

Every desktop platform above ships **both architectures**, so take the ARM file on an ARM machine rather than letting it emulate the x86-64 one. Nothing is 32-bit for desktop; build from source if you need an architecture the matrix does not cover.

### Staying up to date

Desktop builds update themselves. UniSSH asks the release feed (at most once an hour) whether a newer version exists, verifies the download against a signing key compiled into the app, and installs when you click — never silently. You can turn the check off in **Settings → About**.

Because the updater fetches the new version itself rather than going through a browser, macOS never quarantines it: the Gatekeeper step above is a one-time cost at first install.

`.deb` and `.rpm` update in place as well, but the install shells out to `dpkg -i` / `rpm -U`, which needs root — expect a polkit prompt or a graphical password dialog. On a system with neither, the update cannot complete from a desktop launcher and UniSSH opens the release page instead.

The mobile sideload builds are not covered, nor is anything installed from **v0.1.1 or earlier** — those predate the updater, so install the current release once by hand and it takes over from there.

### Verify what you downloaded

Every release attaches `SHA256SUMS`, a `SHA256SUMS.minisig` signature over it, and a build-provenance attestation.

```bash
# checksum
sha256sum -c SHA256SUMS --ignore-missing

# signature over the checksum file — the key carries no identity by design
minisign -Vm SHA256SUMS -P 'RWQvV7DIid665aUPiJiN5NXimAehmWEjgRS9uLgi2nSWIUiiBY7ZKCAs'

# provenance — proves the artifact was built by this repo's CI, not forged
# (needs GitHub CLI >= 2.49; older gh prints its help instead of an error)
gh attestation verify UniSSH_0.1.0_amd64.AppImage --repo goduni/unissh
```

## Building from source

Everything below is for compiling a component yourself. The [Quickstart](../quickstart/) then walks the local, no-server flow, and [Build from source](../../operations/build/) covers the `just` targets in detail.

## Top-level toolchain

For the Rust workspace (core + server) you need:

- **Rust 1.94+** — pinned in `rust-toolchain.toml`; `rustup` honors it automatically.
- A **C toolchain** and the system **OpenSSL** development headers — required for the bundled **SQLCipher** that backs the local encrypted database.
- **[`just`](https://github.com/casey/just)** — the monorepo task runner. Run `just` with no arguments to list targets.

For the JavaScript front-ends (client and admin panel):

- **Node 20.19+ / 22.12+** (the Vite 8 requirement).

:::note
The Rust core builds and tests **offline** — no network and no server are required. Integration tests for the SSH transport spin up a local `sshd`, so `sshd`, `ssh-keygen`, and `sftp-server` need to be present to run them.
:::

## Per-component prerequisites

### rust-core (the library)

- Rust + a C toolchain + system OpenSSL (for bundled SQLCipher).
- For the integration tests only: `sshd` / `ssh-keygen` / `sftp-server`.

```bash
cargo build --workspace
cargo test  --workspace      # core crates + the SSH integration tests
```

### server

- Same Rust toolchain. The server performs **no payload crypto** — only Ed25519 signature verification — so its dependency surface is small. TLS is optional in-process (rustls) and off by default; terminate it at a reverse proxy instead.
- Backed by **SQLite** by default; **Postgres** is optional for scale.

See [Server configuration](../../operations/configuration/) and [Docker Compose deployment](../../operations/deploy/).

### client (Tauri 2 desktop / mobile)

- **Node 20.19+ / 22.12+** and **Rust 1.85+**.
- The sibling `rust-core/` must be present — the client consumes it as a path dependency (`unissh-ffi`).

**Linux desktop build** additionally needs the WebKitGTK and supporting dev packages:

```bash
sudo apt-get install -y \
  libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
  libjavascriptcoregtk-4.1-dev librsvg2-dev libssl-dev \
  libxdo-dev libayatana-appindicator3-dev patchelf xdg-utils
```

`patchelf` and `xdg-utils` are needed for the AppImage bundle (the bundler copies `xdg-open` into the AppDir); drop them only if you build `.deb`/`.rpm` alone. A desktop install usually has `xdg-utils` already — a minimal container or a slim ARM image often does not.

**Mobile builds:**

- **iOS:** macOS + Xcode + CocoaPods.
- **Android:** Android Studio + SDK + NDK.

See [Desktop & mobile client](../../components/client/).

### server-ui (admin panel)

The admin panel uses **real cryptography in the browser** via a WebAssembly module built from the core. Install the wasm toolchain once:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

Then build the wasm crate and the SPA:

```bash
npm run build:wasm     # → crypto-wasm/pkg/
npm install
npm run build          # tsc --noEmit && vite build → dist/
```

:::caution
If `crypto-wasm/pkg/` is not built, the panel still loads, but keyset operations (unlock, claim, rotation) report "wasm not loaded". See [Admin panel](../../components/server-ui/).
:::

## Quick bootstrap with `just`

From the repository root:

```bash
just              # list all targets
just build        # cargo build --workspace (core + server)
just test         # core unit tests + server integration tests
just lint         # fmt --check + clippy -D warnings

just install      # npm install in client and server-ui
just build-ui     # wasm-pack + build the admin panel
just dev-client   # run the client (tauri dev)
just dev-ui       # run the admin panel (vite)
```

Next: the [Quickstart (local, no server)](../quickstart/).
