---
title: Install & prerequisites
description: Toolchain and system prerequisites for building UniSSH from source — core, server, client, and admin panel.
---

UniSSH builds from source. There is no installer; you compile the parts you need. This page lists the prerequisites per component. The [Quickstart](../quickstart/) then walks the local, no-server flow, and [Build from source](../../operations/build/) covers the `just` targets in detail.

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

- Same Rust toolchain. The server performs **no payload crypto** — only TLS and Ed25519 signature verification — so its dependency surface is small.
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
  libxdo-dev libayatana-appindicator3-dev
```

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
