---
title: Build from source
description: Build and test UniSSH from source — the just task runner for the monorepo, cargo for the core and server, and wasm-pack for the admin panel.
---

UniSSH builds from source with **[`just`](https://github.com/casey/just)** as the monorepo task runner over `cargo`, `npm`, and `wasm-pack`. Make sure you have the [prerequisites](../../overview/install/) first: Rust 1.94+, a C toolchain, system OpenSSL, Node 20.19+/22.12+, and `just`.

## The `just` targets

Run `just` with no arguments to list everything. The principal targets:

```bash
just              # list all targets

# Rust workspace (core + server)
just build        # cargo build --workspace
just build-server # cargo build -p unissh-server --release
just build-cli    # cargo build -p unissh-cli --release
just test         # cargo test --workspace --lib --bins  +  cargo test -p unissh-server
just test-pg      # Postgres integration test (needs a live PG; single-threaded)
just lint         # log-redaction guard  +  cargo fmt --all --check  +  cargo clippy --workspace --all-targets -- -D warnings
just fmt          # cargo fmt --all

# JS front-ends
just install      # npm install in client and server-ui
just build-wasm   # wasm-pack build the server-ui crypto-wasm crate (release)
just build-ui     # build-wasm + npm run build in server-ui
just build-client # npm run build in client (frontend only)
just dev-client   # npm run tauri dev
just dev-ui       # npm run dev (vite) in server-ui
just tauri-build  # npm run tauri build (desktop bundle)

# everything / clean
just build-all    # build (core+server) + build-wasm + build-client + server-ui build
just clean        # cargo clean + remove node_modules / dist / wasm pkg
```

## Building the core directly

The [core](../crates/) builds and tests standalone, offline:

```bash
cargo build --workspace
cargo test  --workspace
```

The `ssh-transport` and `ffi` integration tests spin up a local `sshd`, so they require `sshd`, `ssh-keygen`, and `sftp-server` to be installed. The crypto, keychain, storage, and vault crates need no network and no SSH tooling.

## Building and running the server

```bash
cargo build --release
cp config.example.toml config.toml          # then edit
./target/release/unissh-server migrate --config config.toml   # also auto-applied on serve
./target/release/unissh-server --config config.toml
```

Testing the server:

```bash
cargo test                      # SQLite + the byte-compat oracle vs. rust-core

# Postgres integration (needs a live PG):
docker run -d --name pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=unissh \
  -p 55433:5432 postgres:16-alpine
UNISSH_TEST_PG=postgres://postgres:test@127.0.0.1:55433/unissh \
  cargo test -p unissh-server --test pg_integration -- --test-threads=1
```

The oracle test runs the **real core sync engine** against a live server over HTTP and asserts identical results to the reference in-memory transport — so a successful `cargo test` proves wire-format parity with the core. See [Server & API surface](../../components/server/).

## Building the admin panel

The panel needs the wasm crypto module built first:

```bash
rustup target add wasm32-unknown-unknown    # once
cargo install wasm-pack                     # once

npm run build:wasm                          # → crypto-wasm/pkg/
npm install
npm run build                               # tsc --noEmit && vite build → dist/
```

See [Admin panel](../../components/server-ui/).

## Building the client

```bash
cd client
npm install
npm run build            # typecheck + vite production build (frontend only)
npm run tauri build      # full desktop bundle
```

A full `tauri build` (codegen + link) and on-device runs require a machine with a display and adequate disk. iOS has dedicated `just` targets (`just ios-init`, `just ios-dev`, `just ios-build`); Android builds run through the client's own `npm run tauri android …`. See [Desktop & mobile client](../../components/client/).

For continuous integration and release artifacts, see [CI/CD & releases](../ci-cd/). For deploying the built server, see [Docker Compose deployment](../deploy/).
