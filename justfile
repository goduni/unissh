# UniSSH monorepo — task runner. `just` shows the list of targets.
set shell := ["bash", "-uc"]

default:
    @just --list

# ---------- bootstrap (JS) ----------
install: install-client install-ui
install-client:
    cd client && npm install
install-ui:
    cd server-ui && npm install

# ---------- Rust (root workspace: core + server) ----------
build:
    cargo build --workspace
build-server:
    cargo build -p unissh-server --release
build-cli:
    cargo build -p unissh-cli --release
test:
    cargo test --workspace --lib --bins
    cargo test -p unissh-server
test-pg:
    cargo test -p unissh-server --test pg_integration -- --test-threads=1
lint: lint-logs
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
# Fail if any log/print call interpolates a secret-bearing value (redaction rule).
lint-logs:
    python3 scripts/check-log-redaction.py
fmt:
    cargo fmt --all

# ---------- WASM (server-ui/crypto-wasm, excluded) ----------
build-wasm:
    cd server-ui/crypto-wasm && wasm-pack build --target web --out-dir pkg --release

# ---------- Frontends ----------
build-client:
    cd client && npm run build
dev-client:
    cd client && npm run tauri dev
tauri-build:
    cd client && npm run tauri build
build-ui: build-wasm
    cd server-ui && npm run build
dev-ui:
    cd server-ui && npm run dev

# ---------- iOS (mobile · macOS only) ----------
# Generate the iOS Xcode project, then apply the post-gen fixups that the
# cargo-mobile2 template otherwise breaks on recent Xcode (script-sandboxing
# off, deployment target = tauri.conf.json minimum). Use this instead of a bare
# `tauri ios init` — gen/apple is gitignored/regenerated, so the fixups must
# follow every init (they survive `ios build`/`ios dev`).
ios-init:
    cd client && npm run tauri ios init
    bash scripts/ios-fix-xcodeproj.sh
# Re-apply the iOS Xcode-project fixups without regenerating (e.g. after Xcode
# or Tauri reset the project).
ios-fix:
    bash scripts/ios-fix-xcodeproj.sh
ios-dev:
    cd client && npm run tauri ios dev
ios-build:
    cd client && npm run tauri ios build

# ---------- All / clean ----------
build-all: build build-wasm build-client
    cd server-ui && npm run build
clean:
    cargo clean
    rm -rf client/node_modules server-ui/node_modules client/dist server-ui/dist server-ui/crypto-wasm/pkg

# ---------- Self-host (local evaluation) ----------
# Print a fresh random ops token for a .env file. There is no bootstrap token —
# a fresh instance is claimed with the one-time setup code the server prints to
# its log on first boot, so there is nothing to pre-generate for onboarding.
gen-secrets:
    @echo "UNISSH__OPS__TOKEN=$(openssl rand -hex 32)"

# Zero-config local stack on https://localhost (Caddy self-signed CA — the
# browser cert warning is expected). Creates .env from deploy/.env.localhost on
# first run, then builds + starts the stack. Claim the instance with the setup
# code the server prints to its log on first boot.
up-local:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f .env ]; then
      echo "→ .env already exists; leaving it untouched."
    else
      cp deploy/.env.localhost .env
      echo "→ wrote .env from deploy/.env.localhost."
    fi
    docker compose --env-file .env up -d --build
    echo "→ open https://localhost/ (accept the self-signed cert)."
    echo "→ claim the instance with the one-time setup code from the server log:"
    echo "     docker compose --env-file .env logs server 2>&1 | grep -i 'setup code'"

# Tear the local stack down (keep volumes/data).
down-local:
    docker compose --env-file .env down
