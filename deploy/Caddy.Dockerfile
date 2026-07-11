# =============================================================================
# UniSSH SPA + Caddy image (multi-stage). Build context: REPO ROOT (".").
#
#   Stage 1 (rust)  : wasm-pack builds server-ui/crypto-wasm. It path-depends on
#                     ../../rust-core/crates/crypto, so rust-core MUST be in the
#                     context — hence context "." (the repo root).
#   Stage 2 (node)  : `npm ci` + `npm run build` (tsc --noEmit && vite build),
#                     with the wasm pkg/ already in place.
#   Stage 3 (caddy) : official caddy:2 serving the built dist same-origin and
#                     reverse-proxying the API to the internal server service.
#
# Pinned to Rust 1.94 per rust-toolchain.toml.
# =============================================================================

# ---- Stage 1: build the crypto-wasm package ---------------------------------
FROM rust:1.94-slim AS wasm
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
# wasm-pack (pinned) — built from source via cargo, with the crate's own locked
# deps (--locked). Avoids piping an UNVERIFIED prebuilt binary (no checksum) into
# the trusted image that produces the browser crypto-wasm. Slower, but a tampered
# release tarball can no longer slip weakened crypto into users' browsers.
RUN cargo install --locked wasm-pack@0.13.1

WORKDIR /build
# crypto-wasm needs its own source + the rust-core crypto crate it path-depends on.
# The crypto crate uses `edition.workspace = true` (etc.), so its workspace root —
# the repo-root Cargo.toml (members = rust-core/crates/*, server) — MUST be present
# or cargo fails to resolve it ("failed to find a workspace root"). Only the root
# manifest is needed here: the `server` member is never built in this stage.
COPY Cargo.toml /build/Cargo.toml
COPY rust-core /build/rust-core
COPY server-ui/crypto-wasm /build/server-ui/crypto-wasm
WORKDIR /build/server-ui/crypto-wasm
RUN wasm-pack build --target web --out-dir pkg --release

# ---- Stage 2: build the Vite SPA --------------------------------------------
FROM node:22-slim AS spa
WORKDIR /build/server-ui
# Install deps first (better layer caching).
COPY server-ui/package.json server-ui/package-lock.json ./
RUN npm ci
# App sources.
COPY server-ui/ ./
# Drop in the freshly built wasm package (overwrites any stale local pkg/).
COPY --from=wasm /build/server-ui/crypto-wasm/pkg ./crypto-wasm/pkg
# tsc --noEmit && vite build  ->  dist/
RUN npm run build

# ---- Stage 3: Caddy runtime -------------------------------------------------
FROM caddy:2
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=spa /build/server-ui/dist /srv
EXPOSE 80 443
