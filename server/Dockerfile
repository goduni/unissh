# UniSSH Server — multi-stage build → distroless, non-root (spec §14.1).
#
# IMPORTANT: the build context is the PARENT directory (which holds both `server/`
# and `rust-core/`), because the server dev-dependencies reference ../rust-core by
# path (byte-compat oracle). A release-binary build does NOT compile dev-deps, but
# cargo requires the paths to exist in order to parse the manifest.
#   docker build -f server/Dockerfile -t unissh-server ..
# (docker-compose is configured for this automatically.)

# Pin the builder to Debian 12 (bookworm, glibc 2.36) to MATCH the distroless
# cc-debian12 runtime below. Plain `rust:1.94-slim` tracks Debian 13 (glibc 2.38+),
# whose binaries fail on cc-debian12 with `GLIBC_2.38 not found`.
FROM rust:1.94-slim-bookworm AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev cmake clang && rm -rf /var/lib/apt/lists/*
# cargo-chef is built here rather than pulled from a prebuilt third-party image.
# That costs one cached layer and keeps the builder's provenance to rust: + Debian,
# which matters more than the minute it saves for a project whose whole pitch is
# that you can check what built your binary. `--locked` so the tool itself is
# reproducible.
RUN cargo install cargo-chef --locked
WORKDIR /build

# WHY THE THREE STAGES. Previously this Dockerfile copied the source and then ran
# one `cargo build`, so ANY edit to rust-core/ or server/ invalidated that layer
# and every third-party dependency was recompiled from scratch — which is why a
# "cached" image build still took over an hour.
#
# cargo-chef splits that in two. `prepare` distils the workspace into a recipe
# that depends only on the manifests, and `cook` compiles the dependency graph
# from it. The cook layer is therefore reused for as long as Cargo.toml/Cargo.lock
# are unchanged, and a source-only edit recompiles just this workspace's crates.
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY rust-core /build/rust-core
COPY server /build/server
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
# `--bin unissh-server` on BOTH cook and build, deliberately. Cooking the whole
# workspace would compile dependencies this binary never links (the ssh/agent
# crates), and — worse — cooking a different selection than the build asks for
# leaves the cache unused while still paying to fill it.
RUN cargo chef cook --release --bin unissh-server --recipe-path recipe.json
# Cargo workspace root lives at the repo root (members = rust-core/crates/*, server);
# crates inherit [workspace.package] via `edition.workspace = true`, so the root
# Cargo.toml/Cargo.lock MUST be present or cargo fails with "workspace root not found".
COPY Cargo.toml Cargo.lock ./
COPY rust-core /build/rust-core
COPY server /build/server
RUN cargo build --release --bin unissh-server
RUN mkdir -p /out/data

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /build/target/release/unissh-server /usr/local/bin/unissh-server
COPY --from=builder /build/server/migrations /app/migrations
COPY --from=builder --chown=65532:65532 /out/data /app/data
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/unissh-server"]
CMD ["--config", "/app/config.toml"]
