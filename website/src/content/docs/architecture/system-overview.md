---
title: System overview
description: How UniSSH is structured — a universal Rust core, a thin zero-knowledge server, and clients that consume the core through a stable FFI contract.
---

UniSSH is a monorepo built around one principle and one shared foundation.

## The principle: control plane, not data plane

The backend is a **control plane**. It stores metadata, encrypted keys, access policy, audit, and synchronization state. It is **not** a data plane: your SSH traffic flows **directly** from client to host, or through your own bastion via `ProxyJump`. SSH bytes never traverse the UniSSH backend.

Any design that proposes "proxy the connection through the service" is against this principle. UniSSH bets on `ProxyJump` instead of a built-in relay (see [Components → Server](../../components/server/)).

## The foundation: a universal Rust core

The cryptography, vault unlock, key management, SSH transport, the embedded agent, the sync engine, local storage, and multi-instance management are all written **once**, in Rust, and shared by every client. The UI is left to each client (the stack is free per client) and talks to the core across a stable **FFI contract**.

```
                         ┌─────────────────────────────┐
   desktop / mobile UI ──┤  unissh-ffi  (UniFFI facade) │
   (Tauri, native, …)    └──────────────┬──────────────┘
                                         │  no plaintext keys cross this line
   ┌─────────────────────────────────────────────────────────────┐
   │  rust-core crates                                            │
   │  crypto · keychain · storage · vault · ssh-agent ·           │
   │  ssh-transport · sync · ffi · cli                            │
   └─────────────────────────────────────────────────────────────┘
                                         │  (sync: opaque ciphertext blobs)
                         ┌───────────────┴───────────────┐
                         │  server (axum + sqlx)          │  ← untrusted
                         │  ciphertext store · sync ·      │     ciphertext
                         │  RBAC · audit                  │     store
                         └───────────────┬───────────────┘
                                         │  /v1 JSON over TLS
                         ┌───────────────┴───────────────┐
                         │  server-ui (admin panel, wasm) │
                         └────────────────────────────────┘
```

A hard rule sits at the FFI boundary: **the UI never receives plaintext private keys** — only management calls and session data streams. The single deliberate exception is password/note reveal, which is strictly type-gated.

## Monorepo layout

| Directory | Role | Stack |
|---|---|---|
| `rust-core/` | Crypto core, vaults, SSH transport, sync, FFI (9 crates) | Rust (Cargo workspace) |
| `server/` | Zero-knowledge control plane: ciphertext store + sync + RBAC + audit | Rust (axum + sqlx) |
| `client/` | Cross-platform SSH client (desktop/mobile) | Tauri 2 + React + Vite |
| `server-ui/` | Self-hosted admin panel | React + Vite + wasm |

`rust-core` is the shared base: `server`, `client`, and `server-ui/crypto-wasm` all depend on its crates.

### Cargo structure

The root `Cargo.toml` is a virtual workspace of `rust-core/crates/*` plus `server` (one shared `Cargo.lock`). Two members are deliberately **excluded** into their own workspace roots with their own lockfiles: `client/src-tauri` (a Tauri requirement) and `server-ui/crypto-wasm` (its own wasm release profile).

## Module map and build order

UniSSH was built as a **vertical slice, not a layered stack** — one thin line carried all the way through (crypto → storage → SSH → UI) to a working product, then widened. The work is organized into milestones.

### Milestone 1 — local client, no server

A fully working single-device SSH client with an encrypted local store. **No server needed** — it uses a local vault (an "instance without a server"). Crates, bottom-up:

1. `crypto` — primitives, envelope wrapping, blob versioning, AEAD with associated data, signatures.
2. `keychain` — the key hierarchy: Argon2id, Secret Key, unlock, the personal keyset.
3. `storage` — the local SQLCipher database; per-instance isolation; the item/vault/version/tombstone/signature model.
4. `vault` — local vault, Vault Key, per-item keys.
5. `ssh-agent` — the embedded in-memory agent (`mlock`/`zeroize`).
6. `ssh-transport` — `russh`: `ProxyJump` + chains, forwards, host-key TOFU/pinning, `~/.ssh/config` import.
7. `ffi` — the UI contract, with no UI access to plaintext keys.

This milestone's Definition of Done is **complete**, and the core was then extended with local features (passwords/notes with version history, host groups and tags, fleet operations, streaming exec, auto-reconnect, resumable SFTP, encrypted vault backup, local integrity audit, ssh-config export and known_hosts/PuTTY import) — all on the same crates, with no server, no network, and no new crypto.

### Milestone 2 — the server, plus cloud and multi-device

The server stands up **on top of** the finished core and adds exactly what a local client lacks: instance management with **spaces** (teams) under one account, cloud-vault sharing wrappers and VK rotation, the `sync` engine (offline-first, item-level cursors, signed-version LWW with conflict detection, tombstones), onboarding (setup-code **claim** for the owner, space-scoped **invite links**, **SSO/OIDC**, and **escrow sign-in** or QR-approve to recover a keyset on a fresh device), recovery (Emergency Kit), and the self-hosted backend itself (identity/auth, vault metadata, vault RBAC, audit, the sync blob store).

### Milestone 3 — the remaining clients

Linux, Windows, iOS, Android (native UI through the same FFI), and the web admin panel.

## Where to read next

- The security guarantees and the honest limits → [Security & zero-knowledge model](../zero-knowledge-model/).
- The key hierarchy and primitives → [Crypto & key hierarchy](../crypto-and-keys/).
- How devices converge safely → [Sync & anti-rollback model](../sync-model/).
- Per-component detail → [Components](../../components/rust-core/).
