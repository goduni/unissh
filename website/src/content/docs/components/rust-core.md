---
title: "rust-core: the universal core"
description: The shared Rust library at the heart of UniSSH — crypto, vaults, the embedded SSH agent, transport, sync, and the FFI contract, built and tested offline.
---

`rust-core` is the universal foundation of UniSSH: the cryptography, vault unlock, key management, SSH transport, the embedded agent, the sync engine, local storage, and multi-instance management — written **once** and shared by every client. It is **only the core** (a library): no server, no UI. It builds and tests **standalone, offline**.

## The stack

- **SSH:** [`russh`](https://crates.io/crates/russh).
- **Local storage:** SQLite + **SQLCipher**.
- **Crypto:** audited **RustCrypto** crates + `hpke` (RFC 9180). No custom crypto.
- **FFI:** **UniFFI** bindings (Swift / Kotlin / …).

The core compiles and runs on all five target platforms (macOS, Windows, Linux, iOS, Android). UI delivery is pushed out to the clients, so the maturity of any one UI framework does not block the project.

## Crate map

```
crates/
  crypto         primitives, envelope wrapping, AEAD + associated data,
                 signatures, blob versioning (crypto agility)
  keychain       Secret Key, Argon2id, Unlock Key, the personal keyset
  storage        SQLite + SQLCipher, per-instance isolation, the sync model
  vault          local vault, Vault Key, per-item keys, membership/grants
  ssh-agent      embedded in-memory agent, mlock/zeroize
  ssh-transport  russh: ProxyJump, forwards, host-key TOFU, ssh-config
  sync           client sync engine: verify-before-apply, LWW, anti-rollback
  ffi            the UniFFI contract for the UI (no plaintext keys)
  cli            a temporary CLI harness to drive the core from a terminal
```

Dependencies run bottom-up; upper crates reuse lower ones. Each crate ships its own README, documented public API, and tests (including negative cases). Detailed per-crate roles are in the [Crate reference](../crates/).

## What the core can do today

Milestone 1's Definition of Done is **complete** — all seven foundational crates in one workspace, an end-to-end local scenario working with no server and no UI, the CLI harness in place, the FFI boundary in place (UniFFI Swift/Kotlin bindings generated on demand) and proven not to leak plaintext keys, and blob formats laid down for future sync. On top of that, the core has been extended with local, sync-ready features (no server, network, or new crypto):

- **Secrets in the vault:** SSH keys (generate/import) and user certificates, connection profiles ("hosts"), **server passwords**, **encrypted notes**, and nested **host groups**. Password/note **reveal** is strictly type-gated — you cannot extract a private key through it.
- **Secret version history** — past versions of a password/note are archived (per-item retention), any version can be revealed, and history is purged on deletion.
- **Authentication** by key (through the embedded agent — the private key never leaves the core), by password (inline or from the vault, with `keyboard-interactive` fallback), or by certificate.
- **SSH sessions** — interactive PTY with resize; **streaming exec** (separate stdout/stderr); **auto-reconnect** (backoff, MITM-stop).
- **Fleet operations** — multi-host exec with a concurrency limit and per-host timeout; runs by **group**, by **tag**, dry-run; **broadcast** (one input → N PTYs, cluster-ssh); **fleet-push** of a file to many hosts over SFTP.
- **SFTP** — the full set plus **resumable** download/upload with progress and cancellation.
- **Tunnels** — local / remote / dynamic (SOCKS5) forwards, `ProxyJump` chains.
- **Integrity / audit** — `verify_chain` (checks signatures of all versions, including history and tombstones) and `check_consistency` (a structural DB check), with no secret leakage in the report.
- **Interop** — import/export of `~/.ssh/config`, import of `~/.ssh/known_hosts` and **PuTTY** sessions (`.reg`).
- **Backup** — a portable encrypted **vault export/import** (passphrase + Argon2id), re-encrypted under the target instance's keys on import.

## Security guarantees

No custom crypto is written. Secrets are zeroized; plaintext private keys are never written to disk; pages holding a key are `mlock`-ed where possible. The core↔UI boundary **does not hand out plaintext keys** — the only agreed exception is password/note reveal (user secrets, not key material), strictly type-gated. Blob versioning, signed monotonic versions, tombstones, and associated-data binding were laid down from the start for future sync; the same signatures are checked by the local integrity audit (`verify_chain`).

## Releases

CI runs on every push/PR and weekly (rustfmt, clippy, the full workspace test suite on Linux, and cargo-deny). The core is **not** published as a standalone artifact — it is consumed as a path dependency by the server and client, and its FFI bindings are generated on demand. The shippable binaries are the desktop client bundles; see [CI/CD & releases](../../operations/ci-cd/).

## What is not here

The server instance, network sync, the UI, and all future items (CA orchestration, relay, person-to-person sharing flow, device-bound/FIDO2, key transparency, PQ-hybrid, CRDT, P2P) are separate milestones. The extension points for them are laid down; the implementations are not.

## License

Dual-licensed **MIT OR Apache-2.0**, at the user's choice.
