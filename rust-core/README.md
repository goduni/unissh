# UniSSH Core (Rust)

The universal UniSSH Rust core — an open-source, self-hosted,
cross-platform SSH client with zero-knowledge encrypted vaults.
**This repository is the core only** (a library): no server, no UI. It builds
and tests standalone (offline).

## Crate map

```
crates/
  crypto         primitives, envelope wrappers, AEAD+associated data, signatures,
                 blob versioning (crypto agility)                    [SPEC 5.4–5.5]
  keychain       Secret Key, Argon2id, Unlock Key, personal keyset   [SPEC 5.1]
  storage        SQLite+SQLCipher, instance isolation, sync model     [SPEC 2A, 9]
  vault          local vault, Vault Key, per-item keys               [SPEC 5.2–5.3]
  ssh-agent      built-in in-memory agent, mlock/zeroize              [SPEC 10.1]
  ssh-transport  russh: ProxyJump, forwards, TOFU, ssh-config         [SPEC 10.4]
  local-pty      desktop local shells and terminal I/O
  sync           encrypted vault synchronization and verification
  automation     native MCP grants, approvals, revocation and managed SSH exec
  mcp            authenticated loopback HTTP adapter and nine MCP tool contracts
  ffi            UniFFI contract for the UI (no plaintext keys)       [SPEC 4]
  cli            temporary CLI harness to "kick the tires" on the core
```

Every crate ships its own README, a documented public API, and tests
(including negative ones). Dependencies flow bottom-up; higher layers reuse lower ones.

Desktop MCP uses `mcp` for HTTP and tool contracts, `automation` for native access
control, and the `automation/core` feature to execute through `ffi`. The adapter
does not depend on vault storage or SSH credentials. See the
[automation broker](crates/automation/README.md), [MCP adapter](crates/mcp/README.md)
and [desktop setup guide](../docs/desktop-mcp.md).

Milestone 1 (steps 1–7, the Definition of Done from the SPEC) is **complete**; on
top of it the core has been extended with a set of local capabilities (see below) —
without a server, networking, or breaking the hard rules.

## Core capabilities

Everything is local, built on the existing crates, in a sync-ready blob format.

- **Secrets in the vault** (item types): SSH keys (generate/import) and user certificates,
  connection profiles ("hosts"), **server passwords**, **encrypted notes**,
  **host groups** (nested). Revealing passwords/notes is strictly type-gated
  (a private key can never be extracted through it).
- **Secret version history** — past versions of a password/note are archived
  (per-item retention), reveal any version; history is purged on deletion.
- **Authentication:** by key (via the built-in agent, the private key never leaves the core),
  by password (inline / from the vault) with a fallback to `keyboard-interactive`, by certificate.
- **SSH sessions:** interactive PTY with resize; **streaming exec** (separate
  stdout/stderr); **auto-reconnect** (backoff, MITM stop).
- **Fleet operations:** multi-host exec with a concurrency limit and per-host timeout;
  run by **group**, by **tags**, dry-run; **broadcast** (one input → N PTYs,
  cluster-ssh); **fleet-push** of a file to many hosts over SFTP.
- **SFTP:** full set + **resumable** download/upload with progress and cancellation.
- **Tunnels:** local / remote / dynamic (SOCKS5), ProxyJump chains.
- **Integrity/audit:** `verify_chain` (verifies the signatures of all versions, incl.
  history and tombstones) and `check_consistency` (structural DB check) — without
  leaking secrets into the report.
- **Interop:** import/export of `~/.ssh/config`, import of `~/.ssh/known_hosts` and
  **PuTTY** sessions (`.reg`).
- **Backup:** portable encrypted **vault export/import** (passphrase +
  Argon2id), re-encryption under the target instance's keys on import.

## Build and tests

```bash
cargo build --workspace
cargo test  --workspace          # ~194 tests (incl. integration against sshd)
```

Requirements: Rust 1.74+, a C toolchain, and system OpenSSL (for bundled SQLCipher).
The `ssh-transport`/`ffi` integration tests spin up a local `sshd`
(`sshd`/`ssh-keygen` required).

## Build and CI

Part of the [`goduni/unissh`](https://github.com/goduni/unissh) monorepo: the root
Cargo workspace builds the core together with the server, and tasks are orchestrated by `just`
(`just build`, `just test`, `just lint`). CI at the repository root runs rustfmt,
clippy, and the tests on every push/PR (Linux, with a local `sshd` for the integration
tests) plus cargo-deny. The lint policy is described in
[`CONTRIBUTING.md`](../CONTRIBUTING.md#lint-policy).

## End-to-end scenario (local, no server)

```bash
SK=$(cargo run -p unissh-cli -- init --password pw | tail -1)   # Secret Key (Emergency Kit)
cargo run -p unissh-cli -- create-vault --secret-key $SK --password pw --id default --name Default
cargo run -p unissh-cli -- gen-key      --secret-key $SK --password pw --vault default --item id_ed25519
cargo run -p unissh-cli -- exec --secret-key $SK --password pw --vault default --item id_ed25519 \
    --host 10.0.0.5 --user deploy --command "uname -a" --jump bastion:22:admin:id_ed25519
# interactive terminal (PTY):
cargo run -p unissh-cli -- shell --secret-key $SK --password pw --vault default --item id_ed25519 \
    --host 10.0.0.5 --user deploy
```

Authentication goes through `russh::auth::Signer` on top of the built-in agent —
the private key never leaves the agent. The interactive session (`open_session`/`SshSession`)
streams output through the `SessionObserver` callback.

## Security guarantees

No custom crypto is written (RustCrypto/`hpke`/SQLCipher). Secrets are zeroized;
plaintext private keys are never written to disk; pages holding a key are `mlock`ed
where possible. The core↔UI boundary **never hands out plaintext keys** — the only
sanctioned exception is revealing passwords/notes (user secrets, not key
material), strictly type-gated. Blob versioning, signed monotonic versions,
tombstones, and associated-data binding are built in from the start for
future sync; the same signatures are verified by the local integrity audit (`verify_chain`).
The encrypted vault backup is a portable, passphrase-protected file (Argon2id), not sync.
See the crate READMEs for details.

## What is NOT here

The server instance, network sync, the UI, and everything marked ⏳ LATER in the SPEC (CA, relay,
sharing between people, VK rotation, device-bound/FIDO2, key transparency, PQ hybrid, CRDT,
P2P) are separate milestones. The extension points for them are in place, but the implementation is not.

## License

Dual-licensed at the user's option:

- MIT ([`LICENSE-MIT`](./LICENSE-MIT))
- Apache 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE))

`SPDX-License-Identifier: MIT OR Apache-2.0`. Any contribution is accepted under the terms
of this dual license without additional stipulations (Apache-2.0 §5).
