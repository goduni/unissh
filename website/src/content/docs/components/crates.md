---
title: Crate reference
description: A per-crate tour of the UniSSH Rust core — crypto, keychain, storage, vault, ssh-agent, ssh-transport, sync, and the FFI facade.
---

The [rust-core](../rust-core/) workspace is a stack of focused crates. Dependencies run bottom-up; each crate is `#![forbid(unsafe_code)]` (except `ssh-agent`, which has a single audited `unsafe` module for `mlock`). This page summarizes the role and public surface of each.

## `crypto` — the cryptographic foundation

The audited-primitives base everything else builds on. Self-contained: builds and tests with no storage, SSH, UI, or network. **No custom crypto** — only RustCrypto crates and `hpke` (RFC 9180).

Modules: blob `version`ing (crypto agility), zeroizing key `keys` types, `kdf` (Argon2id), `aead` (XChaCha20-Poly1305 with associated data), `hpke_seal` (wrap a symmetric key under an X25519 public key, with `vk_wrap_info` epoch binding), `keywrap`, `signature` (versioned-object Ed25519 + rollback detection), `domain_sig` (domain-separated signatures), and `server_auth` (a signed server-auth challenge).

The blob formats, the algorithm registry, the associated-data construction, and the signed-object layout are documented in [Crypto & key hierarchy](../../architecture/crypto-and-keys/).

## `keychain` — the key hierarchy

Implements the per-instance hierarchy on top of `crypto`: the **Secret Key** (~128-bit, device-generated, never sent to the server), **Argon2id** over the master password, the **Unlock Key** = `combine(Argon2id(password), Secret Key)` via HKDF, and the **personal keyset** (X25519 + Ed25519) encrypted under it.

Key API: `create_account` (first device — returns the Secret Key, the encrypted keyset, and the unlocked keyset), `unlock_account`, and `change_password` (re-wrap the keyset under a new Unlock Key, generation+1, with old-credentials verification to prevent bricking). A password-less **SSO + trusted-devices** mode (`UnlockMode::SecretKeyOnly`) is supported; biometrics belong to the platform UI layer, not here.

For Milestone 2 it also provides account-id generation and self-attested registration (`build_registration` / `verify_registration`), server-challenge signing (`sign_server_challenge`), an `unlock_account_checked` with a trusted **keyset-generation floor** (anti-rollback), and the **device-to-device PAKE onboarding** flow (SPAKE2 with mandatory key-confirmation, secrets relayed only end-to-end-encrypted).

## `storage` — the local encrypted store

**SQLite + SQLCipher** (bundled, linked to system OpenSSL). Stores already-encrypted blobs plus open metadata. **Per-instance isolation:** each instance is a separate encrypted DB file with its own 32-byte raw key, so instances never physically mix.

Storage **does not encrypt content or verify signatures** — that is the `vault` layer. It provides instance isolation, ciphertext storage, **version monotonicity** (anti-rollback at the DB level), soft deletion (tombstones), and host-key TOFU pinning (`known_hosts`). Records carry sync fields from day one: `version`, `signature`/`author_pubkey`, `tombstone`, `server_seq`, wrapped keys, and name/content blobs. The schema (currently `user_version` 9) also holds membership manifests/grants, pinned member keys, an append-only `audit_log`, sync-state, and per-vault epoch floors — the storage substrate for Milestone-2 sync and sharing.

## `vault` — vaults, Vault Keys, membership

Local vaults on top of `crypto` + `keychain` + `storage`. A vault has a random 256-bit **Vault Key (VK)**, wrapped under the owner's X25519 public key (HPKE — the same format used for sharing). Content is encrypted with **per-item keys** wrapped by the VK (not by the VK directly), each record signed (Ed25519) with a monotonic version; `open`/`get_item` verify the signature.

API highlights: `Vault::create` / `open`, `put_item` / `get_item` / `list_items`, `rename_item`, `set_name`, `delete_item` (tombstone). Milestone-2 primitives add **membership manifests** (one per `key_epoch`, listing the whole member-set with roles, admin-signed), a **sigchain authority** model (each epoch's manifest must be signed by an admin from the previous epoch), **per-member grants** (the VK sealed to a member, epoch-bound), `add_member`, **`rotate_vk`** (eager VK rotation for revocation — new VK, new manifest, re-wrapped items, raised epoch floor, all in one transaction), `purge_vault` (cooperative hard-delete; **not** a remote wipe), and member-pubkey TOFU pinning.

## `ssh-agent` — the embedded in-memory agent

The built-in agent (**not** the system ssh-agent): private keys live only inside the core process. Ed25519, ECDSA (p256/p384/p521), and RSA (`rsa-sha2-512`) are supported for signing; an RSA key may also be imported public-key-only. User certificates are supported.

The private key (the Ed25519 seed) sits in **`mlock`-ed** memory and is **zeroized** on removal/drop; the signing key is reconstructed from the seed only for the duration of a signature and zeroized immediately. The plaintext key is **never written to disk**. Where memory locking is unavailable, the buffer is still zeroized (best-effort `mlock`, always-on zeroize). Agent **forwarding is not done** — `ProxyJump` is used instead.

## `ssh-transport` — `russh`-based transport

Connect + authenticate by key (from the embedded agent) or password (with automatic `password → keyboard-interactive` fallback, bounded rounds). **`ProxyJump` and jump chains** (`connect_through`). **Forwards:** local, dynamic SOCKS5, remote. **SFTP** (protocol v3). **Host-key TOFU + pinning** via `storage.known_hosts` — a mismatch surfaces as a structured `HostKeyMismatch { host, port, fingerprint }` for MITM warning, with a deliberate `trust_host_key` to accept a new key. **`~/.ssh/config` import** (`Host`/`HostName`/`Port`/`User`/`IdentityFile`/`ProxyJump`, wildcards, first-value-wins). **Agent forwarding is off by default.**

## `sync` — the client sync engine

The offline-first engine: `sync_pull` (fetch the delta beyond the cursor, verify-before-apply, signed-version LWW, surface conflicts, advance the trusted cursor forward) and `sync_push`. It models the server as a `SyncTransport` trait (no real network in the core) and treats the transport as **untrusted** — distrusting `server_seq`, ordering, and content. Full detail in [Sync & anti-rollback](../../architecture/sync-model/).

## `ffi` — the UniFFI contract

The stable UI boundary. A `Core` facade binds `keychain` + `storage` + `vault` + `ssh-agent` + `ssh-transport` (+ `sync`) into a contract for Swift/Kotlin/etc.

**The hard rule:** the UI/FFI **never** receives plaintext keys. Private SSH keys are generated and live in the core; only the public key leaves. No method returns a private key or keyset secret — proven by an end-to-end test. The only secrets that cross by explicit request are a **server password** (`get_password`) and a **note** (`get_note`) for reveal — user-level secrets, not key material, each strictly type-gated.

The facade covers vaults, keys/items, known-hosts, `ssh_exec` and the streaming/fleet/broadcast variants, sessions, tunnels, SFTP, secret version history, integrity audit, interop, encrypted vault backup, connection profiles, and the Milestone-2 surface (cloud vaults, membership/grants, identity/auth, device onboarding, audit append/query, and the `FfiSyncTransport` callback). Bindings (Swift, Kotlin, …) are generated on demand with `uniffi-bindgen` (UniFFI 0.31) and are **not** committed to the repository. The temporary [`cli`](../../overview/quickstart/) crate drives this facade for the `init → create-vault → gen-key → exec` flow.

See also: [System overview](../../architecture/system-overview/) for how the crates fit together.
