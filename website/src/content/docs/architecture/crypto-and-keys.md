---
title: Crypto & key hierarchy
description: UniSSH's envelope encryption, the per-instance key hierarchy, the cryptographic primitives, blob formats, and recovery via the Emergency Kit.
---

UniSSH writes **no custom cryptography**. It uses only audited libraries — RustCrypto crates and `hpke` (RFC 9180), with SQLCipher for storage at rest. This page describes the key hierarchy, the primitives, the on-disk blob formats, and recovery.

All of this is **per-instance**: a user has a separate keyset, Secret Key, and Emergency Kit for every instance.

## The key hierarchy (envelope encryption)

From the bottom up:

1. **Master password** → **Argon2id**. Used not to encrypt data directly, but to unwrap the personal key. (In SSO + trusted-devices mode there may be no password; then the root is the Secret Key plus device biometric unlock.)
2. **Secret Key** — high-entropy (~128 bits), generated **on the device**, and it **never goes to the server**. It makes offline password guessing infeasible even against a full database dump (the idea from 1Password's design). Per-instance.
3. **Unlock Key** `= combine(Argon2id(password), Secret Key)` — derived via HKDF-SHA256 with domain separation. It decrypts the **personal keyset**: an X25519 pair (encryption) + an Ed25519 pair (signing).
4. Each **vault** has a random symmetric **Vault Key (VK)**, 256-bit.
5. Content is encrypted with **per-item keys**, each wrapped under the VK (not under the VK directly) — giving granular revocation and a limited blast radius.

```
password ──Argon2id──┐
                     ├─HKDF──> Unlock Key ──AEAD──> personal keyset (X25519 + Ed25519)
Secret Key ──────────┘                                    │
                                                          │ HPKE
                                                          ▼
                                               wrapped_vk ──> Vault Key (256-bit, per vault)
                                                                  │ keywrap
                                                                  ▼
                                                          per-item key ──AEAD(+AD)──> content
```

## Primitives

| Purpose | Algorithm | Crate |
|---|---|---|
| KDF (password → key) | **Argon2id** (memory 64+ MiB, adaptive per-device params) | `argon2` |
| Default symmetric AEAD | **XChaCha20-Poly1305** (192-bit nonce, no AES-NI dependency) | `chacha20poly1305` |
| Public-key encryption | **HPKE** (RFC 9180), DHKEM(X25519, HKDF-SHA256) + ChaCha20-Poly1305 | `hpke` |
| Signatures | **Ed25519** (`verify_strict`) | `ed25519-dalek` |
| Content digest for signing | SHA-256 | `sha2` |

AES-256-GCM is **reserved** in the registry as a FIPS/compliance option — the id is allocated, but the algorithm is not yet implemented (there is no `aes-gcm` dependency). Every encrypted/signed blob is **versioned** (a format-version byte + a 2-byte algorithm id) for **crypto agility**, and a hybrid X25519 + ML-KEM wrap (post-quantum) is likewise reserved in the registry — the format is laid down now, the algorithm is future work.

## Blob formats

Every encrypted or signed blob starts with a **3-byte header**:

```text
[0]      format_version : u8           (currently 0x01)
[1..3]   alg_id         : u16 big-endian
[3..]    body, algorithm-dependent
```

The algorithm-id registry is stable forever and ids are never reused:

| id | Algorithm | Status |
|---|---|---|
| `0x0001` | XChaCha20-Poly1305 (AEAD) | implemented |
| `0x0002` | AES-256-GCM (AEAD) | reserved (FIPS option) |
| `0x0010` | HPKE DHKEM-X25519-HKDF-SHA256 + ChaCha20-Poly1305 | implemented |
| `0x0011` | HPKE hybrid X25519 + ML-KEM | reserved (post-quantum) |
| `0x0020` | Ed25519 signature | implemented |
| `0x0030` | Argon2id KDF params | implemented |

Bodies:

```text
AEAD       (0x0001):  header || nonce(24) || ciphertext || tag(16)
HPKE-seal  (0x0010):  header || enc(32)   || ciphertext+tag
Ed25519    (0x0020):  header || signature(64)
KDF-params (0x0030):  header || kdf_id:u8 || mem_kib:u32 be || iterations:u32 be
                              || parallelism:u32 be || salt_len:u8 || salt
```

Key-wrapping reuses the AEAD format: a wrapped key is just an AEAD ciphertext over the 32-byte key.

### Associated data — binding to context

The associated data is **not written into the blob**; the caller reconstructs it, feeds it to AEAD, and it is part of the signed object. Its canonical, length-prefixed form:

```text
len(vault_id):u16 || vault_id || len(item_id):u16 || item_id || version:u64 be
```

Because this is authenticated, the server cannot silently substitute or reorder blobs — decrypting a foreign or reordered blob fails AEAD authentication.

### The signed object and rollback detection

```text
domain("unissh-sig-v1") || AssociatedData.canonical || content_digest(32, SHA-256)
```

One signature authorizes the object's identity, version, and content together. **Rollback detection is stateless**: the signature is valid for an old version too (an attacker could keep a valid old signed blob), so freshness is checked by comparing `version` against the last-seen value — and tracking "last seen" is the storage layer's job.

### Domain-separated signatures and VK-wrap binding

For contexts outside a versioned object — a server-auth challenge, an audit record — there is a domain-separated Ed25519 signature over an arbitrary canonical payload, with stable domains such as `unissh-server-auth-v1` and `unissh-audit-v1`. The construction is built so that no domain signature can be passed off as a `VersionedObject` signature or vice versa.

VK wrappers are bound with `vk_wrap_info(vault_id, member_pubkey, key_epoch)`, which goes into the HPKE key schedule. Any mismatch (wrong vault, recipient, or epoch) fails to open. Binding the **epoch** is what stops a server from passing an old `Enc(VK_old, member_pub)` off as a fresh wrapper after rotation.

## At-rest storage

The local database is **SQLite + SQLCipher**. Each instance is a **separate encrypted database file with its own 32-byte raw key**, so instances never physically mix and one instance's key does not unlock another. The SQLCipher key is derived (HKDF) from the secrets of the **unlocked** keyset — the database cannot be opened without unlocking. See [storage in the Crate reference](../../components/crates/).

## Security properties of the crypto layer

- **Zeroization.** Secret keys are zeroized on drop (`zeroize`); transient buffers holding decrypted keys are zeroized by hand. Raw secret bytes are reachable only through explicit `expose_*` methods, so a leak into a log or serialization is visible in code.
- **No oracles.** Errors are terse: an AEAD failure does not distinguish "wrong key" from "wrong associated data".
- **No panics on bad input** — only `Err`.
- **`#![forbid(unsafe_code)]`** throughout the crypto crate.

## Recovery — the Emergency Kit

When you create an identity in an instance, the core **generates the Secret Key on the device** and shows an **Emergency Kit** (printable PDF). The Secret Key is generated locally and **never goes to the server**.

- **New device:** Secret Key from the Kit + (if used) password → the keyset is reconstructed locally.
- **Total loss** (no device and no Kit) = that instance's data is lost. **This is stated honestly at creation.**

A planned org/admin **escrow** (an org recovery keypair wrapped under several admins, M-of-N, opt-in, audited, with personal vaults excluded) has its storage fields laid down now; the flow is future work. The hard rule stands: **never reset a zero-knowledge vault via email.**

Continue to the [zero-knowledge model](../zero-knowledge-model/) for the threat model, or [Sync & anti-rollback](../sync-model/) for how signed versions defend convergence.
