---
title: Sync & anti-rollback model
description: How UniSSH synchronizes encrypted vaults offline-first through an untrusted server, using signed monotonic versions, tombstones, last-write-wins, and an anti-rollback cursor.
---

UniSSH sync is **offline-first** and treats the server as an **untrusted relay**. The local encrypted database (SQLCipher) is the source of truth for working; the server is a rendezvous point. Everything works offline and syncs in the background.

## Principles

- **The sync server is a dumb, reliable box of versioned encrypted blobs.** It can accept a new version of an object, return "what changed since cursor N", and report its own version. **Merge logic lives on the client**, after decryption.
- **The unit of sync is the item**, not the whole vault — each item carries its own wrapped key.
- **End-to-end encryption is preserved always**, even over a compromised TLS channel.

## Delta without decryption

Every object gets a server-side **monotonic cursor / sequence** (`server_seq`) — open metadata. A client remembers "synced up to N" and asks for "everything after N". The server never decrypts to compute a delta.

## Conflict resolution

Version 1 is **last-write-wins by item version, with conflict detection**. The losing version is **not destroyed** — it is preserved into history / trash. Field-level merge / CRDT is deliberately deferred until there is a real need.

## Deletion is a first-class event

A delete is a **tombstone**: a synced record with a version and a **signature**, exactly like any other change. This is why deletions propagate correctly and why a stale restore can be reasoned about precisely (see [Backups & anti-rollback restore](../../operations/backups/)).

## The untrusted-transport model

The client sync engine does **not** trust `server_seq`, ordering, or content. Each incoming object is checked in order, and only then applied — **verify before apply**:

1. **Signature** verifies (via the crypto/vault layer) → else REJECTED.
2. **`key_epoch >= floor`** (the vault's stored epoch floor) → else REJECTED.
3. **Author authority** under the vault's membership model → else REJECTED.
4. **Keyset generation `>= floor`** → else REJECTED.
5. Only then the monotonic `put_*` (LWW).

Guarantees (the engine never panics):

| Situation | Outcome |
|---|---|
| Stale / rolled-back version | **SKIP** (`skipped_stale`) |
| Equal version, different content | **Conflict** — local copy not overwritten |
| Equivocating manifest at an epoch (a different member-set, even validly signed) | **Conflict** — the trusted manifest is not overwritten (anti-equivocation) |
| Forged / non-member object | **REJECTED**, not applied |
| `key_epoch` or generation below floor | **REJECTED** |
| Transport reporting a cursor below last-seen | **REJECTED** (`TransportRollback`) |

## The anti-rollback cursor

This is the heart of defending against a malicious or restored-stale server.

`server_seq` is a single instance-wide monotonic counter. Each client keeps a **trusted last-seen cursor outside the server**, stored locally-to-the-instance and **never replicated back** from the server. The invariant: the server's reported version (`report_version()`, equal to `next_seq`) must **never drop below a cursor a client has already seen**. If it does, the client treats it as a snapshot-replay **attack** and refuses to sync (a fatal `TransportRollback`).

The cursor advances **incrementally** in strict `server_seq` ascending order after each object is processed — applied, skipped, conflicted, and verify-rejected objects all advance it; a below-cursor read does not. So an interrupted delta loses no progress and never skips an unverified tail.

:::note[Why the floor lives on the client]
Per-record version monotonicity catches a single object being lowered. But a whole-database snapshot rollback is caught only by a floor the server cannot move. Hence the trusted cursor (and the keyset-generation and vault-epoch floors) are held **client-side** and never advanced from untrusted, replicated data. The server additionally enforces an operator-anchored instance-generation floor at startup (see [Backups](../../operations/backups/) and [Configuration](../../operations/configuration/)).
:::

### Keyset floors move only on trusted paths

A keyset blob's `generation` is header bytes that are authenticated only when the keyset is actually unlocked. The sync engine therefore **never raises** the keyset generation floor from that untrusted field — it only rejects deliveries with a generation **below** the trusted floor. The floor is raised only on the trusted unlock path (a verified unlock or a password change), so an untrusted transport cannot poison it and lock out a legitimate keyset.

## What the engine is — and is not

The client sync engine models the server as a `SyncTransport` trait with an in-memory mock for tests; there is no real network in the core. A `SyncObject` is a tagged record (`Vault` / `Item` / `MembershipManifest` / `MembershipGrant` / `Audit` / `Keyset` / `AccountState`) carrying **already-encrypted, already-signed** blobs plus open metadata, serialized with a hand-rolled length-prefixed byte codec (no `serde`). The engine only transports and verifies — it never decrypts content, and **no plaintext crosses out of it**.

The server side that implements this transport over HTTP is described in [Server & API surface](../../components/server/); the server's own anti-rollback machinery (`server_seq`, `seq-bump`, instance generation) and the safety of a full re-push are covered in [Backups & anti-rollback restore](../../operations/backups/).
