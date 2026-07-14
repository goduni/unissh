---
title: Backups & anti-rollback restore
description: How to back up and restore a UniSSH server safely — why a stale restore looks like a rollback, the seq-bump command, and why a full re-push cannot corrupt data.
---

Backing up a UniSSH server is mostly ordinary — the data is **only ciphertext** (zero-knowledge is preserved). The one subtlety is the **anti-rollback invariant**: a restore that *lowers* the server's sequence looks like a snapshot-replay attack to clients. This page explains exactly what to do, and why a full re-push is safe.

## The invariant you must respect

`server_seq` is a single instance-wide **monotonic counter**, and each client keeps a trusted last-seen cursor **outside** the server. The invariant: `report_version()` (= `next_seq`) must **never drop below a cursor a client has seen** — otherwise the client treats it as a snapshot-replay **attack** and refuses to sync (a fatal `TransportRollback`). So a restore that lowers `next_seq` breaks sync until corrected. (The model is detailed in [Sync & anti-rollback](../../architecture/sync-model/).)

The good news: **no WAL/PITR setup is required for self-hosting.**

## Failure modes and what to do

### Crash / power loss → do nothing

SQLite WAL recovers the live DB to the last committed write on restart. No corruption, no `next_seq` regression. This is the common failure and it needs no backup at all.

### Disk dies / file deleted / bad `rm` → restore a snapshot, then `seq-bump`

A plain nightly `cp data/unissh.db …` (or a volume snapshot, or `VACUUM INTO`) is fine for a homelab. The snapshot is stale, so after restoring, raise the floor:

```bash
unissh-server seq-bump --config config.toml --by 100000000      # raise by a delta
# or raise the instance counter to an exact floor:
unissh-server seq-bump --config config.toml --to <N>
```

In the Compose stack: `docker compose run --rm server seq-bump ...`.

`seq-bump` only ever **raises** `next_seq` (never lowers). Once `report_version` is above every client's cursor, clients stop seeing a rollback and **resume**. Because each client does a **full re-push** on sync, it re-uploads its whole vault state — so anything that still lives on at least one client is **re-populated automatically**. One command, then it heals itself.

## Why a full re-push cannot corrupt data

The server **never merges**. Clients resolve deterministically by **signed monotonic version (LWW)** with verify-before-apply:

- Re-pushing an object the server already has (same version + content) is an **idempotent no-op**.
- A **lower-or-equal** version can **never overwrite** a newer one (`skipped_stale`); the highest signed version always wins, re-propagated from whichever device holds it. An offline device returning with stale data converges *up* on its next pull.
- **Equal version, different content** surfaces as an explicit **Conflict** — the local copy is **not** overwritten (no silent corruption).
- A client can only push objects it can **sign** — it cannot forge another author's record. With `validate_signatures` on (the default), the server also re-verifies signatures.
- **Membership / revocation / key-rotation are not undone** by a stale restore: the epoch-floor and keyset-generation floor are **client-side** and never regress, so clients reject down-epoch objects regardless of what the restored server serves; the admin's re-push heals the server's manifests/grants.

## The one honest data hazard of a stale restore

The most-recent **server-only** changes are lost — specifically a deletion (tombstone) or a newer edit **that no surviving client still holds** (e.g. made by a device that is now gone). Since the old version is validly signed and no higher version exists anywhere, LWW accepts it → a deleted item can **reappear**, or a superseded edit can come back.

That is **loss-of-latest-state, not corruption**, and it is exactly the window between your snapshot and the failure.

:::tip[Tighten the window cheaply]
Snapshot the instance **`next_seq`** to a tiny out-of-band durable key, more often than the full backup. That lets you `seq-bump --to` precisely after a restore. You can also anchor `[sync] min_instance_generation` (the instance-wide `next_seq`) out-of-band — see [Configuration](../configuration/) — so the server refuses to boot below a known floor.
:::

## Backend specifics

- **SQLite:** stop the stack (or snapshot the `unissh-data` volume / `/app/data/unissh.db`). A nightly file copy or `VACUUM INTO` is sufficient.
- **Postgres:** `pg_dump` the database (or snapshot the `unissh-pg` volume). Postgres operators get a **zero-touch** upgrade if they want it — WAL archiving + PITR, or a streaming replica → restore with ~0 loss and **no `seq-bump`** — but that is an *option*, not a requirement.

Either way, backups contain only ciphertext. See [Docker Compose deployment](../deploy/) for the volume layout.
