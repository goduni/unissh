---
title: What is UniSSH
description: An open-source, self-hosted, zero-knowledge SSH client with end-to-end encrypted secret vaults, fleet operations, real terminals, SFTP and tunnels.
---

UniSSH is a cross-platform SSH client with team access and **encrypted vaults** for secrets. It sits at the intersection of a secrets manager (think 1Password) and a network tool (think Termius), with a strong bias toward security and toward teams that operate from hardened infrastructure.

It is **fully open source**, **self-hosted**, and **not a SaaS**. Teams stand up their own server instances; there is no global UniSSH account.

## The core idea

The backend is a **control plane, not a data plane**.

- The **control plane** (a server instance) holds metadata, encrypted keys, access policy, audit, and synchronization.
- The **data plane** (your SSH traffic) flows **directly** from client to host, or through your own bastion via `ProxyJump`. SSH traffic **never** passes through the UniSSH backend.

Combined with end-to-end encryption, this means the server is an **untrusted ciphertext store**: it routes blobs and applies policy, but never holds anything in the clear.

:::tip[Zero-knowledge in one sentence]
A full dump of a UniSSH server database yields only ciphertext and open metadata — never your secrets, vault keys, private SSH keys, or note/password content.
:::

## Who it is for

Teams and engineers working from places with good infrastructure — their own bastions, their own CA, real security requirements. The design assumption is that **they will not change their infrastructure to fit the product**: UniSSH integrates into what already exists rather than replacing it. (Hence `ProxyJump` over a built-in relay, and orchestrating an external CA rather than being one — see [Components](../../components/server/).)

## What you get

- **End-to-end encrypted vaults** holding SSH keys, host profiles, server passwords, encrypted notes, and host groups.
- **Real terminals** — interactive PTY sessions backed by [`russh`](https://crates.io/crates/russh), streaming exec with separate stdout/stderr, and auto-reconnect.
- **Fleet and broadcast ops** — multi-host exec with concurrency limits and per-host timeouts, runs by host group or tag, dry-run target resolution, broadcast (one input fanned out to N PTYs), and fleet file push over SFTP.
- **SFTP** with resumable transfers, progress, and cancellation.
- **Tunnels** — local, remote, and dynamic (SOCKS5) forwards, including `ProxyJump` chains.
- **A self-hostable zero-knowledge server** — a ciphertext store with device/team sync, membership/sharing/revocation (RBAC), and a tamper-evident audit log.
- **A web admin panel** for operating an instance.

## The multi-instance model

UniSSH is deliberately multi-instance. An organization or team runs **its own server instance**, and instances are fully independent (e.g. a dev environment and a prod environment, or two different companies, or a company plus a personal project).

- **An instance is a trust boundary.** Two instances know nothing about each other: no shared users, no shared keysets, no shared identities, no shared keys.
- **The client is an aggregator of isolated connections.** In the UI you see a list of instances ("Dev", "Prod", "Customer X", "Personal") and switch between them like workspaces.
- **The on-device database keeps each instance in its own, never-mixed partition.** Compromise of one instance's data must not drag in another.
- **Identity is created fresh per instance.** "Vasya on instance A" and "Vasya on instance B" are cryptographically different people — each with their own keyset, Secret Key, and Emergency Kit.

A **local vault** is a special case: an "instance with no server" that lives only on the device and is connected to nothing.

## One account, many spaces

Within a single instance, teams are first-class **spaces** (Backend, Security, …) — groupings under one account, **not** identity boundaries. A person has **one account** across every space they belong to (no separate login per team), and a shared people **directory** spans those spaces.

- An **account = one keyset identity**; its Ed25519 public key is the canonical member-id that vault grants are keyed on, and an account's devices share that keyset.
- **Onboarding** is by a space-scoped, revocable **invite link** (`/join`) or **SSO (OIDC)** with a group→space mapping that is reconciled on every login (dropping an IdP group removes that space). An existing account joins further spaces via a directory-add.
- **Server-trusted roles** — **owner** (the first user to *claim* the instance with its one-time setup code), **space-admin**, and **member** — govern who may administer the server. They are distinct from the cryptographic **vault roles** (viewer/editor/admin) that decide who can actually decrypt a vault.

## Repository at a glance

UniSSH is a monorepo. The Rust core is the shared foundation; the server, client, and admin panel all build on it.

| Directory | Role | Stack |
|---|---|---|
| `rust-core/` | Crypto core, vaults, SSH transport, sync, FFI (9 crates) | Rust (Cargo workspace) |
| `server/` | Zero-knowledge control plane: ciphertext store + sync + RBAC + audit | Rust (axum + sqlx) |
| `client/` | Cross-platform SSH client (desktop/mobile) | Tauri 2 + React + Vite |
| `server-ui/` | Self-hosted admin panel | React + Vite + wasm |

Continue to [Install & prerequisites](../install/), then run the [local quickstart](../quickstart/). To understand the design, read the [System overview](../../architecture/system-overview/) and the [Security & zero-knowledge model](../../architecture/zero-knowledge-model/).

## License

Dual-licensed: **MIT OR Apache-2.0**.
