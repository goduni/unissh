---
title: Admin panel (server-ui)
description: The UniSSH self-hosted admin panel — a React SPA that does real cryptography in the browser, signing in by escrow or SSO with the account keyset unlocked in-page.
---

`server-ui` is the production web admin panel for a self-hosted UniSSH **zero-knowledge** control plane. It is a single-page app that connects to a **live** server API and shares its visual language with the desktop client (it ports the client's design tokens).

**Stack:** React 18 · Vite · TypeScript · Zustand · i18next (ru/en) · **real cryptography via WebAssembly** built from the core.

## Real crypto in the browser

Keyset operations in the panel use genuine cryptography, not a re-implementation. A `crypto-wasm` crate — a `wasm-bindgen` wrapper over `rust-core/crates/crypto` — provides them.

It deliberately **does not pull in** `keychain`/`vault` (those depend on `storage` → rusqlite/SQLCipher, which does not compile to wasm). Instead it **vendors the storage-free keyset crypto 1:1**, so the panel's signatures are **byte-compatible** with real clients (domains `unissh-server-auth-v1`, `unissh-registration-v1`).

:::caution
If `crypto-wasm/pkg/` is not built, the panel still loads, but keyset operations (unlock, claim, rotation) report "wasm not loaded". Build it with `npm run build:wasm` — see [Install & prerequisites](../../overview/install/).
:::

## Signing in

The panel administers **one instance** (there is no tenant switcher). You sign in as the **owner** or a **space-admin** — the same account you use in the desktop client:

1. **Escrow sign-in** — enter **handle + password + Secret Key**. The panel fetches the account's **encrypted** keyset from escrow and unlocks it **in the browser** (the keyset never leaves the page, and never reaches the server); a single flow then mints the admin session and the keyset stays unlocked for crypto actions. **Lock** wipes it. There is **no `.keyset` file to import** and **no ops token to enter first**.
2. **SSO** — if the instance has `[oidc]` enabled, "Sign in with SSO" runs the browser OIDC flow instead.
3. **QR-approve** — a brand-new browser that isn't linked yet is onboarded by scanning a QR from an already-trusted device (the device-to-device relay).
4. **Claim** — if the instance is still unclaimed, the login screen offers to claim it with the setup code from the server log.

Both levels of the session (the admin/ops access token and the unlocked keyset) are established **together** by escrow/claim sign-in; nothing is persisted, so a reload returns to the sign-in screen. Cryptographic sections sit behind a `LockGate` until the keyset is unlocked, and dangerous actions go through a confirmation dialog (for `seq-bump`, you re-type the identifier). There is no read-only role — the server does not have one.

The optional server-trusted **ops** break-glass token (`[ops] token`, `X-UniSSH-Ops-Token`) is a separate, default-off infrastructure lever for `/v1/ops/*` (overview / instance / `seq-bump`) — **not** the panel's normal way in, and never a decryption key.

## Layout

```
src/
  api/         typed client (headers/idempotency/error envelope), auth-service
  crypto/      CryptoProvider (seam) + wasm-provider (real crypto)
  store/       Zustand: session (access + keyset-unlocked), prefs, ui, meta
  theme/       ported tokens + ThemeProvider (CSS vars, dark/light × 5 accents)
  ui/          primitives, DataTable, overlays (Drawer/Modal/ConfirmDialog/LockGate/Toaster)
  shell/       window chrome: Titlebar, Sidebar (instance identity + nav), SettingsPanel
  access/      Login (escrow / SSO), ClaimModal, InviteModal
  screens/     ~16 screens (Instance / Identity / Access / Data)
  i18n/        ru/en
crypto-wasm/   Rust → wasm crate (crypto)
```

The screens cover instance operations (overview, devices, sessions, config, health, metrics, maintenance, migrations), identity (accounts, **spaces**, **directory**, invites), access (vaults, grants), and data (objects, audit, relay) — all driven by the server's [admin read-projections](../server/), which expose only **open metadata** and never ciphertext.

## Build and deploy

```bash
npm run build:wasm          # → crypto-wasm/pkg/
npm install
npm run dev                 # http://localhost:5180
npm run build               # tsc --noEmit && vite build → dist/
npm run preview
```

The `dist/` artifact is served behind a reverse proxy (respect the server's `trust_proxy`/TLS mode) or, optionally, from a static route on the server itself. By default the panel talks to the **same origin**; the instance address is configurable on the login screen and in settings.

In the recommended Docker Compose deployment, the SPA is served **same-origin** by Caddy, so its API client uses a relative base, CORS stays off, and the only CSP relaxation needed is `script-src 'self' 'wasm-unsafe-eval'` for the wasm module. See [Docker Compose deployment](../../operations/deploy/).
