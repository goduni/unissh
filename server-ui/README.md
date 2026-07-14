# UniSSH Admin — server administration web panel

A production SPA for the self-hosted **zero-knowledge** UniSSH control plane. It implements
the design mockup (16 screens) and connects to the **live** server API. Styled consistently
with `unissh-client` (a port of the design tokens in `client/src/theme`).

**Stack:** React 18 · Vite · TypeScript · Zustand · i18next (ru/en) · real
crypto via wasm from `rust-core` (`crypto-wasm/`).
## Build and run

```bash
# 1) build the wasm crypto (needs rustup + wasm-pack; see below)
npm run build:wasm          # → crypto-wasm/pkg/

# 2) dev server
npm install
npm run dev                 # http://localhost:5180

# 3) prod build
npm run build               # tsc --noEmit && vite build → dist/
npm run preview
```

**wasm toolchain (one-time):**
```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```
`crypto-wasm/` — a `wasm-bindgen` crate on top of `rust-core/crates/crypto`. It
**does not pull in** `keychain`/`vault` (they depend on `unissh-storage` → rusqlite/sqlcipher,
which does not compile to wasm), and instead **vendors** the storage-free keyset crypto logic 1-to-1, so
signatures are **byte-compatible** with the real clients (domains `unissh-server-auth-v1`,
`unissh-registration-v1`). If `pkg/` is not built, the panel still works, but keyset operations
(unlock, claim, rotation) show "wasm not loaded".

## Sign-in (one instance, no tenant switcher)

The panel administers **one instance**. You sign in as the **owner** or a **space-admin** —
the same account you use in the desktop client:

1. **Escrow sign-in** — `handle + password + Secret Key`. The panel fetches the account's
   **encrypted** keyset from escrow and `unlock`s it in the browser (key in memory only);
   a single flow then mints the admin session (`auth/challenge` → sign via wasm →
   `auth/verify`) and leaves the keyset unlocked for crypto actions. **Lock** wipes it.
   There is **no `.keyset` file to import** and **no ops token to enter first**.
2. **SSO** — if the instance has `[oidc]` enabled, "Sign in with SSO" runs the browser OIDC flow.
3. **QR-approve** — a brand-new, unlinked browser is onboarded by scanning a QR from an
   already-trusted device (the device-to-device relay).
4. **Claim** — while the instance is unclaimed, the login screen offers to claim it with
   the setup code from the server log.

Crypto sections are behind `LockGate` until the keyset is unlocked. Dangerous actions go through
`ConfirmDialog` (for `seq-bump` — re-entering the identifier). There is no read-only role (there
isn't one on the server either).

The optional server-trusted **ops** break-glass token (`[ops] token`, `X-UniSSH-Ops-Token`) is a
separate, default-off lever for `/v1/ops/*` (overview / instance / seq-bump) — **not** the panel's
normal way in, and never a decryption key.

## Deploy

The `dist/` artifact is served behind a reverse proxy (mind the server's `trust_proxy`/TLS modes)
or, optionally, from a dedicated static route on the server. By default the panel talks to the same
origin; the instance address is configured on the login screen and in settings.

## Structure

```
src/
  api/         typed client (headers/idempotency/error envelope), auth-service
  crypto/      CryptoProvider (seam) + wasm-provider (real crypto)
  store/       Zustand: session (access + keyset-unlocked), prefs, ui, meta
  theme/       token port + ThemeProvider (CSS variables, dark/light × 5 accents)
  ui/          primitives, DataTable, overlays (Drawer/Modal/ConfirmDialog/LockGate/Toaster)
  shell/       Win chrome: Titlebar, Sidebar (instance identity + nav), SettingsPanel
  access/      Login (escrow / SSO), ClaimModal, InviteModal
  screens/     16 screens (Instance / Identity / Access / Data)
  i18n/        ru/en
crypto-wasm/   Rust → wasm crate (crypto)
```
