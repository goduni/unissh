# UniSSH — cross-platform client (Tauri v2)

A cross-platform SSH client (macOS / iOS / Linux / Windows / Android) built on **Tauri v2** with a
**React 18 + TypeScript** frontend and a **Rust backend** that wraps the existing UniSSH core
(`../rust-core`, crate `unissh-ffi`) directly as a path dependency.

The UI is a pixel-faithful implementation of a bespoke design system:
dark-first, premium-technological, Hanken Grotesk + JetBrains Mono, 5 accent colors, dark/light/auto
app theme, 7 terminal themes, desktop three-panel shell + a native mobile shell.

## Architecture

```
src/                      React + TS frontend
  theme/      tokens.ts (exact design tokens), ThemeProvider, theme.css (keyframes/fonts)
  components/ primitives.tsx (Icon+~70 glyphs, Btn, Tag, AuthBadge, StatusDot, Logo, Win, Segmented, Toggle…)
  shell/      Shell.tsx (title bar, sidebar 220px ↔ icon rail <880px, vault switcher, nav)
  bridge/     types.ts (DTO mirrors) + api.ts (typed invoke wrappers for every command)
  store/      app.ts (zustand: route/vault/data/terminals/tunnels/overlays), ctx.ts, toast.ts
  views/      ViewHosts, ViewTerminal (real xterm.js), ViewFleet, ViewBroadcast, ViewSftp,
              ViewTunnels, ViewKnown, ViewAgent, ViewSecrets, ViewSettings
  overlays/   Entry (onboarding/kit/unlock), Modals (host/key/tunnel), CommandPalette,
              ImportPreview, GroupsModal, Feedback (toasts/confirm/shortcuts)
  mobile/     MobileApp.tsx (bottom tabs, push stack, sheets, FAB, key-accessory row)
  App.tsx, main.tsx

src-tauri/                Rust backend
  src/lib.rs              Tauri builder, plugins, ~75 command handlers, AppState
  src/commands.rs         every command wraps the blocking core call in spawn_blocking
  src/dto.rs              serde DTOs <-> unissh-ffi records/enums
  src/observers.rs        SessionObserver/Exec/Broadcast/SftpProgress -> tauri::ipc::Channel
  src/state.rs            registries the core does not keep (sessions/tunnels/sftp/broadcast/cancel)
  src/error.rs            ApiError mirrors FfiError (keeps structured HostKeyMismatch for TOFU)
  Cargo.toml              depends on `unissh-ffi = { path = "../../rust-core/crates/ffi" }`
```

**Core integration facts**
- The core's `Core` facade is **synchronous/blocking** (it owns its own tokio runtime). Every Tauri
  command therefore runs the call on a blocking thread via `tauri::async_runtime::spawn_blocking`.
- Terminal/SFTP/broadcast output streams back over `tauri::ipc::Channel` (the Rust observer forwards
  the bytes; the frontend feeds them straight into xterm.js).
- The core hands out `Arc<SshSession|SshTunnel|SftpFfi|…>` and forgets them, so `AppState` owns the
  lifecycle, keyed by a generated id.
- **Security boundary respected:** the UI never receives plaintext private keys (only public keys +
  fingerprints + session data). Password/note reveal is the only type-gated exception.

## Honesty to the core

The prototype showed some indicators the core cannot back; these were intentionally dropped or made
real (not faked): host "online"/ping/cipher labels are **removed** (a host shows as active only when it
has a live terminal session in-app); clipboard auto-clear and biometric unlock are wired to real
platform features (biometric is mobile-only); the per-host "agent forwarding" toggle is omitted (the
core keeps forwarding off by default and prefers ProxyJump).

## Prerequisites

- Node 20.19+ / 22.12+ (Vite 8 requirement) and Rust 1.95+.
- **Linux desktop build:** `libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev
  libjavascriptcoregtk-4.1-dev librsvg2-dev libssl-dev libxdo-dev libayatana-appindicator3-dev`.
- **iOS:** macOS + Xcode + CocoaPods. **Android:** Android Studio + SDK + NDK.
- The sibling `../rust-core` must be present (it is consumed as a path dependency).

## Develop / build

```bash
npm install
npm run tauri dev        # desktop dev (vite + the Rust app)
npm run build            # typecheck + vite production build (frontend only)
npm run tauri build      # desktop bundle (.app/.dmg/.deb/.AppImage/.msi)

# mobile (run init once):
npm run tauri ios init   && npm run tauri ios dev
npm run tauri android init && npm run tauri android dev
```

## Verified status

- `cargo check` (lib + bin) — **passes** against the real `unissh-ffi` + full Tauri v2 stack.
- `tsc --noEmit` — **0 errors**; `vite build` — **passes**.
- A full `cargo build`/`tauri build` (codegen + link) and on-device runs require a machine with a
  display and adequate disk — not performed in the headless build environment.