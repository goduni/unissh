---
title: Desktop & mobile client
description: The UniSSH cross-platform client — a Tauri 2 + React app wrapping the Rust core directly, with real terminals, fleet ops, SFTP, and tunnels.
---

The UniSSH client is a cross-platform SSH client (macOS / iOS / Linux / Windows / Android) built on **Tauri v2** with a **React 18 + TypeScript** frontend and a **Rust backend** that wraps the existing core (`rust-core`, crate `unissh-ffi`) directly as a path dependency.

The UI is dark-first and premium-technological — Hanken Grotesk + JetBrains Mono, three theme families (**mono** is the default; **nebula** and **candy** are opt-in), five accent presets, light/dark/auto modes with an AA-verified twin each, **nine** terminal themes (two of them light), a desktop shell and a purpose-built mobile shell.

## Architecture

```
src/                      React + TS frontend
  theme/      design tokens, ThemeProvider, keyframes/fonts
  components/ primitives (Icon + ~70 glyphs, Btn, Tag, AuthBadge, StatusDot, …)
  shell/      Shell.tsx (title bar, sidebar ↔ icon rail, vault switcher, nav)
  bridge/     types.ts (DTO mirrors) + api.ts (typed invoke wrappers per command)
  store/      zustand: route/vault/data/terminals/tunnels/overlays, ctx, toast
  views/      ViewHosts, ViewTerminal (real xterm.js), ViewRun (mounts ViewFleet
              and ViewBroadcast as two modes of one screen), ViewSftp, ViewTunnels,
              ViewKnown, ViewAgent, ViewSecrets, ViewSettings
  overlays/   Entry (onboarding/kit/unlock), Modals, CommandPalette, ImportPreview, …
  mobile/     MobileApp.tsx (bottom tabs, push stack, sheets, FAB)

src-tauri/                Rust backend
  src/lib.rs              Tauri builder, plugins, ~75 command handlers, AppState
  src/commands.rs         every command wraps the blocking core call in spawn_blocking
  src/dto.rs              serde DTOs <-> unissh-ffi records/enums
  src/observers.rs        SessionObserver/Exec/Broadcast/SftpProgress -> tauri::ipc::Channel
  src/state.rs            registries the core does not keep (sessions/tunnels/sftp/…)
  src/error.rs            ApiError mirrors FfiError (keeps structured HostKeyMismatch)
  Cargo.toml              depends on unissh-ffi = { path = "../../rust-core/crates/ffi" }
```

### How the client talks to the core

- The core's `Core` facade is **synchronous/blocking** (it owns its own tokio runtime). Every Tauri command therefore runs the call on a blocking thread via `spawn_blocking`.
- Terminal / SFTP / broadcast output streams back over `tauri::ipc::Channel` — the Rust observer forwards the bytes and the frontend feeds them straight into xterm.js.
- The core hands out `Arc<SshSession|SshTunnel|SftpFfi|…>` and forgets them, so `AppState` owns their lifecycle, keyed by a generated id.

:::tip[The security boundary is respected]
The UI **never receives plaintext private keys** — only public keys, fingerprints, and session data. Password/note reveal is the only type-gated exception. This mirrors the core's [FFI guarantee](../crates/).
:::

## Honesty to the core

The design prototype showed some indicators the core cannot back; these were intentionally dropped or made real rather than faked:

- Host "online" / ping / cipher labels are **removed** — a host shows as active only when it has a live terminal session in-app.
- Clipboard auto-clear and biometric unlock are wired to **real** platform features (biometric is mobile-only).
- The per-host "agent forwarding" toggle is **omitted** — the core keeps forwarding off by default and prefers `ProxyJump`.

## Prerequisites

- **Node 20.19+ / 22.12+** and **Rust 1.85+**.
- The sibling `rust-core/` must be present (consumed as a path dependency).
- **Linux desktop:** `libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev librsvg2-dev libssl-dev libxdo-dev libayatana-appindicator3-dev`.
- **iOS:** macOS + Xcode + CocoaPods. **Android:** Android Studio + SDK + NDK.

See [Install & prerequisites](../../overview/install/).

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

Desktop bundles are produced by CI on every PR/push and attached to GitHub Releases on a version tag — **unsigned by design** (no developer identity is attached). See [CI/CD & releases](../../operations/ci-cd/) for the unsigned-install notes.
