# Changelog

All notable changes to UniSSH are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

GitHub also generates release notes per tag from commit titles. This file exists
because those cannot answer the one question that actually matters here: **will
upgrading break the data I already have, or the server I already run?**

## Compatibility policy

UniSSH is pre-1.0, and [`README.md`](README.md) says plainly that the vault
format and the server protocol may still change. That is a licence to change
them, not a licence to change them quietly. So, for as long as the version
starts with `0.`:

- Every release states its **vault format** and **server protocol** status. If
  both are unchanged, this file says so — silence is not the signal, the
  explicit line is.
- A change to an on-disk or wire format arrives as a **new versioned scheme**,
  never as an edit to an existing one. Old data stays readable through frozen
  legacy codecs pinned by golden byte vectors; the discipline is specified in
  [`SECURITY.md`](SECURITY.md#on-disk-format-changes-migration-discipline) and
  enforced by CI, not by memory.
- Anything that *does* break — a format that stops being readable, a server that
  stops serving an older client, a setting that resets — appears under a
  **`Breaking changes`** heading at the very top of that release's entry, with
  what to do about it. If a release has no such heading, it broke nothing.
- **Server and client are versioned together but deploy separately.** Upgrade the
  server first; a newer server serves older clients, the reverse is not promised.

## [Unreleased]

### Added

- **SFTP: the saved hosts are in the empty pane.** A pane slot with nothing in
  it used to show a line of advice pointing at the `+` in its tab strip; it now
  lists the hosts themselves, one click from a session. The `+` still works and
  still opens the same list — this only stops the empty state from being a
  signpost to a control instead of the thing itself.
- **SFTP: a drive picker in the local pane.** A machine with more than one disk
  had no way to reach the others: the pane opens in your home directory and
  *up* bottoms out at that volume's root, so `D:\` or a mounted USB stick was
  reachable only by typing its path into the breadcrumb. The breadcrumb now
  leads with the current volume, and the button lists the rest with their free
  and total space. It appears only when there is more than one volume, so a
  single-disk machine sees the breadcrumb it has today. Windows drive letters,
  `/Volumes` on macOS, and removable and secondary media on Linux
  (`/media`, `/run/media`, `/mnt`); the list is re-read each time it opens, so a
  stick plugged in after the fact shows up without a restart.

Vault format and server protocol: unchanged.

## [0.3.0] — 2026-08-01

### Added

- **A local terminal** on desktop: a shell on your own machine in a tab, living
  by the same rules as an SSH session — splits, zoom, search, themes,
  copy/paste, snippets, session recording. Three ways in: the `+` picker in the
  tab strip, `⌘⇧S` / `Ctrl+Shift+S` from anywhere (**S** for shell — `L` is
  "lock the instance" and a security control keeps its key; the Shift is because
  a bare `⌘S` saves in the SFTP file editor), and *Split → local shell* in a
  pane's menu. Not in the sidebar: every row there is a destination you return
  to, and a local shell is an action that opens a new tab each time. Settings →
  General picks
  the shell, its arguments and the starting directory; leave any of them empty
  and it follows the system (`$SHELL` → your `/etc/passwd` entry → `/bin/sh`;
  `pwsh` → `powershell` → `cmd` on Windows).

  A local pane is **always marked as local** — a laptop icon in the tab and the
  session rail, and the machine's own name with the word *local* in the status
  bar. Running the right command on the wrong machine is exactly the failure
  this feature could otherwise introduce, so telling the two apart is not left
  to memory. A local shell also never auto-reconnects: it does not drop off the
  network, it exits, and the pane offers **Restart** in the same place.

  Auto-lock closes local tabs along with everything else and terminates the
  processes running in them — Settings says so rather than leaving you to find
  out. Recording local sessions is off by default and, when switched on, writes
  to your **personal** vault where you have one, so a recording of your own
  machine does not sync to a shared team vault; if there is no personal vault,
  Settings names the vault it would use instead.

  **Not on mobile.** On iOS this is not a matter of effort: the sandbox forbids
  `fork`/`exec` and there is no shell in the bundle — which is why terminal apps
  there either link commands as a library or ship an x86 emulator. Android could
  do it and deliberately does not. The entry points are hidden there and the
  core answers "not available on this platform".
- **Windows builds for ARM64** (`_arm64-setup.exe` and `_arm64_en-US.msi`),
  alongside the existing x86-64 ones. Windows on ARM already ran the x64 build
  under emulation, so this is a performance gap rather than a coverage one — but
  emulation taxes exactly the two things this app does continuously, vault crypto
  and terminal I/O. Every desktop platform now ships both architectures. The
  bundles are built natively on `windows-11-arm` rather than cross-compiled,
  because cross-compiling would also have to cross-build the vendored OpenSSL
  that SQLCipher links on Windows.
- **The window frame can now be left to your window manager** — on Linux,
  Settings → Appearance → *Draw our own title bar*. Until you touch it, the
  answer follows your desktop: off under a tiling window manager (niri, sway,
  Hyprland, river, i3 and friends), which draws no title bar and closes windows
  from the keyboard, and on everywhere else, so no existing desktop changes
  shape. Off removes the bar entirely rather than emptying it, and hands the
  frame back to the compositor. macOS and Windows are untouched by this and do
  not show the setting: on macOS the traffic lights are drawn by the system over
  our bar, and it is our bar that reserves the strip they sit in.

### Fixed

- **The AppImage would not start at all on a current Wayland desktop**, dying
  before any window with `Could not create default EGL display: EGL_BAD_PARAMETER`.
  We bundled `libwayland-*`, and because the AppImage puts its own libraries
  first on the search path, the host's Mesa — which we do *not* bundle — loaded
  our copy instead of the one it was built against. The bundle no longer ships
  those four files; the host's are correct by construction. Worth stating plainly
  because the workarounds circulating for this error do not work: neither
  `EGL_PLATFORM=x11` nor `WEBKIT_DISABLE_DMABUF_RENDERER` helps, since the
  mismatch bites when Mesa loads the library, before any of those settings mean
  anything.
- **The window could not be closed at all** — not by the button, not by a WM
  hotkey, not by the compositor, leaving `Ctrl+C` in the launching terminal or
  killing the process as the only way out. Two separate causes, both fixed.

  The one that bit every platform: asking for the confirm-on-quit prompt is not a
  passive subscription. Once the app listens for the close, Tauri stops closing
  the window itself and waits for the app to finish the job — and finishing it
  needs a permission that *closing* does not, which we had never granted. So the
  final step was refused every time, silently, on every route out of the window.
  It went unnoticed for as long as it did because `⌘Q` on macOS quits the app
  without going through the window at all, and because on Linux the app drew its
  own close button until this release handed the frame to tiling window managers
  — which is how it surfaced, from an Arch/niri desktop where the compositor is
  the only way to close a window.

  The second: Tauri destroys the window only once our handler returns, and it
  neither catches exceptions nor times out, so any failure inside it disabled
  closing permanently rather than merely skipping the confirmation. Every path
  through that handler now fails open.
- **On Linux the Secret Key was remembered in the wrong place.** "Remember on
  this device" wrote to the kernel keyutils facility, which is a cache: it is
  held in memory, it is cleared by a reboot, and nothing in it appears in
  Seahorse, KWalletManager or any other tool where you would look for — or
  revoke — a stored credential. It now uses the Secret Service (GNOME Keyring,
  KWallet, or whatever your desktop provides), which is the actual counterpart of
  the macOS Keychain and the Windows Credential Manager: it survives a reboot and
  it is visible and revocable where you expect. A key an older build left in
  keyutils is moved across the first time it is read, so upgrading in a session
  you have not rebooted keeps your key; upgrading after a reboot means entering
  it once more, which was already true every time you rebooted. On a desktop
  running no Secret Service at all the feature cannot work and now says so in the
  log instead of appearing to work until the next boot.
- **"New snippet" jumped across the header one frame after opening Snippets**,
  and Recordings had the same defect. Both views sized themselves by their own
  content instead of filling the window, so the header was laid out twice: once
  against the width of the header alone, then again once the list underneath it
  arrived. One frame, but a very visible one on a fast display. Snippets,
  Recordings and Tunnels also gained the entry motion the rest of the app has
  had — they were the three views still appearing without any.
- **Resizing the window was laggy.** The root component kept the window width in
  state as a pixel value, so every frame of a resize re-rendered the entire app —
  though the only question ever asked of that number was whether the sidebar
  fits. It now holds the answer instead of the width. Most visible under tiling
  window managers, which resize windows constantly rather than only on a drag.
- `GDK_BACKEND` is no longer forced in the AppImage launcher. It still *defaults*
  to `x11`, which remains the right default for GTK on Wayland — but the launcher
  used to overwrite the variable outright, so exporting it yourself silently did
  nothing.

### Compatibility

Vault format unchanged. Server protocol unchanged. A recording of a local
session is an ordinary recording item — same type, same asciicast v2 document,
stamped `localhost` and your OS account — so an older client lists and plays it
without knowing where it came from.

`latest.json` gains a `windows-aarch64` key alongside `windows-x86_64`; the two
are separate entries and neither displaces the other. **An existing x64 install
on an ARM machine does not switch feeds and is not stranded** — the updater
matches the architecture a binary was compiled for, not the one it is running
on, so it keeps following `windows-x86_64` and keeps updating. Moving to the
native build is a deliberate, manual reinstall.

The window-chrome setting is stored locally, per install, alongside the other
appearance preferences — it is not part of the vault and does not sync. Leaving
it untouched keeps the detection live on every boot, which is what makes the
same vault behave correctly on a tiling session and a plain desktop; setting it
once freezes the answer for that install.

**Linux only:** the store behind "remember the Secret Key on this device"
changes (see Fixed), and the cloud refresh token moves with it. Nothing in the
vault or on the wire is affected, and no other platform is touched. Whatever the
old build left in keyutils is carried across on first read, so upgrading in a
session you have not rebooted keeps both your Secret Key and your server
session; if keyutils had already been cleared — by a reboot, which is what
keyutils does — you enter the Secret Key and sign in once more, and after that
they last.

## [0.2.0] — 2026-07-30

### Breaking changes

- **The per-host tmux toggle is gone.** It was typed, not executed: the attach
  went out as text into the PTY the moment the shell opened, which raced slow
  logins, landed blind on endpoints that are not a POSIX shell, and re-ran into
  whatever a reattached pane was already running. The replacement is honest
  about being a command: add a **startup snippet** with `tmux new -A -s main`
  (or your variant) to the same host. Profiles that carried the old flag keep
  it, inert — the field round-trips unknown, nothing needs migrating — but
  sessions stop self-attaching until you add the snippet.

### Added

- **Two-factor logins work.** A `keyboard-interactive` prompt that no stored
  secret can answer — a one-time code, a push confirmation, a forced password
  change — is now put to you instead of being answered with your password. That
  was the actual defect: a two-factor login sends two rounds, and both were
  answered from storage, so the second was always wrong and the failure looked
  like a bad password. The stored password still answers a plain PAM round by
  itself, so nothing prompts needlessly.
- **Hardware keys, through the system ssh-agent.** A per-host auth kind that
  delegates signing to the operating system's agent — which is how a FIDO/U2F
  token, a PKCS#11 smart card, a Secure Enclave key, 1Password or gpg-agent
  becomes usable at all. For such a host the key lives outside the vault, by
  definition; [`THREAT_MODEL.md`](THREAT_MODEL.md) states that plainly. What is
  stored is the public key, which is a handle.
- **Agent forwarding — one key, one confirmation at a time.** Off by default,
  per host. It exists so that git or ssh running *on* that machine can use your
  key without the key being copied there — the case ProxyJump cannot help with.
  Deliberately narrower than OpenSSH's: only the key this connection
  authenticated with is offered (the full agent is a map of everywhere you log
  in), and every signature raises a prompt that names where it would log in.
- **A portable, encrypted backup of the whole vault.** Export writes a
  `.unisshbak` that opens with its passphrase *alone* — no keyset, no account,
  no server — and restore, beside "Create vault", always creates a **new**
  vault next to the original rather than replacing anything live. The
  passphrase is asked for twice and never stored, and the dialog says what that
  buys and costs in those terms: a bundle any instance can open, and a typo you
  will not notice for months is an unrecoverable file. This is also the
  documented way *out* — the README now says so where it compares vendors.
- **Version history for passwords and notes.** The vault kept every earlier
  value all along; nothing in the app called the API, so overwriting a secret
  looked exactly like destroying it. A clock button now lists versions, newest
  first, live one marked — and each old value reveals on its own, through the
  same deliberate control as a live one, instead of sitting decrypted in a
  dialog.
- **The window chrome is ours.** The native title bar is gone; the app's own
  toolbar is the title bar. Windows and Linux get close/minimize/maximize to
  the left of the logo; macOS keeps its native traffic lights — untouched, with
  the zoom button's tiling menu intact — and the bar shapes itself to them
  instead of the other way round, collapsing the reserved space when native
  fullscreen hides the lights. A locked window still drags and closes, and an
  undecorated Linux window keeps its resize borders, invisibly.
- **Right-click a host.** Connect, SFTP, and group membership — a checkmark per
  group, click to add or remove, "Manage groups…" for the rest — titled with
  the host's name. The first per-host path to groups that does not detour
  through the editor or multi-select.
- **Terminal scrollback is a setting**, default 10 000 rows, with no ceiling
  beyond xterm's own — a live "≈ N MB per session" readout spends the honesty
  budget where a cap would have spent a workaround.
- **Authentication is a list, not five tiles.** Each auth kind carries its
  one-line description in the picker — "Personal" and "System agent" finally
  explain themselves — and the long switch copy for recording and forwarding
  moved behind a "?" instead of turning the switches into footnotes.
- **An expired access token rotates itself.** Meeting one is routine — they are
  short-lived on purpose — so sync refreshes and retries instead of failing
  with an error whose manual remedy only appeared to work on the second try.
- **Barbie** replaced Candy Holo as the opt-in theme family: same slot, pink
  light hero, dark twin, its own terminal palettes — with three colours
  deepened past their nominal values because the contrast is measured, not
  eyeballed.
- **Snippets** — a command library that is vault content, so it is encrypted at
  rest and syncs. Reachable from ⌘K, where selecting one types it into the
  active pane without running it, and linkable per host as startup commands,
  where they do run, in the order you picked them.
- **Session recording** as [asciicast v2], encrypted in the vault, per host.
  Exportable to a file that plays in `asciinema`, because a recording only its
  own tool can read is not evidence anyone else can check. Capped at 8 MB per
  session; a recording that reaches the cap says so instead of ending quietly.
- A **modern-only algorithm policy**: post-quantum key exchange required with no
  classical fallback, Ed25519 host keys, AEAD ciphers. Off by default, because a
  server without ML-KEM then stops connecting.
- **Post-quantum key exchange is now documented.** It is not new — the transport
  has negotiated the hybrid `mlkem768x25519-sha256` ahead of classical
  curve25519 since the first release. It had simply never been written down.
- **Shell integration (OSC 133)**: jump between prompts, and a gutter mark on a
  prompt whose command failed. Nothing is inferred — a shell that emits no marks
  produces none.
- **GPU terminal rendering on desktop**, opt-in. Phones already had it.
- `~/.ssh/config` import now applies `LocalForward`, `RemoteForward`,
  `DynamicForward`, `SetEnv`, `ServerAliveInterval`, `ConnectTimeout` and
  `Compression`, follows `Include`, and — the point — **reports every directive
  it cannot apply**, with its line. A real config is mostly directives UniSSH
  does not implement, and importing in silence left people believing their
  `ProxyCommand` came across.

[asciicast v2]: https://docs.asciinema.org/manual/asciicast/v2/

- Desktop builds for macOS now ship as a **universal binary** — one `.dmg` that
  runs on both Apple Silicon and Intel. Previously the release carried an
  arm64-only build, because GitHub's `macos-latest` runner is Apple Silicon, so
  Intel Macs silently had no artifact at all. Existing installs keep updating
  normally: the updater manifest still advertises `darwin-aarch64`, now alongside
  `darwin-x86_64`.
- Android builds now cover **every ABI**. The release carries a universal APK
  that installs on any device, plus smaller per-ABI APKs (`arm64`, `armv7`,
  `x86_64`, `x86`) for people who want them. Previously only `arm64` was built,
  which left x86-64 emulators and armv7 devices with nothing.
- **Linux builds for ARM64** (`.deb`, `.rpm`, `.AppImage`), alongside the existing
  x86-64 ones. This was the last remaining platform gap: an SSH client is used on
  Asahi, on ARM laptops and on a Raspberry Pi that has a screen attached, and none
  of those had an artifact. ARM *servers* are a different question and were already
  answered — the container images are multi-arch. Windows remains x86-64 only.
- Sideloading instructions for **Android and iOS** in
  [Installing unsigned builds](README.md#installing-unsigned-builds), including
  the Play Protect warning and what re-signing an unsigned `.ipa` with your own
  Apple ID does and does not cost you.
- `.github/dependabot.yml` covering all seven ecosystems (three Cargo
  workspaces, three npm projects, GitHub Actions), grouped so routine updates
  arrive as one pull request per ecosystem per month while security updates are
  not held back by that schedule.
- [Independent review status](SECURITY.md#independent-review-status) in
  `SECURITY.md` — an explicit statement that no third-party audit exists, what
  a stranger can verify without trusting the maintainer, and what remains
  unreviewed.
- This file.

### Changed

- **A chosen host is framed, not filled.** The selection tint recoloured the
  card itself — lightened in dark mode, darkened in light — which read as the
  object changing state rather than being chosen. Selection is now marked
  around the object, in the same voice as the active nav tick; hover keeps its
  faint fill, because pointer feedback is transient and state is not.
- **Sidebar numbers mean "running now", not "stored total".** Open terminals
  and active tunnels count, green-dotted, hidden at zero; the Secrets and
  Known-hosts inventory figures are gone; hosts and groups keep their filter
  counts. A tunnel you forgot you left open is exactly what a sidebar should
  hold in your peripheral vision — how many notes you own is not.
- Release notes and the README download table now name the **architecture** of
  every artifact, and name the architectures that are deliberately not built
  (Windows is x86-64 only; nothing ships 32-bit for desktop).

### Fixed

- **A remote forward (`-R`) bound its port and refused every connection to
  it.** RFC 4254 puts a port in the `tcpip-forward` reply only when the request
  asked for port 0; for a named port the reply is empty, and the delivery table
  was keyed on that emptiness — so the far side listened and every connection
  came back reset while `-L` on the same port worked.
- **Closing a tab threw the session recording away.** Ending the same session
  with `exit` saved it; the ✕ aborted the reader task that delivers the close
  event, and the close event is where recordings are written — deliberately,
  because a dropped connection is exactly the session you want the recording
  of.
- **⌘K opened the palette everywhere except the terminal** — the one place a
  snippet library is any use — and ⌘N, ⌘T, ⌘L, zoom and ⌘1–9 were equally dead
  while a pane had focus. xterm cancels every key it recognises before a
  bubble-phase listener can see it.
- **"Restore as" named the new vault after the source.** The name is a signed
  record inside the bundle, so restoring "Personal" beside the original
  produced two entries called Personal and the field you had just typed into
  did nothing but mint an invisible id. The restore now renames the vault to
  the entered name as part of the same operation — and if that half fails, the
  message leads with "restored, but", because "could not restore" would invite
  a second attempt against the vault the first one just created.
- **A recording could corrupt non-ASCII output at chunk boundaries.** A
  character split across two PTY reads is reassembled instead of becoming a
  replacement character; a genuinely invalid byte is still passed through
  rather than waited on, because a continuation that never comes would stall
  the recording for the rest of the session.
- In the host editor, adding a second new group reopened the input pre-filled
  with the first one's name — and typing then renamed it live. The input edits
  a draft now; Escape discards it, and the committed name only changes on
  Enter.
- Clicking the empty space around the auth picker activated it: the `<label>`
  wrapping the section forwarded every stray click to its first control.
- A fresh key claimed it was "updated 57 years ago" — seconds read as
  milliseconds land in January 1970 — plus five more small findings from the
  same test pass, and two earlier fixes that had only reached one of their two
  call sites.
- In compact density, the hover Connect button rode out of the row it belongs
  to: its offset was tuned for the comfortable card's padding.
- Android ships a real two-layer adaptive icon instead of Tauri's placeholder,
  with a CI check that proves the replacement happened.
- Release notes describe the release they are attached to.
- The docs site's internal links are checked in CI, as are the frontends.
- Documentation claimed `.deb` and `.rpm` installs do not auto-update. They do.
- Removed an unsupported claim that the shared core is "audited" — it is not.
  See [Independent review status](SECURITY.md#independent-review-status).
- **`Match` blocks in `~/.ssh/config` rewrote the host above them.** The
  directive was not recognised, so everything inside a `Match` was merged into
  the preceding `Host` — a config with `Host prod` followed by `Match user root`
  imported prod with the wrong user and the wrong address. Silent, and in the
  one place nobody rereads.
- **`Include` was appended instead of spliced.** Resolution is
  first-match-wins, so a config opening with `Include conf.d/*` and then a
  catch-all `Host *` handed every host the catch-all's user.
- **A FIDO/U2F (`sk-*`) key imported cleanly and then failed at
  authentication.** The file holds a key handle, not a private scalar, so it
  parsed; the opaque signing error that followed read as a broken client. It is
  now refused at import, with the reason.
- **Returning from the background is treated as a reconnect, not a retry.** A
  suspended phone spends its retry budget against a machine that was never going
  to answer, then makes you wait out a backoff computed for a flaky link.
- Unsolicited agent-forwarding channels are refused. russh accepts them by
  default and we inherited that; nothing leaked, since no agent protocol is
  served over such a channel, but accepting a channel whose purpose is to ask us
  to sign was the wrong answer.
- A session recording could deadlock the app. The write ran on a runtime worker
  and needed a lock a concurrent connect held across the network phase.
- The core lock is no longer held across a handshake at all, so a connection —
  30 seconds, or minutes while you type a one-time code or touch a token — stops
  freezing every other operation.

### Compatibility

**Vault format extended, additively. Server protocol unchanged.** Two new item
types — snippets and session recordings — and four new connection-profile fields
(startup snippets, session recording, agent forwarding, system-agent identity).
One field is retired: the per-host tmux attach (see Breaking changes). A profile
that still carries it round-trips with the key intact and inert, through the
same `extra`-map path that protects fields in the other direction. The
`.unisshbak` backup bundle is a new, self-contained format — it is opened by
its passphrase alone and does not touch the vault scheme.

Nothing breaks, and the discipline that makes that true is worth stating rather
than asserting: an older client filters items by type, so it ignores the two new
ones instead of choking on them; and profile fields it does not know round-trip
through the record's `extra` map, so re-saving a host on an old device does not
strip settings made on a new one. New fields are omitted from the encoding
entirely when unset, so existing signed items keep their exact bytes.

## [0.1.3] — 2026-07-25

Version bump only, cutting a release that carries the `v0.1.2` fixes to the
updater signing path (see below) in correctly-versioned artifacts.

### Compatibility

Vault format unchanged. Server protocol unchanged.

## [0.1.2] — 2026-07-25

### Added

- **Desktop auto-update**, verified against a minisign key compiled into the
  app. This is what makes an unsigned distributable safe to keep current: the
  client checks the release feed, verifies the payload's signature before
  executing anything, and installs on your click — never silently. Turn it off
  in Settings → About. The updater key is deliberately **separate** from the key
  that signs `SHA256SUMS`; one authorizes code execution, the other authorizes
  nothing.
- **Terminal appearance settings** — font, cursor, spacing, text colour and
  contrast — with eight built-in themes behind a contrast gate, a live preview
  built from the same options real panes use, and preferences applied to already
  open panes.
- A **Support** settings tab and a `/support` page on the site, with donation QR
  codes rendered offline.

### Fixed

- Updater artifacts were not actually signed on tag builds: an inverted
  GitHub Actions expression (`a && b || c` returns a *value*, and the empty
  string is falsy) resolved to `--no-sign` on exactly the builds that needed
  signing.
- The tag/manifest agreement guard ran under PowerShell on the Windows runner,
  where bash parameter expansion silently yields an empty string — so it had been
  "passing" without checking anything.
- Connection settings moved out of Appearance into General.

### Compatibility

Vault format unchanged. Server protocol unchanged. The first release whose
desktop artifacts carry updater metadata — 0.1.0 and 0.1.1 installs do not
auto-update and must be replaced by hand once.

## [0.1.1] — 2026-07-23

### Added

- **Mobile builds in the release pipeline** — a sideload Android APK signed by
  an identity-free self-signed key, and an unsigned iOS `.ipa`. Both get the same
  `SHA256SUMS` and SLSA provenance treatment as desktop.
- The **age public key** for encrypted vulnerability reports is published in
  `SECURITY.md`, along with the shipped integrity pipeline.
- Server-side **member vault catalog** and targeted delta sync; a client can pull
  or push one specific server vault instead of everything.

### Fixed

- **A vault could fail to bind.** An unbound cloud vault can now be bound from
  Settings, a re-pull binds a vault that landed unbound, pulled vaults are born
  bound, and Bind pushes immediately rather than waiting for the next sync.
- **Vault tombstones are version-gated on the server.** Without this, a delete
  could resurrect or duplicate vault state.
- **SQLCipher first-open is serialized** — the global crypto initialization
  raced, which could fail an open on a cold start.
- The mobile client no longer carries a 780-line fork of the hosts view; the
  shell is a shell. Layouts now collapse on *content* width rather than window
  width, which is what was overflowing on Russian text in narrow windows.

### Compatibility

Vault format unchanged. **Server protocol changed additively** — new catalog and
targeted-delta endpoints, plus version-gating on vault tombstones. Upgrade the
server before clients; older clients keep working against the newer server.

## [0.1.0] — 2026-07-15

First public release: 179 commits, no prior tag. Everything below is "added" by
definition, so it is summarized rather than enumerated.

### Added

- **Zero-knowledge vaults** — secrets encrypted client-side with a key the server
  never sees, built on RustCrypto, `hpke` (RFC 9180), Argon2id, SQLCipher, and
  Ed25519 with `verify_strict`.
- **A shared Rust core** of nine crates (`crypto`, `keychain`, `storage`,
  `vault`, `ssh-agent`, `ssh-transport`, `ffi`, `cli`, `sync`) behind a UniFFI
  boundary. Crypto, blob formats, storage, SSH, and agent logic exist only here —
  every client calls the same implementation.
- **Desktop clients** for macOS, Windows, and Linux (Tauri), with an embedded
  in-memory SSH agent whose keys never leave the core process.
- **An optional self-hosted sync server** (axum) and a **WASM admin panel**.
  Local-only operation is the default and needs no server.
- **Release integrity without a code-signing certificate** — `SHA256SUMS`, a
  `minisign` signature over it, and GitHub build provenance (SLSA attestations)
  proving the public CI built the exact artifacts from the exact public commit.

### Compatibility

The baseline everything below is measured against: local storage schema
version 9, server HTTP surface `/v1`. Both are unchanged as of 0.1.3 — no
release so far has broken a vault or a deployed server.

[Unreleased]: https://github.com/goduni/unissh/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/goduni/unissh/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/goduni/unissh/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/goduni/unissh/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/goduni/unissh/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/goduni/unissh/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/goduni/unissh/releases/tag/v0.1.0
