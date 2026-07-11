// Central app store (zustand). Holds instance/unlock status, navigation, the
// active vault and its core-backed data, open terminal tabs, and UI overlay
// slots. Mirrors the role of the prototype's `App` state + `ctx` DI bus.

import { create } from "zustand";
import * as api from "@/bridge/api";
import { onVaultMutated } from "@/bridge/sync-hook";
import { clearSecretKey } from "@/bridge/secretKey";
import { i18n, refineLangFromSystem } from "@/i18n";

/** Sentinel for the "all hosts" filter — decoupled from its display label so the
 *  label can be localized without breaking filter comparisons. */
export const HOST_FILTER_ALL = "__all";
import type {
  ConnectionProfile,
  ItemInfo,
  KnownHostInfo,
  ServerGroup,
  ServerStatus,
  SyncReport,
  VaultInfo,
} from "@/bridge/types";
import { apiErrorMessage } from "@/bridge/types";
import { logWarn, logError, logDebug } from "@/bridge/log";
import type { TermTheme } from "@/theme/tokens";
import type { SftpSession, Transfer } from "@/store/sftp-types";
import { cancelAll as cancelAllTransfers } from "@/sftp/transfer-runner";

export type Route =
  | "hosts"
  | "terminal"
  | "run"
  | "fleet"
  | "broadcast"
  | "sftp"
  | "tunnels"
  | "known"
  | "keys"
  | "passwords"
  | "notes"
  | "identities"
  | "settings";

// "repair": disk shows a half-written instance (exactly one of DB/keyset) —
//   neither unlockable nor recreatable, so we explain + offer a safe reset.
// "retry": instance_status itself failed (transient backend error) — don't
//   mislead a returning user into onboarding; offer a retry instead.
export type Overlay = "onboarding" | "kit" | "unlock" | "repair" | "retry" | "join" | null;
export type ModalKind =
  | null
  | { kind: "host"; edit?: ConnectionProfile }
  | { kind: "bindHost"; host: ConnectionProfile; vaultId: string }
  | { kind: "key" }
  | { kind: "tunnel" }
  | {
      kind: "vault";
      edit?: VaultInfo;
      onCreated?: (vaultId: string) => void;
      /** Keep the current global active vault (don't switch to the newly created one).
       *  Used when creating an identity vault from Secrets, so the hosts/terminal view
       *  isn't yanked to an empty vault. */
      keepActive?: boolean;
    }
  /** Purpose-built "create a vault to hold identities" flow: Local, an existing Space you
   *  own, or a NEW Space bootstrapped on a server with an enrollment grant. Never touches
   *  the global active vault; reports the created vault id back via onCreated. */
  | { kind: "identityVault"; onCreated?: (vaultId: string) => void }
  | { kind: "termtheme"; edit?: TermTheme }
  | { kind: "copyKeyToServer"; openssh: string; keyItemId: string };

export type Device = "desktop" | "mobile";

export type TermStatus = "connecting" | "online" | "closed" | "error";

/** A single terminal session: one xterm bound to one backend PTY. The pane is the
 *  unit that connects/reconnects; a tab arranges one or more panes in a layout.
 *  (Was `TerminalTab` before split support — the fields are unchanged.) */
export interface TerminalPaneState {
  id: string; // local pane id
  sessionId: string | null; // backend session id (null until opened)
  title: string;
  profile?: ConnectionProfile;
  status: TermStatus;
  error?: string;
  /** Set when a connect attempt failed with a host-key mismatch. Drives the
   *  in-pane security card; while present, no reconnect is offered for the pane. */
  mismatch?: PendingMismatch;
  preview?: string[]; // last output lines, for the hosts-rail live session preview
  gen: number; // reconnect generation — bumped to re-open a session in the same pane
  // Auto-reconnect budget lives on the pane (not pane refs) so it survives a pane
  // remount and stays consistent across the desktop/mobile shells.
  reconnects: number; // consecutive auto-reconnect attempts (capped)
  lastOnlineAt: number; // epoch ms the session last went online (0 = never)
}

/** Recursive split layout inside a tab. A `pane` leaf references a pane by id; a
 *  `split` node holds two children side-by-side (`row`, vertical divider) or
 *  stacked (`col`, horizontal divider), with `ratio` = child `a`'s fraction of
 *  the axis (clamped 0.1..0.9). `id` identifies the split for divider drags. */
export type TermLayout =
  | { kind: "pane"; paneId: string }
  | { kind: "split"; id: string; dir: "row" | "col"; ratio: number; a: TermLayout; b: TermLayout };

/** A terminal tab: a titled container arranging one or more panes in a layout.
 *  A brand-new tab holds a single pane; splitting grows the layout tree. */
export interface TerminalTab {
  id: string; // local tab id
  title: string;
  customTitle?: boolean; // user renamed it — don't auto-derive from the host
  panes: TerminalPaneState[];
  layout: TermLayout;
  activePaneId: string; // focused pane (input target; split/close act on it)
}

// --- id helpers (shared with ctx.ts so tab/pane ids are generated one way) ---
let paneSeq = 0;
let tabSeq = 0;
let splitSeq = 0;
export const mkPaneId = (host: string): string =>
  `pane-${host}-${(paneSeq += 1)}-${performance.now().toFixed(0)}`;
export const mkTabId = (host: string): string =>
  `tab-${host}-${(tabSeq += 1)}-${performance.now().toFixed(0)}`;
export const mkSplitId = (): string => `split-${(splitSeq += 1)}-${performance.now().toFixed(0)}`;

/** Build a fresh connecting pane for a host profile. */
export function makePane(profile: ConnectionProfile): TerminalPaneState {
  return {
    id: mkPaneId(profile.profileId),
    sessionId: null,
    title: profile.label,
    profile,
    status: "connecting",
    gen: 0,
    reconnects: 0,
    lastOnlineAt: 0,
  };
}

// --- pure layout-tree helpers ---
function replaceInLayout(node: TermLayout, paneId: string, replacement: TermLayout): TermLayout {
  if (node.kind === "pane") return node.paneId === paneId ? replacement : node;
  return { ...node, a: replaceInLayout(node.a, paneId, replacement), b: replaceInLayout(node.b, paneId, replacement) };
}
/** Remove a pane leaf, collapsing its parent split (the surviving sibling is
 *  promoted). Returns null only if the whole tree was that one pane. */
function removePaneFromLayout(node: TermLayout, paneId: string): TermLayout | null {
  if (node.kind === "pane") return node.paneId === paneId ? null : node;
  const a = removePaneFromLayout(node.a, paneId);
  const b = removePaneFromLayout(node.b, paneId);
  if (a === null) return b;
  if (b === null) return a;
  return { ...node, a, b };
}
function firstPaneId(node: TermLayout): string {
  return node.kind === "pane" ? node.paneId : firstPaneId(node.a);
}
function setRatioInLayout(node: TermLayout, splitId: string, ratio: number): TermLayout {
  if (node.kind === "pane") return node;
  if (node.id === splitId) return { ...node, ratio };
  return { ...node, a: setRatioInLayout(node.a, splitId, ratio), b: setRatioInLayout(node.b, splitId, ratio) };
}
/** Ordered pane ids as they appear left→right / top→bottom (for directional nav). */
export function layoutPaneOrder(node: TermLayout): string[] {
  return node.kind === "pane" ? [node.paneId] : [...layoutPaneOrder(node.a), ...layoutPaneOrder(node.b)];
}
/** Close every pane's backend PTY so a dropped tab never orphans a core session. */
function closeTabSessions(tab: TerminalTab): void {
  for (const p of tab.panes) if (p.sessionId) void api.sessionClose(p.sessionId).catch(() => {});
}

export interface ConfirmData {
  title: string;
  body?: string;
  danger?: boolean;
  confirmLabel?: string;
  icon?: string;
  onConfirm: () => void;
}

/** A view registers a nav guard when leaving it would destroy live work (an open
 *  broadcast, an in-flight edit). `go`/`goFiltered` call the guard before routing:
 *  a non-null return blocks the navigation behind a confirm carrying that copy. */
export interface NavGuardSpec {
  title: string;
  body?: string;
  confirmLabel?: string;
}

export type TunnelType = "local" | "remote" | "dynamic";
export interface ActiveTunnel {
  id: string; // backend tunnel id
  label: string;
  type: TunnelType;
  bindAddress: string;
  route: string; // human description e.g. "localhost:5432 → db:5432"
  via?: string;
  on: boolean;
}

export interface PendingMismatch {
  host: string;
  port: number;
  fingerprint: string;
}

/** Live cloud-sync state — only real facts: whether a sync is running, the last
 *  report, the last error and the wall-clock time of the last successful sync. */
export interface SyncStatus {
  syncing: boolean;
  lastReport: SyncReport | null;
  lastError: string | null;
  lastSyncAt: number | null; // epoch ms of the last successful sync, or null
}

interface AppStore {
  // boot / instance
  booted: boolean;
  instanceExists: boolean;
  unlocked: boolean;
  /** Whether the instance needs a master password; null = unknown (no keyset).
   *  Drives the honest "start unlocked" gating in Settings. */
  requiresPassword: boolean | null;
  /** Idle minutes before auto-lock; null = never. Store-backed so a Settings
   *  change re-arms the idle timer live (App.tsx effect depends on it). */
  autolockMin: number | null;

  // navigation
  route: Route;
  /** Bumped on every route write (even to the same value). A same-value `route`
   *  set fires no selector, so a repeated go("known") was a silent no-op; mobile
   *  subscribes to this monotonic counter to react to every navigation. */
  routeSeq: number;
  device: Device;

  // vault + data
  vaultId: string | null;
  vaults: VaultInfo[];
  hosts: ConnectionProfile[];
  groups: ServerGroup[];
  items: ItemInfo[];
  knownHosts: KnownHostInfo[];
  loading: boolean;

  // hosts view helpers
  hostFilter: string; // HOST_FILTER_ALL | tag | groupId | "__untagged"

  /** Fleet/Broadcast selection (profile ids). Empty = nothing picked: Fleet runs
   *  on nothing (Run disabled until the user checks hosts), Broadcast falls back
   *  to the whole vault. A carried selection (from the hosts multi-select bar) or
   *  the in-Fleet picker fills it. Views clear it on leave/dismiss so a stale
   *  selection can never widen or shift a later run. Lives in the store (not
   *  ViewFleet local state) so the host-key review detour preserves it. */
  fleetSelection: string[];

  // terminals
  terminals: TerminalTab[];
  activeTermId: string | null;
  /** Bumped by the "new tab" keyboard shortcut so the tab strip opens its inline
   *  host picker (the strip owns the picker's open state, this just pokes it). */
  newTabNonce: number;
  /** The tab currently being dragged, so the terminal viewport can show drop
   *  zones and merge it in on drop (drag a tab onto the terminal = combine). */
  draggingTabId: string | null;
  /** Zoom offset added to the device base terminal font size (persisted). */
  termZoom: number;
  /** Auto-reconnect a session that drops unexpectedly (persisted; default on). */
  autoReconnect: boolean;
  /** SSH keepalive interval (seconds) pushed to the core; 0 = off (persisted). */
  keepaliveSecs: number;
  /** How many files to transfer in parallel over one SFTP connection (channel
   *  pool size). 1 = strictly sequential. Persisted; passed to sftpOpen. */
  sftpParallelism: number;
  /** profileId → epoch ms of the last connect (persisted; drives recent sort). */
  lastConnected: Record<string, number>;

  // active tunnels (core has no registry; we keep them here)
  tunnels: ActiveTunnel[];

  // active broadcast session ids (ViewBroadcast registers/unregisters its session
  // here so a vault switch can tear them down like terminals and tunnels)
  broadcasts: string[];

  // SFTP sessions + transfer queue — held here like terminals/tunnels so they
  // survive route changes and are torn down on vault switch/lock.
  sftpSessions: SftpSession[];
  transfers: Transfer[];

  // pending TOFU host-key mismatch (surfaced from a connect attempt)
  pendingMismatch: PendingMismatch | null;

  // cloud server — an instance may be linked to multiple servers at once.
  // `servers` is the full list; `serverStatus` mirrors the active one (kept for
  // existing call sites); `activeServerId` is the active selection.
  servers: ServerStatus[];
  activeServerId: string | null;
  serverStatus: ServerStatus | null;
  syncStatus: SyncStatus;

  // overlay slots
  overlay: Overlay;
  modal: ModalKind;
  palette: boolean;
  importing: boolean;
  groupsModal: boolean;
  shortcuts: boolean;
  confirm: ConfirmData | null;
  navGuard: (() => NavGuardSpec | null) | null;
  connecting: ConnectionProfile | null;

  // ── actions ──
  boot: () => Promise<void>;
  go: (r: Route) => void;
  goFiltered: (filter: string) => void;
  /** Register (or clear, with null) a guard the router consults before leaving the
   *  current view. Views set this on mount and clear it on unmount. */
  setNavGuard: (g: (() => NavGuardSpec | null) | null) => void;
  /** Pin a host-key mismatch for review: stashes it in `pendingMismatch` and
   *  navigates to the Known-hosts view. Shared by every review entry point. */
  reviewMismatch: (m: PendingMismatch) => void;
  setDevice: (d: Device) => void;
  setAutolockMin: (m: number | null) => void;
  setVault: (id: string) => Promise<void>;
  reloadVault: () => Promise<void>;
  reloadVaults: () => Promise<void>;
  lockInstance: () => Promise<void>;

  // cloud server
  reloadServerStatus: () => Promise<void>;
  setActiveServer: (serverId: string) => Promise<void>;
  maybeBindLegacyCloudVaults: () => Promise<void>;
  syncNow: () => Promise<void>;
  /** Full re-pull of ONE server (defaults to active): reset its pull cursor, then
   *  sync. Recovers vaults an incremental sync can't — ones rejected under a prior
   *  identity whose seqs the cursor already advanced past. Shares the `syncing` flag. */
  repull: (serverId?: string) => Promise<void>;
  /** Pull/push cloud vaults once a session is (re)established — fire-and-forget,
   *  coalesced. No-op without a live session. Lets cloud vaults appear on a fresh
   *  device after unlock/connect/join without a manual "Sync now". */
  cloudAutoSync: () => void;

  setOverlay: (o: Overlay) => void;
  openModal: (m: ModalKind) => void;
  closeModal: () => void;
  setPalette: (b: boolean) => void;
  setImporting: (b: boolean) => void;
  setGroupsModal: (b: boolean) => void;
  setShortcuts: (b: boolean) => void;
  setConfirm: (c: ConfirmData | null) => void;
  setHostFilter: (f: string) => void;

  // terminal zoom
  setTermZoom: (z: number) => void;
  bumpTermZoom: (delta: number) => void;
  resetTermZoom: () => void;
  setAutoReconnect: (b: boolean) => void;
  setKeepaliveSecs: (secs: number) => void;
  setSftpParallelism: (n: number) => void;

  // group / tag membership (bulk — driven by the host multi-select bar)
  addHostsToGroup: (groupId: string, profileIds: string[]) => Promise<void>;
  removeHostsFromGroup: (groupId: string, profileIds: string[]) => Promise<void>;
  createGroupWithHosts: (label: string, profileIds: string[]) => Promise<void>;
  addTagToHosts: (tag: string, profileIds: string[]) => Promise<void>;
  removeTagFromHosts: (tag: string, profileIds: string[]) => Promise<void>;
  /** Permanently delete the given hosts from the active vault. */
  deleteHosts: (profileIds: string[]) => Promise<void>;
  /** Stamp a host as just-connected (now), persisted, for the recent sort. */
  markConnected: (profileId: string) => void;

  // terminals — tabs (containers), each arranging one or more panes in a layout
  addTerminal: (t: TerminalTab) => void;
  closeTerminal: (id: string) => void; // closes the tab AND every pane's backend session
  setActiveTerm: (id: string | null) => void;
  moveTerminal: (id: string, toIndex: number) => void; // reorder (drag)
  /** Signal the tab strip to open its inline host picker (keyboard "new tab"). */
  requestNewTab: () => void;
  setDraggingTab: (id: string | null) => void;
  /** Merge a whole tab's pane(s) into a pane of another tab as a split in the
   *  given direction — the gesture behind "drag a tab onto the terminal to
   *  combine two sessions on one screen" (side-by-side or stacked). */
  mergeTabIntoPane: (
    sourceTabId: string,
    targetTabId: string,
    targetPaneId: string,
    dir: "left" | "right" | "top" | "bottom",
  ) => void;
  duplicateTerminal: (id: string) => void; // new tab, same host as the active pane
  renameTerminal: (id: string, title: string) => void;
  closeOtherTerminals: (id: string) => void;
  closeTerminalsToRight: (id: string) => void;
  /** All panes across all tabs (flattened) — for the hosts rail, nav badge, etc. */
  allPanes: () => TerminalPaneState[];

  // terminals — panes within a tab (split support)
  updatePane: (tabId: string, paneId: string, patch: Partial<TerminalPaneState>) => void;
  setActivePane: (tabId: string, paneId: string) => void;
  /** Split the pane: duplicate its host into a new pane beside/below it. */
  splitPane: (tabId: string, paneId: string, dir: "row" | "col") => void;
  /** Close one pane (its session); collapses the split, or closes the tab if last. */
  closePane: (tabId: string, paneId: string) => void;
  setSplitRatio: (tabId: string, splitId: string, ratio: number) => void;
  /** Re-open the session in the SAME pane (keeps xterm scrollback): close any
   *  lingering backend session, reset to connecting and bump `gen` so the Terminal
   *  view's open effect re-runs. `manual` (a user tap) also resets the auto-
   *  reconnect attempt budget so the next drop gets a fresh round of retries. */
  reconnectPane: (tabId: string, paneId: string, manual?: boolean) => void;

  // tunnels
  addTunnel: (t: ActiveTunnel) => void;
  removeTunnel: (id: string) => void;
  patchTunnel: (id: string, patch: Partial<ActiveTunnel>) => void;

  // broadcasts
  addBroadcast: (id: string) => void;
  removeBroadcast: (id: string) => void;

  // sftp
  addSftpSession: (s: SftpSession) => void;
  closeSftpSession: (id: string) => void;
  patchSftpSession: (id: string, patch: Partial<SftpSession>) => void;
  enqueueTransfer: (t: Transfer) => void;
  patchTransfer: (id: string, patch: Partial<Transfer>) => void;
  clearFinishedTransfers: () => void;

  setPendingMismatch: (m: PendingMismatch | null) => void;
  setFleetSelection: (ids: string[]) => void;
}

const lsDevice = (): Device => {
  try {
    return (localStorage.getItem("unissh.device") as Device) || "desktop";
  } catch {
    return "desktop";
  }
};

/** Idle minutes before auto-lock, parsed from the Settings value. "never" → null
 *  (disabled). Defaults to 15, matching the Settings UI default. */
const lsAutolockMin = (): number | null => {
  try {
    const v = localStorage.getItem("unissh.autolock") ?? "15";
    if (v === "never") return null;
    const n = parseInt(v, 10);
    return Number.isFinite(n) && n > 0 ? n : 15;
  } catch {
    return 15;
  }
};

const lsRead = (key: string): string | null => {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
};

/** Persisted terminal zoom offset, applied on top of the device base font size.
 *  Clamped so a hand-edited store can't produce an unusable size. */
const TERM_ZOOM_MIN = -4;
const TERM_ZOOM_MAX = 10;
const lsTermZoom = (): number => {
  try {
    const n = parseInt(localStorage.getItem("unissh.termZoom") ?? "0", 10);
    return Number.isFinite(n) ? Math.min(TERM_ZOOM_MAX, Math.max(TERM_ZOOM_MIN, n)) : 0;
  } catch {
    return 0;
  }
};

/** Slug for a generated group id (matches the host modal's scheme). Non-latin
 *  labels collapse to the fallback; uniqueness comes from the timestamp suffix. */
const slugify = (s: string): string =>
  s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "group";

/** Normalize a tag the way the host modal does: trimmed, no leading '#'. */
const cleanTag = (s: string): string => s.trim().replace(/^#/, "");

/** Auto-reconnect dropped sessions by default. Persisted; opt-out via Settings. */
const lsAutoReconnect = (): boolean => {
  try {
    return localStorage.getItem("unissh.autoReconnect") !== "0";
  } catch {
    return true;
  }
};

/** SSH keepalive interval (seconds) the core should use for new connections; 0 =
 *  off. Persisted locally; pushed to the core on boot and on Settings change. */
const lsKeepaliveSecs = (): number => {
  try {
    const n = parseInt(localStorage.getItem("unissh.keepalive") ?? "15", 10);
    return Number.isFinite(n) && n >= 0 ? n : 15;
  } catch {
    return 15;
  }
};

/** Bounds for the SFTP channel-pool size (parallel transfers). Kept modest: each
 *  channel costs a per-channel SSH window of memory, and most servers throttle a
 *  single connection's aggregate anyway. */
export const SFTP_PARALLELISM_MIN = 1;
export const SFTP_PARALLELISM_MAX = 8;
const SFTP_PARALLELISM_DEFAULT = 4;

/** How many files to transfer concurrently over one SFTP connection. Persisted
 *  locally (device-local UX/perf knob, not vault data); clamped to [MIN, MAX]. */
const lsSftpParallelism = (): number => {
  try {
    const n = parseInt(
      localStorage.getItem("unissh.sftpParallelism") ?? String(SFTP_PARALLELISM_DEFAULT),
      10,
    );
    if (!Number.isFinite(n)) return SFTP_PARALLELISM_DEFAULT;
    return Math.min(SFTP_PARALLELISM_MAX, Math.max(SFTP_PARALLELISM_MIN, n));
  } catch {
    return SFTP_PARALLELISM_DEFAULT;
  }
};

/** Per-host "last connected at" (epoch ms), persisted locally — drives the
 *  "recently connected" host sort. A device-local UX hint, not vault data, so it
 *  lives in localStorage rather than the synced core. */
const lsLastConnected = (): Record<string, number> => {
  try {
    const raw = localStorage.getItem("unissh.lastConnected");
    if (!raw) return {};
    const o = JSON.parse(raw);
    if (!o || typeof o !== "object") return {};
    const out: Record<string, number> = {};
    for (const [k, v] of Object.entries(o)) if (typeof v === "number") out[k] = v;
    return out;
  } catch {
    return {};
  }
};

/** Run `nav`, but if the current view registered a nav guard that objects, route
 *  the change through a confirm first. Shared by `go` and `goFiltered`. */
function guardedNav(get: () => AppStore, nav: () => void) {
  const guard = get().navGuard;
  const spec = guard?.() ?? null;
  if (!spec) {
    nav();
    return;
  }
  get().setConfirm({
    title: spec.title,
    body: spec.body,
    danger: true,
    icon: "alert",
    confirmLabel: spec.confirmLabel,
    onConfirm: () => {
      // The leaving view's unmount does the teardown; clear the guard so it can't
      // re-fire on the next hop and just navigate.
      get().setNavGuard(null);
      nav();
    },
  });
}

export const useApp = create<AppStore>((set, get) => ({
  booted: false,
  instanceExists: false,
  unlocked: false,
  requiresPassword: null,
  autolockMin: lsAutolockMin(),
  route: "hosts", // always open on the all-hosts view (hostFilter defaults to HOST_FILTER_ALL)
  routeSeq: 0,
  device: lsDevice(),
  vaultId: null,
  vaults: [],
  hosts: [],
  groups: [],
  items: [],
  knownHosts: [],
  loading: false,
  hostFilter: HOST_FILTER_ALL,
  fleetSelection: [],
  terminals: [],
  activeTermId: null,
  newTabNonce: 0,
  draggingTabId: null,
  termZoom: lsTermZoom(),
  autoReconnect: lsAutoReconnect(),
  keepaliveSecs: lsKeepaliveSecs(),
  sftpParallelism: lsSftpParallelism(),
  lastConnected: lsLastConnected(),
  tunnels: [],
  broadcasts: [],
  sftpSessions: [],
  transfers: [],
  pendingMismatch: null,
  servers: [],
  activeServerId: null,
  serverStatus: null,
  syncStatus: { syncing: false, lastReport: null, lastError: null, lastSyncAt: null },
  overlay: null,
  modal: null,
  palette: false,
  importing: false,
  groupsModal: false,
  shortcuts: false,
  confirm: null,
  navGuard: null,
  connecting: null,

  boot: async () => {
    void refineLangFromSystem(); // refine language from OS locale on first run
    // Push the persisted keepalive interval to the core before any connection.
    void api
      .setKeepaliveSecs(get().keepaliveSecs)
      .catch((e) => logWarn(`boot: keepalive push failed: ${apiErrorMessage(e)}`));
    try {
      let status = await api.instanceStatus();
      // Auto-unlock a passwordless (Secret-Key-only) instance straight from the
      // keychain — there's nothing for the user to type, so open the vault. Default
      // behaviour; the "start locked" setting is the explicit opt-out. A master-
      // password instance can't auto-unlock (the password is stored nowhere) → it
      // falls to the unlock screen. The keychain read is cached and shared with that
      // screen, so a miss here doesn't cause a second OS prompt.
      if (
        status.exists &&
        !status.partial &&
        !status.unlocked &&
        status.requiresPassword === false &&
        lsRead("unissh.startup") !== "locked"
      ) {
        try {
          // Unlock inside Rust — the Secret Key never crosses into the JS heap
          // (no webview XSS could read it). No key stored → throws → unlock screen.
          await api.keychainUnlock(null);
          status = { ...status, unlocked: true };
        } catch {
          /* no key in keychain or unlock failed → fall through to unlock screen */
        }
      }
      set({
        instanceExists: status.exists,
        unlocked: status.unlocked,
        requiresPassword: status.requiresPassword,
        booted: true,
        overlay: status.partial
          ? "repair"
          : !status.exists
            ? "onboarding"
            : !status.unlocked
              ? "unlock"
              : null,
      });
      if (status.unlocked) {
        await get().reloadVaults();
        await get().reloadServerStatus();
        // Bind legacy unbound cloud vaults to the single linked server. Also runs
        // after a manual unlock (see Entry.tsx), because on a normal locked cold
        // start this boot() branch doesn't run (the core is locked).
        await get().maybeBindLegacyCloudVaults();
        // Restore each linked server's session from its keychain refresh token —
        // access tokens are in-memory only, so they're gone after a restart.
        // Best-effort, per server (one failing doesn't block the others).
        const linked = get().servers.filter((s) => s.connected && !s.hasSession);
        if (linked.length) {
          await Promise.all(
            linked.map(async (s) => {
              if (!s.serverId) return;
              try {
                await api.serverRefreshSession(s.serverId);
              } catch {
                // Refresh token dead/absent (long offline, revoked, or the server
                // dropped the lineage). Fall back to a full keyset re-auth: the core
                // is unlocked here (boot runs after unlock), so it can sign a fresh
                // challenge — the account identity is the local keyset, not the token.
                try {
                  await api.serverLogin(s.serverId);
                } catch (e2) {
                  logDebug(`boot: session restore failed for a server: ${apiErrorMessage(e2)}`);
                }
              }
            }),
          );
          await get().reloadServerStatus();
        }
        // Pull cloud vaults for any live session — so they appear without a manual
        // "Sync now" (especially a fresh device right after onboarding).
        get().cloudAutoSync();
      }
    } catch (e) {
      // Any failure in this block (instance_status, or a follow-up reload) is a
      // transient backend error, not "no instance" — so route to a retry screen
      // rather than pushing a returning user into onboarding.
      logError(`boot failed: ${apiErrorMessage(e)}`);
      set({ booted: true, overlay: "retry" });
    }
  },

  go: (r) => {
    const nav = () => set((s) => ({ route: r, routeSeq: s.routeSeq + 1 }));
    guardedNav(get, nav);
  },
  goFiltered: (filter) => {
    const nav = () => set((s) => ({ hostFilter: filter, route: "hosts", routeSeq: s.routeSeq + 1 }));
    guardedNav(get, nav);
  },
  setNavGuard: (g) => set({ navGuard: g }),
  reviewMismatch: (m) => {
    set((s) => ({ pendingMismatch: m, route: "known", routeSeq: s.routeSeq + 1 }));
  },
  setDevice: (d) => {
    set({ device: d });
    try {
      localStorage.setItem("unissh.device", d);
    } catch {
      /* ignore */
    }
  },
  setAutolockMin: (m) => set({ autolockMin: m }),

  reloadVaults: async () => {
    let vaults = await api.listVaults();
    // A freshly created instance has no vaults yet — make one so the user can
    // immediately add hosts/keys/passwords/notes (all live inside a vault).
    if (vaults.length === 0) {
      try {
        await api.createVault("personal", i18n.t("vault.defaultName"));
        vaults = await api.listVaults();
      } catch (e) {
        logWarn(`reloadVaults: default vault creation failed: ${apiErrorMessage(e)}`);
      }
    }
    set({ vaults });
    const cur = get().vaultId;
    const next = cur && vaults.some((v) => v.vaultId === cur) ? cur : vaults[0]?.vaultId ?? null;
    if (next && next !== cur) {
      await get().setVault(next);
    } else if (next) {
      await get().reloadVault();
    }
  },

  setVault: async (id) => {
    // Re-selecting the active vault is a no-op (don't kill its live sessions).
    if (get().vaultId === id) return;

    // Tear down every connection bound to the OUTGOING vault, then switch. Closing
    // the backend session/tunnel/broadcast is the only thing that actually frees the
    // PTY — clearing the arrays alone would orphan them — so close first, then clear.
    const teardownAndSwitch = async () => {
      const { terminals, tunnels, broadcasts, sftpSessions } = get();
      cancelAllTransfers();
      await Promise.allSettled([
        ...terminals
          .flatMap((t) => t.panes)
          .filter((p) => p.sessionId)
          .map((p) => api.sessionClose(p.sessionId as string)),
        ...tunnels.map((t) => api.tunnelClose(t.id)),
        ...broadcasts.map((bid) => api.broadcastClose(bid)),
        ...sftpSessions.map((s) => api.sftpClose(s.id)),
      ]);
      set({
        vaultId: id,
        hostFilter: HOST_FILTER_ALL,
        fleetSelection: [], // profile ids belong to the outgoing vault
        terminals: [],
        activeTermId: null,
        tunnels: [],
        broadcasts: [],
        sftpSessions: [],
        transfers: [],
      });
      await get().reloadVault();
    };

    const s = get();
    const openCount =
      s.terminals.length + s.tunnels.length + s.broadcasts.length + s.sftpSessions.length;
    // Only prompt for a genuine user switch away from a still-valid vault. When the
    // current vault is gone (deleted) or unset (boot) the switch is forced/programmatic
    // (reloadVaults only calls setVault when next!==cur, i.e. cur was removed), so we
    // tear down + switch directly rather than deferring behind a dialog.
    const curExists = s.vaultId != null && s.vaults.some((v) => v.vaultId === s.vaultId);
    if (curExists && openCount > 0) {
      // Confirm before closing live connections — the cycle-vault shortcut makes an
      // accidental switch easy, and closing sessions is destructive.
      get().setConfirm({
        title: i18n.t("vault.switchCloseTitle"),
        body: i18n.t("vault.switchCloseBody", { count: openCount }),
        danger: true,
        confirmLabel: i18n.t("vault.switchCloseConfirm"),
        icon: "alert",
        onConfirm: () => {
          void teardownAndSwitch();
        },
      });
      return;
    }
    await teardownAndSwitch();
  },

  reloadVault: async () => {
    const vaultId = get().vaultId;
    if (!vaultId) return;
    set({ loading: true });
    try {
      const [hosts, groups, items, knownHosts] = await Promise.all([
        api.listConnections(vaultId),
        api.listGroups(vaultId),
        api.listItems(vaultId),
        api.listKnownHosts(),
      ]);
      set({ hosts, groups, items, knownHosts, loading: false });
    } catch (e) {
      logWarn(`reloadVault: failed to load vault data: ${apiErrorMessage(e)}`);
      set({ loading: false });
    }
  },

  lockInstance: async () => {
    try {
      await api.lock();
    } catch (e) {
      logWarn(`lockInstance: core lock failed (zeroing state anyway): ${apiErrorMessage(e)}`);
    }
    // Drop the cached Secret Key so a post-lock heap inspection can't recover it.
    clearSecretKey();
    cancelAllTransfers();
    set({
      unlocked: false,
      overlay: "unlock",
      hosts: [],
      groups: [],
      items: [],
      fleetSelection: [],
      terminals: [],
      activeTermId: null,
      tunnels: [],
      broadcasts: [],
      sftpSessions: [],
      transfers: [],
      servers: [],
      activeServerId: null,
      serverStatus: null,
      syncStatus: { syncing: false, lastReport: null, lastError: null, lastSyncAt: null },
    });
  },

  reloadServerStatus: async () => {
    // The cloud integration is additive: a local-only instance has no server
    // linked. Tolerate any failure (no server, locked, offline) → empty list.
    try {
      const list = await api.serverList();
      const active = list.servers.find((s) => s.serverId === list.active) ?? null;
      set({
        servers: list.servers,
        activeServerId: list.active,
        serverStatus: active,
      });
    } catch (e) {
      // Expected for a local-only / locked / offline instance — debug, not warn.
      logDebug(`reloadServerStatus: no server list (local/locked/offline): ${apiErrorMessage(e)}`);
      set({ servers: [], activeServerId: null, serverStatus: null });
    }
  },

  setActiveServer: async (serverId) => {
    try {
      await api.serverSetActive(serverId);
      await get().reloadServerStatus();
    } catch (e) {
      logWarn(`setActiveServer failed: ${apiErrorMessage(e)}`);
      await get().reloadServerStatus(); // re-sync truth even on failure
      throw e; // surface to the caller so the UI can show an error
    }
  },

  maybeBindLegacyCloudVaults: async () => {
    // One-time 1:1 migration: cloud vaults created before binding existed have no
    // syncTenant. They were all made under the single pre-multi-server server, so
    // bind them to THAT one — but ONLY when exactly one server is linked, so the
    // binding can't go to the wrong one. Idempotent; safe on every boot/unlock.
    // With 0 or 2+ servers it no-ops (the user binds such vaults manually).
    const servers = get().servers;
    if (
      servers.length === 1 &&
      get().vaults.some((v) => v.syncTarget === "cloud" && !v.syncTenant)
    ) {
      try {
        await api.serverBindUnboundCloudVaults(servers[0].serverId ?? undefined);
        await get().reloadVaults();
      } catch (e) {
        // best-effort — retries next boot/unlock while one server is linked
        logDebug(`maybeBindLegacyCloudVaults: bind skipped (will retry): ${apiErrorMessage(e)}`);
      }
    }
  },

  syncNow: async () => {
    if (get().syncStatus.syncing) return;
    set((s) => ({ syncStatus: { ...s.syncStatus, syncing: true, lastError: null } }));
    try {
      // A cloud vault only pushes to its bound server, so syncing just the active
      // server would skip vaults bound to other linked servers. Sync every linked
      // server that has a live session and aggregate the report.
      const targets = get().servers.filter((sv) => sv.hasSession && sv.serverId);
      const ids: (string | undefined)[] = targets.length
        ? targets.map((sv) => sv.serverId as string)
        : [undefined];
      const agg = { applied: 0, skippedStale: 0, conflicts: 0, rejected: 0, pushed: 0 };
      // Isolate per-server failures: one unreachable/erroring server must not abort
      // syncing the others (each cloud vault is bound 1:1 to its own server).
      const errors: string[] = [];
      for (const id of ids) {
        try {
          const r = await api.serverSyncNow(id);
          agg.applied += r.applied;
          agg.skippedStale += r.skippedStale;
          agg.conflicts += r.conflicts;
          agg.rejected += r.rejected;
          agg.pushed += r.pushed;
        } catch (e) {
          errors.push(apiErrorMessage(e));
          logWarn(`syncNow (server ${id ?? "active"}) failed: ${apiErrorMessage(e)}`);
        }
      }
      const lastError = errors.length ? errors.join("; ") : null;
      set({ syncStatus: { syncing: false, lastReport: agg, lastError, lastSyncAt: Date.now() } });
      // sync may have applied remote records into local vaults — refresh them.
      await get().reloadVaults();
    } catch (e) {
      logWarn(`syncNow failed: ${apiErrorMessage(e)}`);
      set((s) => ({
        syncStatus: { ...s.syncStatus, syncing: false, lastError: apiErrorMessage(e) },
      }));
      throw e;
    }
  },

  repull: async (serverId) => {
    if (get().syncStatus.syncing) return;
    set((s) => ({ syncStatus: { ...s.syncStatus, syncing: true, lastError: null } }));
    try {
      const r = await api.serverRepull(serverId);
      set({ syncStatus: { syncing: false, lastReport: r, lastError: null, lastSyncAt: Date.now() } });
      // a full re-pull can materialize vaults absent locally — refresh the list.
      await get().reloadVaults();
    } catch (e) {
      logWarn(`repull failed: ${apiErrorMessage(e)}`);
      set((s) => ({
        syncStatus: { ...s.syncStatus, syncing: false, lastError: apiErrorMessage(e) },
      }));
      throw e;
    }
  },

  cloudAutoSync: () => {
    // Only when a live session exists (a fresh device right after join, or any
    // unlock/connect with a restored session). runAutoSync coalesces, so calling
    // this alongside the mutation-driven auto-sync never stacks duplicate passes.
    if (get().servers.some((s) => s.hasSession)) runAutoSync();
  },

  setOverlay: (o) => set({ overlay: o }),
  openModal: (m) => set({ modal: m }),
  closeModal: () => set({ modal: null }),
  setPalette: (b) => set({ palette: b }),
  setImporting: (b) => set({ importing: b }),
  setGroupsModal: (b) => set({ groupsModal: b }),
  setShortcuts: (b) => set({ shortcuts: b }),
  setConfirm: (c) => set({ confirm: c }),
  setHostFilter: (f) => set({ hostFilter: f }),

  setTermZoom: (z) => {
    const v = Math.min(TERM_ZOOM_MAX, Math.max(TERM_ZOOM_MIN, Math.round(z)));
    set({ termZoom: v });
    try {
      localStorage.setItem("unissh.termZoom", String(v));
    } catch {
      /* ignore (private mode / quota) */
    }
  },
  bumpTermZoom: (delta) => get().setTermZoom(get().termZoom + delta),
  resetTermZoom: () => get().setTermZoom(0),
  setAutoReconnect: (b) => {
    set({ autoReconnect: b });
    try {
      localStorage.setItem("unissh.autoReconnect", b ? "1" : "0");
    } catch {
      /* ignore */
    }
  },
  setKeepaliveSecs: (secs) => {
    const v = Number.isFinite(secs) && secs >= 0 ? Math.round(secs) : 15;
    set({ keepaliveSecs: v });
    try {
      localStorage.setItem("unissh.keepalive", String(v));
    } catch {
      /* ignore */
    }
    // Push to the core; surface a failure (don't silently leave UI and core out of
    // sync) — the value still persists so the next boot retries the push.
    void api.setKeepaliveSecs(v).catch((e) => logWarn(`setKeepaliveSecs: ${apiErrorMessage(e)}`));
  },
  setSftpParallelism: (n) => {
    const v = Number.isFinite(n)
      ? Math.min(SFTP_PARALLELISM_MAX, Math.max(SFTP_PARALLELISM_MIN, Math.round(n)))
      : SFTP_PARALLELISM_DEFAULT;
    set({ sftpParallelism: v });
    try {
      localStorage.setItem("unissh.sftpParallelism", String(v));
    } catch {
      /* ignore (private mode / quota) */
    }
    // Applies to SFTP sessions opened AFTER this change (the pool size is fixed at
    // open time); existing tabs keep their current parallelism until reopened.
  },

  addHostsToGroup: async (groupId, profileIds) => {
    const vault = get().vaultId;
    const g = get().groups.find((x) => x.groupId === groupId);
    if (!vault || !g || profileIds.length === 0) return;
    const memberIds = Array.from(new Set([...g.memberIds, ...profileIds]));
    if (memberIds.length === g.memberIds.length) return; // nothing new
    await api.saveGroup(vault, { ...g, memberIds });
    await get().reloadVault();
  },
  removeHostsFromGroup: async (groupId, profileIds) => {
    const vault = get().vaultId;
    const g = get().groups.find((x) => x.groupId === groupId);
    if (!vault || !g || profileIds.length === 0) return;
    const drop = new Set(profileIds);
    const memberIds = g.memberIds.filter((m) => !drop.has(m));
    if (memberIds.length === g.memberIds.length) return; // nothing removed
    await api.saveGroup(vault, { ...g, memberIds });
    await get().reloadVault();
  },
  createGroupWithHosts: async (label, profileIds) => {
    const vault = get().vaultId;
    const name = label.trim();
    if (!vault || !name) return;
    const group: ServerGroup = {
      groupId: `${slugify(name)}-${Date.now()}`,
      label: name,
      memberIds: Array.from(new Set(profileIds)),
      parentId: null,
    };
    await api.saveGroup(vault, group);
    await get().reloadVault();
  },
  addTagToHosts: async (tag, profileIds) => {
    const vault = get().vaultId;
    const tg = cleanTag(tag);
    if (!vault || !tg || profileIds.length === 0) return;
    const target = new Set(profileIds);
    let changed = false;
    for (const h of get().hosts) {
      if (target.has(h.profileId) && !h.tags.includes(tg)) {
        await api.saveConnection(vault, { ...h, tags: [...h.tags, tg] });
        changed = true;
      }
    }
    if (changed) await get().reloadVault();
  },
  removeTagFromHosts: async (tag, profileIds) => {
    const vault = get().vaultId;
    const tg = cleanTag(tag);
    if (!vault || !tg || profileIds.length === 0) return;
    const target = new Set(profileIds);
    let changed = false;
    for (const h of get().hosts) {
      if (target.has(h.profileId) && h.tags.includes(tg)) {
        await api.saveConnection(vault, { ...h, tags: h.tags.filter((x) => x !== tg) });
        changed = true;
      }
    }
    if (changed) await get().reloadVault();
  },
  deleteHosts: async (profileIds) => {
    const vault = get().vaultId;
    if (!vault || profileIds.length === 0) return;
    // Group memberIds may keep a dangling id afterwards, but every count/filter in
    // the UI intersects against live hosts, so a deleted host simply disappears —
    // no separate group cleanup needed (matches single-host delete).
    for (const id of profileIds) {
      await api.deleteConnection(vault, id);
    }
    await get().reloadVault();
  },
  markConnected: (profileId) => {
    const next = { ...get().lastConnected, [profileId]: Date.now() };
    set({ lastConnected: next });
    try {
      localStorage.setItem("unissh.lastConnected", JSON.stringify(next));
    } catch {
      /* ignore (private mode / quota) */
    }
  },

  addTerminal: (t) =>
    set((s) => ({
      terminals: [...s.terminals, t],
      activeTermId: t.id,
      route: "terminal",
      routeSeq: s.routeSeq + 1,
    })),
  closeTerminal: (id) =>
    set((s) => {
      // Close every pane's backend session so a closed tab never orphans a
      // LiveSession in the core's map (idempotent if already closed).
      const tab = s.terminals.find((t) => t.id === id);
      if (tab) closeTabSessions(tab);
      const terminals = s.terminals.filter((t) => t.id !== id);
      const activeTermId =
        s.activeTermId === id ? terminals[terminals.length - 1]?.id ?? null : s.activeTermId;
      return { terminals, activeTermId };
    }),
  setActiveTerm: (id) => set({ activeTermId: id }),
  moveTerminal: (id, toIndex) =>
    set((s) => {
      const from = s.terminals.findIndex((t) => t.id === id);
      if (from < 0) return {};
      const terminals = s.terminals.slice();
      const [moved] = terminals.splice(from, 1);
      // toIndex was computed against the original array; removing an earlier item
      // shifts every later insertion point left by one.
      const idx = Math.max(0, Math.min(terminals.length, from < toIndex ? toIndex - 1 : toIndex));
      terminals.splice(idx, 0, moved);
      return { terminals };
    }),
  requestNewTab: () =>
    set((s) => ({ newTabNonce: s.newTabNonce + 1, route: "terminal", routeSeq: s.routeSeq + 1 })),
  setDraggingTab: (id) => set({ draggingTabId: id }),
  mergeTabIntoPane: (sourceTabId, targetTabId, targetPaneId, dir) =>
    set((s) => {
      if (sourceTabId === targetTabId) return {};
      const source = s.terminals.find((t) => t.id === sourceTabId);
      const target = s.terminals.find((t) => t.id === targetTabId);
      if (!source || !target) return {};
      const splitDir = dir === "left" || dir === "right" ? "row" : "col";
      const sourceFirst = dir === "left" || dir === "top";
      const targetLeaf: TermLayout = { kind: "pane", paneId: targetPaneId };
      // source.layout already references source.panes' ids; moving those panes into
      // target keeps every id unique, so the subtree stays valid.
      const splitNode: TermLayout = {
        kind: "split",
        id: mkSplitId(),
        dir: splitDir,
        ratio: 0.5,
        a: sourceFirst ? source.layout : targetLeaf,
        b: sourceFirst ? targetLeaf : source.layout,
      };
      const newTarget: TerminalTab = {
        ...target,
        panes: [...target.panes, ...source.panes],
        layout: replaceInLayout(target.layout, targetPaneId, splitNode),
        activePaneId: source.activePaneId, // focus the just-dropped session
      };
      const terminals = s.terminals
        .filter((t) => t.id !== sourceTabId)
        .map((t) => (t.id === targetTabId ? newTarget : t));
      const activeTermId = s.activeTermId === sourceTabId ? targetTabId : s.activeTermId;
      return { terminals, activeTermId, draggingTabId: null };
    }),
  duplicateTerminal: (id) =>
    set((s) => {
      const tab = s.terminals.find((t) => t.id === id);
      const src = tab?.panes.find((p) => p.id === tab.activePaneId) ?? tab?.panes[0];
      if (!tab || !src?.profile) return {};
      const pane = makePane(src.profile);
      const newTab: TerminalTab = {
        id: mkTabId(src.profile.profileId),
        title: tab.customTitle ? tab.title : src.profile.label,
        customTitle: tab.customTitle,
        panes: [pane],
        layout: { kind: "pane", paneId: pane.id },
        activePaneId: pane.id,
      };
      return {
        terminals: [...s.terminals, newTab],
        activeTermId: newTab.id,
        route: "terminal",
        routeSeq: s.routeSeq + 1,
      };
    }),
  renameTerminal: (id, title) =>
    set((s) => ({
      terminals: s.terminals.map((t) =>
        t.id === id ? { ...t, title: title.trim() || t.title, customTitle: true } : t,
      ),
    })),
  closeOtherTerminals: (id) =>
    set((s) => {
      for (const t of s.terminals) if (t.id !== id) closeTabSessions(t);
      const kept = s.terminals.filter((t) => t.id === id);
      return { terminals: kept, activeTermId: kept.length ? id : null };
    }),
  closeTerminalsToRight: (id) =>
    set((s) => {
      const idx = s.terminals.findIndex((t) => t.id === id);
      if (idx < 0) return {};
      for (const t of s.terminals.slice(idx + 1)) closeTabSessions(t);
      const terminals = s.terminals.slice(0, idx + 1);
      const activeTermId = terminals.some((t) => t.id === s.activeTermId) ? s.activeTermId : id;
      return { terminals, activeTermId };
    }),
  allPanes: () => get().terminals.flatMap((t) => t.panes),

  updatePane: (_tabId, paneId, patch) =>
    set((s) => ({
      // Address the pane by its globally-unique id, not tabId: a merge moves a pane
      // to a different tab than the caller (e.g. TerminalPane's effect) captured, so
      // a tabId-keyed update would silently miss it.
      terminals: s.terminals.map((t) =>
        t.panes.some((p) => p.id === paneId)
          ? { ...t, panes: t.panes.map((p) => (p.id === paneId ? { ...p, ...patch } : p)) }
          : t,
      ),
    })),
  setActivePane: (tabId, paneId) =>
    set((s) => ({
      terminals: s.terminals.map((t) => (t.id === tabId ? { ...t, activePaneId: paneId } : t)),
    })),
  splitPane: (tabId, paneId, dir) =>
    set((s) => ({
      terminals: s.terminals.map((tab) => {
        if (tab.id !== tabId) return tab;
        const src = tab.panes.find((p) => p.id === paneId);
        if (!src?.profile) return tab; // can only duplicate a real host pane
        const pane = makePane(src.profile);
        const splitNode: TermLayout = {
          kind: "split",
          id: mkSplitId(),
          dir,
          ratio: 0.5,
          a: { kind: "pane", paneId },
          b: { kind: "pane", paneId: pane.id },
        };
        return {
          ...tab,
          panes: [...tab.panes, pane],
          layout: replaceInLayout(tab.layout, paneId, splitNode),
          activePaneId: pane.id,
        };
      }),
    })),
  closePane: (tabId, paneId) =>
    set((s) => {
      const tab = s.terminals.find((t) => t.id === tabId);
      if (!tab) return {};
      const pane = tab.panes.find((p) => p.id === paneId);
      if (pane?.sessionId) void api.sessionClose(pane.sessionId).catch(() => {});
      const remaining = tab.panes.filter((p) => p.id !== paneId);
      if (remaining.length === 0) {
        // Last pane closed → drop the tab.
        const terminals = s.terminals.filter((t) => t.id !== tabId);
        const activeTermId =
          s.activeTermId === tabId ? terminals[terminals.length - 1]?.id ?? null : s.activeTermId;
        return { terminals, activeTermId };
      }
      const layout = removePaneFromLayout(tab.layout, paneId) as TermLayout; // non-null: remaining>0
      const activePaneId = tab.activePaneId === paneId ? firstPaneId(layout) : tab.activePaneId;
      return {
        terminals: s.terminals.map((t) =>
          t.id === tabId ? { ...t, panes: remaining, layout, activePaneId } : t,
        ),
      };
    }),
  setSplitRatio: (tabId, splitId, ratio) =>
    set((s) => ({
      terminals: s.terminals.map((t) =>
        t.id === tabId
          ? { ...t, layout: setRatioInLayout(t.layout, splitId, Math.min(0.9, Math.max(0.1, ratio))) }
          : t,
      ),
    })),
  reconnectPane: (_tabId, paneId, manual = false) =>
    set((s) => {
      // Look the pane up by its unique id (a merge can move it to another tab).
      const pane = s.terminals.flatMap((t) => t.panes).find((p) => p.id === paneId);
      // Evict any still-registered backend session so a reconnect never orphans a
      // LiveSession in the core's session map (idempotent if already closed).
      if (pane?.sessionId) void api.sessionClose(pane.sessionId).catch(() => {});
      return {
        terminals: s.terminals.map((t) =>
          t.panes.some((p) => p.id === paneId)
            ? {
                ...t,
                panes: t.panes.map((p) =>
                  p.id !== paneId
                    ? p
                    : {
                        ...p,
                        status: "connecting" as const,
                        sessionId: null,
                        error: undefined,
                        mismatch: undefined,
                        gen: p.gen + 1,
                        reconnects: manual ? 0 : p.reconnects,
                      },
                ),
              }
            : t,
        ),
      };
    }),

  addTunnel: (t) => set((s) => ({ tunnels: [...s.tunnels, t] })),
  removeTunnel: (id) => set((s) => ({ tunnels: s.tunnels.filter((t) => t.id !== id) })),
  patchTunnel: (id, patch) =>
    set((s) => ({ tunnels: s.tunnels.map((t) => (t.id === id ? { ...t, ...patch } : t)) })),

  addBroadcast: (id) =>
    set((s) => (s.broadcasts.includes(id) ? {} : { broadcasts: [...s.broadcasts, id] })),
  removeBroadcast: (id) => set((s) => ({ broadcasts: s.broadcasts.filter((b) => b !== id) })),

  // sftp sessions + transfer queue
  addSftpSession: (sess) => set((s) => ({ sftpSessions: [...s.sftpSessions, sess] })),
  closeSftpSession: (id) => {
    api.sftpClose(id).catch(() => {});
    set((s) => ({ sftpSessions: s.sftpSessions.filter((x) => x.id !== id) }));
  },
  patchSftpSession: (id, patch) =>
    set((s) => ({
      sftpSessions: s.sftpSessions.map((x) => (x.id === id ? { ...x, ...patch } : x)),
    })),
  enqueueTransfer: (t) => set((s) => ({ transfers: [...s.transfers, t] })),
  patchTransfer: (id, patch) =>
    set((s) => ({ transfers: s.transfers.map((t) => (t.id === id ? { ...t, ...patch } : t)) })),
  clearFinishedTransfers: () =>
    set((s) => ({
      transfers: s.transfers.filter(
        (t) => t.state !== "done" && t.state !== "cancelled" && t.state !== "error",
      ),
    })),

  setPendingMismatch: (m) => set({ pendingMismatch: m }),
  setFleetSelection: (ids) => set({ fleetSelection: ids }),
}));

// ── auto-sync ──────────────────────────────────────────────────
// Push cloud-vault changes to their server immediately after any vault mutation,
// so the user never has to press "Sync now". Coalesces concurrent triggers: if a
// sync is already running, exactly one more pass runs afterwards so the latest
// change always reaches the server.
let autoSyncRunning = false;
let autoSyncPending = false;

function runAutoSync(): void {
  if (autoSyncRunning) {
    autoSyncPending = true;
    return;
  }
  const st = useApp.getState();
  if (st.syncStatus.syncing) {
    // A (manual) sync is in flight — retry shortly so this change still pushes.
    autoSyncPending = true;
    setTimeout(() => {
      if (autoSyncPending) {
        autoSyncPending = false;
        runAutoSync();
      }
    }, 1000);
    return;
  }
  autoSyncRunning = true;
  void st
    .syncNow()
    .catch(() => {
      /* syncNow already records lastError; auto-sync is best-effort */
    })
    .finally(() => {
      autoSyncRunning = false;
      if (autoSyncPending) {
        autoSyncPending = false;
        runAutoSync();
      }
    });
}

onVaultMutated((vaultId) => {
  const st = useApp.getState();
  // Need a linked server with a live session, else there's nothing to push to.
  if (!st.servers.some((s) => s.hasSession)) return;
  // Skip purely-local vaults; a vault that's already gone (deleted) still syncs
  // so the deletion propagates.
  const v = st.vaults.find((x) => x.vaultId === vaultId);
  if (v && v.syncTarget !== "cloud") return;
  runAutoSync();
});
