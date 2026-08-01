// useCtx() — the action bundle passed implicitly to views, mirroring the
// prototype's `ctx` DI object so ported views read almost 1:1.

import { useTheme } from "@/theme/ThemeProvider";
import { apiErrorMessage, type ConnectionProfile } from "@/bridge/types";
import { openSession } from "@/views/sftp/session";
import { useApp, makeLocalPane, makePane, mkTabId, type ModalKind, type Route } from "./app";
import { resolveLocalPaneSpec } from "./localShell";
import { toast } from "./toast";

/** Open a new terminal tab (single pane) for a saved host profile. The Terminal
 *  view performs the actual session_open (it needs the xterm write callback). */
export function connectProfile(profile: ConnectionProfile) {
  const s = useApp.getState();
  s.markConnected(profile.profileId);
  const pane = makePane(profile);
  s.addTerminal({
    id: mkTabId(profile.profileId),
    title: profile.label,
    panes: [pane],
    layout: { kind: "pane", paneId: pane.id },
    activePaneId: pane.id,
  });
}

export function connectById(profileId: string) {
  const s = useApp.getState();
  const profile = s.hosts.find((h) => h.profileId === profileId);
  if (profile) connectProfile(profile);
}

/** Open a new tab running a shell on this machine.
 *
 *  The spec is resolved first, so the pane is born with a concrete program and a
 *  real title — a pane holding "" as its shell would have nothing to put in the
 *  tab, nothing to restart, and nothing to name in an error. A failure to even
 *  resolve it (the core is unreachable) surfaces as a toast rather than a dead
 *  pane, because at that point there is no pane to put the message in. */
export async function openLocalTerminal(): Promise<void> {
  const spec = await resolveLocalPaneSpec().catch((e) => {
    toast(apiErrorMessage(e), "err");
    return null;
  });
  if (!spec) return;
  const pane = makeLocalPane(spec);
  useApp.getState().addTerminal({
    id: mkTabId("local"),
    title: spec.label,
    panes: [pane],
    layout: { kind: "pane", paneId: pane.id },
    activePaneId: pane.id,
  });
}

/** Split a pane, putting a local shell in the new half. */
export async function splitLocalTerminal(
  tabId: string,
  paneId: string,
  dir: "row" | "col",
): Promise<void> {
  const spec = await resolveLocalPaneSpec().catch((e) => {
    toast(apiErrorMessage(e), "err");
    return null;
  });
  if (!spec) return;
  useApp.getState().splitPane(tabId, paneId, dir, { kind: "local", spec });
}

/** Quick SFTP: open an SFTP session to a host and jump to the SFTP view with the
 *  new session focused. openSession surfaces its own failure toast / mismatch. */
export async function connectSftp(profile: ConnectionProfile) {
  const s = useApp.getState();
  s.markConnected(profile.profileId);
  const id = await openSession(profile);
  if (!id) return;
  s.setPendingSftpFocus(id);
  s.go("sftp");
}

export interface Ctx {
  go: (r: Route) => void;
  goFiltered: (f: string) => void;
  vault: string | null;
  hostFilter: string;
  setHostFilter: (f: string) => void;
  openModal: (m: ModalKind) => void;
  onNewHost: () => void;
  openImport: () => void;
  openGroups: () => void;
  openPalette: () => void;
  onLock: () => void;
  onShowKit: () => void;
  confirm: (c: import("./app").ConfirmData) => void;
  toast: typeof toast;
  connect: (profile: ConnectionProfile) => void;
  connectSftp: (profile: ConnectionProfile) => Promise<void>;
  connectById: (id: string) => void;
  /** Open a new tab with a shell on this machine (desktop only). */
  openLocal: () => void;
  reloadVault: () => Promise<void>;
  termThemeId: string;
}

export function useCtx(): Ctx {
  const s = useApp();
  const theme = useTheme();
  return {
    go: s.go,
    goFiltered: s.goFiltered,
    vault: s.vaultId,
    hostFilter: s.hostFilter,
    setHostFilter: s.setHostFilter,
    openModal: s.openModal,
    onNewHost: () => s.openModal({ kind: "host" }),
    openImport: () => s.setImporting(true),
    openGroups: () => s.setGroupsModal(true),
    openPalette: () => s.setPalette(true),
    onLock: s.lockInstance,
    onShowKit: () => s.setOverlay("kit"),
    confirm: (c) => s.setConfirm(c),
    toast,
    connect: connectProfile,
    connectSftp,
    connectById,
    openLocal: () => void openLocalTerminal(),
    reloadVault: s.reloadVault,
    termThemeId: theme.termThemeId,
  };
}
