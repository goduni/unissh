// SFTP — drag-first, multi-location file manager. Desktop: two pane slots, each
// with its own location tabs; drag between them (or onto a tab) to transfer.
// Narrow/mobile: a single slot whose tab strip holds every location. This file
// is the orchestrator — it owns slot locations, transfer/dialog/menu state, and
// the conflict resolver; the heavy lifting lives in useSlot / the runner.

import { useEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { Icon, type IconName } from "@/components/primitives";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import { useApp } from "@/store/app";
import { toast } from "@/store/toast";
import { writeText as clipboardWrite } from "@tauri-apps/plugin-clipboard-manager";
import { apiErrorMessage } from "@/bridge/types";
import type { ConnectionProfile } from "@/bridge/types";
import { sourceFor, type FileSource } from "@/bridge/sources";
import type { Entry, LocationRef, Transfer } from "@/store/sftp-types";
import { useSlot, type SlotCtl } from "./useSlot";
import { PaneSlot } from "./PaneSlot";
import type { TabInfo } from "./TabStrip";
import { TransferQueue } from "./TransferQueue";
import { ContextMenu, type MenuItem } from "@/components/ContextMenu";
import { NewFolderDialog, RenameDialog, ConfirmDeleteDialog, ConflictDialog, ChmodDialog } from "./dialogs";
import { TextEditor } from "./TextEditor";
import { openSession } from "./session";
import { dragCtx } from "./drag";
import {
  makeTransferSemaphore,
  serializeResolver,
  startTransfer,
  teardownGeneration,
  type ConflictResolution,
  type ConflictResolver,
} from "@/sftp/transfer-runner";
import { dedupeName } from "@/sftp/paths";

const refOf = (id: string): LocationRef => (id === "local" ? { kind: "local" } : { kind: "remote", sessionId: id });
const keyOf = (l: LocationRef): string => (l.kind === "remote" ? l.sessionId : l.kind);
const sendIcon = (l: LocationRef): IconName => (l.kind === "remote" ? "upload" : "download");

// Module-level (survives view remounts, so ids never collide with the persistent
// queue) and crypto-free — crypto.randomUUID throws in a non-secure-context
// webview, which would make every transfer silently fail before it's enqueued.
let transferSeq = 0;
const nextTransferId = (): string => `tf${++transferSeq}`;

type Dialog =
  | { kind: "newfolder"; slot: SlotCtl }
  | { kind: "rename"; slot: SlotCtl; entry: Entry }
  | { kind: "delete"; slot: SlotCtl; entries: Entry[] }
  | { kind: "chmod"; slot: SlotCtl; entry: Entry }
  | null;

interface ConflictReq {
  name: string;
  targetSize: number;
  sourceSize: number;
  resumable: boolean;
  sameSize: boolean;
  batchable: boolean;
  resolve: (r: ConflictResolution) => void;
}

export function ViewSftp() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const sessions = useApp((s) => s.sftpSessions);
  const hosts = useApp((s) => s.hosts);
  const enqueueTransfer = useApp((s) => s.enqueueTransfer);
  const closeSftpSession = useApp((s) => s.closeSftpSession);
  const pendingSftpFocus = useApp((s) => s.pendingSftpFocus);
  const setPendingSftpFocus = useApp((s) => s.setPendingSftpFocus);

  const [leftLoc, setLeftLoc] = useState<LocationRef>({ kind: "local" });
  // Right pane starts empty (a "pick a host" prompt) so the remote half of a
  // transfer is self-evident on first run, instead of a duplicate Local view.
  const [rightLoc, setRightLoc] = useState<LocationRef>({ kind: "none" });
  const left = useSlot(leftLoc, sessions);
  const right = useSlot(rightLoc, sessions);

  const [menu, setMenu] = useState<{ items: MenuItem[]; title?: string; x: number; y: number } | null>(null);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [conflict, setConflict] = useState<ConflictReq | null>(null);
  const [editor, setEditor] = useState<{ source: FileSource; path: string; name: string; size: number } | null>(null);
  const [dropTab, setDropTab] = useState<{ slot: "left" | "right"; id: string } | null>(null);

  // "Quick SFTP" from the Hosts view opens a session then routes here; show it in
  // the RIGHT pane (Local stays on the left — the natural transfer layout) and
  // clear the one-shot flag.
  useEffect(() => {
    if (!pendingSftpFocus) return;
    setRightLoc({ kind: "remote", sessionId: pendingSftpFocus });
    setPendingSftpFocus(null);
  }, [pendingSftpFocus, setPendingSftpFocus]);

  // Live refs so a refresh fired after a long transfer targets the slot's
  // CURRENT location/cwd, not the render that started the transfer.
  const leftRef = useRef(left);
  leftRef.current = left;
  const rightRef = useRef(right);
  rightRef.current = right;

  // Last-known local cwd, so "send to Local" / a Local tab-drop has a real
  // destination even when neither pane is currently showing Local.
  const localCwd = useRef("/");
  useEffect(() => {
    (async () => {
      try {
        const path = await import("@tauri-apps/api/path");
        localCwd.current = isMobile ? await path.documentDir() : await path.homeDir();
      } catch {
        /* keep previous */
      }
    })();
  }, [isMobile]);
  useEffect(() => {
    if (left.location.kind === "local" && left.cwd) localCwd.current = left.cwd;
    if (right.location.kind === "local" && right.cwd) localCwd.current = right.cwd;
  }, [left.location, left.cwd, right.location, right.cwd]);

  // Settle an open conflict prompt if the view unmounts mid-batch (e.g. a route
  // shortcut), so the awaiting transfer loop doesn't strand forever.
  const mounted = useRef(true);
  const pendingResolve = useRef<((r: ConflictResolution) => void) | null>(null);
  useEffect(
    () => () => {
      mounted.current = false;
      pendingResolve.current?.({ choice: "skip", applyAll: true });
      pendingResolve.current = null;
    },
    [],
  );

  // If a slot points at a session that was closed elsewhere, fall back to local.
  useEffect(() => {
    if (leftLoc.kind === "remote" && !sessions.some((s) => s.id === leftLoc.sessionId)) setLeftLoc({ kind: "local" });
    if (rightLoc.kind === "remote" && !sessions.some((s) => s.id === rightLoc.sessionId)) setRightLoc({ kind: "local" });
  }, [sessions, leftLoc, rightLoc]);

  const tabs: TabInfo[] = [
    { id: "local", label: t("sftp.paneLocal"), kind: "local" },
    ...sessions.map((s) => ({ id: s.id, label: s.label, kind: "remote" as const })),
  ];

  // ── transfers ────────────────────────────────────────────────
  /** Where a location is currently rooted: the cwd of a slot showing it, else
   *  the remote session's home (or "/" for an off-screen local). */
  const cwdOf = (loc: LocationRef): string => {
    if (keyOf(left.location) === keyOf(loc)) return left.cwd;
    if (keyOf(right.location) === keyOf(loc)) return right.cwd;
    if (loc.kind === "remote") return sessions.find((s) => s.id === loc.sessionId)?.home ?? "/";
    return localCwd.current;
  };

  const refreshShowing = (loc: LocationRef) => {
    const l = leftRef.current;
    const r = rightRef.current;
    if (keyOf(l.location) === keyOf(loc)) l.refresh();
    if (keyOf(r.location) === keyOf(loc)) r.refresh();
  };

  async function runTransfers(
    entries: Entry[],
    fromLoc: LocationRef,
    fromCwd: string,
    toLoc: LocationRef,
    toCwd: string,
  ) {
    let fromSource, toSource;
    try {
      fromSource = sourceFor(fromLoc, sessions);
      toSource = sourceFor(toLoc, sessions);
    } catch {
      return;
    }
    let batch: ConflictResolution | null = null;
    // A dir can yield many interior conflicts, so apply-to-all is offered for any
    // multi-item or directory transfer (not just >1 top-level entries).
    const batchable = entries.length > 1 || entries.some((e) => e.isDir);
    const resolver: ConflictResolver = (info) =>
      new Promise<ConflictResolution>((resolve) => {
        if (batch) return resolve(batch);
        if (!mounted.current) return resolve({ choice: "skip", applyAll: true });
        const settle = (r: ConflictResolution) => {
          pendingResolve.current = null;
          if (r.applyAll) batch = r;
          setConflict(null);
          resolve(r);
        };
        pendingResolve.current = settle;
        setConflict({ ...info, batchable, resolve: settle });
      });

    // Build + enqueue every item up front (state "queued") so the queue's
    // cancel-all can mark items the batch loop hasn't reached yet.
    const built: Transfer[] = [];
    for (const entry of entries) {
      const fromPath = await fromSource.join(fromCwd, entry.name);
      built.push({
        id: nextTransferId(),
        label: entry.name,
        from: fromLoc,
        to: toLoc,
        toDir: toCwd,
        fromPath,
        kind: entry.isDir ? "dir" : "file",
        bytesDone: 0,
        bytesTotal: entry.isDir ? 0 : entry.size,
        filesDone: 0,
        filesTotal: entry.isDir ? 0 : 1,
        speedBps: 0,
        etaSec: 0,
        state: "queued",
        offset: 0,
      });
    }
    built.forEach(enqueueTransfer);

    // Run the batch's transfers concurrently, all sharing ONE semaphore sized to
    // the parallel-transfers setting: many loose files move at once, and a folder's
    // legs draw from the same budget, so global concurrency never exceeds the pool.
    // Each transfer is independent — pausing/cancelling one no longer stops the
    // rest (use pause-all / cancel-all for that). The conflict resolver is
    // serialized so parallel legs can't race the single conflict dialog.
    const gen = teardownGeneration();
    const sem = makeTransferSemaphore();
    const serialized = serializeResolver(resolver);
    const { patchTransfer } = useApp.getState();
    await Promise.all(
      built.map(async (tr) => {
        // A vault switch / lock bumps the teardown generation: don't start work.
        if (teardownGeneration() !== gen) {
          patchTransfer(tr.id, { state: "cancelled" });
          return;
        }
        // Skip items cancelled while still queued.
        if (useApp.getState().transfers.find((x) => x.id === tr.id)?.state === "cancelled") return;
        await startTransfer(tr, fromSource, toSource, serialized, sem);
      }),
    );
    refreshShowing(toLoc);
  }

  const sendTo = (entries: Entry[], fromSlot: SlotCtl, toLoc: LocationRef) => {
    if (!entries.length || toLoc.kind === "none") return;
    runTransfers(entries, fromSlot.location, fromSlot.cwd, toLoc, cwdOf(toLoc));
  };

  const handleDrop = async (toLoc: LocationRef, toCwd: string) => {
    const pl = dragCtx.get();
    dragCtx.clear();
    setDropTab(null);
    if (!pl) return;
    let entries = pl.entries;
    if (keyOf(pl.loc) === keyOf(toLoc)) {
      if (pl.cwd === toCwd) return; // same dir, no-op
      // Drop into self / own descendant: filter out any dragged folder whose
      // path is the target dir or an ancestor of it.
      let src;
      try {
        src = sourceFor(pl.loc, sessions);
      } catch {
        return;
      }
      const kept: Entry[] = [];
      for (const e of entries) {
        if (e.isDir) {
          const abs = await src.join(pl.cwd, e.name);
          if (toCwd === abs || toCwd.startsWith(`${abs}/`) || toCwd.startsWith(`${abs}\\`)) continue;
        }
        kept.push(e);
      }
      entries = kept;
    }
    if (entries.length) runTransfers(entries, pl.loc, pl.cwd, toLoc, toCwd);
  };

  const handleTabDrop = (slotKey: "left" | "right", tabId: string) => {
    const loc = refOf(tabId);
    // Prefer the destination pane's own cwd (a location can be shown in both
    // panes at different dirs), else fall back to where it's rooted.
    const dest = slotKey === "left" ? leftRef.current : rightRef.current;
    const toCwd = keyOf(dest.location) === keyOf(loc) ? dest.cwd : cwdOf(loc);
    void handleDrop(loc, toCwd);
  };

  // ── file operations ──────────────────────────────────────────
  async function doMkdir(slot: SlotCtl, name: string) {
    if (!slot.source) return;
    try {
      await slot.source.mkdir(await slot.source.join(slot.cwd, name));
      slot.refresh();
      toast(t("sftp.toast.folderCreated"), "ok");
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  }
  async function doRename(slot: SlotCtl, oldName: string, newName: string) {
    if (!slot.source) return;
    try {
      await slot.source.rename(await slot.source.join(slot.cwd, oldName), await slot.source.join(slot.cwd, newName));
      slot.refresh();
      toast(t("sftp.toast.renamed"), "ok");
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  }
  async function doChmod(slot: SlotCtl, entry: Entry, mode: number) {
    if (!slot.source?.chmod) return;
    try {
      await slot.source.chmod(await slot.source.join(slot.cwd, entry.name), mode);
      slot.refresh();
      toast(t("sftp.toast.chmodDone"), "ok");
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  }
  async function doDelete(slot: SlotCtl, entries: Entry[]) {
    if (!slot.source) return;
    for (const e of entries) {
      try {
        const path = await slot.source.join(slot.cwd, e.name);
        if (e.isDir) await slot.source.rmdir(path);
        else await slot.source.remove(path);
      } catch (err) {
        toast(apiErrorMessage(err), "err");
      }
    }
    slot.refresh();
    toast(t("sftp.toast.deleted"), "ok");
  }
  async function copyPath(slot: SlotCtl, entry: Entry) {
    if (!slot.source) return;
    try {
      const path = await slot.source.join(slot.cwd, entry.name);
      await clipboardWrite(path);
      toast(t("sftp.toast.copied"), "ok");
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  }
  async function openEditor(slot: SlotCtl, entry: Entry) {
    if (!slot.source) return;
    const path = await slot.source.join(slot.cwd, entry.name);
    setEditor({ source: slot.source, path, name: entry.name, size: entry.size });
  }
  /** Pull files into the local pane via the OS document picker — the inbound
   *  path on iOS (where the FS isn't browsable), and a convenience on desktop. */
  async function importFromFiles(slot: SlotCtl) {
    if (slot.location.kind !== "local" || !slot.source) return;
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const picked = await open({ multiple: true });
      if (!picked) return;
      const files = Array.isArray(picked) ? picked : [picked];
      const { copyFile } = await import("@tauri-apps/plugin-fs");
      const { basename, join } = await import("@tauri-apps/api/path");
      // Don't clobber existing files: de-dupe the target name (keep both).
      const taken = new Set((await slot.source.list(slot.cwd)).map((e) => e.name));
      for (const src of files) {
        const name = dedupeName(await basename(src), taken);
        taken.add(name);
        await copyFile(src, await join(slot.cwd, name));
      }
      slot.refresh();
      toast(t("sftp.toast.imported"), "ok");
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  }

  // ── context menus ────────────────────────────────────────────
  const rowMenu = (entry: Entry, slot: SlotCtl, x: number, y: number) => {
    const entries = slot.selection.has(entry.name) && slot.selection.size > 1 ? slot.selectedEntries() : [entry];
    const items: MenuItem[] = [];
    if (entry.isDir) items.push({ icon: "folderOpen", label: t("common.open"), onClick: () => slot.navigate(entry.name) });
    else items.push({ icon: "note", label: t("common.open"), onClick: () => void openEditor(slot, entry) });
    for (const tab of tabs) {
      if (tab.id === keyOf(slot.location)) continue;
      items.push({
        icon: tab.kind === "remote" ? "upload" : "download",
        label: t("sftp.menu.sendTo", { name: tab.label }),
        onClick: () => sendTo(entries, slot, refOf(tab.id)),
      });
    }
    items.push({ icon: "pencil", label: t("sftp.menu.rename"), onClick: () => setDialog({ kind: "rename", slot, entry }) });
    if (slot.source?.chmod)
      items.push({ icon: "shield", label: t("sftp.menu.permissions"), onClick: () => setDialog({ kind: "chmod", slot, entry }) });
    items.push({ icon: "copy", label: t("sftp.menu.copyPath"), onClick: () => copyPath(slot, entry) });
    items.push({ icon: "trash", label: t("sftp.menu.delete"), danger: true, onClick: () => setDialog({ kind: "delete", slot, entries }) });
    setMenu({ items, title: entries.length > 1 ? t("sftp.selected", { count: entries.length }) : entry.name, x, y });
  };

  const emptyMenu = (slot: SlotCtl, x: number, y: number) => {
    setMenu({
      items: [
        { icon: "folders", label: t("sftp.menu.newFolder"), onClick: () => setDialog({ kind: "newfolder", slot }) },
        { icon: "refresh", label: t("common.refresh"), onClick: () => slot.refresh() },
      ],
      x,
      y,
    });
  };

  // ── tab actions ──────────────────────────────────────────────
  const pickHost = async (set: (l: LocationRef) => void, h: ConnectionProfile) => {
    const id = await openSession(h);
    if (id) set({ kind: "remote", sessionId: id });
  };

  const paneProps = (slot: SlotCtl, slotKey: "left" | "right", counterpart: SlotCtl, setLoc: (l: LocationRef) => void) => ({
    slot,
    slotKey,
    tabs,
    activeTabId: keyOf(slot.location),
    hosts,
    actionIcon: isMobile || counterpart.location.kind === "none" ? undefined : sendIcon(counterpart.location),
    onActivateTab: (id: string) => setLoc(refOf(id)),
    onCloseTab: (id: string) => closeSftpSession(id),
    onPickHost: (h: ConnectionProfile) => pickHost(setLoc, h),
    onSend: (entries: Entry[]) => sendTo(entries, slot, counterpart.location),
    onRowContext: (entry: Entry, x: number, y: number) => rowMenu(entry, slot, x, y),
    onEmptyContext: (x: number, y: number) => emptyMenu(slot, x, y),
    onNewFolder: () => setDialog({ kind: "newfolder", slot }),
    onImport: slot.location.kind === "local" ? () => void importFromFiles(slot) : undefined,
    onDropHere: (cwd: string) => void handleDrop(slot.location, cwd),
    onTabDrop: (id: string) => handleTabDrop(slotKey, id),
    dropTargetTab: dropTab?.slot === slotKey ? dropTab.id : null,
    onTabDragEnter: (id: string) => setDropTab({ slot: slotKey, id }),
    onTabDragLeave: (id: string) => setDropTab((d) => (d?.slot === slotKey && d.id === id ? null : d)),
  });

  const dialogExisting = (slot: SlotCtl) => slot.entries.map((e) => e.name);

  return (
    <div
      className="uh-view"
      style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, background: p.bg0, overflow: "hidden" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: isMobile ? "14px 14px 10px" : "16px 22px 12px" }}>
        <Icon name="folders" size={20} color={p.accent} />
        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, letterSpacing: -0.5 }}>SFTP</h1>
      </div>

      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: isMobile ? "column" : "row",
          alignItems: "stretch",
          gap: 12,
          padding: isMobile ? "0 14px 12px" : "0 22px 12px",
          minHeight: 0,
          ...(isMobile ? { overflow: "auto" } : {}),
        }}
      >
        <PaneSlot {...paneProps(left, "left", right, setLeftLoc)} />
        {!isMobile && <PaneSlot {...paneProps(right, "right", left, setRightLoc)} />}
      </div>

      <TransferQueue />

      {menu && <ContextMenu items={menu.items} title={menu.title} x={menu.x} y={menu.y} onClose={() => setMenu(null)} />}

      {dialog?.kind === "newfolder" && (
        <NewFolderDialog
          existing={dialogExisting(dialog.slot)}
          onSubmit={(name) => doMkdir(dialog.slot, name)}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "rename" && (
        <RenameDialog
          name={dialog.entry.name}
          existing={dialogExisting(dialog.slot)}
          onSubmit={(newName) => doRename(dialog.slot, dialog.entry.name, newName)}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "delete" && (
        <ConfirmDeleteDialog
          names={dialog.entries.map((e) => e.name)}
          hasDir={dialog.entries.some((e) => e.isDir)}
          onConfirm={() => doDelete(dialog.slot, dialog.entries)}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "chmod" && (
        <ChmodDialog
          name={dialog.entry.name}
          mode={dialog.entry.mode ?? 0o644}
          onSubmit={(mode) => doChmod(dialog.slot, dialog.entry, mode)}
          onClose={() => setDialog(null)}
        />
      )}
      {conflict && (
        <ConflictDialog
          name={conflict.name}
          targetSize={conflict.targetSize}
          sourceSize={conflict.sourceSize}
          resumable={conflict.resumable}
          batchable={conflict.batchable}
          onResolve={conflict.resolve}
        />
      )}
      {editor && (
        <TextEditor
          source={editor.source}
          path={editor.path}
          name={editor.name}
          size={editor.size}
          onClose={() => setEditor(null)}
        />
      )}
    </div>
  );
}
