import { isWithin, mapWorkers } from "@/sftp/transfer-engine";
// SFTP — drag-first, multi-location file manager. Desktop: two pane slots, each
// with its own location tabs; drag between them (or onto a tab) to transfer.
// Narrow/mobile: a single slot whose tab strip holds every location. This file
// is the orchestrator — it owns slot locations, transfer/dialog/menu state, and
// the conflict resolver; the heavy lifting lives in useSlot / the runner.

import { useEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { rem, TEXT } from "@/theme/tokens";
import { Icon, type IconName } from "@/components/primitives";
import { useIsMobile, useNarrow } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import { useApp } from "@/store/app";
import { toast } from "@/store/toast";
import { writeText as clipboardWrite } from "@tauri-apps/plugin-clipboard-manager";
import { open } from "@tauri-apps/plugin-dialog";
import { basename, documentDir, homeDir, join } from "@tauri-apps/api/path";
import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import type { ConnectionProfile } from "@/bridge/types";
import { sourceFor, type FileSource } from "@/bridge/sources";
import type { Entry, LocationRef, Transfer } from "@/store/sftp-types";
import { useSlot, type SlotCtl } from "./useSlot";
import { PaneSlot } from "./PaneSlot";
import type { TabInfo } from "./TabStrip";
import { TransferQueue } from "./TransferQueue";
import { ExternalEdits } from "./ExternalEdits";
import { startExternalEdit } from "@/sftp/external-edit";
import { ContextMenu, type MenuItem } from "@/components/ContextMenu";
import { NewEntryDialog, RenameDialog, ConfirmDeleteDialog, ConfirmMoveDialog, ConflictDialog, ChmodDialog } from "./dialogs";
import { TextEditor } from "./TextEditor";
import { openSession } from "./session";
import { dragCtx } from "./drag";
import { shortcutAria, shortcutLabel, useShortcuts } from "@/store/shortcuts";
import { sftpShortcutId, type SftpAction } from "@/support/keybindings";
import { actionTargets, type ListCursor } from "./shortcuts";
import { isWalkableDir } from "@/sftp/paths";
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
  | { kind: "newfile"; slot: SlotCtl }
  | { kind: "rename"; slot: SlotCtl; entry: Entry }
  | { kind: "delete"; slot: SlotCtl; entries: Entry[] }
  | { kind: "move"; entries: Entry[]; fromLoc: LocationRef; fromCwd: string; toLoc: LocationRef; toCwd: string }
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
  const isMobile = useNarrow(); // width-aware: also true on a narrow desktop window
  // Platform, not width: a narrowed desktop window still has an external editor,
  // and a phone still doesn't. Gates the external-editor entries.
  const isTouch = useIsMobile();
  // Collapse to a single pane based on the CONTENT width, not the raw window width:
  // two panes need ~536px, and a wide sidebar can starve the content area below that
  // while the window is still > the useNarrow breakpoint (otherwise the 2nd pane
  // overflows with no scroll). Measure the pane area itself.
  const paneAreaRef = useRef<HTMLDivElement>(null);
  const [paneAreaW, setPaneAreaW] = useState(0);
  useEffect(() => {
    const el = paneAreaRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((ents) => {
      for (const e of ents) setPaneAreaW(e.contentRect.width);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const oneCol = isMobile || (paneAreaW > 0 && paneAreaW < 560);
  const sessions = useApp((s) => s.sftpSessions);
  const externalEditDefault = useApp((s) => s.sftpExternalEditDefault);
  const hosts = useApp((s) => s.hosts);
  const enqueueTransfers = useApp((s) => s.enqueueTransfers);
  const closeSftpSession = useApp((s) => s.closeSftpSession);
  const pendingSftpFocus = useApp((s) => s.pendingSftpFocus);
  const setPendingSftpFocus = useApp((s) => s.setPendingSftpFocus);
  const shortcutOverrides = useShortcuts((s) => s.overrides);
  /** Menu-item hint for an action: its first bound key, and all of them for AT. */
  const keysOf = (action: SftpAction) => ({
    keys: shortcutLabel(sftpShortcutId(action), shortcutOverrides),
    ariaKeys: shortcutAria(sftpShortcutId(action), shortcutOverrides),
  });

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
        localCwd.current = isMobile ? await documentDir() : await homeDir();
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

  // The right pane keeps its listing while a narrow layout hides it, but a walk
  // nobody can see or stop should not keep querying a server.
  useEffect(() => {
    if (oneCol) rightRef.current.cancelFolderSizes();
  }, [oneCol]);

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
    move = false,
  ) {
    const gen = teardownGeneration();
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
    const resolver: ConflictResolver = (info, signal) =>
      new Promise<ConflictResolution>((resolve) => {
        if (batch) return resolve(batch);
        if (!mounted.current) return resolve({ choice: "skip", applyAll: true });
        let settled = false;
        const aborted = () => settle({ choice: "skip", applyAll: false });
        const settle = (r: ConflictResolution) => {
          if (settled) return;
          settled = true;
          signal?.removeEventListener("abort", aborted);
          pendingResolve.current = null;
          if (r.applyAll) batch = r;
          setConflict(null);
          resolve(r);
        };
        if (signal?.aborted) return resolve({ choice: "skip", applyAll: false });
        signal?.addEventListener("abort", aborted, { once: true });
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
        kind: entry.isDir && !entry.isSymlink ? "dir" : "file",
        isSymlink: entry.isSymlink,
        ...(move ? { move } : {}),
        bytesDone: 0,
        bytesTotal: entry.isDir || entry.isSymlink ? 0 : entry.size,
        filesDone: 0,
        filesTotal: entry.isDir && !entry.isSymlink ? 0 : 1,
        speedBps: 0,
        etaSec: 0,
        state: "queued",
        offset: 0,
      });
    }
    if (teardownGeneration() !== gen) return;
    enqueueTransfers(built);

    // Run the batch's transfers concurrently, all sharing ONE semaphore sized to
    // the parallel-transfers setting: many loose files move at once, and a folder's
    // legs draw from the same budget, so global concurrency never exceeds the pool.
    // Each transfer is independent — pausing/cancelling one no longer stops the
    // rest (use pause-all / cancel-all for that). The conflict resolver is
    // serialized so parallel legs can't race the single conflict dialog.
    const sem = makeTransferSemaphore();
    const serialized = serializeResolver(resolver);
    const { patchTransfer } = useApp.getState();
    await mapWorkers(built, sem.capacity, async (tr) => {
        // A vault switch / lock bumps the teardown generation: don't start work.
        if (teardownGeneration() !== gen) {
          patchTransfer(tr.id, { state: "cancelled" });
          return;
        }
        // Skip items cancelled while still queued.
        if (useApp.getState().transfers.find((x) => x.id === tr.id)?.state === "cancelled") return;
        await startTransfer(tr, fromSource, toSource, serialized, sem);
      });
    refreshShowing(toLoc);
    // A move empties the source too. One location is refreshed once: the call
    // above already reached every pane showing it.
    if (move && keyOf(fromLoc) !== keyOf(toLoc)) refreshShowing(fromLoc);
  }

  /** Where a transfer out of `fromSlot` lands in `toLoc`: the other pane's
   *  folder when it shows that location, else wherever the location is rooted. */
  const landingCwd = (fromSlot: SlotCtl, toLoc: LocationRef): string => {
    const other = fromSlot === left ? right : left;
    return keyOf(other.location) === keyOf(toLoc) ? other.cwd : cwdOf(toLoc);
  };

  const sendTo = (entries: Entry[], fromSlot: SlotCtl, toLoc: LocationRef, toCwd?: string) => {
    toCwd ??= landingCwd(fromSlot, toLoc);
    if (!entries.length || toLoc.kind === "none") return;
    runTransfers(entries, fromSlot.location, fromSlot.cwd, toLoc, toCwd);
  };

  /** A move removes its sources, so nothing starts before the user has seen
   *  what goes where. What can never work is refused here, before the question. */
  const askMove = async (entries: Entry[], fromSlot: SlotCtl, toLoc: LocationRef, toCwd?: string) => {
    toCwd ??= landingCwd(fromSlot, toLoc);
    if (!entries.length || toLoc.kind === "none" || !fromSlot.source) return;
    if (keyOf(fromSlot.location) === keyOf(toLoc)) {
      if (fromSlot.cwd === toCwd) {
        toast(t("sftp.toast.moveSameFolder"), "err");
        return;
      }
      try {
        for (const e of entries) {
          if (!e.isDir || e.isSymlink || !isWithin(await fromSlot.source.join(fromSlot.cwd, e.name), toCwd, true)) continue;
          toast(t("sftp.toast.moveIntoItself", { name: e.name }), "err");
          return;
        }
      } catch (e) {
        toast(apiErrorMessage(e), "err");
        return;
      }
    }
    setDialog({ kind: "move", entries, fromLoc: fromSlot.location, fromCwd: fromSlot.cwd, toLoc, toCwd });
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
          if (isWithin(abs, toCwd, true)) continue;
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
  async function doTouch(slot: SlotCtl, name: string) {
    if (!slot.source) return;
    try {
      const path = await slot.source.join(slot.cwd, name);
      // The dialog only knows the names it listed, so check the real thing. This
      // is for the message, not for safety: createNew is exclusive, so losing
      // the race costs an error rather than someone else's file.
      if (await slot.source.stat(path)) {
        // The listing is stale by definition here — show the entry we refused to
        // clobber, or the message reads as the pane contradicting itself.
        slot.refresh();
        toast(t("sftp.toast.nameTaken", { name }), "err");
        return;
      }
      await slot.source.createNew(path);
      slot.refresh();
      toast(t("sftp.toast.fileCreated"), "ok");
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
  /** Copy a remote file down, hand it to whatever the OS opens it with, and
   *  watch it. Remote only — a local file is already open-able by every other
   *  tool on the machine, and offering it here would mean handing the OS
   *  launcher an unrestricted path scope for no real gain. */
  async function openExternally(slot: SlotCtl, entry: Entry) {
    if (!slot.source || slot.location.kind !== "remote") return;
    try {
      const path = await slot.source.join(slot.cwd, entry.name);
      const sessionId = slot.location.sessionId;
      const profileId = sessions.find((s) => s.id === sessionId)?.profileId ?? "";
      const started = await startExternalEdit(slot.source, sessionId, profileId, path, entry.name);
      // Silence would read as a dead menu item — unless the user is the one who
      // stopped it, in which case a message about their own action is noise.
      if (!started.ok && started.reason === "already") toast(t("sftp.extEdit.alreadyOpening"), "info");
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  }
  /** Pull files into the local pane via the OS document picker — the inbound
   *  path on iOS (where the FS isn't browsable), and a convenience on desktop. */
  async function importFromFiles(slot: SlotCtl) {
    if (slot.location.kind !== "local" || !slot.source) return;
    try {
      const picked = await open({ multiple: true });
      if (!picked) return;
      const files = Array.isArray(picked) ? picked : [picked];
      // Don't clobber existing files: de-dupe the target name (keep both).
      const taken = new Set((await slot.source.list(slot.cwd)).map((e) => e.name));
      for (const src of files) {
        const name = dedupeName(await basename(src), taken);
        taken.add(name);
        await api.localCopyFile(src, await join(slot.cwd, name));
      }
      slot.refresh();
      toast(t("sftp.toast.imported"), "ok");
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  }

  // ── operations shared by the context menus and the keyboard ──
  const askRename = (slot: SlotCtl, entry: Entry) => setDialog({ kind: "rename", slot, entry });
  const askDelete = (slot: SlotCtl, entries: Entry[]) => setDialog({ kind: "delete", slot, entries });
  const askNewFolder = (slot: SlotCtl) => setDialog({ kind: "newfolder", slot });
  /** The pane a "copy to the other pane" lands in — none when only one pane is
   *  shown, or the other one has no location yet. */
  const paneAcross = (slot: SlotCtl): SlotCtl | null => {
    const other = slot === left ? right : left;
    return oneCol || other.location.kind === "none" ? null : other;
  };
  /** One menu item per destination, for copying ("Send to …") or moving. */
  const sendItems = (entries: Entry[], slot: SlotCtl, move = false): MenuItem[] => {
    const here = keyOf(slot.location);
    const across = paneAcross(slot);
    const acrossId = across && keyOf(across.location);
    return tabs
      // Its own tab is a destination only as the other pane's folder — where the
      // copy key sends, so the item is there to carry the hint.
      .filter((tab) => tab.id !== here || tab.id === acrossId)
      .map((tab) => ({
        icon: move ? "arrows" : tab.kind === "remote" ? "upload" : "download",
        label: t(move ? "sftp.menu.moveTo" : "sftp.menu.sendTo", { name: tab.label }),
        ...(tab.id === acrossId ? keysOf(move ? "move" : "copy") : {}),
        onClick: () => (move ? void askMove(entries, slot, refOf(tab.id)) : sendTo(entries, slot, refOf(tab.id))),
      }));
  };
  /** The folder-size action over `entries`: a total for each folder among them
   *  — or, while any of those is still being counted, stopping the count. Null
   *  when there is no folder to total. */
  const folderSizeAction = (entries: Entry[], slot: SlotCtl): { cancels: boolean; run: () => void } | null => {
    const names = entries.filter(isWalkableDir).map((e) => e.name);
    if (!names.length) return null;
    const cancels = names.some((name) => slot.folderSizes.get(name)?.state === "pending");
    return { cancels, run: () => (cancels ? slot.cancelFolderSizes(names) : slot.startFolderSizes(names)) };
  };
  const titleOf = (entries: Entry[]) =>
    entries.length > 1 ? t("sftp.selected", { count: entries.length }) : entries[0]?.name;

  // ── context menus ────────────────────────────────────────────
  const rowMenu = (entry: Entry, slot: SlotCtl, x: number, y: number) => {
    const entries = actionTargets(entry, slot);
    const items: MenuItem[] = [];
    const inApp = { icon: "note" as const, ...keysOf("edit"), onClick: () => void openEditor(slot, entry) };
    if (entry.isDir) items.push({ icon: "folderOpen", label: t("common.open"), onClick: () => slot.navigate(entry.name) });
    else if (isTouch || slot.location.kind !== "remote") {
      // A phone has no external editor to hand a copy to (and the receiving app
      // generally can't write it back); a local file needs no copy at all.
      items.push({ ...inApp, label: t("common.open") });
    } else if (externalEditDefault) {
      items.push({ icon: "link", label: t("common.open"), onClick: () => void openExternally(slot, entry) });
      items.push({ ...inApp, label: t("sftp.menu.openInApp") });
    } else {
      items.push({ ...inApp, label: t("common.open") });
      items.push({ icon: "link", label: t("sftp.menu.openExternal"), onClick: () => void openExternally(slot, entry) });
    }
    items.push(...sendItems(entries, slot), ...sendItems(entries, slot, true));
    items.push({ icon: "pencil", label: t("sftp.menu.rename"), ...keysOf("rename"), onClick: () => askRename(slot, entry) });
    if (slot.source?.chmod)
      items.push({ icon: "shield", label: t("sftp.menu.permissions"), onClick: () => setDialog({ kind: "chmod", slot, entry }) });
    items.push({ icon: "copy", label: t("sftp.menu.copyPath"), onClick: () => copyPath(slot, entry) });
    const sizing = folderSizeAction(entries, slot);
    if (sizing)
      items.push({
        icon: sizing.cancels ? "x" : "database",
        label: t(sizing.cancels ? "sftp.menu.folderSizeCancel" : "sftp.menu.folderSize"),
        ...keysOf("folderSize"),
        onClick: sizing.run,
      });
    items.push({ icon: "trash", label: t("sftp.menu.delete"), danger: true, ...keysOf("delete"), onClick: () => askDelete(slot, entries) });
    setMenu({ items, title: titleOf(entries), x, y });
  };

  const emptyMenu = (slot: SlotCtl, x: number, y: number) => {
    setMenu({
      items: [
        { icon: "folders", label: t("sftp.menu.newFolder"), ...keysOf("newFolder"), onClick: () => askNewFolder(slot) },
        { icon: "file", label: t("sftp.menu.newFile"), onClick: () => setDialog({ kind: "newfile", slot }) },
        { icon: "refresh", label: t("common.refresh"), onClick: () => slot.refresh() },
      ],
      x,
      y,
    });
  };

  // ── keyboard (the `sftp` shortcut scope) ─────────────────────
  // One handler per registry action; the registry decides which key means which.
  /** F5 and F6 differ only in what happens to the source. */
  const transferShortcut = (move: boolean) => (slot: SlotCtl, cursor: ListCursor): void => {
    const entries = actionTargets(cursor.entry, slot);
    if (!entries.length) return;
    const across = paneAcross(slot);
    if (across) return move ? void askMove(entries, slot, across.location, across.cwd) : sendTo(entries, slot, across.location, across.cwd);
    // No pane across to aim at: offer the same destinations the row menu does.
    const items = sendItems(entries, slot, move);
    if (items.length) setMenu({ items, title: titleOf(entries), x: cursor.x, y: cursor.y });
  };
  const shortcutHandlers: Record<SftpAction, (slot: SlotCtl, cursor: ListCursor) => void | false> = {
    switchPane: () => {
      const lists = paneAreaRef.current?.querySelectorAll<HTMLElement>("[data-sftp-list]") ?? [];
      const other = Array.from(lists).find((el) => el !== document.activeElement);
      // Nothing to switch to: let Tab move on as it would anywhere else.
      if (!other) return false;
      other.focus();
    },
    parentDir: (slot) => {
      // At the filesystem root there is no parent: leave the listing and the selection alone.
      void slot.source?.parent(slot.cwd).then((dir) => {
        if (dir !== slot.cwd) slot.up();
      });
    },
    selectAll: (slot) => slot.selectAll(),
    pageUp: (_slot, cursor) => cursor.page(-1),
    pageDown: (_slot, cursor) => cursor.page(1),
    rename: (slot, { entry }) => {
      if (entry) askRename(slot, entry);
    },
    edit: (slot, { entry }) => {
      if (entry && !entry.isDir) void openEditor(slot, entry);
    },
    copy: transferShortcut(false),
    move: transferShortcut(true),
    newFolder: (slot) => askNewFolder(slot),
    delete: (slot, { entry }) => {
      const entries = actionTargets(entry, slot);
      if (entries.length) askDelete(slot, entries);
    },
    folderSize: (slot, { entry }) => folderSizeAction(actionTargets(entry, slot), slot)?.run(),
  };
  // A menu, a dialog or the editor owns the keyboard while it is up.
  const keyboardBusy = !!(menu || dialog || conflict || editor);

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
    onSend: (entries: Entry[]) => sendTo(entries, slot, counterpart.location, counterpart.cwd),
    onRowContext: (entry: Entry, x: number, y: number) => rowMenu(entry, slot, x, y),
    onEmptyContext: (x: number, y: number) => emptyMenu(slot, x, y),
    onShortcut: keyboardBusy ? undefined : (action: SftpAction, cursor: ListCursor) => shortcutHandlers[action](slot, cursor),
    onNewFolder: () => askNewFolder(slot),
    onNewFile: () => setDialog({ kind: "newfile", slot }),
    onImport: slot.location.kind === "local" ? () => void importFromFiles(slot) : undefined,
    onDropHere: () => void handleDrop(slot.location, slot.cwd),
    onTabDrop: (id: string) => handleTabDrop(slotKey, id),
    dropTargetTab: dropTab?.slot === slotKey ? dropTab.id : null,
    onTabDragEnter: (id: string) => setDropTab({ slot: slotKey, id }),
    onTabDragLeave: (id: string) => setDropTab((d) => (d?.slot === slotKey && d.id === id ? null : d)),
  });

  /** A location and folder as the move question names them: "prod: /var/www". */
  const placeOf = (loc: LocationRef, cwd: string) => `${tabs.find((tab) => tab.id === keyOf(loc))?.label ?? ""}: ${cwd}`;
  const dialogExisting = (slot: SlotCtl) => slot.entries.map((e) => e.name);

  // A live external edit outlives the pane that started it, so the watcher can't
  // hold a source: it asks for one each time it needs to push. This copy feeds
  // the strip below; the watcher's own resolver is registered in App, which no
  // overlay can unmount.
  const remoteSourceFor = (sessionId: string, profileId: string) => {
    // Prefer the original session; fall back to any live one for the same host,
    // because a reconnect mints a new id and the edit would otherwise be
    // stranded with a file it can no longer send anywhere.
    const session =
      sessions.find((s) => s.id === sessionId) ?? sessions.find((s) => s.profileId === profileId && profileId);
    if (!session) return null;
    try {
      return { source: sourceFor({ kind: "remote", sessionId: session.id }, sessions), sessionId: session.id };
    } catch {
      return null;
    }
  };
  return (
    <div
      className="uh-view"
      style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, background: p.bg0, overflow: "hidden" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: rem(10), padding: isMobile ? `${rem(14)} ${rem(14)} ${rem(10)}` : `${rem(16)} ${rem(22)} ${rem(12)}` }}>
        <Icon name="folders" size={20} color={p.accentText} />
        <h1 style={{ margin: 0, fontSize: TEXT.h2, fontWeight: 800, letterSpacing: rem(-0.5) }}>SFTP</h1>
      </div>

      <div
        ref={paneAreaRef}
        style={{
          flex: 1,
          display: "flex",
          flexDirection: oneCol ? "column" : "row",
          alignItems: "stretch",
          gap: rem(12),
          padding: isMobile ? `0 ${rem(14)} ${rem(12)}` : `0 ${rem(22)} ${rem(12)}`,
          minHeight: 0,
          ...(oneCol ? { overflow: "auto" } : {}),
        }}
      >
        <PaneSlot {...paneProps(left, "left", right, setLeftLoc)} />
        {!oneCol && <PaneSlot {...paneProps(right, "right", left, setRightLoc)} />}
      </div>

      <ExternalEdits sourceFor={remoteSourceFor} />

      <TransferQueue />

      {menu && <ContextMenu items={menu.items} title={menu.title} x={menu.x} y={menu.y} onClose={() => setMenu(null)} />}

      {dialog?.kind === "newfolder" && (
        <NewEntryDialog
          kind="folder"
          existing={dialogExisting(dialog.slot)}
          onSubmit={(name) => doMkdir(dialog.slot, name)}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "newfile" && (
        <NewEntryDialog
          kind="file"
          existing={dialogExisting(dialog.slot)}
          onSubmit={(name) => void doTouch(dialog.slot, name)}
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
      {dialog?.kind === "move" && (
        <ConfirmMoveDialog
          names={dialog.entries.map((e) => e.name)}
          from={placeOf(dialog.fromLoc, dialog.fromCwd)}
          to={placeOf(dialog.toLoc, dialog.toCwd)}
          onConfirm={() => void runTransfers(dialog.entries, dialog.fromLoc, dialog.fromCwd, dialog.toLoc, dialog.toCwd, true)}
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
