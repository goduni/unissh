// Versioned device-local layouts. Persist references, never connection profiles,
// terminal output, passwords, backend session ids or shell-supplied titles.
import type { ConnectionProfile, LocalPaneSpec } from "@/bridge/types";
import type { TerminalTab, TerminalPaneState, TermLayout } from "./app";

interface WorkspaceDocument {
  version: 2;
  activeVaultId: string | null;
  vaults: Record<string, unknown>;
  named: Record<string, unknown>;
}

export interface NamedWorkspace {
  id: string;
  name: string;
  layout: unknown;
}

export type WorkspaceEditError = "unavailable" | "invalidName" | "duplicateName" | "emptyLayout" | "missing";

export function workspaceCounts(layout: unknown) {
  const tabs = object(layout) && Array.isArray(layout.tabs) ? layout.tabs : [];
  return { tabs: tabs.length, panes: tabs.reduce((n, tab: unknown) =>
    n + (object(tab) && Array.isArray(tab.panes) ? tab.panes.length : 0), 0) };
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function snapshotWorkspace(tabs: TerminalTab[], activeId: string | null) {
  return {
    activeId,
    tabs: tabs.map((tab) => ({
      id: tab.id,
      ...(tab.customTitle ? { title: tab.title } : {}),
      activePaneId: tab.activePaneId,
      layout: tab.layout,
      panes: tab.panes.map((pane) => ({
        id: pane.id,
        target: pane.target.kind === "ssh"
          ? { kind: "ssh", profileId: pane.target.profile.profileId }
          : {
              kind: "local",
              spec: {
                shell: pane.target.spec.shell,
                args: [...pane.target.spec.args],
                cwd: pane.target.spec.cwd,
                label: pane.target.spec.label,
              },
            },
      })),
    })),
  };
}

function localSpec(value: unknown): LocalPaneSpec | null {
  if (!object(value) || typeof value.shell !== "string" || !value.shell ||
      typeof value.label !== "string" || !Array.isArray(value.args) ||
      !value.args.every((arg) => typeof arg === "string") ||
      (value.cwd !== undefined && typeof value.cwd !== "string")) return null;
  return { shell: value.shell, label: value.label, args: [...value.args], cwd: value.cwd };
}

/** Missing/deleted hosts are pruned and their splits collapse. Fresh runtime ids
 * prevent late callbacks from an old session from attaching to a restored pane. */
export function restoreWorkspace(value: unknown, hosts: ConnectionProfile[], allowLocal: boolean) {
  const terminals: TerminalTab[] = [];
  let activeTermId: string | null = null;
  let removed = 0;
  if (!object(value) || !Array.isArray(value.tabs)) return { terminals, activeTermId, removed };
  const profiles = new Map(hosts.map((host) => [host.profileId, host]));
  for (const saved of value.tabs) {
    if (!object(saved) || !Array.isArray(saved.panes)) continue;
    const panes = new Map<string, TerminalPaneState>();
    for (const item of saved.panes) {
      if (!object(item) || typeof item.id !== "string" || panes.has(item.id) || !object(item.target)) continue;
      let target: TerminalPaneState["target"] | null = null;
      if (item.target.kind === "ssh" && typeof item.target.profileId === "string") {
        const profile = profiles.get(item.target.profileId);
        if (profile) target = { kind: "ssh", profile };
      } else if (item.target.kind === "local" && allowLocal) {
        const spec = localSpec(item.target.spec);
        if (spec) target = { kind: "local", spec };
      }
      if (!target) { removed++; continue; }
      panes.set(item.id, {
        id: crypto.randomUUID(), target,
        title: target.kind === "ssh" ? target.profile.label : target.spec.label,
        status: "restored", sessionId: null, gen: 0, reconnects: 0, lastOnlineAt: 0,
      });
    }
    const used = new Set<string>();
    const layoutOf = (node: unknown): TermLayout | null => {
      if (!object(node)) return null;
      if (node.kind === "pane" && typeof node.paneId === "string") {
        const pane = panes.get(node.paneId);
        if (!pane || used.has(node.paneId)) return null;
        used.add(node.paneId);
        return { kind: "pane", paneId: pane.id };
      }
      if (node.kind !== "split" || (node.dir !== "row" && node.dir !== "col") ||
          typeof node.ratio !== "number" || !Number.isFinite(node.ratio)) return null;
      const a = layoutOf(node.a), b = layoutOf(node.b);
      if (!a) return b;
      if (!b) return a;
      return { kind: "split", id: crypto.randomUUID(), dir: node.dir,
        ratio: Math.min(0.9, Math.max(0.1, node.ratio)), a, b };
    };
    let layout: TermLayout | null;
    try { layout = layoutOf(saved.layout); } catch { continue; }
    if (!layout) continue;
    const restored = [...used].map((id) => panes.get(id)!);
    const selected = typeof saved.activePaneId === "string" && used.has(saved.activePaneId)
      ? panes.get(saved.activePaneId)! : restored[0];
    const id = crypto.randomUUID();
    terminals.push({
      id, panes: restored, layout, activePaneId: selected.id,
      title: typeof saved.title === "string" ? saved.title : selected.title,
      customTitle: typeof saved.title === "string",
    });
    if (saved.id === value.activeId) activeTermId = id;
  }
  activeTermId ??= terminals[0]?.id ?? null;
  return { terminals, activeTermId, removed };
}

type Parsed = { version: 1 | 2; activeVaultId: string | null; vaults: Record<string, unknown>; named?: unknown };

/** `future` is a newer format this build must not overwrite; `null` is unreadable. */
function parseDocument(text: string | null): Parsed | "future" | null {
  if (text === null) return { version: 1, activeVaultId: null, vaults: {} };
  let doc: unknown;
  try { doc = JSON.parse(text); } catch { return null; }
  if (object(doc) && typeof doc.version === "number" && doc.version > 2) return "future";
  if (!object(doc) || (doc.version !== 1 && doc.version !== 2) || !object(doc.vaults) ||
      (doc.version === 2 && !object(doc.named)) ||
      (doc.activeVaultId !== null && typeof doc.activeVaultId !== "string")) return null;
  return doc as Parsed;
}

/** Coalesce changes while a write is in flight and serialize writes so an older
 * layout cannot win. A failed read or a newer format leaves persistence disabled
 * for this unlock; an unreadable layout is replaced on the next save. */
export class WorkspaceStorage {
  private document: WorkspaceDocument | null = null;
  private loading: Promise<void> | null = null;
  private writing: Promise<void> | null = null;
  private pending: string | null = null;
  private last: string | null = null;
  private epoch = 0;
  private nativeEpoch = 0;
  private warned = false;

  constructor(private io: {
    load: () => Promise<[number, string | null]>;
    save: (epoch: number, document: string) => Promise<void>;
    error: (kind: "failed" | "reset") => void;
  }) {}

  private reportError(): void {
    if (!this.warned) { this.warned = true; this.io.error("failed"); }
  }

  async load(): Promise<void> {
    if (this.document) return;
    if (this.loading) return this.loading;
    const epoch = this.epoch;
    this.loading = (async () => {
      let loaded: [number, string | null];
      try { loaded = await this.io.load(); } catch {
        if (epoch === this.epoch) this.reportError();
        return;
      }
      if (epoch !== this.epoch) return;
      const [nativeEpoch, text] = loaded;
      const doc = parseDocument(text);
      if (doc === "future") { this.reportError(); return; }
      this.nativeEpoch = nativeEpoch;
      if (!doc) {
        // A corrupt layout must not disable persistence on every unlock.
        this.document = { version: 2, activeVaultId: null, vaults: {}, named: {} };
        this.io.error("reset");
        return;
      }
      // Version 1 held only the automatic per-vault layout. Upgrade in memory;
      // the next successful write persists version 2 without losing those tabs.
      this.document = { version: 2, activeVaultId: doc.activeVaultId, vaults: doc.vaults,
        named: doc.version === 2 && object(doc.named) ? doc.named : {} };
      this.last = text;
    })();
    return this.loading;
  }

  get activeVaultId() { return this.document?.activeVaultId ?? null; }
  get available() { return this.document !== null; }
  forVault(id: string): unknown { return this.document?.vaults[id]; }

  namedForVault(vaultId: string): NamedWorkspace[] {
    const value = this.document?.named[vaultId];
    if (!Array.isArray(value)) return [];
    const ids = new Set<string>();
    return value.filter((entry): entry is NamedWorkspace => {
      if (!object(entry) || typeof entry.id !== "string" || ids.has(entry.id) ||
          typeof entry.name !== "string" || !object(entry.layout) || !Array.isArray(entry.layout.tabs)) return false;
      ids.add(entry.id);
      return true;
    });
  }

  private checkName(vaultId: string, name: string, id?: string): WorkspaceEditError | null {
    if (!this.document) return "unavailable";
    if (!name || name.length > 80) return "invalidName";
    if (this.namedForVault(vaultId).some((entry) => entry.id !== id && entry.name.toLowerCase() === name.toLowerCase()))
      return "duplicateName";
    return null;
  }

  saveNamed(vaultId: string, name: string, tabs: TerminalTab[], activeId: string | null, id?: string): WorkspaceEditError | null {
    name = name.trim();
    const error = this.checkName(vaultId, name, id);
    if (error) return error;
    if (!tabs.length) return "emptyLayout";
    const entries = this.namedForVault(vaultId);
    if (id && !entries.some((entry) => entry.id === id)) return "missing";
    const saved = { id: id ?? crypto.randomUUID(), name, layout: snapshotWorkspace(tabs, activeId) };
    this.setNamed(vaultId, id ? entries.map((entry) => entry.id === id ? saved : entry) : [...entries, saved]);
    return null;
  }

  renameNamed(vaultId: string, id: string, name: string): WorkspaceEditError | null {
    name = name.trim();
    const error = this.checkName(vaultId, name, id);
    if (error) return error;
    const entries = this.namedForVault(vaultId);
    if (!entries.some((entry) => entry.id === id)) return "missing";
    this.setNamed(vaultId, entries.map((entry) => entry.id === id ? { ...entry, name } : entry));
    return null;
  }

  deleteNamed(vaultId: string, id: string): void {
    if (this.document) this.setNamed(vaultId, this.namedForVault(vaultId).filter((entry) => entry.id !== id));
  }

  private setNamed(vaultId: string, entries: NamedWorkspace[]): void {
    if (!this.document) return;
    this.document = { ...this.document, named: { ...this.document.named, [vaultId]: entries } };
    this.queueWrite();
  }

  save(vaultId: string, tabs: TerminalTab[], activeId: string | null): void {
    if (!this.document) return;
    // Vaults missing from the list are kept: a deleted vault can be restored.
    this.document = { ...this.document, activeVaultId: vaultId,
      vaults: { ...this.document.vaults, [vaultId]: snapshotWorkspace(tabs, activeId) } };
    this.queueWrite();
  }

  /** Drop a purged vault's layouts, including their labels and local shell paths. */
  forgetVault(vaultId: string): void {
    if (!this.document || !(vaultId in this.document.vaults || vaultId in this.document.named)) return;
    const { [vaultId]: _layout, ...vaults } = this.document.vaults;
    const { [vaultId]: _named, ...named } = this.document.named;
    this.document = { ...this.document, vaults, named,
      activeVaultId: this.document.activeVaultId === vaultId ? null : this.document.activeVaultId };
    this.queueWrite();
  }

  private queueWrite(): void {
    const text = JSON.stringify(this.document);
    if (text === this.last) return;
    this.last = text;
    this.pending = text;
    void this.flush();
  }

  async flush(): Promise<void> {
    if (this.writing) return this.writing;
    const epoch = this.epoch;
    this.writing = (async () => {
      while (this.pending !== null && epoch === this.epoch) {
        const text = this.pending;
        this.pending = null;
        try { await this.io.save(this.nativeEpoch, text); }
        catch {
          if (epoch === this.epoch) { this.last = null; this.reportError(); }
        }
      }
    })();
    try { await this.writing; }
    finally {
      if (epoch === this.epoch) {
        this.writing = null;
        if (this.pending !== null) await this.flush();
      }
    }
  }

  clear(): void {
    this.epoch++;
    this.document = null;
    this.loading = null;
    this.writing = null;
    this.pending = null;
    this.last = null;
    this.warned = false;
  }
}
