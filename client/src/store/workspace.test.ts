import { describe, expect, it, vi } from "vitest";
import type { ConnectionProfile } from "@/bridge/types";
import type { TerminalTab } from "./app";
import { restoreWorkspace, snapshotWorkspace, WorkspaceStorage } from "./workspace";

const host = {
  profileId: "host1", label: "Production", host: "old.example", user: "deploy",
  auth: { type: "password", password: "never-persist-this" },
} as unknown as ConnectionProfile;

function tabs(): TerminalTab[] {
  return [{
    id: "tab1", title: "shell-output-secret", activePaneId: "local",
    layout: { kind: "split", id: "split1", dir: "col", ratio: 0.7,
      a: { kind: "pane", paneId: "ssh" }, b: { kind: "pane", paneId: "local" } },
    panes: [
      { id: "ssh", title: "remote-secret-title", target: { kind: "ssh", profile: host },
        status: "online", sessionId: "backend-id", gen: 3, reconnects: 2, lastOnlineAt: 99,
        preview: ["secret-output"], error: "secret-error" },
      { id: "local", title: "local-secret-title", target: { kind: "local", spec: {
        shell: "/bin/bash", args: ["-l"], cwd: "/work", label: "bash",
      } }, status: "online", sessionId: "local-backend", gen: 1, reconnects: 0, lastOnlineAt: 99 },
    ],
  }];
}

describe("terminal workspace", () => {
  it("saves references and geometry without credentials, output or runtime state", () => {
    const encoded = JSON.stringify(snapshotWorkspace(tabs(), "tab1"));
    for (const secret of ["secret", "backend", "old.example", "deploy", "sessionId", "reconnects"])
      expect(encoded).not.toContain(secret);
    expect(encoded).toContain("host1");
    expect(encoded).toContain('"ratio":0.7');
  });

  it("restores fresh idle panes with current profiles, focus, local settings and custom names", () => {
    const saved = tabs();
    saved[0].customTitle = true;
    saved[0].title = "Operations";
    const currentHost = { ...host, host: "new.example", label: "Renamed host" };
    const restored = restoreWorkspace(snapshotWorkspace(saved, "tab1"), [currentHost], true);
    const tab = restored.terminals[0];
    expect(tab.title).toBe("Operations");
    expect(tab.customTitle).toBe(true);
    expect(tab.layout).toMatchObject({ kind: "split", dir: "col", ratio: 0.7 });
    expect(tab.activePaneId).toBe(tab.panes[1].id);
    expect(restored.activeTermId).toBe(tab.id);
    expect(tab.panes[0].target).toEqual({ kind: "ssh", profile: currentHost });
    expect(tab.panes[1].target).toEqual(saved[0].panes[1].target);
    for (const pane of tab.panes) {
      expect(pane).toMatchObject({ status: "restored", sessionId: null, gen: 0, reconnects: 0 });
      expect(["ssh", "local"]).not.toContain(pane.id);
      expect(pane.preview).toBeUndefined();
    }
  });

  it("prunes deleted hosts, collapses splits and drops unavailable local shells on mobile", () => {
    const snapshot = snapshotWorkspace(tabs(), "tab1");
    const withoutHost = restoreWorkspace(snapshot, [], true);
    expect(withoutHost.removed).toBe(1);
    expect(withoutHost.terminals[0].layout.kind).toBe("pane");
    expect(withoutHost.terminals[0].panes[0].target.kind).toBe("local");
    const mobile = restoreWorkspace(snapshot, [host], false);
    expect(mobile.terminals[0].panes).toHaveLength(1);
    expect(mobile.terminals[0].activePaneId).toBe(mobile.terminals[0].panes[0].id);
    expect(restoreWorkspace(snapshot, [], false).terminals).toEqual([]);
  });

  it("preserves tab order and the selected tab across repeated restoration", () => {
    const first = tabs()[0];
    const second = { ...first, id: "tab2", customTitle: true, title: "Second" };
    const saved = snapshotWorkspace([second, first], first.id);
    const restored = restoreWorkspace(saved, [host], true);
    expect(restored.terminals.map((tab) => tab.customTitle ? tab.title : null)).toEqual(["Second", null]);
    expect(restored.activeTermId).toBe(restored.terminals[1].id);
    const again = restoreWorkspace(snapshotWorkspace(restored.terminals, restored.activeTermId), [host], true);
    expect(again.terminals.map((tab) => tab.title)).toEqual(restored.terminals.map((tab) => tab.title));
    expect(again.activeTermId).toBe(again.terminals[1].id);
  });

  it("rejects malformed geometry and never renders a duplicate pane", () => {
    const snapshot = snapshotWorkspace(tabs(), "tab1");
    snapshot.tabs[0].layout = { kind: "split", id: "x", dir: "row", ratio: 10,
      a: { kind: "pane", paneId: "ssh" }, b: { kind: "pane", paneId: "ssh" } };
    expect(restoreWorkspace(snapshot, [host], true).terminals[0].panes).toHaveLength(1);
    expect(restoreWorkspace({ tabs: [null, { panes: [], layout: {} }] }, [], true).terminals).toEqual([]);
    expect(restoreWorkspace(null, [], true).terminals).toEqual([]);
  });
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

describe("workspace persistence lifecycle", () => {
  it("serializes writes, coalesces intermediate changes, and saves an explicitly empty layout", async () => {
    const first = deferred<void>();
    const save = vi.fn().mockImplementationOnce(() => first.promise).mockResolvedValue(undefined);
    const storage = new WorkspaceStorage({ load: async () => [7, null], save, error: vi.fn() });
    await storage.load();
    storage.save("v", tabs(), "tab1");
    storage.save("v", tabs(), null);
    storage.save("v", [], null);
    expect(save).toHaveBeenCalledTimes(1);
    first.resolve();
    await storage.flush();
    expect(save).toHaveBeenCalledTimes(2);
    expect(save.mock.calls[1][0]).toBe(7);
    expect(JSON.parse(save.mock.calls[1][1]).vaults.v.tabs).toEqual([]);
  });

  it("keeps layouts separate per vault and remembers the selected vault", async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    const storage = new WorkspaceStorage({ load: async () => [7, null], save, error: vi.fn() });
    await storage.load();
    storage.save("first", tabs(), "tab1");
    storage.save("second", [], null);
    await storage.flush();
    expect(storage.activeVaultId).toBe("second");
    expect(restoreWorkspace(storage.forVault("first"), [host], true).terminals).toHaveLength(1);
    // A vault missing from the list may be restored; only a purge forgets it.
    storage.forgetVault("first");
    expect(storage.forVault("first")).toBeUndefined();
    expect(storage.forVault("second")).toBeDefined();
  });

  it("moves a vault's current and named layouts to its new id", async () => {
    const storage = new WorkspaceStorage({ load: async () => [7, null], save: vi.fn().mockResolvedValue(undefined), error: vi.fn() });
    await storage.load();
    storage.save("local", tabs(), "tab1");
    expect(storage.saveNamed("local", "Ops", tabs(), "tab1")).toBeNull();
    storage.moveVault("local", "cloud");
    expect(storage.forVault("local")).toBeUndefined();
    expect(restoreWorkspace(storage.forVault("cloud"), [host], true).terminals).toHaveLength(1);
    expect(storage.namedForVault("cloud").map((w) => w.name)).toEqual(["Ops"]);
    expect(storage.activeVaultId).toBe("cloud");
  });

  it("ignores a late load after lock and does not overwrite unreadable or future data", async () => {
    const read = deferred<[number, string | null]>();
    const io = { load: () => read.promise, save: vi.fn(), error: vi.fn() };
    const storage = new WorkspaceStorage(io);
    const loading = storage.load();
    storage.clear();
    read.resolve([7, JSON.stringify({ version: 1, activeVaultId: "old", vaults: {} })]);
    await loading;
    storage.save("new", [], null);
    expect(storage.activeVaultId).toBeNull();
    expect(io.save).not.toHaveBeenCalled();
    const future = new WorkspaceStorage({ ...io, load: async () => [7, '{"version":3,"vaults":{}}'] });
    await future.load();
    future.save("v", [], null);
    expect(io.error).toHaveBeenCalledExactlyOnceWith("failed");
    expect(io.save).not.toHaveBeenCalled();
  });

  it("resets an unreadable layout instead of disabling persistence", async () => {
    for (const text of ["invalid", '{"version":2,"vaults":[]}']) {
      const io = { load: async (): Promise<[number, string | null]> => [7, text],
        save: vi.fn().mockResolvedValue(undefined), error: vi.fn() };
      const storage = new WorkspaceStorage(io);
      await storage.load();
      expect(io.error).toHaveBeenCalledExactlyOnceWith("reset");
      expect(storage.available).toBe(true);
      storage.save("v", tabs(), "tab1");
      await storage.flush();
      expect(io.save).toHaveBeenCalledOnce();
      expect(JSON.parse(io.save.mock.calls[0][1]).version).toBe(2);
    }
  });

  it("reports failed writes and retries on the next layout change", async () => {
    const save = vi.fn().mockRejectedValueOnce(new Error("disk full")).mockResolvedValue(undefined);
    const error = vi.fn();
    const storage = new WorkspaceStorage({ load: async () => [7, null], save, error });
    await storage.load();
    storage.save("v", [], null);
    await storage.flush();
    expect(error).toHaveBeenCalledOnce();
    storage.save("v", [], null);
    await storage.flush();
    expect(save).toHaveBeenCalledTimes(2);
  });
});

describe("named workspaces", () => {
  it("migrates version 1, keeps snapshots independent of autosave, and reloads version 2", async () => {
    let document = JSON.stringify({ version: 1, activeVaultId: "v", vaults: { v: snapshotWorkspace(tabs(), "tab1") } });
    const io = { load: async (): Promise<[number, string]> => [7, document],
      save: async (_epoch: number, text: string) => { document = text; }, error: vi.fn() };
    const storage = new WorkspaceStorage(io);
    await storage.load();
    expect(restoreWorkspace(storage.forVault("v"), [host], true).terminals).toHaveLength(1);
    expect(storage.saveNamed("v", " Production ", tabs(), "tab1")).toBeNull();
    storage.save("v", [], null);
    await storage.flush();
    expect(JSON.parse(document).version).toBe(2);
    const reloaded = new WorkspaceStorage(io);
    await reloaded.load();
    expect(restoreWorkspace(reloaded.forVault("v"), [host], true).terminals).toEqual([]);
    const saved = reloaded.namedForVault("v")[0];
    expect(saved.name).toBe("Production");
    expect(restoreWorkspace(saved.layout, [host], true).terminals[0].panes).toHaveLength(2);
    for (const secret of ["never-persist-this", "secret-output", "remote-secret-title", "backend-id"])
      expect(document).not.toContain(secret);
  });

  it("validates names, supports explicit updates and scopes entries to a vault", async () => {
    const storage = new WorkspaceStorage({ load: async () => [7, null], save: vi.fn(), error: vi.fn() });
    await storage.load();
    expect(storage.saveNamed("one", "   ", tabs(), "tab1")).toBe("invalidName");
    expect(storage.saveNamed("one", "x".repeat(81), tabs(), "tab1")).toBe("invalidName");
    expect(storage.saveNamed("one", "Production", [], null)).toBe("emptyLayout");
    expect(storage.saveNamed("one", "Production", tabs(), "tab1")).toBeNull();
    expect(storage.saveNamed("one", "production", tabs(), "tab1")).toBe("duplicateName");
    expect(storage.saveNamed("two", "Production", tabs(), "tab1")).toBeNull();
    const id = storage.namedForVault("one")[0].id;
    expect(storage.renameNamed("one", id, "Operations")).toBeNull();
    expect(storage.renameNamed("two", id, "Other")).toBe("missing");
    const changed = tabs();
    changed[0].customTitle = true;
    changed[0].title = "Updated";
    expect(storage.saveNamed("one", "Operations", changed, "tab1", id)).toBeNull();
    expect(restoreWorkspace(storage.namedForVault("one")[0].layout, [host], true).terminals[0].title).toBe("Updated");
    storage.deleteNamed("one", id);
    expect(storage.namedForVault("one")).toEqual([]);
    expect(storage.namedForVault("two")).toHaveLength(1);
    storage.save("one", tabs(), "tab1");
    expect(storage.namedForVault("two")).toHaveLength(1);
    storage.forgetVault("two");
    expect(storage.namedForVault("two")).toEqual([]);
  });

  it("does not edit named layouts when storage could not load", async () => {
    const save = vi.fn();
    const storage = new WorkspaceStorage({ load: async () => [7, '{"version":3}'], save, error: vi.fn() });
    await storage.load();
    expect(storage.available).toBe(false);
    expect(storage.saveNamed("v", "Production", tabs(), "tab1")).toBe("unavailable");
    storage.deleteNamed("v", "missing");
    expect(save).not.toHaveBeenCalled();
  });
});
