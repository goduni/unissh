import { beforeEach, describe, expect, it, vi } from "vitest";

const io = vi.hoisted(() => ({
  load: vi.fn(), save: vi.fn(), connections: vi.fn(), vaults: vi.fn(), lock: vi.fn(), invalidate: vi.fn(), close: vi.fn(),
}));
vi.mock("@/bridge/api", () => ({
  terminalWorkspaceLoad: io.load, terminalWorkspaceSave: io.save,
  listConnections: io.connections, listVaults: io.vaults, lock: io.lock,
  listGroups: async () => [], listItems: async () => [], listKnownHosts: async () => [],
  sftpInvalidate: io.invalidate, sessionClose: io.close, sftpClose: async () => {},
}));
vi.mock("@/bridge/log", () => ({ logWarn: vi.fn(), logError: vi.fn(), logDebug: vi.fn() }));
vi.mock("./toast", () => ({ toast: vi.fn() }));

import { useApp, flushTerminalWorkspace, type ActiveTunnel } from "./app";
import type { ConnectionProfile } from "@/bridge/types";
import { shouldRetryOnResume } from "@/views/terminal/paneSession";

const host = { profileId: "h", label: "Host", host: "current.example" } as ConnectionProfile;
const saved = JSON.stringify({ version: 1, activeVaultId: "two", vaults: {
  two: { activeId: "tab", tabs: [{ id: "tab", title: "Work", activePaneId: "pane",
    panes: [{ id: "pane", target: { kind: "ssh", profileId: "h" } }],
    layout: { kind: "pane", paneId: "pane" } }] },
} });

beforeEach(async () => {
  await useApp.getState().lockInstance();
  io.load.mockReset().mockResolvedValue([7, saved]);
  io.save.mockReset().mockResolvedValue(undefined);
  io.connections.mockReset().mockResolvedValue([host]);
  io.vaults.mockReset().mockResolvedValue([{ vaultId: "one" }, { vaultId: "two" }]);
  io.lock.mockReset().mockResolvedValue(undefined);
  io.invalidate.mockReset().mockResolvedValue(undefined);
  io.close.mockReset().mockResolvedValue(undefined);
  useApp.setState({ unlocked: true, vaultId: null, vaults: [], terminals: [], activeTermId: null,
    workspaceReady: false, tunnels: [], broadcasts: [], sftpSessions: [], confirm: null });
});

describe("workspace in the app lifecycle", () => {
  it("opens a named workspace only after confirmation and closes only terminal sessions", async () => {
    await useApp.getState().reloadVaults();
    expect(useApp.getState().saveNamedWorkspace("Production")).toBeNull();
    const savedId = useApp.getState().namedWorkspaces[0].id;
    const tab = useApp.getState().terminals[0];
    useApp.getState().updatePane(tab.id, tab.activePaneId, { status: "online", sessionId: "live" });
    const tunnel: ActiveTunnel = { id: "tunnel", label: "Database", type: "local", bindAddress: "127.0.0.1:5432", route: "db:5432", on: true };
    useApp.setState({ tunnels: [tunnel] });
    await useApp.getState().openNamedWorkspace(savedId);
    expect(io.close).not.toHaveBeenCalled();
    expect(useApp.getState().terminals[0].panes[0].sessionId).toBe("live");
    useApp.getState().confirm?.onConfirm();
    await vi.waitFor(() => expect(useApp.getState().terminals[0].panes[0].status).toBe("restored"));
    expect(io.close).toHaveBeenCalledExactlyOnceWith("live");
    expect(useApp.getState().terminals[0].panes[0].id).not.toBe(tab.activePaneId);
    expect(useApp.getState().tunnels).toEqual([tunnel]);
    expect(useApp.getState().terminals[0].panes[0].sessionId).toBeNull();
  });

  it("keeps current tabs when a saved workspace has no available targets", async () => {
    await useApp.getState().reloadVaults();
    useApp.getState().saveNamedWorkspace("Production");
    const id = useApp.getState().namedWorkspaces[0].id;
    const terminals = useApp.getState().terminals;
    useApp.setState({ hosts: [] });
    await useApp.getState().openNamedWorkspace(id);
    useApp.getState().confirm?.onConfirm();
    expect(useApp.getState().terminals).toBe(terminals);
    expect(io.close).not.toHaveBeenCalled();
  });

  it("keeps current tabs and re-enables saves when a terminal cannot close", async () => {
    await useApp.getState().reloadVaults();
    useApp.getState().saveNamedWorkspace("Production");
    const id = useApp.getState().namedWorkspaces[0].id;
    const tab = useApp.getState().terminals[0];
    useApp.getState().updatePane(tab.id, tab.activePaneId, { status: "online", sessionId: "live" });
    io.close.mockRejectedValueOnce(new Error("IPC unavailable"));
    await useApp.getState().openNamedWorkspace(id);
    useApp.getState().confirm?.onConfirm();
    await vi.waitFor(() => expect(useApp.getState().workspaceReady).toBe(true));
    expect(useApp.getState().terminals[0].id).toBe(tab.id);
    expect(useApp.getState().terminals[0].panes[0].sessionId).toBe("live");
    expect(useApp.getState().saveNamedWorkspace("Still editable")).toBeNull();
  });

  it("ignores workspace confirmation after a vault switch and clears names on lock", async () => {
    await useApp.getState().reloadVaults();
    useApp.getState().saveNamedWorkspace("Production");
    const id = useApp.getState().namedWorkspaces[0].id;
    await useApp.getState().openNamedWorkspace(id);
    const confirm = useApp.getState().confirm!;
    await useApp.getState().setVault("one");
    confirm.onConfirm();
    expect(useApp.getState().terminals).toEqual([]);
    expect(useApp.getState().namedWorkspaces).toEqual([]);
    await useApp.getState().setVault("two");
    expect(useApp.getState().namedWorkspaces[0].name).toBe("Production");
    await useApp.getState().lockInstance();
    expect(useApp.getState().namedWorkspaces).toEqual([]);
    expect(useApp.getState().saveNamedWorkspace("Locked")).toBe("unavailable");
  });

  it("ignores background reloads during vault teardown and preserves both layouts", async () => {
    await useApp.getState().reloadVaults();
    await useApp.getState().setVault("one");
    let finish!: () => void;
    io.invalidate.mockImplementationOnce(() => new Promise<void>((resolve) => { finish = resolve; }));
    const switching = useApp.getState().setVault("two");
    io.vaults.mockClear();
    await useApp.getState().reloadVaults();
    expect(io.vaults).not.toHaveBeenCalled();
    await useApp.getState().reloadVault();
    finish();
    await switching;
    expect(useApp.getState().vaultId).toBe("two");
    expect(useApp.getState().terminals.map((tab) => tab.title)).toEqual(["Work"]);
    await useApp.getState().setVault("one");
    expect(useApp.getState().terminals).toEqual([]);
    await useApp.getState().setVault("two");
    expect(useApp.getState().terminals.map((tab) => tab.title)).toEqual(["Work"]);
  });

  it("discards a pending vault switch after lock and allows restoration on unlock", async () => {
    await useApp.getState().reloadVaults();
    let finish!: () => void;
    io.invalidate.mockImplementationOnce(() => new Promise<void>((resolve) => { finish = resolve; }));
    const switching = useApp.getState().setVault("one");
    await useApp.getState().lockInstance();
    useApp.setState({ unlocked: true });
    await useApp.getState().reloadVaults();
    finish();
    await switching;
    expect(useApp.getState().vaultId).toBe("two");
    expect(useApp.getState().terminals.map((tab) => tab.title)).toEqual(["Work"]);
    expect(useApp.getState().workspaceReady).toBe(true);
  });

  it("does not block vault loading after a lock interrupts a starting vault switch", async () => {
    await useApp.getState().reloadVaults();
    let unlockCore!: () => void;
    io.lock.mockImplementationOnce(() => new Promise<void>((resolve) => { unlockCore = resolve; }));
    let finish!: () => void;
    io.invalidate.mockImplementationOnce(() => new Promise<void>((resolve) => { finish = resolve; }));
    const locking = useApp.getState().lockInstance();
    await vi.waitFor(() => expect(io.lock).toHaveBeenCalled());
    // The switch starts after lock has bumped the epoch but before it clears `unlocked`.
    const switching = useApp.getState().setVault("one");
    unlockCore();
    await locking;
    finish();
    await switching;
    useApp.setState({ unlocked: true });
    io.vaults.mockClear();
    await useApp.getState().reloadVaults();
    expect(io.vaults).toHaveBeenCalled();
    expect(useApp.getState().workspaceReady).toBe(true);
  });

  it("refreshes hosts while a named workspace closes its sessions", async () => {
    await useApp.getState().reloadVaults();
    useApp.getState().saveNamedWorkspace("Production");
    const id = useApp.getState().namedWorkspaces[0].id;
    const tab = useApp.getState().terminals[0];
    useApp.getState().updatePane(tab.id, tab.activePaneId, { status: "online", sessionId: "live" });
    let closed!: () => void;
    io.close.mockImplementationOnce(() => new Promise<void>((resolve) => { closed = resolve; }));
    await useApp.getState().openNamedWorkspace(id);
    useApp.getState().confirm?.onConfirm();
    await vi.waitFor(() => expect(io.close).toHaveBeenCalled());
    const edited = { ...host, label: "Edited" };
    io.connections.mockResolvedValue([edited]);
    await useApp.getState().reloadVault();
    closed();
    await vi.waitFor(() => expect(useApp.getState().terminals[0].panes[0].status).toBe("restored"));
    expect(useApp.getState().hosts).toEqual([edited]);
    expect(useApp.getState().loading).toBe(false);
    expect(useApp.getState().terminals).toHaveLength(1);
  });

  it("restores the selected vault on boot, lock/unlock and vault switching without connecting", async () => {
    await useApp.getState().reloadVaults();
    expect(useApp.getState().vaultId).toBe("two");
    let pane = useApp.getState().terminals[0].panes[0];
    expect(pane.status).toBe("restored");
    expect(shouldRetryOnResume(pane)).toBe(false);
    await flushTerminalWorkspace();
    io.load.mockResolvedValue([7, io.save.mock.calls[io.save.mock.calls.length - 1][1]]);
    await useApp.getState().lockInstance();
    expect(useApp.getState().terminals).toEqual([]);
    useApp.setState({ unlocked: true });
    await useApp.getState().reloadVaults();
    pane = useApp.getState().terminals[0].panes[0];
    expect(pane.status).toBe("restored");
    await useApp.getState().setVault("one");
    expect(useApp.getState().confirm).toBeNull();
    expect(useApp.getState().terminals).toEqual([]);
    await useApp.getState().setVault("two");
    expect(useApp.getState().terminals[0].title).toBe("Work");
    expect(useApp.getState().terminals[0].panes[0].id).not.toBe(pane.id);
  });

  it("uses the latest host profile when explicitly starting a restored pane", async () => {
    await useApp.getState().reloadVaults();
    const tab = useApp.getState().terminals[0];
    const latest = { ...host, host: "edited.example" };
    useApp.setState({ hosts: [latest] });
    useApp.getState().reconnectPane(tab.id, tab.activePaneId, true);
    expect(useApp.getState().terminals[0].panes[0]).toMatchObject({
      status: "connecting", gen: 1, target: { kind: "ssh", profile: latest },
    });
  });

  it("never reconnects a host deleted after restoration", async () => {
    await useApp.getState().reloadVaults();
    const tab = useApp.getState().terminals[0];
    useApp.setState({ hosts: [] });
    useApp.getState().reconnectPane(tab.id, tab.activePaneId, true);
    expect(useApp.getState().terminals[0].panes[0].status).toBe("restored");
  });

  it("does not restore or write from a vault load that finishes after lock", async () => {
    let finish!: (hosts: ConnectionProfile[]) => void;
    io.connections.mockImplementation(() => new Promise<ConnectionProfile[]>((resolve) => { finish = resolve; }));
    const reload = useApp.getState().reloadVaults();
    await vi.waitFor(() => expect(io.connections).toHaveBeenCalled());
    await useApp.getState().lockInstance();
    finish([host]);
    await reload;
    expect(useApp.getState().terminals).toEqual([]);
    expect(useApp.getState().hosts).toEqual([]);
    expect(io.save).not.toHaveBeenCalled();
  });
});
