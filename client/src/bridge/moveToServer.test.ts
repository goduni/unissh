import { describe, it, expect } from "vitest";
import { planMoveToServer } from "./moveToServer";
import { ItemType, type ServerStatus, type SpaceInfo } from "./types";

const server = (serverId: string, hasSession: boolean): ServerStatus => ({
  serverId,
  connected: true,
  active: false,
  hasSession,
  baseUrl: `https://${serverId}.example`,
  instanceId: null,
  accountId: null,
  deviceId: null,
  handle: null,
  owned: false,
  spaceId: null,
  spaces: [],
});
const admin = (spaceId: string): SpaceInfo => ({ spaceId, name: spaceId, role: "admin" });
const items = (...types: number[]) => types.map((itemType) => ({ itemType }));

describe("planMoveToServer", () => {
  it("counts items by kind in display order, leaving out absent kinds", () => {
    const plan = planMoveToServer(
      items(ItemType.SshKey, ItemType.Connection, ItemType.Connection, ItemType.Snippet, ItemType.Recording),
      [server("a", true)],
    );
    expect(plan.counts).toEqual([
      { kind: "hosts", count: 2 },
      { kind: "keys", count: 1 },
      { kind: "snippets", count: 1 },
      { kind: "other", count: 1 },
    ]);
  });

  it("keeps the vault personal unless a space is picked, even when the primary space is yours", () => {
    const member: SpaceInfo = { spaceId: "team", name: "Team", role: "member" };
    const servers = [{ ...server("a", true), spaceId: "lab" }];
    const spaces = [admin("own"), admin("lab"), member];
    const byDefault = planMoveToServer([], servers, { spaces });
    expect({ space: byDefault.space, nonPrimary: byDefault.nonPrimarySpace }).toEqual({ space: null, nonPrimary: false });
    const picked = planMoveToServer([], servers, { spaces, spaceId: "own" });
    expect({ space: picked.space?.spaceId, nonPrimary: picked.nonPrimarySpace }).toEqual({ space: "own", nonPrimary: true });
  });

  it("offers a space choice only among the spaces you administer", () => {
    const member: SpaceInfo = { spaceId: "team", name: "Team", role: "member" };
    const servers = [server("a", true)];
    expect(planMoveToServer([], servers, { spaces: [member] }).needsSpacePicker).toBe(false);
    const one = planMoveToServer([], servers, { spaces: [admin("own"), member] });
    expect(one.needsSpacePicker).toBe(true);
    expect(one.spaces.map((sp) => sp.spaceId)).toEqual(["own"]);
    expect(planMoveToServer([], servers, { spaces: [member], spaceId: "team" }).space).toBeNull();
  });

  it("offers only signed-in servers, defaulting to the active one", () => {
    const servers = [server("a", true), server("b", false), server("c", true)];
    const plan = planMoveToServer([], servers, { activeServerId: "c" });
    expect(plan.servers.map((s) => s.serverId)).toEqual(["a", "c"]);
    expect(plan.needsServerPicker).toBe(true);
    expect(plan.server?.serverId).toBe("c");
    expect(planMoveToServer([], [server("b", false)]).server).toBeNull();
  });
});
