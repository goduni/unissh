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

  it("asks for a space only when the server has more than one space you administer, defaulting to the primary", () => {
    const member: SpaceInfo = { spaceId: "team", name: "Team", role: "member" };
    const servers = [{ ...server("a", true), spaceId: "lab" }];
    expect(planMoveToServer([], servers, { spaces: [admin("own"), member] }).needsSpacePicker).toBe(false);
    const two = planMoveToServer([], servers, { spaces: [admin("own"), admin("lab"), member] });
    expect(two.needsSpacePicker).toBe(true);
    expect(two.spaces.map((sp) => sp.spaceId)).toEqual(["own", "lab"]);
    expect({ space: two.space?.spaceId, nonPrimary: two.nonPrimarySpace }).toEqual({ space: "lab", nonPrimary: false });
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
