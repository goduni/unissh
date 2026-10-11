import { describe, it, expect } from "vitest";
import type { ServerStatus } from "./types";
import { cloudVaultServers } from "./vaults";

const link = (serverId: string, over: Partial<ServerStatus>): ServerStatus => ({
  serverId,
  connected: true,
  active: false,
  hasSession: false,
  baseUrl: `https://${serverId}.example`,
  instanceId: null,
  accountId: null,
  deviceId: null,
  handle: null,
  owned: false,
  spaceId: "space",
  spaces: [],
  ...over,
});

describe("cloudVaultServers", () => {
  it("offers a linked server without a live session, but not a link with no space label", () => {
    const servers = [
      link("signed-out", {}),
      link("signed-in", { hasSession: true }),
      link("no-label", { hasSession: true, spaceId: null }),
      link("unlinked", { connected: false }),
    ];
    expect(cloudVaultServers(servers).map((s) => s.serverId)).toEqual(["signed-out", "signed-in"]);
  });
});
