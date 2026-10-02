import { describe, it, expect } from "vitest";
import { isKeyOld, keyUsage, keyUsageCount, parseKeyAgeDays } from "./keyHygiene";
import type { ConnectionProfile, JumpHost, ProfileAuth } from "@/bridge/types";

const hop = (keyItemId: string): JumpHost => ({
  host: "bastion",
  port: 22,
  user: "ops",
  auth: { type: "agent", vaultId: "v", keyItemId },
});

const host = (profileId: string, auth: ProfileAuth, jumps: JumpHost[] = []): ConnectionProfile => ({
  profileId,
  uid: profileId,
  label: profileId,
  host: `${profileId}.example`,
  port: 22,
  user: "root",
  auth,
  jumps,
  tags: [],
  startupSnippetIds: [],
  recordSessions: false,
  agentForward: false,
});

const ids = (hs: ConnectionProfile[]) => hs.map((h) => h.profileId);

describe("keyUsage", () => {
  it("lists a host that logs in with the key as direct", () => {
    const u = keyUsage([host("web", { type: "key", keyItemId: "k" })], "k");
    expect([ids(u.direct), ids(u.jump)]).toEqual([["web"], []]);
  });

  it("lists a host that only hops with the key as jump", () => {
    const u = keyUsage([host("db", { type: "promptPassword" }, [hop("k")])], "k");
    expect([ids(u.direct), ids(u.jump)]).toEqual([[], ["db"]]);
  });

  it("splits direct and jump users across hosts", () => {
    const u = keyUsage(
      [host("web", { type: "key", keyItemId: "k" }), host("db", { type: "personal" }, [hop("k")])],
      "k",
    );
    expect([ids(u.direct), ids(u.jump), keyUsageCount(u)]).toEqual([["web"], ["db"], 2]);
  });

  it("finds nothing when no host references the key", () => {
    const u = keyUsage([host("web", { type: "key", keyItemId: "other" }, [hop("other")])], "k");
    expect([ids(u.direct), ids(u.jump), keyUsageCount(u)]).toEqual([[], [], 0]);
  });

  it("lists a host using the key twice once per category and counts it once", () => {
    const u = keyUsage([host("api", { type: "key", keyItemId: "k" }, [hop("k"), hop("k")])], "k");
    expect([ids(u.direct), ids(u.jump), keyUsageCount(u)]).toEqual([["api"], ["api"], 1]);
  });
});

describe("key age", () => {
  const DAY = 86_400;
  const now = 1_800_000_000 * 1000;

  it("marks a key old only past an enabled threshold", () => {
    const created = now / 1000 - 400 * DAY;
    expect([
      isKeyOld(created, 365, now),
      isKeyOld(created, 730, now),
      isKeyOld(created, 0, now),
      isKeyOld(0, 365, now),
    ]).toEqual([true, false, false, false]);
  });

  it("reads back a stored threshold, keeping 0 and defaulting the rest", () => {
    expect([
      parseKeyAgeDays(String(730)),
      parseKeyAgeDays(String(0)),
      parseKeyAgeDays(null),
      parseKeyAgeDays("junk"),
    ]).toEqual([730, 0, 365, 365]);
  });
});
