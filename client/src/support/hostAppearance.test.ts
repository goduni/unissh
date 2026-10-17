import { describe, expect, it } from "vitest";
import { effectiveHostColor, indexAppearance, liveHost, type AppearanceGroup } from "./hostAppearance";

const host = (color?: string | null) => ({ profileId: "h", color });
const group = (groupId: string, g: Partial<AppearanceGroup> = {}): AppearanceGroup => ({
  groupId,
  label: groupId,
  memberIds: [],
  ...g,
});
const colorOf = (h: { profileId: string; color?: string | null }, groups: AppearanceGroup[]) =>
  effectiveHostColor(h, indexAppearance(groups));

describe("effectiveHostColor", () => {
  it("prefers the host's own colour over its group's", () => {
    expect(colorOf(host("red"), [group("g", { memberIds: ["h"], color: "green" })])).toBe("red");
  });

  it("inherits through the parent chain of the group listing the host", () => {
    const groups = [
      group("leaf", { memberIds: ["h"], parentId: "mid" }),
      group("mid", { parentId: "root" }),
      group("root", { color: "teal" }),
    ];
    expect(colorOf(host(), groups)).toBe("teal");
  });

  it("inherits nothing when the containing groups disagree", () => {
    const groups = [group("a", { memberIds: ["h"], color: "red" }), group("b", { memberIds: ["h"], color: "green" })];
    expect(colorOf(host(), groups)).toBeNull();
  });

  // A newer client's colour is still a colour: "lime" beside "red" is a
  // disagreement, not a red host.
  it("counts a group's unknown colour as a disagreeing vote", () => {
    const groups = [group("a", { memberIds: ["h"], color: "lime" }), group("b", { memberIds: ["h"], color: "red" })];
    expect(colorOf(host(), groups)).toBeNull();
  });

  it("terminates on a parent cycle", () => {
    const groups = [group("a", { memberIds: ["h"], parentId: "b" }), group("b", { parentId: "a" })];
    expect(colorOf(host(), groups)).toBeNull();
  });

  // A newer client's id is a colour that was SET — showing the folder's colour
  // in its place would mislabel the host.
  it("an unknown own colour blocks inheritance instead of falling through", () => {
    expect(colorOf(host("lime"), [group("g", { memberIds: ["h"], color: "red" })])).toBeNull();
  });
});

describe("liveHost", () => {
  const index = indexAppearance([group("g", { memberIds: ["h"], color: "red" })]);
  const loaded = [{ uid: "u1", profileId: "h", color: null, icon: "database" }];

  // The snapshot an open pane holds is stale the moment the host is restyled.
  it("follows the loaded host with the same uid", () => {
    expect(liveHost({ uid: "u1", profileId: "h", color: "blue", icon: null }, loaded, index)).toEqual({
      color: "red",
      icon: "database",
    });
  });

  // Another vault's host sharing the profileId must not lend it this vault's groups.
  it("ignores a loaded host with the same profileId but another uid", () => {
    expect(liveHost({ uid: "u2", profileId: "h", color: "blue", icon: null }, loaded, index)).toEqual({
      color: "blue",
      icon: null,
    });
  });

  // A tab must not lose the colour it inherited from a folder just because
  // that host's vault is no longer the one loaded.
  it("falls back to the tag last seen for the uid when the host is not loaded", () => {
    const remembered = new Map([["u2", { color: "red" as const, icon: "database" }]]);
    expect(liveHost({ uid: "u2", profileId: "h", color: null, icon: null }, loaded, index, remembered)).toEqual({
      color: "red",
      icon: "database",
    });
  });
});
