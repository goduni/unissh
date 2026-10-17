import { describe, expect, it } from "vitest";
import { resolveAppPalette } from "@/theme/tokens";
import { appearanceIcon, effectiveHostColor, liveHostColor, swatchColor, type AppearanceGroup } from "./appearance";

const host = (color?: string | null) => ({ profileId: "h", color });
const group = (groupId: string, g: Partial<AppearanceGroup> = {}): AppearanceGroup => ({
  groupId,
  memberIds: [],
  ...g,
});

describe("effectiveHostColor", () => {
  it("prefers the host's own colour over its group's", () => {
    expect(effectiveHostColor(host("red"), [group("g", { memberIds: ["h"], color: "green" })])).toBe("red");
  });

  it("inherits through the parent chain of the group listing the host", () => {
    const groups = [group("leaf", { memberIds: ["h"], parentId: "mid" }), group("mid", { parentId: "root" }), group("root", { color: "teal" })];
    expect(effectiveHostColor(host(), groups)).toBe("teal");
  });

  it("inherits nothing when the containing groups disagree", () => {
    const groups = [group("a", { memberIds: ["h"], color: "red" }), group("b", { memberIds: ["h"], color: "green" })];
    expect(effectiveHostColor(host(), groups)).toBeNull();
  });

  it("terminates on a parent cycle", () => {
    const groups = [group("a", { memberIds: ["h"], parentId: "b" }), group("b", { parentId: "a" })];
    expect(effectiveHostColor(host(), groups)).toBeNull();
  });

  // A newer client's id is a colour that was SET — showing the folder's colour
  // in its place would mislabel the host.
  it("an unknown own colour blocks inheritance instead of falling through", () => {
    expect(effectiveHostColor(host("lime"), [group("g", { memberIds: ["h"], color: "red" })])).toBeNull();
  });
});

describe("unknown ids render as the default", () => {
  it("draws no swatch for an unknown colour and the fallback glyph for an unknown icon", () => {
    expect(swatchColor("lime", resolveAppPalette("mono", "light"))).toBeNull();
    expect(appearanceIcon("rocket", "server")).toBe("server");
  });
});

describe("liveHostColor", () => {
  // The snapshot an open pane holds is stale the moment the host is recoloured;
  // another vault's host sharing the profileId must not lend it this vault's groups.
  it("follows the loaded host with the same uid, and only that one", () => {
    const groups = [group("g", { memberIds: ["h"], color: "red" })];
    const loaded = [{ uid: "u1", profileId: "h", color: null }];
    expect(liveHostColor({ uid: "u1", profileId: "h", color: "blue" }, loaded, groups)).toBe("red");
    expect(liveHostColor({ uid: "u2", profileId: "h", color: "blue" }, loaded, groups)).toBe("blue");
  });
});
