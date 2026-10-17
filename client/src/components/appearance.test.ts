import { describe, expect, it } from "vitest";
import { resolveAppPalette } from "@/theme/tokens";
import { appearanceIcon, swatchColor } from "./appearance";

describe("unknown ids render as the default", () => {
  it("draws no swatch for an unknown colour", () => {
    expect(swatchColor("lime", resolveAppPalette("mono", "light"))).toBeNull();
  });

  it("draws the fallback glyph for an unknown icon", () => {
    expect(appearanceIcon("rocket", "server")).toBe("server");
  });
});
