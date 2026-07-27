import { describe, expect, it } from "vitest";
import { fmtRelative, fmtRelativeUnix } from "./mono";

/** Offsets are kept away from the rounding boundaries on purpose: 90 seconds is
 *  exactly 1.5 minutes, and `Math.round(-1.5)` is -1 in JS, so a "90s → 2 minutes
 *  ago" assertion flips on sub-millisecond timing. */
describe("relative time", () => {
  const nowMs = Date.now();
  const nowSecs = Math.floor(nowMs / 1000);

  it("reads a UNIX timestamp as seconds", () => {
    expect(fmtRelativeUnix(nowSecs - 100, "en")).toBe("2 minutes ago");
    expect(fmtRelativeUnix(nowSecs - 3 * 86400, "en")).toBe("3 days ago");
  });

  it("still reads Date.now() milliseconds", () => {
    expect(fmtRelative(nowMs - 100_000, "en")).toBe("2 minutes ago");
    expect(fmtRelative(nowMs - 3 * 86_400_000, "en")).toBe("3 days ago");
  });

  /** The reported bug: a key generated a moment ago read "updated 57 years ago",
   *  because the core stores SECONDS and this formatter takes milliseconds. */
  it("a just-written UNIX timestamp reads as fresh, not as decades", () => {
    expect(fmtRelativeUnix(nowSecs, "en")).toMatch(/^(now|\d+ seconds? ago)$/);
    expect(fmtRelative(nowSecs, "en")).toMatch(/years ago$/);
  });
});
