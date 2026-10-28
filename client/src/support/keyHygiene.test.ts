import { describe, it, expect } from "vitest";
import { isKeyOld, parseKeyAgeDays } from "./keyHygiene";

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
