import { describe, expect, it } from "vitest";
import {
  durationSeconds,
  formatDuration,
  initialDuration,
  MAX_GRANT_SECONDS,
} from "./duration";

describe("MCP grant duration", () => {
  it("preserves finite grants when reopening the editor, rounding countdown seconds to minutes", () => {
    expect(initialDuration(3598).choice).toBe(3600);
    expect(initialDuration(86399).choice).toBe(86400);
    expect(initialDuration(7199)).toEqual({
      choice: "custom",
      amount: "2",
      unit: "hours",
    });
    expect(durationSeconds(initialDuration(3 * 86400 - 1))).toBe(3 * 86400);
    expect(durationSeconds(initialDuration(75 * 60 - 10))).toBe(75 * 60);
    expect(durationSeconds(initialDuration(null))).toBeNull();
    expect(
      durationSeconds(initialDuration(MAX_GRANT_SECONDS)),
    ).toBeLessThanOrEqual(MAX_GRANT_SECONDS);
  });

  it.each([
    "",
    "0",
    "-1",
    "1.5",
    "Infinity",
    "NaN",
    "1e3",
    "0x10",
    "9999999999999999",
  ])(
    "rejects invalid custom values (%s) instead of granting unbounded access",
    (amount) => {
      expect(
        durationSeconds({ choice: "custom", amount, unit: "hours" }),
      ).toBeUndefined();
    },
  );

  it("converts minutes, hours and days without exceeding the native u32 contract", () => {
    expect(
      durationSeconds({ choice: "custom", amount: "45", unit: "minutes" }),
    ).toBe(2700);
    expect(
      durationSeconds({ choice: "custom", amount: "12", unit: "hours" }),
    ).toBe(43200);
    expect(
      durationSeconds({ choice: "custom", amount: "7", unit: "days" }),
    ).toBe(604800);
    expect(
      durationSeconds({ choice: "custom", amount: "49710", unit: "days" }),
    ).toBe(4294944000);
    expect(
      durationSeconds({ choice: "custom", amount: "49711", unit: "days" }),
    ).toBeUndefined();
  });

  it("renders long grants as days/hours/minutes instead of thousands of minutes", () => {
    expect(formatDuration(90061, "en")).toBe("1 day 1 hr 2 min");
    expect(formatDuration(3600, "en")).toBe("1 hr");
    expect(formatDuration(0, "en")).toBe("0 min");
    expect(formatDuration(1800, "ru")).toContain("30");
  });
});
