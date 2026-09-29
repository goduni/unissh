import { describe, expect, it } from "vitest";
import { visibleRows } from "./virtualRows";

describe("file list window", () => {
  it("bounds the rendered rows in a 50,000-file directory", () => {
    for (const rowHeight of [27, 30, 33, 37.5, 45, 44]) {
      for (const top of [-60, 0, 15000, 50000 * rowHeight - 800]) {
        const { start, end } = visibleRows(50000, rowHeight, top, 800);
        expect(start).toBeGreaterThanOrEqual(0);
        expect(end).toBeLessThanOrEqual(50000);
        expect(end - start).toBeLessThanOrEqual(Math.ceil(800 / rowHeight) + 17);
        const firstVisible = Math.max(0, Math.floor(top / rowHeight));
        const lastVisible = Math.min(50000, Math.ceil((top + 800) / rowHeight));
        expect(start).toBeLessThanOrEqual(firstVisible);
        expect(end).toBeGreaterThanOrEqual(lastVisible);
      }
    }
  });

  it("keeps the remaining matches mounted before a stale scroll position resets", () => {
    expect(visibleRows(3, 30, 1000000, 800)).toEqual({ start: 0, end: 3 });
    expect(visibleRows(0, 30, 1000000, 800)).toEqual({ start: 0, end: 0 });
  });

  it("includes the last row and overscan at the end", () => {
    expect(visibleRows(50000, 30, 1499970, 800)).toEqual({ start: 49991, end: 50000 });
  });
});
