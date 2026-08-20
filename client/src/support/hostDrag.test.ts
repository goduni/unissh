import { describe, it, expect, beforeEach } from "vitest";
import { draggedHostIds, hostDrag } from "./hostDrag";

describe("draggedHostIds", () => {
  it("carries the whole selection when the grabbed host is in it", () => {
    expect(draggedHostIds("api", ["web", "api", "db"])).toEqual(["web", "api", "db"]);
  });

  it("carries only the grabbed host when it is outside the selection", () => {
    // Grabbing a host that isn't selected moves that host — not the six others
    // that happened to still be ticked, which the user would have to undo one
    // by one.
    expect(draggedHostIds("cache", ["web", "api", "db"])).toEqual(["cache"]);
  });

  it("carries the grabbed host when nothing is selected", () => {
    expect(draggedHostIds("web", [])).toEqual(["web"]);
  });

  it("does not duplicate a selection of one that is the grabbed host", () => {
    expect(draggedHostIds("web", ["web"])).toEqual(["web"]);
  });

  it("does not hand out the caller's selection array", () => {
    // The payload outlives the render that produced it; sharing the array would
    // let a later setSel mutation rewrite a drag already in flight.
    const sel = ["web", "api"];
    const carried = draggedHostIds("web", sel);
    expect(carried).not.toBe(sel);
  });
});

describe("hostDrag payload", () => {
  beforeEach(() => hostDrag.clear());

  it("is empty until a drag starts", () => {
    expect(hostDrag.get()).toEqual([]);
  });

  it("holds what the drag set", () => {
    hostDrag.set(["web", "api"]);
    expect(hostDrag.get()).toEqual(["web", "api"]);
  });

  it("is empty again once cleared", () => {
    // An Escape-cancelled or dropped-on-nothing drag ends here, so a later
    // unrelated drop can't consume a stale payload.
    hostDrag.set(["web"]);
    hostDrag.clear();
    expect(hostDrag.get()).toEqual([]);
  });
});
