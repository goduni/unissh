import { describe, it, expect } from "vitest";
import { nextRow, pickerRows, type PickerHost } from "./pickerRows";

const HOSTS: PickerHost[] = [
  { label: "prod-db", host: "10.0.0.5", port: 22, user: "deploy" },
  { label: "Edge", host: "edge.example.com", port: 2222, user: "root" },
];

const labels = (rows: ReturnType<typeof pickerRows>) =>
  rows.map((r) => (r.kind === "local" ? "<local>" : r.host.label));

describe("pickerRows", () => {
  it("keeps every host, in order, when nothing is typed", () => {
    expect(labels(pickerRows(HOSTS, "", null))).toEqual(["prod-db", "Edge"]);
  });

  it("matches a label regardless of case", () => {
    expect(labels(pickerRows(HOSTS, "EDGE", null))).toEqual(["Edge"]);
  });

  it("matches the address the row actually shows", () => {
    // The row prints user@host:port, so that whole string is searchable — typing
    // "deploy@" or ":2222" has to find the host it is printed under.
    expect(labels(pickerRows(HOSTS, "deploy@10.0.0.5", null))).toEqual(["prod-db"]);
    expect(labels(pickerRows(HOSTS, ":2222", null))).toEqual(["Edge"]);
  });

  it("ignores surrounding whitespace in the query", () => {
    expect(labels(pickerRows(HOSTS, "  edge  ", null))).toEqual(["Edge"]);
  });

  it("returns no rows when nothing matches", () => {
    expect(pickerRows(HOSTS, "nothing-here", null)).toEqual([]);
  });

  it("leads with the local row when the picker offers one", () => {
    expect(labels(pickerRows(HOSTS, "", "Local shell this machine"))).toEqual([
      "<local>",
      "prod-db",
      "Edge",
    ]);
  });

  it("filters the local row like any other row", () => {
    // A list being narrowed that keeps one row regardless reads as a bug.
    expect(labels(pickerRows(HOSTS, "shell", "Local shell this machine"))).toEqual(["<local>"]);
    expect(labels(pickerRows(HOSTS, "edge", "Local shell this machine"))).toEqual(["Edge"]);
  });

  it("omits the local row entirely when the picker has no local target", () => {
    expect(labels(pickerRows(HOSTS, "", null))).not.toContain("<local>");
  });
});

describe("nextRow", () => {
  it("steps forward and back", () => {
    expect(nextRow(0, 1, 3)).toBe(1);
    expect(nextRow(2, -1, 3)).toBe(1);
  });

  it("wraps at both ends, so the keyboard never dead-ends", () => {
    expect(nextRow(2, 1, 3)).toBe(0);
    expect(nextRow(0, -1, 3)).toBe(2);
  });

  it("stays at zero when there is nothing to move through", () => {
    expect(nextRow(0, 1, 0)).toBe(0);
  });

  it("comes back to the nearest edge when the list shrank under the highlight", () => {
    // Typing narrows the list while the highlight sits past its new end. That is
    // not a position to step from, so the next key lands on an edge rather than
    // wherever the arithmetic happens to fall.
    expect(nextRow(7, 1, 3)).toBe(0);
    expect(nextRow(7, -1, 3)).toBe(2);
  });
});
