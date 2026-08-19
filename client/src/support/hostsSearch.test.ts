import { describe, expect, it } from "vitest";

import { filterHosts, matchesQuery, searchKeyAction } from "./hostsSearch";

const host = (label: string, over: Partial<Parameters<typeof matchesQuery>[0]> = {}) => ({
  label,
  host: "10.0.0.1",
  user: "root",
  tags: [] as string[],
  ...over,
});

describe("matchesQuery", () => {
  it("keeps everything for an empty or blank query", () => {
    expect(matchesQuery(host("prod-db"), "")).toBe(true);
    expect(matchesQuery(host("prod-db"), "   ")).toBe(true);
  });

  it("matches the label, address, user and tags", () => {
    const h = host("prod-db", { host: "db.example.com", user: "deploy", tags: ["prod", "eu"] });
    expect(matchesQuery(h, "prod-db")).toBe(true);
    expect(matchesQuery(h, "example.com")).toBe(true);
    expect(matchesQuery(h, "deploy")).toBe(true);
    expect(matchesQuery(h, "eu")).toBe(true);
    expect(matchesQuery(h, "staging")).toBe(false);
  });

  it("is case-insensitive and ignores the whitespace people type around a word", () => {
    expect(matchesQuery(host("PROD-DB"), "prod")).toBe(true);
    expect(matchesQuery(host("prod-db"), "  PROD  ")).toBe(true);
  });

  it("matches on a substring, not only a prefix", () => {
    expect(matchesQuery(host("eu-prod-db"), "prod")).toBe(true);
  });
});

describe("filterHosts", () => {
  const hosts = [
    host("alpha", { tags: ["prod"] }),
    host("beta", { host: "beta.internal" }),
    host("gamma", { user: "prod-deploy" }),
  ];

  it("returns the list untouched when nothing was typed", () => {
    expect(filterHosts(hosts, "")).toEqual(hosts);
    expect(filterHosts(hosts, "  ")).toEqual(hosts);
  });

  it("keeps the given order — sorting is the sort control's job, not the query's", () => {
    expect(filterHosts(hosts, "prod").map((h) => h.label)).toEqual(["alpha", "gamma"]);
  });

  it("can match nothing", () => {
    expect(filterHosts(hosts, "nonesuch")).toEqual([]);
  });
});

// What a keystroke in the search box does — the rule the reported bug was about.
// The component only dispatches this, so these ARE the key bindings.
describe("searchKeyAction", () => {
  const typed = { hasQuery: true, hasHit: true };

  it("opens on Enter and connects on ⌘/Ctrl+Enter", () => {
    expect(searchKeyAction({ key: "Enter" }, typed)).toEqual({ kind: "open" });
    expect(searchKeyAction({ key: "Enter", metaKey: true }, typed)).toEqual({ kind: "connect" });
    expect(searchKeyAction({ key: "Enter", ctrlKey: true }, typed)).toEqual({ kind: "connect" });
  });

  it("does nothing on Enter with an empty box", () => {
    // A phone's Return key is always there; without this it would open whichever
    // host happens to be first and push the user into a detail screen.
    expect(searchKeyAction({ key: "Enter" }, { hasQuery: false, hasHit: true })).toBeNull();
  });

  it("does nothing on Enter when the query matches nothing", () => {
    expect(searchKeyAction({ key: "Enter" }, { hasQuery: true, hasHit: false })).toBeNull();
  });

  it("ignores the Enter that commits an IME candidate", () => {
    expect(searchKeyAction({ key: "Enter", isComposing: true }, typed)).toBeNull();
  });

  it("moves the highlight with the arrows, typed or not", () => {
    expect(searchKeyAction({ key: "ArrowDown" }, typed)).toEqual({ kind: "move", delta: 1 });
    expect(searchKeyAction({ key: "ArrowUp" }, typed)).toEqual({ kind: "move", delta: -1 });
  });

  it("clears on Escape only when there is something to clear", () => {
    // On an empty box Escape belongs to the rail or the dialog stack above.
    expect(searchKeyAction({ key: "Escape" }, typed)).toEqual({ kind: "clear" });
    expect(searchKeyAction({ key: "Escape" }, { hasQuery: false, hasHit: false })).toBeNull();
  });

  it("leaves ordinary typing alone", () => {
    expect(searchKeyAction({ key: "a" }, typed)).toBeNull();
    expect(searchKeyAction({ key: "Tab" }, typed)).toBeNull();
  });
});
