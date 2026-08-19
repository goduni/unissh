import { describe, expect, it } from "vitest";

import { filterHosts, matchesQuery } from "./hostsSearch";
import { nextRow } from "@/support/listNav";

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

// The highlight the search drives: Enter acts on `shown[cursor]`, so these are the
// rules that decide WHICH host a keystroke opens.
describe("nextRow, as the Hosts search uses it", () => {
  it("wraps at both ends", () => {
    expect(nextRow(2, 1, 3)).toBe(0);
    expect(nextRow(0, -1, 3)).toBe(2);
  });

  it("lands on an edge when the list shrank under the highlight", () => {
    // Typing another letter can cut the list from 9 matches to 2 — a stale index
    // must not step to an arbitrary row.
    expect(nextRow(8, 1, 2)).toBe(0);
    expect(nextRow(8, -1, 2)).toBe(1);
  });

  it("stays at 0 when nothing matches, so Enter has nothing to open", () => {
    expect(nextRow(-1, 1, 0)).toBe(0);
  });
});
