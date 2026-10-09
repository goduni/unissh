import { describe, it, expect } from "vitest";
import { compareByGroup, effectiveHostFilter, indexHostGroups, isUngrouped } from "./hostGroups";
import { HOST_FILTER_ALL, HOST_FILTER_UNGROUPED } from "@/store/app";

const g = (groupId: string, label: string, memberIds: string[]) => ({ groupId, label, memberIds });
const h = (profileId: string, label = profileId) => ({ profileId, label });

/** The order the group sort puts `hosts` in, as profile ids. */
const sorted = (groups: ReturnType<typeof g>[], hosts: ReturnType<typeof h>[]) =>
  [...hosts].sort(compareByGroup(indexHostGroups(groups))).map((x) => x.profileId);

describe("isUngrouped", () => {
  it("is true only for a host no group lists", () => {
    const index = indexHostGroups([g("1", "prod", ["web"])]);
    expect([isUngrouped(index, "web"), isUngrouped(index, "db")]).toEqual([false, true]);
  });
});

describe("compareByGroup", () => {
  it("orders the group blocks by group label", () => {
    const groups = [g("1", "staging", ["a"]), g("2", "prod", ["z"])];
    expect(sorted(groups, [h("a"), h("z")])).toEqual(["z", "a"]);
  });

  it("puts ungrouped hosts after every group", () => {
    const groups = [g("1", "zeta", ["z"])];
    expect(sorted(groups, [h("a"), h("z")])).toEqual(["z", "a"]);
  });

  it("orders hosts by name within a block", () => {
    const groups = [g("1", "prod", ["p2", "p1"])];
    const hosts = [h("u2", "delta"), h("p2", "beta"), h("u1", "charlie"), h("p1", "alpha")];
    expect(sorted(groups, hosts)).toEqual(["p1", "p2", "u1", "u2"]);
  });

  it("files a host that is in several groups under the first one by label", () => {
    // Stored staging-first on purpose: the group a host is filed under (and the
    // one the column names) must not depend on which group was created first.
    const groups = [g("1", "staging", ["multi", "s"]), g("2", "prod", ["multi"])];
    expect(sorted(groups, [h("s", "aaa"), h("multi", "zzz")])).toEqual(["multi", "s"]);
  });

  it("keeps two groups that share a label as separate blocks", () => {
    const groups = [g("1", "prod", ["a", "c"]), g("2", "prod", ["b"])];
    expect(sorted(groups, [h("a"), h("b"), h("c")])).toEqual(["a", "c", "b"]);
  });
});

describe("effectiveHostFilter", () => {
  it("reads the ungrouped filter as all hosts once the vault has no groups", () => {
    expect([
      effectiveHostFilter(HOST_FILTER_UNGROUPED, [g("1", "prod", [])]),
      effectiveHostFilter(HOST_FILTER_UNGROUPED, []),
    ]).toEqual([HOST_FILTER_UNGROUPED, HOST_FILTER_ALL]);
  });
});
