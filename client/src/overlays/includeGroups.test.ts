import { describe, it, expect } from "vitest";
import {
  groupFile,
  includeGroupName,
  planIncludeGroups,
  planIncludeGroupWrites,
} from "./includeGroups";

const CONFIG = "/home/u/.ssh/config";

/** A host from `file`, or from the picked config when `file` is null. */
const host = (alias: string, file: string | null) => ({ alias, originFile: file });

const plan = (over: Partial<Parameters<typeof planIncludeGroups>[0]> = {}) =>
  planIncludeGroups({
    configPath: CONFIG,
    hosts: [],
    files: [],
    subgroups: true,
    optedOut: [],
    target: null,
    groups: [],
    ...over,
  });

describe("includeGroupName", () => {
  it("names the group after the directory when the file is that directory's config", () => {
    expect(includeGroupName("/home/u/.ssh/project1/config", CONFIG)).toBe("project1");
  });

  it("names the group after the file when a directory holds several configs", () => {
    expect(includeGroupName("/home/u/.ssh/conf.d/work.conf", CONFIG)).toBe("work");
    expect(includeGroupName("/home/u/.ssh/conf.d/home", CONFIG)).toBe("home");
  });

  it("falls back to the file name for a config beside the one that was picked", () => {
    // `.ssh` is not a project, and the directory rule would name the group after it.
    expect(includeGroupName("/home/u/.ssh/config.local", CONFIG)).toBe("config.local");
    expect(includeGroupName("/home/u/.ssh/config", CONFIG)).toBe("config");
  });

  it("reads Windows paths", () => {
    expect(
      includeGroupName("C:\\Users\\u\\.ssh\\project1\\config", "C:\\Users\\u\\.ssh\\config"),
    ).toBe("project1");
  });
});

describe("planIncludeGroups", () => {
  it("turns each included file into a group holding its hosts", () => {
    const p = plan({
      hosts: [
        host("a", "/home/u/.ssh/project1/config"),
        host("b", "/home/u/.ssh/project1/config"),
        host("c", "/home/u/.ssh/project2/config"),
      ],
    });
    expect(p.groups.map((g) => g.label)).toEqual(["project1", "project2"]);
    expect(p.groups[0].aliases).toEqual(["a", "b"]);
    expect(p.groups[1].aliases).toEqual(["c"]);
    expect(p.ungrouped).toEqual([]);
  });

  it("leaves the picked config's own hosts in the target", () => {
    const p = plan({
      hosts: [host("local", null), host("a", "/home/u/.ssh/project1/config")],
    });
    expect(p.ungrouped).toEqual(["local"]);
    expect(p.groups).toHaveLength(1);
  });

  it("treats a host attributed to the picked config as the config's own", () => {
    // The core reports the picked file by path when it is reached through an
    // include of itself; it is still not a subgroup.
    const p = plan({ hosts: [host("local", CONFIG)] });
    expect(p.ungrouped).toEqual(["local"]);
    expect(p.groups).toEqual([]);
  });

  it("creates nothing when subgrouping is switched off", () => {
    const p = plan({
      subgroups: false,
      hosts: [host("a", "/home/u/.ssh/project1/config")],
    });
    expect(p.groups).toEqual([]);
    expect(p.ungrouped).toEqual(["a"]);
  });

  it("drops one file's group on opt-out and leaves its hosts in the target", () => {
    const p = plan({
      optedOut: ["/home/u/.ssh/project2/config"],
      hosts: [
        host("a", "/home/u/.ssh/project1/config"),
        host("c", "/home/u/.ssh/project2/config"),
      ],
    });
    expect(p.groups.map((g) => g.label)).toEqual(["project1"]);
    expect(p.ungrouped).toEqual(["c"]);
  });

  it("reuses an existing group with the same name under the same parent", () => {
    // Repeated imports have to converge instead of multiplying groups.
    const p = plan({
      groups: [{ groupId: "g-project1", label: "project1", parentId: null }],
      hosts: [host("a", "/home/u/.ssh/project1/config")],
    });
    expect(p.groups[0].existingId).toBe("g-project1");
  });

  it("does not reuse a same-named group under a different parent", () => {
    const p = plan({
      target: "g-work",
      groups: [{ groupId: "g-project1", label: "project1", parentId: null }],
      hosts: [host("a", "/home/u/.ssh/project1/config")],
    });
    expect(p.groups[0].existingId).toBeNull();
    expect(p.groups[0].parentId).toBe("g-work");
  });

  it("matches an existing group's name regardless of case and padding", () => {
    const p = plan({
      groups: [{ groupId: "g1", label: " Project1 ", parentId: null }],
      hosts: [host("a", "/home/u/.ssh/project1/config")],
    });
    expect(p.groups[0].existingId).toBe("g1");
  });

  it("nests derived groups under the chosen target group", () => {
    const p = plan({
      target: "g-work",
      hosts: [host("a", "/home/u/.ssh/project1/config")],
    });
    expect(p.groups[0].parentId).toBe("g-work");
  });

  it("creates derived groups at the root when there is no target", () => {
    const p = plan({ hosts: [host("a", "/home/u/.ssh/project1/config")] });
    expect(p.groups[0].parentId).toBeNull();
  });

  it("collapses two files that derive the same name into one group", () => {
    const p = plan({
      hosts: [host("a", "/home/u/.ssh/work/config"), host("b", "/home/u/.ssh/other/work.conf")],
    });
    expect(p.groups).toHaveLength(1);
    expect(p.groups[0].label).toBe("work");
    expect(p.groups[0].aliases).toEqual(["a", "b"]);
    expect(p.groups[0].files).toEqual([
      "/home/u/.ssh/work/config",
      "/home/u/.ssh/other/work.conf",
    ]);
  });

  it("places only the hosts it was given", () => {
    // The preview's checkboxes decide what is imported; the plan places what
    // arrives and never resurrects a host the user unticked.
    const p = plan({ hosts: [host("a", "/home/u/.ssh/project1/config")] });
    expect(p.groups[0].aliases).toEqual(["a"]);
  });
});

describe("planIncludeGroupWrites", () => {
  const id = (label: string, i: number) => `new-${label}-${i}`;
  const g = (
    groupId: string,
    memberIds: string[],
    label: string = groupId,
    parentId: string | null = null,
  ) => ({ groupId, label, memberIds, parentId });

  it("creates a group holding the file's hosts, under the target", () => {
    const p = plan({
      target: "g-work",
      hosts: [host("a", "/home/u/.ssh/project1/config")],
    });
    const writes = planIncludeGroupWrites([g("g-work", [])], p, "g-work", id);
    const made = writes.find((w) => w.label === "project1");
    expect(made).toEqual({
      groupId: "new-project1-0",
      label: "project1",
      memberIds: ["a"],
      parentId: "g-work",
    });
  });

  it("adds to the existing group rather than creating a second one", () => {
    const existing = [g("g-project1", ["old"], "project1")];
    const p = plan({ groups: existing, hosts: [host("a", "/home/u/.ssh/project1/config")] });
    const writes = planIncludeGroupWrites(existing, p, null, id);
    expect(writes).toEqual([g("g-project1", ["old", "a"], "project1")]);
  });

  it("takes a re-imported host out of the group it used to be in", () => {
    // Moving a host between included files has to move it between groups, not
    // leave it in both.
    const existing = [g("g-old", ["a"]), g("g-project1", [], "project1")];
    const p = plan({
      groups: existing,
      hosts: [host("a", "/home/u/.ssh/project1/config")],
    });
    const writes = planIncludeGroupWrites(existing, p, null, id);
    expect(writes.find((w) => w.groupId === "g-old")!.memberIds).toEqual([]);
    expect(writes.find((w) => w.groupId === "g-project1")!.memberIds).toEqual(["a"]);
  });

  it("writes nothing for a group that did not change", () => {
    // Every write is a vault item, a sync object and an audit line.
    const existing = [g("g-untouched", ["x"]), g("g-project1", ["a"], "project1")];
    const p = plan({
      groups: existing,
      hosts: [host("a", "/home/u/.ssh/project1/config")],
    });
    // A host already in the right group is taken out and put straight back,
    // which is not a change.
    expect(planIncludeGroupWrites(existing, p, null, id)).toEqual([]);
  });

  it("puts the ungrouped hosts in the target group", () => {
    const existing = [g("g-work", [])];
    const p = plan({ target: "g-work", hosts: [host("local", null)] });
    const writes = planIncludeGroupWrites(existing, p, "g-work", id);
    expect(writes).toEqual([g("g-work", ["local"])]);
  });

  it("leaves the ungrouped hosts at the root when there is no target", () => {
    const p = plan({ hosts: [host("local", null)] });
    expect(planIncludeGroupWrites([], p, null, id)).toEqual([]);
  });
});

describe("groupFile", () => {
  const files = [
    { path: CONFIG, includedBy: null },
    { path: "/home/u/.ssh/project1/config", includedBy: CONFIG },
    { path: "/home/u/.ssh/project1/hosts.conf", includedBy: "/home/u/.ssh/project1/config" },
  ];

  it("groups a nested include by the include the picked config made", () => {
    // One project whose hosts are split across two files is one group, not two,
    // and a deep include tree must not become a deep group tree.
    expect(groupFile("/home/u/.ssh/project1/hosts.conf", CONFIG, files)).toBe(
      "/home/u/.ssh/project1/config",
    );
  });

  it("leaves a file the picked config included directly alone", () => {
    expect(groupFile("/home/u/.ssh/project1/config", CONFIG, files)).toBe(
      "/home/u/.ssh/project1/config",
    );
  });

  it("falls back to the file itself when the chain is unknown", () => {
    expect(groupFile("/home/u/.ssh/x/config", CONFIG, [])).toBe("/home/u/.ssh/x/config");
  });

  it("puts a nested include's hosts in the including file's group", () => {
    const p = planIncludeGroups({
      configPath: CONFIG,
      files,
      hosts: [
        { alias: "a", originFile: "/home/u/.ssh/project1/config" },
        { alias: "b", originFile: "/home/u/.ssh/project1/hosts.conf" },
      ],
      subgroups: true,
      optedOut: [],
      target: null,
      groups: [],
    });
    expect(p.groups).toHaveLength(1);
    expect(p.groups[0].label).toBe("project1");
    expect(p.groups[0].aliases).toEqual(["a", "b"]);
  });

  it("opts a whole include out by the file the picked config named", () => {
    const p = planIncludeGroups({
      configPath: CONFIG,
      files,
      hosts: [{ alias: "b", originFile: "/home/u/.ssh/project1/hosts.conf" }],
      subgroups: true,
      optedOut: ["/home/u/.ssh/project1/config"],
      target: null,
      groups: [],
    });
    expect(p.groups).toEqual([]);
    expect(p.ungrouped).toEqual(["b"]);
  });
});
