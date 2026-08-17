import { describe, it, expect } from "vitest";
import { defaultImportGroup } from "./importTarget";
import { HOST_FILTER_ALL } from "@/store/app";

const GROUPS = [{ groupId: "prod-1712" }, { groupId: "staging-1713" }];

describe("defaultImportGroup", () => {
  it("targets the group the sidebar has selected", () => {
    expect(defaultImportGroup("prod-1712", GROUPS)).toBe("prod-1712");
  });

  it("targets nothing on the all-hosts view", () => {
    expect(defaultImportGroup(HOST_FILTER_ALL, GROUPS)).toBeNull();
  });

  it("targets nothing when the filter is a tag", () => {
    // hostFilter carries a tag, a group id or a sentinel in one field, so the
    // group list is the only thing that says which of them is in there. A tag
    // that happens to be selected must not become an import target.
    expect(defaultImportGroup("db", GROUPS)).toBeNull();
  });

  it("targets nothing on the untagged view", () => {
    expect(defaultImportGroup("__untagged", GROUPS)).toBeNull();
  });

  it("targets nothing when the vault has no groups at all", () => {
    expect(defaultImportGroup("prod-1712", [])).toBeNull();
  });
});
