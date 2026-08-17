import { describe, it, expect } from "vitest";
import { planGroupMove } from "./groupMove";
import type { ServerGroup } from "@/bridge/types";

const g = (groupId: string, memberIds: string[]): ServerGroup => ({
  groupId,
  label: groupId,
  memberIds,
  parentId: null,
});

describe("planGroupMove", () => {
  it("adds the hosts to the target group", () => {
    const plan = planGroupMove([g("prod", ["web"])], "prod", ["db"]);
    expect(plan).toEqual([g("prod", ["web", "db"])]);
  });

  it("takes the hosts out of every other group", () => {
    // Membership is exclusive wherever it is edited — the host modal drops the
    // previous group on save — so leaving a host in two is a state the editor
    // silently repairs by dropping one of them.
    const plan = planGroupMove([g("staging", ["web", "api"]), g("prod", [])], "prod", ["web"]);
    expect(plan).toEqual([g("staging", ["api"]), g("prod", ["web"])]);
  });

  it("writes nothing when the hosts are already exactly there", () => {
    expect(planGroupMove([g("prod", ["web"]), g("staging", [])], "prod", ["web"])).toEqual([]);
  });

  it("leaves other members of the source group alone", () => {
    const plan = planGroupMove([g("staging", ["web", "api", "db"]), g("prod", [])], "prod", ["api"]);
    expect(plan[0].memberIds).toEqual(["web", "db"]);
  });

  it("does not add a duplicate when the host is already in the target", () => {
    const plan = planGroupMove([g("prod", ["web"])], "prod", ["web", "db"]);
    expect(plan).toEqual([g("prod", ["web", "db"])]);
  });

  it("writes nothing when the target group is gone", () => {
    // Deleted by a sync or another window between choosing it and importing.
    // Half a move — evicting the hosts from where they were — would be worse
    // than none.
    expect(planGroupMove([g("staging", ["web"])], "prod", ["web"])).toEqual([]);
  });

  it("writes nothing for an empty host list", () => {
    expect(planGroupMove([g("prod", [])], "prod", [])).toEqual([]);
  });
});
