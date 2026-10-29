import { describe, expect, it } from "vitest";
import type { ConnectionProfile, ProfileAuth } from "@/bridge/types";
import { NEW_GROUP, groupChoice, hopCandidates, identityToLink } from "./hostSave";

function host(profileId: string, auth: ProfileAuth, uid = `uid-${profileId}`): ConnectionProfile {
  return {
    profileId,
    uid,
    label: profileId,
    host: `${profileId}.example`,
    port: 22,
    user: "root",
    auth,
    jumps: [],
    tags: [],
    startupSnippetIds: [],
    recordSessions: false,
    agentForward: false,
  };
}

describe("hopCandidates", () => {
  it("offers key, stored-password and system-agent hosts, not the host itself", () => {
    const hosts = [
      host("key", { type: "key", keyItemId: "k" }),
      host("pw", { type: "vaultPassword", passwordItemId: "p" }),
      host("agent", { type: "systemAgent", publicKey: "ssh-ed25519 AAAA" }),
      host("ask", { type: "promptPassword" }),
      host("personal", { type: "personal" }),
      host("no-uid", { type: "key", keyItemId: "k" }, ""),
      host("self", { type: "key", keyItemId: "k" }),
    ];
    expect(hopCandidates(hosts, "self").map((h) => h.profileId)).toEqual(["key", "pw", "agent"]);
  });
});

describe("groupChoice", () => {
  it("maps the picker onto the core's group choice", () => {
    expect(groupChoice("g1", "")).toEqual({ type: "existing", groupId: "g1" });
    expect(groupChoice("", "")).toEqual({ type: "ungrouped" });
    expect(groupChoice(NEW_GROUP, "  Prod ")).toEqual({ type: "new", label: "Prod" });
    // A pending group whose name was cleared is no group.
    expect(groupChoice(NEW_GROUP, " ")).toEqual({ type: "ungrouped" });
  });
});

describe("identityToLink", () => {
  it("links a picked identity to a personal host only", () => {
    expect(identityToLink(true, "pv", "me")).toEqual({ vaultId: "pv", identityId: "me" });
    expect(identityToLink(false, "pv", "me")).toBeNull();
    expect(identityToLink(true, null, "me")).toBeNull();
    expect(identityToLink(true, "pv", "")).toBeNull();
  });
});
