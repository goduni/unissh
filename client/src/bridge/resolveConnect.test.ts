import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke, Channel: class {} }));

import { resolveConnection, resolveConnectionProfile } from "./api";
import { passwordFillMode } from "@/views/terminal/paneSession";
import type { ConnectionProfile } from "./types";

beforeEach(() => invoke.mockReset());

describe("resolveConnection", () => {
  it("uses the resolved gateway profile for session policy as well as destination", async () => {
    const profile = {
      profileId: "db", host: "gateway.example", label: "Production gateway",
      usernameTemplate: "%u:db", agentForward: false, recordSessions: true,
    } as ConnectionProfile;
    invoke.mockResolvedValue({
      profile, host: profile.host, port: 22, user: "alice:db",
      auth: { type: "vaultPassword", vaultId: "personal", passwordItemId: "pw" },
      jumps: [], proxy: null, askPassword: false,
    });
    const resolved = await resolveConnectionProfile("db", "team");
    expect(resolved.connection).toMatchObject({ host: "gateway.example", user: "alice:db" });
    expect(resolved.profile).toEqual(profile);
    expect(passwordFillMode(resolved.profile, true, true)).toBe("off");
    expect(resolved.profile).toMatchObject({ agentForward: false, recordSessions: true });
  });
  it("asks the core's resolver and fills in a password typed for the connection", async () => {
    const profile = { profileId: "web", host: "web.example", port: 22, jumps: [] } as unknown as ConnectionProfile;
    invoke.mockResolvedValue({
      host: "web.example",
      port: 22,
      user: "root",
      auth: { type: "password", password: "" },
      jumps: [],
      proxy: null,
      askPassword: true,
    });
    expect(await resolveConnection(profile, "vault", "typed")).toEqual({
      host: "web.example",
      port: 22,
      user: "root",
      auth: { type: "password", password: "typed" },
      jumps: [],
      proxy: null,
    });
    expect(invoke).toHaveBeenCalledExactlyOnceWith("resolve_connection", { vaultId: "vault", profileId: "web" });
  });

  it("connects to the destination the core checked, not to a stale profile copy", async () => {
    // The pane still holds the profile as it was when it opened (redirected);
    // the vault has it back on the pinned host, which the core checked.
    const stale = { profileId: "db", host: "evil.example", port: 2222, jumps: [] } as unknown as ConnectionProfile;
    const pinnedHop = { host: "bastion", port: 22, user: "ops", auth: { type: "agent", vaultId: "v", keyItemId: "k" } };
    invoke.mockResolvedValue({
      host: "db.internal",
      port: 22,
      user: "alice",
      auth: { type: "vaultPassword", vaultId: "personal", passwordItemId: "pw" },
      jumps: [pinnedHop],
      proxy: null,
      askPassword: false,
    });
    const dest = await resolveConnection(stale, "team");
    expect(dest).toMatchObject({ host: "db.internal", port: 22, jumps: [pinnedHop] });
  });
});
