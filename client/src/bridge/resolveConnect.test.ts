import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke, Channel: class {} }));

import { resolveConnectAuth } from "./api";
import type { ConnectionProfile } from "./types";

const profile = { profileId: "web" } as ConnectionProfile;

beforeEach(() => invoke.mockReset());

describe("resolveConnectAuth", () => {
  it("asks the core's resolver and fills in a password typed for the connection", async () => {
    invoke.mockResolvedValue({ user: "root", auth: { type: "password", password: "" }, askPassword: true });
    expect(await resolveConnectAuth(profile, "vault", "typed")).toEqual({
      user: "root",
      auth: { type: "password", password: "typed" },
    });
    expect(invoke).toHaveBeenCalledExactlyOnceWith("resolve_connection", { vaultId: "vault", profileId: "web" });
  });
});
