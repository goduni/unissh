import { beforeEach, expect, it, vi } from "vitest";
import type { ConnectionProfile } from "@/bridge/types";
const { state, api, epoch } = vi.hoisted(() => ({
  state: { vaultId: "vault", unlocked: true, sftpParallelism: 8, addSftpSession: vi.fn() },
  epoch: { value: 0 },
  api: { resolveConnectAuth: vi.fn(), sftpOpen: vi.fn(), sftpClose: vi.fn(), sftpRealpath: vi.fn() },
}));
vi.mock("@/store/app", () => ({ useApp: { getState: () => ({ ...state }) } }));
vi.mock("@/bridge/api", () => api);
vi.mock("@/sftp/transfer-runner", () => ({ teardownGeneration: () => epoch.value }));
vi.mock("@/store/toast", () => ({ toast: vi.fn() }));
import { openSession } from "./session";
beforeEach(() => {
  vi.resetAllMocks(); state.unlocked = true; state.vaultId = "vault"; epoch.value = 0;
  api.resolveConnectAuth.mockResolvedValue({ user: "u", auth: {} });
  api.sftpRealpath.mockResolvedValue("/"); api.sftpClose.mockResolvedValue(undefined);
});
it.each(["lock", "switch", "epoch"])("closes a late session after %s", async (kind) => {
  api.sftpOpen.mockImplementation(async () => {
    if (kind === "lock") state.unlocked = false;
    if (kind === "switch") state.vaultId = "next";
    if (kind === "epoch") epoch.value++;
    return "late";
  });
  expect(await openSession({ host: "server", port: 22 } as ConnectionProfile)).toBeNull();
  expect(state.addSftpSession).not.toHaveBeenCalled();
  expect(api.sftpClose).toHaveBeenCalledExactlyOnceWith("late");
});
