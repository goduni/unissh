import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SftpSession } from "@/store/sftp-types";

const { api, fs } = vi.hoisted(() => ({
  api: { sftpStat: vi.fn(), sftpReopen: vi.fn() },
  fs: { stat: vi.fn() },
}));
vi.mock("@/bridge/api", () => api);
vi.mock("@tauri-apps/plugin-fs", () => fs);
import { sourceFor } from "./sources";

const remote = () => sourceFor({ kind: "remote", sessionId: "s" }, [{ id: "s", label: "server" } as SftpSession]);
beforeEach(() => { vi.resetAllMocks(); });

describe("conflict metadata failures", () => {
  it("treats only SFTP no-such-file as a missing target", async () => {
    api.sftpStat.mockRejectedValue({ kind: "ssh", msg: "sftp error: status 2: No such file" });
    expect(await remote().stat("/target")).toBeNull();
  });
  it.each([3, 4, 20])("preserves SFTP status %s instead of bypassing the conflict check", async (code) => {
    const error = { kind: "ssh", msg: `sftp error: status ${code}: Failure` };
    api.sftpStat.mockRejectedValue(error);
    await expect(remote().stat("/target")).rejects.toEqual(error);
  });
  it("preserves a failed reconnect", async () => {
    api.sftpStat.mockRejectedValue({ kind: "ssh", msg: "channel closed" });
    const error = { kind: "ssh", msg: "connection failed" };
    api.sftpReopen.mockRejectedValue(error);
    await expect(remote().stat("/target")).rejects.toEqual(error);
  });
  it.each([2, 3])("recognizes missing local paths with OS error %s", async (code) => {
    fs.stat.mockRejectedValue(`failed to read metadata (os error ${code})`);
    expect(await sourceFor({ kind: "local" }, []).stat("/target")).toBeNull();
  });
  it("preserves local permission failures", async () => {
    fs.stat.mockRejectedValue("Permission denied (os error 13)");
    await expect(sourceFor({ kind: "local" }, []).stat("/target")).rejects.toBe("Permission denied (os error 13)");
  });
});
