import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SftpSession } from "@/store/sftp-types";

const { api } = vi.hoisted(() => ({
  api: { sftpStat: vi.fn(), sftpLstat: vi.fn(), sftpListDir: vi.fn(), localListDir: vi.fn(), localLstat: vi.fn(), localStat: vi.fn(), localRemove: vi.fn(), sftpReopen: vi.fn() },
}));
vi.mock("@/bridge/api", () => api);
import { sourceFor } from "./sources";

const remote = () => sourceFor({ kind: "remote", sessionId: "s" }, [{ id: "s", label: "server", host: "server", user: "user", port: 22 } as SftpSession]);
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
});


describe("link metadata", () => {
  it("recognizes remote links from READDIR permissions", async () => {
    api.sftpListDir.mockResolvedValue([{ filename: "lib64", isDir: false, size: 3, mode: 0o120777 }]);
    expect(await remote().list("/venv")).toEqual([expect.objectContaining({ name: "lib64", isSymlink: true })]);
  });
  it("uses LSTAT for dangling links without following them", async () => {
    api.sftpLstat.mockResolvedValue({ isDir: false, size: 3, mode: 0o120777 });
    expect(await remote().lstat("/broken")).toMatchObject({ isSymlink: true, size: 3 });
    expect(api.sftpStat).not.toHaveBeenCalled();
  });
  it.each([2, 3, 4])("preserves missing/error distinction for LSTAT status %s", async (status) => {
    const error = { kind: "ssh", msg: `sftp error: status ${status}: Failure` };
    api.sftpLstat.mockRejectedValue(error);
    if (status === 2) expect(await remote().lstat("/absent")).toBeNull();
    else await expect(remote().lstat("/link")).rejects.toEqual(error);
  });
  it("keeps local directory links as leaves", async () => {
    const entry = { name: "lib64", isDir: true, isSymlink: true, size: 3, mtime: 0 };
    api.localListDir.mockResolvedValue([entry]); api.localLstat.mockResolvedValue(entry);
    const local = sourceFor({ kind: "local" }, []);
    expect(await local.list("/venv")).toEqual([expect.objectContaining({ isDir: false, isSymlink: true })]);
    expect(await local.lstat("/venv/lib64")).toMatchObject({ isDir: false, isSymlink: true });
    expect(api.localStat).not.toHaveBeenCalled();
  });
});

describe("removing an emptied local folder", () => {
  it("refuses a path that is no longer a real directory", async () => {
    api.localLstat.mockResolvedValue({ name: "moved", isDir: true, isSymlink: true, size: 3, mtime: 0 });
    await expect(sourceFor({ kind: "local" }, []).removeEmptyDir("/src/moved")).rejects.toThrow("Not a directory");
    expect(api.localRemove).not.toHaveBeenCalled();
  });
});
