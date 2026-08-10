import { describe, expect, it } from "vitest";
import { isWinRoot, trimTrailing, volumeName, volumeOf } from "./volumes";
import type { LocalVolume } from "@/bridge/types";

const vol = (path: string, label = ""): LocalVolume => ({
  label,
  path,
  totalBytes: 1000,
  freeBytes: 500,
  removable: false,
});

describe("isWinRoot", () => {
  it("accepts a drive root with or without a separator", () => {
    expect(isWinRoot("C:")).toBe(true);
    expect(isWinRoot("C:\\")).toBe(true);
    expect(isWinRoot("d:/")).toBe(true);
  });
  it("rejects anything deeper, and unix paths", () => {
    expect(isWinRoot("C:\\Users")).toBe(false);
    expect(isWinRoot("/")).toBe(false);
    expect(isWinRoot("/media/me/C:")).toBe(false);
  });
});

describe("trimTrailing", () => {
  it("drops a trailing separator but keeps the unix root", () => {
    expect(trimTrailing("C:\\")).toBe("C:");
    expect(trimTrailing("/media/me/USB/")).toBe("/media/me/USB");
    expect(trimTrailing("/")).toBe("/");
  });
});

describe("volumeName", () => {
  it("names a Windows drive by its letter, even when it has a label", () => {
    expect(volumeName(vol("C:\\", "Windows"))).toBe("C:");
  });
  it("prefers the OS label over the mount point", () => {
    expect(volumeName(vol("/media/me/disk1", "Backup"))).toBe("Backup");
  });
  it("falls back to the last path segment, then the path", () => {
    expect(volumeName(vol("/media/me/USB"))).toBe("USB");
    expect(volumeName(vol("/"))).toBe("/");
  });
});

describe("volumeOf", () => {
  const win = [vol("C:\\", "Windows"), vol("D:\\", "Data")];
  const unix = [vol("/"), vol("/home"), vol("/media/me/USB")];

  it("matches a Windows path case-insensitively and across separators", () => {
    expect(volumeOf(win, "c:/Users/max")?.path).toBe("C:\\");
    expect(volumeOf(win, "D:\\work\\repo")?.path).toBe("D:\\");
  });
  it("picks the deepest mount point, not the first that matches", () => {
    expect(volumeOf(unix, "/home/me/docs")?.path).toBe("/home");
    expect(volumeOf(unix, "/media/me/USB/photos")?.path).toBe("/media/me/USB");
    expect(volumeOf(unix, "/etc")?.path).toBe("/");
  });
  it("matches a mount point exactly", () => {
    expect(volumeOf(unix, "/home")?.path).toBe("/home");
    expect(volumeOf(win, "C:\\")?.path).toBe("C:\\");
  });
  it("does not match a sibling that merely shares a prefix", () => {
    expect(volumeOf([vol("/mnt/data")], "/mnt/database")).toBeNull();
  });
  it("returns null for an empty cwd or an empty list", () => {
    expect(volumeOf(unix, "")).toBeNull();
    expect(volumeOf([], "/home/me")).toBeNull();
  });
});
