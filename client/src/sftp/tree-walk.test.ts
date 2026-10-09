import { describe, expect, it, vi } from "vitest";
import type { FileSource } from "@/bridge/sources";
import type { Entry } from "@/store/sftp-types";
import { Semaphore } from "./transfer-engine";
import { folderSize } from "./tree-walk";

const file = (name: string, size: number): Entry => ({ name, isDir: false, size });
const dir = (name: string): Entry => ({ name, isDir: true, size: 4096 });

/** A source over an in-memory tree keyed by path; a missing path cannot be read. */
function fakeSource(tree: Record<string, Entry[]>, onList?: (path: string) => Promise<void> | void) {
  const list = vi.fn(async (path: string) => {
    await onList?.(path);
    if (!tree[path]) throw new Error(`Permission denied: ${path}`);
    return [...tree[path]];
  });
  const join = async (base: string, name: string) => `${base}/${name}`;
  return { src: { list, join } as unknown as FileSource, list };
}

describe("folder size", () => {
  it("sums the files of a nested tree", async () => {
    const { src } = fakeSource({
      "/r": [file("a.txt", 10), dir("sub"), dir("empty")],
      "/r/sub": [file("b.txt", 20), dir("deep")],
      "/r/sub/deep": [file("c.txt", 30)],
      "/r/empty": [],
    });
    expect(await folderSize(src, "/r", { sem: new Semaphore(2) })).toEqual({ bytes: 60, entries: 6, skipped: 0, partial: false });
  });

  it("does not follow links: a link loop ends and adds nothing", async () => {
    const { src, list } = fakeSource({
      "/r": [file("a.txt", 10), { name: "loop", isDir: true, isSymlink: true, size: 2 }, { name: "big", isDir: false, isSymlink: true, size: 900 }],
      "/r/loop": [dir("r")],
      "/r/loop/r": [file("a.txt", 10), { name: "loop", isDir: true, isSymlink: true, size: 2 }],
    });
    expect((await folderSize(src, "/r", { sem: new Semaphore(2) })).bytes).toBe(10);
    expect(list).toHaveBeenCalledExactlyOnceWith("/r");
  });

  it("counts around a subdirectory it cannot read and marks the result partial", async () => {
    const { src } = fakeSource({
      "/r": [file("a.txt", 10), dir("locked"), dir("open")],
      "/r/open": [file("b.txt", 5)],
    });
    expect(await folderSize(src, "/r", { sem: new Semaphore(2) })).toMatchObject({ bytes: 15, skipped: 1, partial: true });
  });

  it("stops listing once aborted and rejects with the abort reason", async () => {
    const abort = new AbortController();
    const { src, list } = fakeSource(
      { "/r": [dir("a"), dir("b"), dir("c")], "/r/a": [dir("x")], "/r/b": [], "/r/c": [], "/r/a/x": [] },
      (path) => { if (path === "/r/a") abort.abort(new Error("cancelled by user")); },
    );
    await expect(folderSize(src, "/r", { sem: new Semaphore(1), signal: abort.signal })).rejects.toThrow("cancelled by user");
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(list.mock.calls.map(([path]) => path)).toEqual(["/r", "/r/a"]);
  });

  it("never lists more directories at once than the semaphore allows", async () => {
    let inFlight = 0;
    let peak = 0;
    const names = Array.from({ length: 12 }, (_, i) => `d${i}`);
    const { src } = fakeSource(
      { "/r": names.map(dir), ...Object.fromEntries(names.map((n) => [`/r/${n}`, [file("f", 1)]])) },
      async () => {
        peak = Math.max(peak, ++inFlight);
        await new Promise((resolve) => setTimeout(resolve, 1));
        inFlight -= 1;
      },
    );
    expect((await folderSize(src, "/r", { sem: new Semaphore(3) })).bytes).toBe(12);
    expect(peak).toBe(3);
  });

  it("reports running totals no more often than the throttle interval", async () => {
    const { src } = fakeSource({
      "/r": [file("a", 1), dir("s1")],
      "/r/s1": [file("b", 2), dir("s2")],
      "/r/s1/s2": [file("c", 4), dir("s3")],
      "/r/s1/s2/s3": [file("d", 8)],
    });
    // One directory is listed per tick of this clock: 0, 100, 200, 300 ms.
    let clock = -100;
    const onProgress = vi.fn();
    await folderSize(src, "/r", { sem: new Semaphore(1), onProgress, throttleMs: 250, now: () => (clock += 100) });
    expect(onProgress.mock.calls).toEqual([[{ bytes: 1, entries: 2 }], [{ bytes: 15, entries: 7 }]]);
  });
});
