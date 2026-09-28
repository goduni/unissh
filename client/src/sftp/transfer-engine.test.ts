import { describe, expect, it, vi } from "vitest";
import type { FileSource } from "@/bridge/sources";
import type { Entry } from "@/store/sftp-types";
import { abortable, collectTree, Semaphore, Speedometer, walk } from "./transfer-engine";

describe("directory scanning", () => {
  it("scans 10,000 local files with one listing and no per-file path IPC", async () => {
    const entries = Array.from({ length: 10_000 }, (_, i) => ({
      name: `file-${i}`, isDir: false, size: i,
    }));
    const list = vi.fn(async () => [...entries]);
    const join = vi.fn(async (base: string, name: string) => `${base}/${name}`);
    const src = { list, join } as unknown as FileSource;
    const result = await collectTree(src, "/root", new Semaphore(4));
    expect(result.dirs).toEqual([]);
    expect(result.files).toHaveLength(entries.length);
    expect(result.files.reduce((sum, file) => sum + file.size, 0)).toBe(49_995_000);
    expect(new Set(result.files.map((file) => file.relPath))).toEqual(new Set(entries.map((e) => e.name)));
    expect(list).toHaveBeenCalledExactlyOnceWith("/root");
    expect(join).not.toHaveBeenCalled();
  });

  it.each(["parallel", "streaming"])("preserves nested native paths in the %s scan", async (mode) => {
    const tree: Record<string, Entry[]> = {
      "C:\\root": [
        { name: "a", isDir: true, size: 0 },
        { name: "root.txt", isDir: false, size: 10 },
        ...[".", "..", "bad/name", "bad\\name"].map((name) => ({ name, isDir: true, size: 0 })),
      ],
      "C:\\root\\a": [{ name: "b", isDir: true, size: 0 }],
      "C:\\root\\a\\b": [{ name: "nested.txt", isDir: false, size: 20 }],
    };
    const list = vi.fn(async (path: string) => {
      if (!tree[path]) throw new Error(`Unexpected directory: ${path}`);
      return [...tree[path]];
    });
    const join = vi.fn(async (base: string, name: string) => `${base}\\${name}`);
    const src = { list, join } as unknown as FileSource;
    const result = mode === "parallel"
      ? await collectTree(src, "C:\\root", new Semaphore(2))
      : await (async () => {
        const items = [];
        for await (const item of walk(src, "C:\\root")) items.push(item);
        return { dirs: items.filter((item) => item.isDir).map((item) => item.relPath), files: items.filter((item) => !item.isDir) };
      })();
    expect(result.dirs).toEqual(["a", "a/b"]);
    expect(result.files.sort((a, b) => a.relPath.localeCompare(b.relPath))).toEqual([
      { relPath: "a/b/nested.txt", isDir: false, size: 20 },
      { relPath: "root.txt", isDir: false, size: 10 },
    ]);
    expect(list).toHaveBeenCalledTimes(3);
    expect(join.mock.calls).toEqual([["C:\\root", "a"], ["C:\\root\\a", "b"]]);
  });
});

describe("transfer throughput", () => {
  it("does not inflate speed when progress arrives in a burst", () => {
    const s = new Speedometer();
    s.sample(0, 0);
    s.sample(1000, 999);
    s.sample(2000, 1000);
    expect(s.speed()).toBe(2000);
    expect(s.eta(4000)).toBe(2);
  });
  it("includes simultaneous callbacks and decays to zero without progress", () => {
    const s = new Speedometer();
    s.sample(0, 0);
    s.sample(1000, 1000);
    s.sample(3000, 1000);
    expect(s.speed()).toBe(3000);
    for (let ms = 1250; ms <= 4250; ms += 250) s.sample(3000, ms);
    expect(s.speed()).toBe(0);
    expect(s.eta(100)).toBe(Infinity);
  });
  it("waits for a meaningful measurement interval", () => {
    const s = new Speedometer();
    s.sample(0, 0);
    s.sample(1000000, 1);
    expect(s.speed()).toBe(0);
  });
});

describe("interruptible queue", () => {
  it("removes a cancelled waiter without losing the next permit", async () => {
    const sem = new Semaphore(1);
    let release!: () => void;
    const first = sem.run(() => new Promise<void>((resolve) => { release = resolve; }));
    await Promise.resolve();
    const abort = new AbortController();
    let ran = false;
    const second = sem.run(async () => { ran = true; }, abort.signal);
    const rejected = expect(second).rejects.toThrow();
    abort.abort();
    await rejected;
    release();
    await first;
    expect(await sem.run(async () => 42)).toBe(42);
    expect(ran).toBe(false);
  });
  it("interrupts an unresponsive read-only wait", async () => {
    const abort = new AbortController();
    const result = abortable(new Promise(() => {}), abort.signal);
    const rejected = expect(result).rejects.toThrow();
    abort.abort();
    await rejected;
  });
});
