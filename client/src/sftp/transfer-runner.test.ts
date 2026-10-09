import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Transfer } from "@/store/sftp-types";
import type { FileSource } from "@/bridge/sources";
import * as sources from "@/bridge/sources";

const { state, api } = vi.hoisted(() => {
  const state = {
    transfers: [] as Transfer[], sftpParallelism: 1, sftpSessions: [],
    patchTransfers(patches: Map<string, Partial<Transfer>>) { for (const [id, patch] of patches) state.patchTransfer(id, patch); },
    patchTransfer(id: string, patch: Partial<Transfer>) {
      state.transfers = state.transfers.map((t) => t.id === id ? { ...t, ...patch } : t);
    },
  };
  return { state, api: { cancelNew: vi.fn(), cancelTrigger: vi.fn(), cancelDispose: vi.fn(), sftpUpload: vi.fn(), sftpDownload: vi.fn(), sftpRelay: vi.fn(), localCopyPrepared: vi.fn() } };
});
vi.mock("@/store/app", () => ({ useApp: { getState: () => state } }));
vi.mock("@/bridge/api", () => api);
vi.mock("@tauri-apps/api/path", () => ({ join: async (...p: string[]) => p.join("/"), tempDir: async () => "/tmp" }));
import { cancelAll, cancelTransfer, pauseTransfer, startTransfer, serializeResolver, resumeTransfer } from "./transfer-runner";
import { Semaphore } from "./transfer-engine";
import { i18n } from "@/i18n";

// The runner reports a kept source in the app's language.
beforeAll(async () => { await i18n.changeLanguage("en"); });

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const source = (kind: "local" | "remote"): FileSource => {
  const commit = vi.fn().mockResolvedValue(undefined);
  // A destination path holds a file once something was committed onto it.
  const landed = (p: string) => !p.startsWith("/dst") || commit.mock.calls.some((call) => call[1] === p);
  return {
  kind, id: kind, label: kind, join: async (a: string, b: string) => `${a}/${b}`,
  realpath: vi.fn(async (p: string) => p), parent: vi.fn(async (p: string) => p.slice(0, p.lastIndexOf("/"))),
  commit, createNew: vi.fn().mockResolvedValue(undefined), setMetadata: vi.fn().mockResolvedValue(undefined),
  stat: vi.fn().mockResolvedValue(null), lstat: vi.fn(async (p: string) => landed(p) ? { name: "file", isDir: false, size: 100 } : null),
  readlink: vi.fn(), symlink: vi.fn().mockResolvedValue(undefined),
  remove: vi.fn().mockResolvedValue(undefined), unlink: vi.fn().mockResolvedValue(undefined), list: kind === "remote"
    ? vi.fn().mockRejectedValue(new Error("Directory listing unavailable"))
    : vi.fn().mockResolvedValue([]), mkdir: vi.fn().mockResolvedValue(undefined),
  rename: vi.fn().mockResolvedValue(undefined), removeEmptyDir: vi.fn().mockResolvedValue(undefined),
  } as unknown as FileSource;
};
function transfer(id = "t", kind: "file" | "dir" = "file"): Transfer {
  const t: Transfer = { id, kind, label: "file", from: { kind: "local" }, to: { kind: "remote", sessionId: "remote" }, fromPath: "/file", toDir: "/dst", bytesDone: 0, bytesTotal: 100, filesDone: 0, filesTotal: 1, state: "queued", speedBps: 0, etaSec: 0, offset: 0 };
  state.transfers.push(t);
  return t;
}
const moving = (kind: "file" | "dir" = "file"): Transfer => Object.assign(transfer("t", kind), { move: true });
const resolver = vi.fn().mockResolvedValue({ choice: "overwrite", applyAll: true });
const current = (id = "t") => state.transfers.find((t) => t.id === id)!;
beforeEach(() => {
  cancelAll(); state.transfers = []; vi.clearAllMocks();
  let tokenSeq = 0;
  api.cancelNew.mockImplementation(async () => `token-${++tokenSeq}`); api.cancelTrigger.mockResolvedValue(undefined); api.cancelDispose.mockResolvedValue(undefined);
  api.sftpUpload.mockImplementation(async (_id, _from, _to, _offset, progress) => { progress({ transferred: 100, total: 100 }); return true; });
  api.sftpDownload.mockResolvedValue(true);
  api.sftpRelay.mockImplementation(async (_id, _toId, _from, _to, progress) => { progress({ transferred: 200, total: 200 }); return true; });
});

describe("transfer lifecycle", () => {
  it("cancels while stat is hung and ignores its late result", async () => {
    const dest = source("remote"); const stat = deferred<null>();
    vi.mocked(dest.lstat).mockReturnValue(stat.promise);
    const run = startTransfer(transfer(), source("local"), dest, resolver);
    await vi.waitFor(() => expect(dest.lstat).toHaveBeenCalled());
    cancelTransfer("t"); await run;
    expect(current().state).toBe("cancelled");
    stat.resolve(null); await Promise.resolve();
    expect(api.sftpUpload).not.toHaveBeenCalled();
  });
  it("does not start a file cancelled while awaiting token creation", async () => {
    const token = deferred<string>(); api.cancelNew.mockReturnValue(token.promise);
    const run = startTransfer(transfer(), source("local"), source("remote"), resolver);
    await vi.waitFor(() => expect(api.cancelNew).toHaveBeenCalled());
    cancelTransfer("t"); token.resolve("late"); await run;
    expect(api.sftpUpload).not.toHaveBeenCalled();
    expect(api.cancelDispose).toHaveBeenCalledWith("late");
    expect(current().state).toBe("cancelled");
  });
  it("cancels a queued file without waiting for another file's write", async () => {
    const sem = new Semaphore(1); const write = deferred<boolean>(); api.sftpUpload.mockReturnValue(write.promise);
    const first = startTransfer(transfer("first"), source("local"), source("remote"), resolver, sem);
    const secondTransfer = transfer("second"); secondTransfer.label = "second";
    const second = startTransfer(secondTransfer, source("local"), source("remote"), resolver, sem);
    await vi.waitFor(() => expect(api.sftpUpload).toHaveBeenCalledTimes(1));
    expect(current("second").state).not.toBe("done");
    cancelTransfer("second"); await second;
    expect(current("second").state).toBe("cancelled");
    write.resolve(true); await first;
    expect(api.sftpUpload).toHaveBeenCalledTimes(1);
  });
  it("waits for a paused write and preserves pause even if cancellation returns an error", async () => {
    const write = deferred<boolean>(); api.sftpUpload.mockReturnValue(write.promise);
    const t = transfer(); const from = source("local"); const to = source("remote");
    const run = startTransfer(t, from, to, resolver);
    await vi.waitFor(() => expect(api.sftpUpload).toHaveBeenCalled());
    pauseTransfer(t.id); expect(current().state).toBe("pausing");
    await startTransfer(t, from, to, resolver);
    expect(api.sftpUpload).toHaveBeenCalledTimes(1);
    write.reject(new Error("channel closed")); await run;
    expect(current().state).toBe("paused");
    expect(current().error).toBeUndefined();
  });
  it("cancels a hung folder scan", async () => {
    const from = source("local"); vi.mocked(from.list).mockImplementation((_path, signal) => new Promise((_resolve, reject) => signal?.addEventListener("abort", () => reject(signal.reason), { once: true })));
    const run = startTransfer(transfer("t", "dir"), from, source("remote"), resolver);
    await vi.waitFor(() => expect(from.list).toHaveBeenCalled());
    cancelTransfer("t"); await run;
    expect(current().state).toBe("cancelled");
  });
  it("releases the serialized conflict queue when its prompt is cancelled", async () => {
    const dest = source("remote"); vi.mocked(dest.lstat).mockResolvedValue({ name: "file", size: 10, isDir: false });
    const prompt = vi.fn().mockImplementationOnce(() => new Promise(() => {})).mockResolvedValue({ choice: "skip", applyAll: false });
    const serialized = serializeResolver(prompt);
    const one = startTransfer(transfer("one"), source("local"), dest, serialized);
    const two = startTransfer(transfer("two"), source("local"), dest, serialized);
    await vi.waitFor(() => expect(prompt).toHaveBeenCalledTimes(1));
    cancelTransfer("one"); await one; await two;
    expect(current("one").state).toBe("cancelled"); expect(current("two").state).toBe("done");
  });
});

describe("accounting and failed parallel work", () => {
  it("counts both relay legs for a folder", async () => {
    const from = source("remote"); const to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{ name: "a", isDir: false, size: 100 }]);
    api.sftpDownload.mockImplementation(async (_id, _from, _to, _offset, _size, progress) => { progress({transferred:100,total:100}); return true; });
    api.sftpUpload.mockImplementation(async (_id, _from, _to, _offset, progress) => { progress({transferred:100,total:100}); return true; });
    await startTransfer(transfer("t", "dir"), from, to, resolver);
    expect(current()).toMatchObject({state:"done",bytesDone:200,bytesTotal:200,filesDone:1});
  });
  it("preserves original source size when retrying a relay", async () => {
    const t = transfer(); t.bytesTotal = 200; t.sourceSize = 100;
    const from = source("remote"); const to = source("remote");
    await startTransfer(t, from, to, resolver);
    expect(api.sftpRelay).toHaveBeenCalledOnce();
    expect(current().bytesTotal).toBe(200);
  });
  it("cancels sibling writes on error and waits before exposing retry", async () => {
    const from = source("local"); const to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{name:"a",size:100,isDir:false},{name:"b",size:100,isDir:false}]);
    const a = deferred<boolean>(); const b = deferred<boolean>();
    api.sftpUpload.mockReturnValueOnce(a.promise).mockReturnValueOnce(b.promise);
    const t = transfer("t", "dir");
    const run = startTransfer(t, from, to, resolver, new Semaphore(2));
    await vi.waitFor(() => expect(api.sftpUpload).toHaveBeenCalledTimes(2));
    a.reject(new Error("permission denied"));
    await vi.waitFor(() => expect(api.cancelTrigger).toHaveBeenCalled());
    expect(current().state).not.toBe("error");
    await startTransfer(t, from, to, resolver);
    expect(api.sftpUpload).toHaveBeenCalledTimes(2);
    b.resolve(false); await run;
    expect(current()).toMatchObject({state:"error",error:"a: permission denied"});
  });
  it("restarts an unverified partial and measures newly transferred bytes", async () => {
    vi.useFakeTimers();
    try {
      const to = source("remote"); vi.mocked(to.lstat).mockResolvedValue({name:"a",size:80,isDir:false});
      const write = deferred<boolean>(); api.sftpUpload.mockReturnValue(write.promise);
      const run = startTransfer(transfer(), source("local"), to, async () => ({choice:"resume",applyAll:true}));
      await vi.advanceTimersByTimeAsync(0);
      const progress = api.sftpUpload.mock.calls[0][4];
      await vi.advanceTimersByTimeAsync(1000);
      progress({transferred:10,total:100});
      await vi.advanceTimersByTimeAsync(250);
      expect(current().speedBps).toBe(8); // Existing destination bytes are never counted as transfer progress
      await vi.advanceTimersByTimeAsync(6000);
      expect(current()).toMatchObject({speedBps:0,stalled:true});
      cancelTransfer("t"); write.resolve(false); await run;
    } finally { vi.useRealTimers(); }
  });
  it("does not count skipped folder files as network traffic", async () => {
    vi.useFakeTimers();
    try {
      const from = source("local"); const to = source("remote");
      vi.mocked(from.list).mockResolvedValue([{name:"a",size:1000,isDir:false},{name:"b",size:100,isDir:false}]);
      vi.mocked(to.lstat).mockResolvedValueOnce({name:"a",size:1000,isDir:false}).mockResolvedValue(null);
      const write = deferred<boolean>(); api.sftpUpload.mockReturnValue(write.promise);
      const run = startTransfer(transfer("t", "dir"), from, to, async () => ({choice:"skip",applyAll:true}));
      await vi.advanceTimersByTimeAsync(1000);
      expect(current()).toMatchObject({bytesDone:1000,speedBps:0,filesDone:1});
      cancelTransfer("t"); write.resolve(false); await run;
    } finally { vi.useRealTimers(); }
  });
});

describe("parallel conflict state", () => {
  it.each(["skip", "overwrite"] as const)("keeps waiting after %s until every folder conflict is resolved", async (choice) => {
    const from = source("local"); const to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{name:"a",size:100,isDir:false},{name:"b",size:100,isDir:false}]);
    vi.mocked(to.lstat).mockResolvedValue({name:"file",size:10,isDir:false});
    const first = deferred<{choice:"skip" | "overwrite";applyAll:boolean}>();
    const write = deferred<boolean>();
    api.sftpUpload.mockReturnValue(write.promise);
    const second = deferred<{choice:"skip";applyAll:boolean}>();
    const prompt = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const run = startTransfer(transfer("t", "dir"), from, to, serializeResolver(prompt), new Semaphore(2));
    await vi.waitFor(() => expect(prompt).toHaveBeenCalledTimes(1));
    first.resolve({choice,applyAll:false});
    await vi.waitFor(() => expect(prompt).toHaveBeenCalledTimes(2));
    const pendingState = current().state;
    second.resolve({choice:"skip",applyAll:false});
    write.resolve(true);
    await run;
    expect(pendingState).toBe("waiting");
    expect(current().state).toBe("done");
  });
});


describe("conflict wait timing", () => {
  it("does not count time spent deciding as a stalled transfer", async () => {
    vi.useFakeTimers();
    const write = deferred<boolean>();
    let run: Promise<void> | undefined;
    try {
      const to = source("remote");
      vi.mocked(to.lstat).mockResolvedValue({name:"file",size:10,isDir:false});
      const answer = deferred<{choice:"overwrite";applyAll:boolean}>();
      api.sftpUpload.mockReturnValue(write.promise);
      run = startTransfer(transfer(), source("local"), to, () => answer.promise);
      await vi.advanceTimersByTimeAsync(6000);
      expect(current()).toMatchObject({state:"waiting",stalled:false});
      answer.resolve({choice:"overwrite",applyAll:false});
      await vi.advanceTimersByTimeAsync(250);
      expect(current()).toMatchObject({state:"active",stalled:false});
      await vi.advanceTimersByTimeAsync(5000);
      expect(current().stalled).toBe(true);
    } finally {
      cancelTransfer("t"); write.resolve(false); await run;
      vi.useRealTimers();
    }
  });

  it("pauses every outstanding conflict without restoring active state", async () => {
    const from = source("local"); const to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{name:"a",size:100,isDir:false},{name:"b",size:100,isDir:false}]);
    vi.mocked(to.lstat).mockResolvedValue({name:"file",size:10,isDir:false});
    const prompt = vi.fn().mockImplementation(() => new Promise(() => {}));
    const run = startTransfer(transfer("t", "dir"), from, to, serializeResolver(prompt), new Semaphore(2));
    await vi.waitFor(() => expect(prompt).toHaveBeenCalledTimes(1));
    pauseTransfer("t");
    await run;
    expect(current()).toMatchObject({state:"paused",stalled:false});
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(api.sftpUpload).not.toHaveBeenCalled();
  });
});

describe("folder preparation and parallel throughput", () => {
  it.each(["overwrite", "skip", "resume", "keepboth"] as const)("applies %s to 216 conflicts without per-file UI state churn", async (choice) => {
    const from = source("local"); const to = source("remote");
    const files = Array.from({ length: 216 }, (_, i) => ({ name: `file-${i}.txt`, size: 100, isDir: false, mode: 0o100644 }));
    vi.mocked(from.list).mockResolvedValue(files);
    vi.mocked(to.list).mockResolvedValue(files.map((f) => ({ ...f, size: 50 })));
    vi.mocked(to.lstat).mockImplementation(async (path) => {
      const file = files.find((f) => path.endsWith(`/${f.name}`));
      return file ? { ...file, size: 50 } : null;
    });
    const prompt = vi.fn().mockResolvedValue({ choice, applyAll: true });
    const patches = vi.spyOn(state, "patchTransfer");
    vi.useFakeTimers();
    try {
      await startTransfer(transfer("t", "dir"), from, to, serializeResolver(prompt), new Semaphore(8));
      expect(prompt).toHaveBeenCalledTimes(1);
      expect(patches.mock.calls.filter(([, patch]) => patch.state === "waiting")).toHaveLength(1);
      // Store writes cause synchronous React renders. A folder must not trigger
      // hundreds of renders in one microtask chain after applying a decision.
      expect(patches.mock.calls.length).toBeLessThan(20);
      expect(api.sftpUpload).toHaveBeenCalledTimes(choice === "skip" ? 0 : 216);
      expect(current()).toMatchObject({ state: "done", filesDone: 216, bytesDone: 21600 });
      if (choice === "resume") expect(api.sftpUpload.mock.calls.every((args) => args[3] === 0)).toBe(true);
    } finally { patches.mockRestore(); vi.useRealTimers(); }
  });

  it("refuses to infer a retry plan from complete or partial sizes", async () => {
    const from = source("local"); const to = source("remote");
    const files = ["a", "b", "c"].map((name) => ({ name, size: 100, isDir: false, mode: 0o100644 }));
    vi.mocked(from.list).mockResolvedValue(files);
    vi.mocked(to.list).mockResolvedValue([files[0], { ...files[1], size: 50 }]);
    const t = transfer("t", "dir"); t.state = "paused";
    const lookup = vi.spyOn(sources, "sourceFor").mockImplementation((ref) => ref.kind === "local" ? from : to);
    const patches = vi.spyOn(state, "patchTransfer");
    try {
      await resumeTransfer("t");
      expect(api.sftpUpload).not.toHaveBeenCalled();
      expect(current()).toMatchObject({ state: "error", error: expect.stringContaining("plan is unavailable") });
      expect(patches.mock.calls.some(([, patch]) => patch.state === "waiting")).toBe(false);
    } finally { lookup.mockRestore(); patches.mockRestore(); }
  });

  it("transfers 216 files with eight workers, one listing and one cancel token", async () => {
    vi.useFakeTimers();
    let run: Promise<void> | undefined;
    try {
      const from = source("local"); const to = source("remote");
      vi.mocked(from.list).mockResolvedValue(Array.from({ length: 216 }, (_, i) => ({ name: `file-${i}`, size: 4096, isDir: false })));
      vi.mocked(to.list).mockResolvedValue([]);
      let active = 0; let peak = 0;
      api.sftpUpload.mockImplementation(async (_id, _from, _to, _offset, progress) => {
        peak = Math.max(peak, ++active);
        await new Promise((resolve) => setTimeout(resolve, 10));
        progress({ transferred: 4096, total: 4096 });
        active -= 1;
        return true;
      });
      run = startTransfer(transfer("t", "dir"), from, to, resolver, new Semaphore(8));
      await vi.advanceTimersByTimeAsync(1000);
      await run;
      expect(peak).toBe(8);
      expect(api.sftpUpload).toHaveBeenCalledTimes(216);
      expect(to.list).toHaveBeenCalledExactlyOnceWith("/dst/file");
      expect(to.lstat).not.toHaveBeenCalled();
      expect(api.cancelNew).toHaveBeenCalledTimes(1);
      expect(new Set(api.sftpUpload.mock.calls.map((args) => args[5])).size).toBe(1);
      expect(api.cancelDispose).toHaveBeenCalledTimes(1);
      expect(current()).toMatchObject({ state: "done", filesDone: 216, bytesDone: 216 * 4096 });
    } finally {
      cancelAll(); await vi.runAllTimersAsync(); await run; vi.useRealTimers();
    }
  });

  it("does not start a failing sibling while a conflict dialog is unanswered", async () => {
    const from = source("local"); const to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{ name: "a", size: 100, isDir: false }, { name: "b", size: 100, isDir: false }]);
    vi.mocked(to.list).mockResolvedValue([{ name: "a", size: 50, isDir: false }]);
    vi.mocked(to.lstat).mockImplementation(async (path) => path.endsWith("/a") ? { name: "a", size: 50, isDir: false } : null);
    const answer = deferred<{ choice: "skip"; applyAll: boolean }>();
    const prompt = vi.fn().mockReturnValue(answer.promise);
    api.sftpUpload.mockRejectedValue(new Error("sftp error: status 4: Failure"));
    const run = startTransfer(transfer("t", "dir"), from, to, prompt, new Semaphore(8));
    await vi.waitFor(() => expect(prompt).toHaveBeenCalledTimes(1));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(current().state).toBe("waiting");
    expect(api.sftpUpload).not.toHaveBeenCalled();
    answer.resolve({ choice: "skip", applyAll: false });
    await run;
    expect(current()).toMatchObject({ state: "error", error: "b: sftp error: status 4: Failure" });
  });

  it("reserves other incoming filenames when keeping both copies", async () => {
    const from = source("local"); const to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{ name: "a.txt", size: 100, isDir: false }, { name: "a (2).txt", size: 100, isDir: false }]);
    vi.mocked(to.list).mockResolvedValue([{ name: "a.txt", size: 50, isDir: false, mode: 0o100644 }]);
    await startTransfer(transfer("t", "dir"), from, to, async () => ({ choice: "keepboth", applyAll: true }), new Semaphore(8));
    expect(vi.mocked(to.commit).mock.calls.map((args) => args[1]).sort()).toEqual(["/dst/file/a (2).txt", "/dst/file/a (3).txt"]);
    expect(current().state).toBe("done");
  });

  it.each([0o120777, undefined])("stats links or unknown entry types (mode %s) before resuming", async (mode) => {
    const from = source("local"); const to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{ name: "a", size: 100, isDir: false }]);
    vi.mocked(to.list).mockResolvedValue([{ name: "a", size: 7, isDir: false, mode }]);
    vi.mocked(to.lstat).mockResolvedValue({ name: "a", size: 50, isDir: false });
    const prompt = vi.fn().mockResolvedValue({ choice: "resume", applyAll: true });
    await startTransfer(transfer("t", "dir"), from, to, prompt);
    expect(to.lstat).toHaveBeenCalledWith("/dst/file/a");
    expect(prompt.mock.calls[0][0].targetSize).toBe(50);
    expect(api.sftpUpload.mock.calls[0][3]).toBe(0);
    expect(current().state).toBe("done");
  });

  it("verifies case aliases before deciding a target is missing", async () => {
    const from = source("local"); const to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{ name: "a.txt", size: 100, isDir: false }]);
    vi.mocked(to.list).mockResolvedValue([{ name: "A.txt", size: 50, isDir: false, mode: 0o100644 }]);
    vi.mocked(to.lstat).mockResolvedValue({ name: "a.txt", size: 50, isDir: false });
    const prompt = vi.fn().mockResolvedValue({ choice: "skip", applyAll: false });
    await startTransfer(transfer("t", "dir"), from, to, prompt);
    expect(to.lstat).toHaveBeenCalledExactlyOnceWith("/dst/file/a.txt");
    expect(prompt).toHaveBeenCalledOnce();
    expect(api.sftpUpload).not.toHaveBeenCalled();
    expect(current().state).toBe("done");
  });

  it("surfaces mkdir failure before starting writes or conflict prompts", async () => {
    const from = source("local"); const to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{ name: "a", size: 100, isDir: false }]);
    vi.mocked(to.mkdir).mockRejectedValue(new Error("sftp error: status 4: Failure"));
    await startTransfer(transfer("t", "dir"), from, to, resolver);
    expect(current()).toMatchObject({ state: "error", error: "/dst/file: sftp error: status 4: Failure" });
    expect(api.sftpUpload).not.toHaveBeenCalled();
    expect(resolver).not.toHaveBeenCalled();
  });

  it("delegates parallel relays to private native scratch files", async () => {
    const from = source("remote"); const to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{ name: "a", size: 100, isDir: false }, { name: "b", size: 100, isDir: false }]);
    vi.mocked(to.list).mockResolvedValue([]);
    await startTransfer(transfer("t", "dir"), from, to, resolver, new Semaphore(2));
    expect(current().state).toBe("done");
    const paths = api.sftpRelay.mock.calls.map((args) => args[3]);
    expect(paths).toHaveLength(2);
    expect(new Set(paths).size).toBe(2);
    expect(api.sftpDownload).not.toHaveBeenCalled();
    expect(api.sftpUpload).not.toHaveBeenCalled();
    expect(api.cancelNew).toHaveBeenCalledTimes(1);
  });
});

describe("symbolic link transfers", () => {
  it.each([
    ["remote", "local"], ["local", "remote"], ["remote", "remote"], ["local", "local"],
  ] as const)("preserves nested links in a %s → %s folder copy", async (src, dst) => {
    const from = source(src); const to = source(dst);
    vi.mocked(from.list).mockImplementation(async (path) => path === "/file"
      ? [{ name: ".venv", isDir: true, size: 0 }]
      : [{ name: "lib64", isDir: false, isSymlink: true, size: 3 }]);
    vi.mocked(from.readlink).mockResolvedValue("lib");
    vi.mocked(from.stat).mockResolvedValue({ name: "lib64", isDir: true, size: 4096 });
    await startTransfer(transfer("t", "dir"), from, to, resolver);
    expect(to.symlink).toHaveBeenCalledWith("lib", expect.stringContaining("/dst/file/.venv/.unissh-"), dst === "local");
    expect(to.commit).toHaveBeenCalledWith(vi.mocked(to.symlink).mock.calls[0][1], "/dst/file/.venv/lib64", false);
    expect(api.sftpDownload).not.toHaveBeenCalled();
    expect(api.sftpUpload).not.toHaveBeenCalled();
    expect(current()).toMatchObject({ state: "done", filesDone: 1, bytesDone: 0, bytesTotal: 0 });
  });

  it.each(["../missing", "/absolute/missing", "lib", "self"])("preserves the literal target %s for a loose link", async (target) => {
    const from = source("remote"); const to = source("local");
    vi.mocked(from.readlink).mockResolvedValue(target);
    const t = transfer(); t.isSymlink = true;
    await startTransfer(t, from, to, resolver);
    expect(to.symlink).toHaveBeenCalledWith(target, expect.stringMatching(/^\/dst\/.unissh-.*\.part$/), false);
    expect(to.commit).toHaveBeenCalledWith(vi.mocked(to.symlink).mock.calls[0][1], "/dst/file", false);
    expect(api.sftpDownload).not.toHaveBeenCalled();
    expect(current()).toMatchObject({ state: "done", filesDone: 1, bytesTotal: 0 });
  });

  it.each([false, true])("atomically replaces a destination link with isSymlink=%s", async (isSymlink) => {
    const from = source("local"); const to = source("remote");
    const existing = { name: "file", isDir: false, isSymlink: true, size: 3 };
    vi.mocked(to.lstat).mockResolvedValue(existing);
    vi.mocked(from.readlink).mockResolvedValue("lib");
    const t = transfer(); t.isSymlink = isSymlink;
    await startTransfer(t, from, to, resolver);
    expect(resolver).toHaveBeenCalledWith(expect.objectContaining({ resumable: false, sameSize: false }), expect.any(AbortSignal));
    expect(to.unlink).not.toHaveBeenCalled();
    expect(to.commit).toHaveBeenCalledWith(expect.stringContaining(".unissh-"), "/dst/file", true);
    const write = isSymlink ? to.symlink : api.sftpUpload;
    expect(vi.mocked(write).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(to.commit).mock.invocationCallOrder[0]);
    expect(to.remove).not.toHaveBeenCalled();
    expect(current().state).toBe("done");
  });

  it.each(["skip", "keepboth"] as const)("honors %s without unlinking the destination", async (choice) => {
    const from = source("remote"); const to = source("local");
    vi.mocked(from.readlink).mockResolvedValue("lib");
    vi.mocked(to.lstat).mockResolvedValue({ name: "file", isDir: false, isSymlink: true, size: 3 });
    vi.mocked(to.list).mockResolvedValue([{ name: "file", isDir: false, isSymlink: true, size: 3 }]);
    const t = transfer(); t.isSymlink = true;
    await startTransfer(t, from, to, async () => ({ choice, applyAll: true }));
    expect(to.unlink).not.toHaveBeenCalled();
    expect(to.remove).not.toHaveBeenCalled();
    if (choice === "skip") expect(to.symlink).not.toHaveBeenCalled();
    else {
      expect(to.symlink).toHaveBeenCalledTimes(1);
      expect(vi.mocked(to.symlink).mock.calls[0][1]).not.toBe("/dst/file");
    }
    expect(current().state).toBe("done");
  });

  it("leaves an existing file intact if reading the source link fails", async () => {
    const from = source("remote"); const to = source("local");
    vi.mocked(from.readlink).mockRejectedValue(new Error("readlink denied"));
    vi.mocked(to.lstat).mockResolvedValue({ name: "file", isDir: false, size: 50 });
    const t = transfer(); t.isSymlink = true;
    await startTransfer(t, from, to, resolver);
    expect(to.remove).not.toHaveBeenCalled();
    expect(to.symlink).not.toHaveBeenCalled();
    expect(current()).toMatchObject({ state: "error", error: "readlink denied" });
  });

  it("refuses to traverse an existing destination directory link", async () => {
    const from = source("remote"); const to = source("local");
    vi.mocked(from.list).mockResolvedValue([{ name: "a", isDir: false, size: 100 }]);
    vi.mocked(to.mkdir).mockRejectedValue(new Error("already exists"));
    vi.mocked(to.lstat).mockResolvedValue({ name: "file", isDir: true, isSymlink: true, size: 3 });
    await startTransfer(transfer("t", "dir"), from, to, resolver);
    expect(api.sftpDownload).not.toHaveBeenCalled();
    expect(current()).toMatchObject({ state: "error", error: "/dst/file: already exists" });
  });

  it("waits for a pending symlink write before finishing cancellation", async () => {
    const from = source("remote"); const to = source("local");
    vi.mocked(from.readlink).mockResolvedValue("lib");
    const write = deferred<void>(); vi.mocked(to.symlink).mockReturnValue(write.promise);
    const t = transfer(); t.isSymlink = true;
    const run = startTransfer(t, from, to, resolver);
    await vi.waitFor(() => expect(to.symlink).toHaveBeenCalled());
    cancelTransfer(t.id);
    await startTransfer(t, from, to, resolver);
    expect(current().state).toBe("cancelling");
    expect(to.symlink).toHaveBeenCalledTimes(1);
    write.resolve(); await run;
    expect(current().state).toBe("cancelled");
  });
});

describe("transfer integrity regressions", () => {
  it("keeps the original when creating its replacement link fails", async () => {
    const from = source("local"), to = source("remote");
    const original = { name: "file", isDir: false, size: 50 };
    vi.mocked(to.lstat).mockResolvedValue(original);
    vi.mocked(from.readlink).mockResolvedValue("lib");
    vi.mocked(to.symlink).mockRejectedValue(new Error("SYMLINK unsupported"));
    const t = transfer(); t.isSymlink = true;
    await startTransfer(t, from, to, resolver);
    expect(current()).toMatchObject({ state: "error", error: "SYMLINK unsupported" });
    expect(to.remove).not.toHaveBeenCalled();
    expect(to.unlink).not.toHaveBeenCalled();
    expect(to.commit).not.toHaveBeenCalled();
  });

  it("writes only a private sibling before committing an overwrite", async () => {
    const from = source("local"), to = source("remote");
    vi.mocked(to.lstat).mockResolvedValue({ name: "file", isDir: false, size: 50 });
    api.sftpUpload.mockRejectedValue(new Error("disk full"));
    await startTransfer(transfer(), from, to, resolver);
    expect(api.sftpUpload.mock.calls[0][2]).toMatch(/^\/dst\/.unissh-.*\.part$/);
    expect(to.commit).not.toHaveBeenCalled();
    expect(to.remove).toHaveBeenCalledWith(api.sftpUpload.mock.calls[0][2]);
    expect(to.remove).not.toHaveBeenCalledWith("/dst/file");
  });

  it("retries the saved Keep both destination without reusing the original", async () => {
    const from = source("local"), to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{ name: "a", isDir: false, size: 100 }]);
    vi.mocked(to.list).mockResolvedValue([{ name: "a", isDir: false, size: 100, mode: 0o100600 }]);
    const prompt = vi.fn().mockResolvedValue({ choice: "keepboth", applyAll: true });
    api.sftpUpload.mockRejectedValueOnce(new Error("disconnected"));
    await startTransfer(transfer("t", "dir"), from, to, prompt);
    expect(current().state).toBe("error");
    const lookup = vi.spyOn(sources, "sourceFor").mockImplementation((ref) => ref.kind === "local" ? from : to);
    try { await resumeTransfer("t"); } finally { lookup.mockRestore(); }
    expect(current().state).toBe("done");
    expect(prompt).toHaveBeenCalledOnce();
    expect(to.commit).toHaveBeenCalledWith(expect.stringContaining(".unissh-"), "/dst/file/a (2)", false);
    expect(api.sftpUpload.mock.calls.every((call) => call[3] === 0)).toBe(true);
  });

  it("separates incoming case aliases before writing either file", async () => {
    const from = source("local"), to = source("remote");
    vi.mocked(from.list).mockResolvedValue(["A", "a"].map((name) => ({ name, isDir: false, size: 100 })));
    vi.mocked(to.list).mockResolvedValue([]);
    await startTransfer(transfer("t", "dir"), from, to, resolver, new Semaphore(2));
    expect(current().state).toBe("done");
    const paths = vi.mocked(to.commit).mock.calls.map((call) => call[1].toLowerCase());
    expect(new Set(paths).size).toBe(2);
    expect(vi.mocked(to.commit).mock.calls.every((call) => call[2] === false)).toBe(true);
  });

  it("allocates distinct Keep both names across independent batches", async () => {
    const from = source("local"), to = source("remote");
    vi.mocked(to.lstat).mockResolvedValue({ name: "FILE", isDir: false, size: 50 });
    vi.mocked(to.list).mockResolvedValue([{ name: "FILE", isDir: false, size: 50 }]);
    const choose = async () => ({ choice: "keepboth" as const, applyAll: true });
    const sem = new Semaphore(2);
    await Promise.all([startTransfer(transfer("one"), from, to, choose, sem), startTransfer(transfer("two"), from, to, choose, sem)]);
    expect(current("one").state).toBe("done"); expect(current("two").state).toBe("done");
    expect(vi.mocked(to.commit).mock.calls.map((call) => call[1]).sort()).toEqual(["/dst/file (2)", "/dst/file (3)"]);
  });

  it("refuses a canonical self-copy before any write", async () => {
    const from = source("local"), to = source("local");
    vi.mocked(from.realpath).mockResolvedValue("/dst/file");
    await startTransfer(transfer(), from, to, resolver);
    expect(current()).toMatchObject({ state: "error", error: "Cannot copy a path into itself" });
    expect(api.localCopyPrepared).not.toHaveBeenCalled();
  });

  it("shares one timer across a thousand queued transfers", async () => {
    vi.useFakeTimers();
    const write = deferred<boolean>(); api.sftpUpload.mockReturnValue(write.promise);
    const interval = vi.spyOn(globalThis, "setInterval");
    const sem = new Semaphore(1);
    const jobs = Array.from({ length: 1000 }, (_, i) => {
      const t = transfer(`many-${i}`); t.label = `file-${i}`;
      return startTransfer(t, source("local"), source("remote"), resolver, sem);
    });
    try {
      await vi.advanceTimersByTimeAsync(0);
      expect(interval).toHaveBeenCalledTimes(1);
    } finally {
      cancelAll(); write.resolve(false); await Promise.all(jobs);
      interval.mockRestore(); vi.useRealTimers();
    }
  });
});

describe("moving between locations", () => {
  const skip = async () => ({ choice: "skip" as const, applyAll: true });

  it("removes the source file once its copy is committed", async () => {
    const from = source("local"), to = source("remote");
    await startTransfer(moving(), from, to, resolver);
    expect(from.remove).toHaveBeenCalledExactlyOnceWith("/file");
    expect(vi.mocked(to.commit).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(from.remove).mock.invocationCallOrder[0]);
    expect(current().state).toBe("done");
  });

  it("keeps the source when the transfer fails", async () => {
    const from = source("local");
    api.sftpUpload.mockRejectedValue(new Error("disk full"));
    await startTransfer(moving(), from, source("remote"), resolver);
    expect(current()).toMatchObject({ state: "error", error: "disk full" });
    expect(from.remove).not.toHaveBeenCalled();
  });

  it("keeps the source when the transfer is cancelled", async () => {
    const from = source("local"); const write = deferred<boolean>(); api.sftpUpload.mockReturnValue(write.promise);
    const run = startTransfer(moving(), from, source("remote"), resolver);
    await vi.waitFor(() => expect(api.sftpUpload).toHaveBeenCalled());
    cancelTransfer("t"); write.resolve(true); await run;
    expect(current().state).toBe("cancelled");
    expect(from.remove).not.toHaveBeenCalled();
  });

  it("keeps the source of a conflict the user skipped", async () => {
    const from = source("local"), to = source("remote");
    vi.mocked(to.lstat).mockResolvedValue({ name: "file", isDir: false, size: 10 });
    await startTransfer(moving(), from, to, skip);
    expect(current().state).toBe("done");
    expect(from.remove).not.toHaveBeenCalled();
  });

  it("removes emptied source folders bottom-up and keeps one a file stayed in", async () => {
    const from = source("local"), to = source("remote");
    const tree: Record<string, { name: string; isDir: boolean; size: number }[]> = {
      "/file": [{ name: "moved", isDir: true, size: 0 }, { name: "held", isDir: true, size: 0 }],
      "/file/moved": [{ name: "deep", isDir: true, size: 0 }],
      "/file/moved/deep": [{ name: "x", isDir: false, size: 100 }],
      "/file/held": [{ name: "y", isDir: false, size: 100 }],
    };
    vi.mocked(from.list).mockImplementation(async (path) => tree[path]);
    vi.mocked(to.lstat).mockImplementation(async (path) => path.endsWith("/held/y") ? { name: "y", isDir: false, size: 10 }
      : vi.mocked(to.commit).mock.calls.some((call) => call[1] === path) ? { name: "x", isDir: false, size: 100 } : null);
    await startTransfer(moving("dir"), from, to, skip);
    expect(current().state).toBe("done");
    expect(vi.mocked(from.remove).mock.calls).toEqual([["/file/moved/deep/x"]]);
    expect(vi.mocked(from.removeEmptyDir).mock.calls).toEqual([["/file/moved/deep"], ["/file/moved"]]);
  });

  it("reports a source it could not remove and still moves the rest", async () => {
    const from = source("local"), to = source("remote");
    vi.mocked(from.list).mockResolvedValue([{ name: "a", isDir: false, size: 100 }, { name: "b", isDir: false, size: 100 }]);
    vi.mocked(from.remove).mockImplementation(async (path) => { if (path === "/file/a") throw new Error("permission denied"); });
    await startTransfer(moving("dir"), from, to, resolver);
    expect(to.commit).toHaveBeenCalledTimes(2);
    expect(from.remove).toHaveBeenCalledWith("/file/b");
    expect(from.removeEmptyDir).not.toHaveBeenCalled();
    expect(current()).toMatchObject({ state: "error", error: "Copied, but the source was not removed: /file/a: permission denied" });
  });

  it("retries only the removal of a source that was left behind", async () => {
    const from = source("local"), to = source("remote");
    vi.mocked(from.remove).mockRejectedValueOnce(new Error("permission denied"));
    await startTransfer(moving(), from, to, resolver);
    expect(current().state).toBe("error");
    const lookup = vi.spyOn(sources, "sourceFor").mockImplementation((ref) => ref.kind === "local" ? from : to);
    try { await resumeTransfer("t"); } finally { lookup.mockRestore(); }
    expect(current().state).toBe("done");
    expect(from.remove).toHaveBeenCalledTimes(2);
    expect(api.sftpUpload).toHaveBeenCalledOnce();
    expect(to.commit).toHaveBeenCalledOnce();
  });

  it("keeps the source on retry when the copy is no longer at the destination", async () => {
    const from = source("local"), to = source("remote");
    vi.mocked(from.remove).mockRejectedValueOnce(new Error("permission denied"));
    await startTransfer(moving(), from, to, resolver);
    vi.mocked(to.lstat).mockResolvedValue(null);
    const lookup = vi.spyOn(sources, "sourceFor").mockImplementation((ref) => ref.kind === "local" ? from : to);
    try { await resumeTransfer("t"); } finally { lookup.mockRestore(); }
    expect(from.remove).toHaveBeenCalledOnce();
    expect(current()).toMatchObject({ state: "error", error: "Copied, but the source was not removed: /file: the copy at the destination is missing or has changed" });
  });

  it("keeps a source that changed after it was copied", async () => {
    const from = source("local"), to = source("remote");
    const read = { name: "file", isDir: false, size: 100 };
    vi.mocked(from.lstat).mockResolvedValueOnce(read).mockResolvedValueOnce(read).mockResolvedValue({ ...read, size: 150 });
    await startTransfer(moving(), from, to, resolver);
    expect(to.commit).toHaveBeenCalledOnce();
    expect(from.remove).not.toHaveBeenCalled();
    expect(current()).toMatchObject({ state: "error", error: "Copied, but the source was not removed: /file: changed after it was copied" });
  });

  it("leaves both copies when cancelled between the commit and the removal", async () => {
    const from = source("local"), to = source("remote");
    const commit = deferred<void>(); vi.mocked(to.commit).mockReturnValue(commit.promise);
    const run = startTransfer(moving(), from, to, resolver);
    await vi.waitFor(() => expect(to.commit).toHaveBeenCalled());
    cancelTransfer("t"); commit.resolve(); await run;
    expect(current().state).toBe("cancelled");
    expect(from.remove).not.toHaveBeenCalled();
  });

  it("leaves a folder alone when a folder inside it could not be removed", async () => {
    const from = source("local"), to = source("remote");
    const tree: Record<string, { name: string; isDir: boolean; size: number }[]> = {
      "/file": [{ name: "a", isDir: true, size: 0 }],
      "/file/a": [{ name: "b", isDir: true, size: 0 }],
      "/file/a/b": [{ name: "x", isDir: false, size: 100 }],
    };
    vi.mocked(from.list).mockImplementation(async (path) => tree[path]);
    vi.mocked(from.removeEmptyDir).mockRejectedValue(new Error("permission denied"));
    await startTransfer(moving("dir"), from, to, resolver);
    expect(vi.mocked(from.removeEmptyDir).mock.calls).toEqual([["/file/a/b"]]);
    expect(current()).toMatchObject({ state: "error", error: "Copied, but the source was not removed: /file/a/b: permission denied" });
  });

  it("keeps the source when the remote file it replaced looked like the same file", async () => {
    const from = source("remote"), to = Object.assign(source("remote"), { id: "other" });
    vi.mocked(to.lstat).mockResolvedValue({ name: "file", isDir: false, size: 100 });
    await startTransfer(moving(), from, to, resolver);
    expect(to.commit).toHaveBeenCalledWith(expect.stringContaining(".unissh-"), "/dst/file", true);
    expect(from.remove).not.toHaveBeenCalled();
    expect(current()).toMatchObject({ state: "error", error: "Copied, but the source was not removed: /file: the destination looked like the same file" });
  });
});

describe("moving within one location", () => {
  it("renames instead of copying", async () => {
    const here = source("local");
    await startTransfer(moving(), here, source("local"), resolver);
    expect(here.commit).toHaveBeenCalledExactlyOnceWith("/file", "/dst/file", false);
    expect(here.createNew).not.toHaveBeenCalled();
    expect(here.remove).not.toHaveBeenCalled();
    expect(current()).toMatchObject({ state: "done", filesDone: 1 });
  });

  it("asks before taking a name that is in use, and leaves both files on skip", async () => {
    const from = source("local"), to = source("local");
    vi.mocked(to.lstat).mockResolvedValue({ name: "file", isDir: false, size: 10 });
    vi.mocked(from.lstat).mockResolvedValue({ name: "file", isDir: false, size: 10 });
    const prompt = vi.fn().mockResolvedValue({ choice: "skip", applyAll: false });
    await startTransfer(moving(), from, to, prompt);
    expect(prompt).toHaveBeenCalledOnce();
    for (const src of [from, to]) { expect(src.commit).not.toHaveBeenCalled(); expect(src.rename).not.toHaveBeenCalled(); }
    expect(current().state).toBe("done");
  });

  it("does not replace a destination that changed after the user chose to overwrite it", async () => {
    const from = source("local"), to = source("local");
    const asked = { name: "file", isDir: false, size: 10 };
    vi.mocked(to.lstat).mockResolvedValue(asked);
    vi.mocked(from.lstat).mockResolvedValueOnce(asked).mockResolvedValue({ ...asked, size: 20 });
    await startTransfer(moving(), from, to, resolver);
    expect(current()).toMatchObject({ state: "error", error: "Destination changed after the conflict decision" });
    for (const src of [from, to]) { expect(src.commit).not.toHaveBeenCalled(); expect(src.remove).not.toHaveBeenCalled(); }
  });

  it("refuses to move a folder into its own subfolder", async () => {
    const from = source("local"), to = source("local");
    const t = moving("dir"); t.fromPath = "/a"; t.label = "a"; t.toDir = "/a/b";
    await startTransfer(t, from, to, resolver);
    expect(current()).toMatchObject({ state: "error", error: "Cannot move a path into itself" });
    for (const src of [from, to]) { expect(src.rename).not.toHaveBeenCalled(); expect(src.mkdir).not.toHaveBeenCalled(); }
  });

  it("copies and then removes the source when the rename is refused", async () => {
    const from = source("local"), to = source("local");
    vi.mocked(from.commit).mockRejectedValue(new Error("Invalid cross-device link"));
    api.localCopyPrepared.mockResolvedValueOnce(100);
    await startTransfer(moving(), from, to, resolver);
    expect(to.commit).toHaveBeenCalledWith(expect.stringContaining(".unissh-"), "/dst/file", false);
    expect(from.remove).toHaveBeenCalledExactlyOnceWith("/file");
    expect(current().state).toBe("done");
  });
});
