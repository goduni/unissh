import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Transfer } from "@/store/sftp-types";
import type { FileSource } from "@/bridge/sources";

const { state, api } = vi.hoisted(() => {
  const state = {
    transfers: [] as Transfer[], sftpParallelism: 1, sftpSessions: [],
    patchTransfer(id: string, patch: Partial<Transfer>) {
      state.transfers = state.transfers.map((t) => t.id === id ? { ...t, ...patch } : t);
    },
  };
  return { state, api: { cancelNew: vi.fn(), cancelTrigger: vi.fn(), cancelDispose: vi.fn(), sftpUpload: vi.fn(), sftpDownload: vi.fn() } };
});
vi.mock("@/store/app", () => ({ useApp: { getState: () => state } }));
vi.mock("@/bridge/api", () => api);
vi.mock("@tauri-apps/api/path", () => ({ join: async (...p: string[]) => p.join("/"), tempDir: async () => "/tmp" }));
vi.mock("@tauri-apps/plugin-fs", () => ({ remove: vi.fn().mockResolvedValue(undefined), copyFile: vi.fn(), stat: vi.fn() }));
import { cancelAll, cancelTransfer, pauseTransfer, startTransfer, serializeResolver } from "./transfer-runner";
import { Semaphore } from "./transfer-engine";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const source = (kind: "local" | "remote"): FileSource => ({
  kind, id: kind, label: kind, join: async (a: string, b: string) => `${a}/${b}`,
  stat: vi.fn().mockResolvedValue(null), list: vi.fn().mockResolvedValue([]), mkdir: vi.fn().mockResolvedValue(undefined),
} as unknown as FileSource);
function transfer(id = "t", kind: "file" | "dir" = "file"): Transfer {
  const t: Transfer = { id, kind, label: "file", from: { kind: "local" }, to: { kind: "remote", sessionId: "remote" }, fromPath: "/file", toDir: "/dst", bytesDone: 0, bytesTotal: 100, filesDone: 0, filesTotal: 1, state: "queued", speedBps: 0, etaSec: 0, offset: 0 };
  state.transfers.push(t);
  return t;
}
const resolver = vi.fn().mockResolvedValue({ choice: "overwrite", applyAll: true });
const current = (id = "t") => state.transfers.find((t) => t.id === id)!;
beforeEach(() => {
  cancelAll(); state.transfers = []; vi.clearAllMocks();
  let tokenSeq = 0;
  api.cancelNew.mockImplementation(async () => `token-${++tokenSeq}`); api.cancelTrigger.mockResolvedValue(undefined); api.cancelDispose.mockResolvedValue(undefined);
  api.sftpUpload.mockResolvedValue(true); api.sftpDownload.mockResolvedValue(true);
});

describe("transfer lifecycle", () => {
  it("cancels while stat is hung and ignores its late result", async () => {
    const dest = source("remote"); const stat = deferred<null>();
    vi.mocked(dest.stat).mockReturnValue(stat.promise);
    const run = startTransfer(transfer(), source("local"), dest, resolver);
    await vi.waitFor(() => expect(dest.stat).toHaveBeenCalled());
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
    const second = startTransfer(transfer("second"), source("local"), source("remote"), resolver, sem);
    await vi.waitFor(() => expect(api.sftpUpload).toHaveBeenCalledTimes(1));
    expect(current("second").state).toBe("queued");
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
    const from = source("local"); vi.mocked(from.list).mockReturnValue(new Promise(() => {}));
    const run = startTransfer(transfer("t", "dir"), from, source("remote"), resolver);
    await vi.waitFor(() => expect(from.list).toHaveBeenCalled());
    cancelTransfer("t"); await run;
    expect(current().state).toBe("cancelled");
  });
  it("releases the serialized conflict queue when its prompt is cancelled", async () => {
    const dest = source("remote"); vi.mocked(dest.stat).mockResolvedValue({ name: "file", size: 10, isDir: false });
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
    expect(api.sftpDownload.mock.calls[0][4]).toBe(100);
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
    expect(current()).toMatchObject({state:"error",error:"permission denied"});
  });
  it("measures only new bytes after resuming and decays during a stall", async () => {
    vi.useFakeTimers();
    try {
      const to = source("remote"); vi.mocked(to.stat).mockResolvedValue({name:"a",size:80,isDir:false});
      const write = deferred<boolean>(); api.sftpUpload.mockReturnValue(write.promise);
      const run = startTransfer(transfer(), source("local"), to, async () => ({choice:"resume",applyAll:true}));
      await vi.advanceTimersByTimeAsync(0);
      const progress = api.sftpUpload.mock.calls[0][4];
      await vi.advanceTimersByTimeAsync(1000);
      progress({transferred:90,total:100});
      await vi.advanceTimersByTimeAsync(250);
      expect(current().speedBps).toBe(8); // 10 new bytes / 1.25 seconds, not the 80-byte prefix
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
      vi.mocked(to.stat).mockResolvedValueOnce({name:"a",size:1000,isDir:false}).mockResolvedValue(null);
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
    vi.mocked(to.stat).mockResolvedValue({name:"file",size:10,isDir:false});
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
      vi.mocked(to.stat).mockResolvedValue({name:"file",size:10,isDir:false});
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
    vi.mocked(to.stat).mockResolvedValue({name:"file",size:10,isDir:false});
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
