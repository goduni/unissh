import { afterEach, describe, expect, it, vi } from "vitest";
import type { SearchHit, SearchResult } from "@/sftp/tree-search";
import { FileSearch, NO_SEARCH, type RunSearch, type SearchSnapshot } from "./fileSearch";

const hit = (name: string): SearchHit => ({ dir: "/r", rel: name, entry: { name, isDir: false, size: 1 } });
const done: SearchResult = { state: "done", dirs: 1, scanned: 1, skipped: 0, matches: 1 };

/** A search driven by hand: `found` reports matches, `end` settles it. */
function manual() {
  let found!: (...names: string[]) => void;
  let end!: (result: SearchResult) => void;
  const run: RunSearch = (_signal, onProgress) => {
    found = (...names) => onProgress({ dirs: 1, scanned: names.length, skipped: 0 }, names.map(hit));
    return new Promise((resolve) => { end = resolve; });
  };
  return { run, found: (...names: string[]) => found(...names), end: (result: SearchResult) => end(result) };
}

function controller() {
  const commits: SearchSnapshot[] = [];
  const shown = () => commits[commits.length - 1] ?? NO_SEARCH;
  return { commits, shown, search: new FileSearch((snapshot) => { commits.push(snapshot); }, 250) };
}

afterEach(() => { vi.useRealTimers(); });

describe("file search", () => {
  it("takes nothing from a search that was replaced or cleared", async () => {
    vi.useFakeTimers();
    const { search, shown } = controller();
    const replaced = manual();
    const cleared = manual();
    const current = manual();
    search.start(replaced.run);
    search.start(cleared.run);
    search.reset();
    search.start(current.run);
    for (const old of [replaced, cleared]) {
      old.found("stale");
      old.end(done);
    }
    await vi.advanceTimersByTimeAsync(1000);
    expect(shown()).toMatchObject({ state: "searching", hits: [], scanned: 0 });
  });

  it("ends a stopped search as cancelled, with what it had found", async () => {
    vi.useFakeTimers();
    const { search, shown } = controller();
    const { run, found, end } = manual();
    let signal!: AbortSignal;
    search.start((s, onProgress) => {
      signal = s;
      return run(s, onProgress);
    });
    found("a");
    search.stop();
    expect(signal.aborted).toBe(true);
    // The walk still owns the search: it is the one to say how it ended.
    end({ ...done, state: "cancelled" });
    await vi.advanceTimersByTimeAsync(0);
    expect(shown()).toMatchObject({ state: "cancelled", hits: [hit("a")] });
  });

  it("puts matches on screen in batches, and the rest when the search ends", async () => {
    vi.useFakeTimers();
    const { search, commits, shown } = controller();
    const { run, found, end } = manual();
    search.start(run);
    found("a");
    found("b", "c");
    expect(commits).toHaveLength(1); // only "searching" so far
    await vi.advanceTimersByTimeAsync(250);
    expect(commits).toHaveLength(2);
    expect(shown().hits.map((h) => h.rel)).toEqual(["a", "b", "c"]);
    found("d");
    end(done);
    await vi.advanceTimersByTimeAsync(0);
    expect(shown()).toMatchObject({ state: "done", hits: [hit("a"), hit("b"), hit("c"), hit("d")] });
    expect(commits).toHaveLength(3);
  });
});
