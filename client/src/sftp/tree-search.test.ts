import { describe, expect, it } from "vitest";
import type { FileSource } from "@/bridge/sources";
import type { Entry } from "@/store/sftp-types";
import { Semaphore } from "./transfer-engine";
import { nameMatcher, searchTree, type SearchHit, type SearchOptions } from "./tree-search";

const file = (name: string): Entry => ({ name, isDir: false, size: 1 });
const dir = (name: string): Entry => ({ name, isDir: true, size: 4096 });

/** A source over an in-memory tree keyed by path; a missing path cannot be read. */
function fakeSource(tree: Record<string, Entry[]>, onList?: (path: string) => void) {
  const listed: string[] = [];
  const list = async (path: string) => {
    listed.push(path);
    onList?.(path);
    if (!tree[path]) throw new Error(`Permission denied: ${path}`);
    return [...tree[path]];
  };
  const join = async (base: string, name: string) => `${base}/${name}`;
  return { src: { kind: "remote", list, join } as unknown as FileSource, listed };
}

/** Search "/r" one listing at a time; `found` is every match handed over. */
async function search(src: FileSource, query: string, options: Partial<SearchOptions> = {}) {
  const found: SearchHit[] = [];
  const result = await searchTree(src, "/r", {
    sem: new Semaphore(1),
    match: nameMatcher(query)!,
    onProgress: (_progress, hits) => { found.push(...hits); },
    ...options,
  });
  return { result, found, rels: found.map((hit) => hit.rel) };
}

describe("name matcher", () => {
  it("matches a substring whatever the case, and takes a blank query as no search", () => {
    const match = nameMatcher(" ReadMe ")!;
    expect(["my-README.md", "readme", "read.me"].map(match)).toEqual([true, true, false]);
    expect(nameMatcher("  ")).toBeNull();
    // A macOS folder lists names decomposed; the query is typed composed.
    expect(["\u0438\u0306.txt", "\u0439.txt", "\u0438.txt"].map(nameMatcher("\u0439")!)).toEqual([true, true, false]);
  });

  it("matches a pattern against the whole name, with only * and ? special", () => {
    const names = ["a.log", "A.LOG", "a.log.gz", "alog", "ab.log"];
    expect(names.filter(nameMatcher("*.log")!)).toEqual(["a.log", "A.LOG", "ab.log"]);
    expect(names.filter(nameMatcher("?.log")!)).toEqual(["a.log", "A.LOG"]);
    // A `*` that took too little the first time gives way and is tried again.
    expect(nameMatcher("*.log")!("a.lo.log")).toBe(true);
    expect(["abc", "a-b-b-c", "ab-cb-c", "acb", "abcd"].filter(nameMatcher("a*b*c")!)).toEqual(["abc", "a-b-b-c", "ab-cb-c"]);
    // Anything a regular expression would read as syntax is just a character.
    expect(["a(1)+[x].txt", "a1x.txt", "b.txt"].filter(nameMatcher("a(1)+[x].*")!)).toEqual(["a(1)+[x].txt"]);
    expect(["a.txt", "[ab].txt"].filter(nameMatcher("[ab].*")!)).toEqual(["[ab].txt"]);
  });
});

describe("tree search", () => {
  it("finds matches at any depth, each with its folder and its path below the root", async () => {
    const { src } = fakeSource({
      "/r": [file("a.txt"), file("b.md"), dir("sub")],
      "/r/sub": [file("notes.TXT"), dir("deep")],
      "/r/sub/deep": [file("x.txt")],
    });
    const { result, found } = await search(src, ".txt");
    expect(found.map(({ dir: folder, rel, entry }) => [folder, rel, entry.name])).toEqual([
      ["/r", "a.txt", "a.txt"],
      ["/r/sub", "sub/notes.TXT", "notes.TXT"],
      ["/r/sub/deep", "sub/deep/x.txt", "x.txt"],
    ]);
    expect(result).toEqual({ state: "done", dirs: 3, scanned: 6, skipped: 0, matches: 3 });
  });

  it("reports a matching folder and still searches inside it", async () => {
    const { src } = fakeSource({ "/r": [dir("logs")], "/r/logs": [file("logs.txt"), file("other")] });
    expect((await search(src, "logs")).rels).toEqual(["logs", "logs/logs.txt"]);
  });

  it("matches a linked folder by name without going into it", async () => {
    const { src, listed } = fakeSource({
      "/r": [{ name: "link-x", isDir: true, isSymlink: true, size: 2 }],
      "/r/link-x": [file("x")],
    });
    expect((await search(src, "x")).rels).toEqual(["link-x"]);
    expect(listed).toEqual(["/r"]);
  });

  it("stops at the scanned-entries budget and says it was the limit", async () => {
    const { src, listed } = fakeSource({ "/r": [file("a1"), file("a2"), dir("a3")], "/r/a3": [file("a4")] });
    const { result, rels } = await search(src, "a", { maxScanned: 2 });
    expect(result).toMatchObject({ state: "limit", limit: "scanned", scanned: 2 });
    expect(rels).toEqual(["a1", "a2"]);
    expect(listed).toEqual(["/r"]);
  });

  it("stops at the matches budget and says it was the limit", async () => {
    const { src, listed } = fakeSource({ "/r": [dir("a1"), file("b"), file("a2"), file("a3")], "/r/a1": [file("a4")] });
    const { result, rels } = await search(src, "a", { maxMatches: 2 });
    expect(result).toMatchObject({ state: "limit", limit: "matches", matches: 2 });
    expect(rels).toEqual(["a1", "a2"]);
    expect(listed).toEqual(["/r"]);
  });

  it("ends as cancelled when aborted, and lists nothing afterwards", async () => {
    const abort = new AbortController();
    const { src, listed } = fakeSource(
      { "/r": [dir("a"), dir("b")], "/r/a": [dir("x"), file("a-late")], "/r/b": [], "/r/a/x": [] },
      (path) => { if (path === "/r/a") abort.abort(); },
    );
    const { result, rels } = await search(src, "a", { signal: abort.signal });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(result.state).toBe("cancelled");
    expect(rels).toEqual(["a"]);
    expect(listed).toEqual(["/r", "/r/a"]);
  });

  it("counts a subdirectory it cannot read and goes on", async () => {
    const { src } = fakeSource({ "/r": [dir("locked"), dir("open")], "/r/open": [file("hit")] });
    const { result, rels } = await search(src, "hit");
    expect(result).toMatchObject({ state: "done", skipped: 1 });
    expect(rels).toEqual(["open/hit"]);
  });

  it("ends as a lost connection when the session goes away under it", async () => {
    const { src } = fakeSource({ "/r": [file("hit"), dir("sub")], "/r/sub": [] }, (path) => {
      if (path === "/r/sub") throw { kind: "ssh", msg: "channel closed" };
    });
    const { result, rels } = await search(src, "hit");
    expect(result.state).toBe("lost");
    expect(rels).toEqual(["hit"]);
  });
});
