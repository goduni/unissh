// The recursive search of one pane, without React: which walk is the current
// one, what its result list shows, and when that reaches the screen.
//
// There is one search at a time. Starting another, or resetting, takes the
// ownership away from the walk that had it, and a walk that no longer owns the
// search may not write — which is what makes anything it still has to say
// harmless. Stopping is different: the walk keeps the search and ends it as
// "cancelled", with what it had found.

import { apiErrorMessage } from "@/bridge/types";
import type { SearchHit, SearchProgress, SearchResult } from "@/sftp/tree-search";
import { FlushTimer } from "./flushTimer";

/** What the search dialog shows. */
export interface SearchSnapshot extends SearchProgress {
  /** Changes with every search started or cleared: a new one is a new list. */
  run: number;
  state: "idle" | "searching" | SearchResult["state"];
  limit?: SearchResult["limit"];
  error?: string;
  /** In the order found; only ever appended to within one run. */
  hits: readonly SearchHit[];
}

export const NO_SEARCH: SearchSnapshot = { run: 0, state: "idle", hits: [], dirs: 0, scanned: 0, skipped: 0 };

/** Runs one search to its end; `onProgress` takes what each listing adds. */
export type RunSearch = (signal: AbortSignal, onProgress: (progress: SearchProgress, hits: SearchHit[]) => void) => Promise<SearchResult>;

export class FileSearch {
  private shown = NO_SEARCH;
  private runs = NO_SEARCH.run;
  /** The walk that owns the search, while one is running. */
  private walk: AbortController | undefined;
  /** Found but not on screen yet; one timer commits them all. */
  private pending: SearchHit[] = [];
  private progress: SearchProgress | undefined;
  private readonly timer: FlushTimer;

  constructor(
    private readonly onChange: (snapshot: SearchSnapshot) => void,
    flushMs?: number,
  ) {
    this.timer = new FlushTimer(() => this.flush(), flushMs);
  }

  /** Start a search, in place of the one running or shown. */
  start(run: RunSearch): void {
    this.disown();
    const walk = new AbortController();
    this.walk = walk;
    const owns = () => this.walk === walk;
    const finish = (end: Partial<SearchSnapshot>) => {
      if (!owns()) return;
      this.walk = undefined;
      this.timer.disarm();
      this.flush(end);
    };
    this.commit({ ...NO_SEARCH, run: ++this.runs, state: "searching" });
    run(walk.signal, (progress, hits) => {
      if (!owns()) return;
      this.progress = progress;
      for (const hit of hits) this.pending.push(hit);
      this.timer.arm();
    }).then(
      ({ state, limit, error, dirs, scanned, skipped }) => finish({ state, limit, error, dirs, scanned, skipped }),
      (error) => finish({ state: "failed", error: apiErrorMessage(error) }),
    );
  }

  /** Stop the running search; it ends as "cancelled" and keeps its results. */
  stop(): void {
    this.walk?.abort();
  }

  /** Stop the running search and forget every result. */
  reset(): void {
    this.disown();
    if (this.shown.state !== "idle") this.commit({ ...NO_SEARCH, run: ++this.runs });
  }

  private disown(): void {
    this.walk?.abort();
    this.walk = undefined;
    this.pending = [];
    this.progress = undefined;
    this.timer.disarm();
  }

  /** Put what was found since the last flush on screen, with how it ended if it has. */
  private flush(end?: Partial<SearchSnapshot>): void {
    const hits = this.pending.length ? this.shown.hits.concat(this.pending) : this.shown.hits;
    this.pending = [];
    this.commit({ ...this.shown, ...this.progress, hits, ...end });
  }

  private commit(snapshot: SearchSnapshot): void {
    this.shown = snapshot;
    this.onChange(snapshot);
  }
}
