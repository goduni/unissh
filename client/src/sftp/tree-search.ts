// Recursive search by name below a directory, through FileSource — the same for
// the local filesystem and a remote session. SFTP has no server-side search, so
// this is a consumer of `walkTree`: every listing is matched as it arrives, and
// two budgets keep a search started at "/" from running without end.

import type { Entry } from "@/store/sftp-types";
import { apiErrorMessage } from "@/bridge/types";
import { isSftpDisconnect, type FileSource } from "@/bridge/sources";
import type { Semaphore } from "@/sftp/transfer-engine";
import { underCancelToken, walkTree } from "@/sftp/tree-walk";

/** Entries a search looks at before it stops by itself. */
export const SEARCH_MAX_SCANNED = 200_000;
/** Matches a search keeps before it stops by itself. */
export const SEARCH_MAX_MATCHES = 2_000;

/** `*` is any run of characters and `?` exactly one; the rest is literal. */
function globMatch(pattern: string[], text: string[]): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let resume = 0;
  while (t < text.length) {
    if (pattern[p] === "*") {
      star = p++;
      resume = t;
    } else if (p < pattern.length && (pattern[p] === "?" || pattern[p] === text[t])) {
      p += 1;
      t += 1;
    } else if (star >= 0) {
      // Let the last `*` take one more character and try again from there.
      p = star + 1;
      t = ++resume;
    } else return false;
  }
  while (pattern[p] === "*") p += 1;
  return p === pattern.length;
}

/** The test a query puts a name to, or null when the query is blank. Without
 *  wildcards it is a substring of the name; with `*` or `?` it is a pattern for
 *  the whole name. Never case-sensitive. */
export function nameMatcher(query: string): ((name: string) => boolean) | null {
  const q = query.trim().toLowerCase();
  if (!q) return null;
  if (!/[*?]/.test(q)) return (name) => name.toLowerCase().includes(q);
  // By code point, so that `?` stands for one character as the user sees it.
  const pattern = [...q];
  return (name) => globMatch(pattern, [...name.toLowerCase()]);
}

/** One entry whose name matched. */
export interface SearchHit {
  /** The folder it is in, as a path on the source. */
  dir: string;
  /** Its path relative to the search root, joined with "/". */
  rel: string;
  entry: Entry;
}

export interface SearchProgress {
  /** Directories listed so far. */
  dirs: number;
  /** Entries looked at so far: files, folders and links alike. */
  scanned: number;
  /** Subdirectories that could not be read. */
  skipped: number;
}

export interface SearchResult extends SearchProgress {
  /** How the search ended. "lost" is a remote session that went away under it;
   *  "failed" is a root that could not be read. */
  state: "done" | "limit" | "cancelled" | "lost" | "failed";
  /** The budget that ended it, when `state` is "limit". */
  limit?: "scanned" | "matches";
  /** Why it failed, when `state` is "failed". */
  error?: string;
  matches: number;
}

export interface SearchOptions {
  sem: Semaphore;
  /** Aborting ends the search as "cancelled"; nothing is listed after. */
  signal?: AbortSignal;
  match: (name: string) => boolean;
  maxScanned?: number;
  maxMatches?: number;
  /** Called once per listed directory with the totals so far and the matches
   *  found in it (often none). Every match is handed over before the search
   *  settles; the final totals are the returned result. */
  onProgress: (progress: SearchProgress, hits: SearchHit[]) => void;
}

/** Find the entries under `root` whose name matches. Files and folders both
 *  match, and a matching folder is still searched. Links are matched by name
 *  and never followed. Does not reject: how it ended is in the result. */
export async function searchTree(
  source: FileSource,
  root: string,
  { sem, signal, match, maxScanned = SEARCH_MAX_SCANNED, maxMatches = SEARCH_MAX_MATCHES, onProgress }: SearchOptions,
): Promise<SearchResult> {
  // The walk has a signal of its own, so that a spent budget stops it — and
  // the listings in flight — exactly as the caller's abort does.
  const walk = new AbortController();
  const cancel = () => walk.abort(signal?.reason);
  if (signal?.aborted) cancel();
  else signal?.addEventListener("abort", cancel, { once: true });

  const progress: SearchProgress = { dirs: 0, scanned: 0, skipped: 0 };
  let matches = 0;
  let limit: SearchResult["limit"];
  let failure: { error: unknown } | undefined;
  try {
    await underCancelToken(source, walk.signal, (src) =>
      walkTree(src, root, {
        sem,
        signal: walk.signal,
        onSkip: () => { progress.skipped += 1; },
        onDir: ({ path, rel, entries }) => {
          // A listing that had already arrived when the walk was stopped.
          if (walk.signal.aborted) return;
          progress.dirs += 1;
          const hits: SearchHit[] = [];
          for (const entry of entries) {
            // A budget is spent only by what would go past it: a tree of
            // exactly that size still ends as "done".
            if (progress.scanned === maxScanned) { limit = "scanned"; break; }
            progress.scanned += 1;
            if (!match(entry.name)) continue;
            if (matches === maxMatches) { limit = "matches"; break; }
            matches += 1;
            hits.push({ dir: path, rel: rel ? `${rel}/${entry.name}` : entry.name, entry });
          }
          onProgress({ ...progress }, hits);
          if (limit) walk.abort();
        },
      }));
  } catch (error) {
    failure = { error };
  } finally {
    signal?.removeEventListener("abort", cancel);
  }

  const end = (state: SearchResult["state"], more?: Pick<SearchResult, "limit" | "error">): SearchResult =>
    ({ state, ...more, ...progress, matches });
  if (limit) return end("limit", { limit });
  if (walk.signal.aborted) return end("cancelled");
  if (!failure) return end("done");
  const error = apiErrorMessage(failure.error);
  // Only a remote source has a session to lose.
  return source.kind === "remote" && isSftpDisconnect(error) ? end("lost") : end("failed", { error });
}
