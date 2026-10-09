// Shared filter+sort for a directory listing — used by FileList (rendering) and
// useSlot (shift-range selection needs the same visible order).

import type { Entry, SortKey, SortState } from "@/store/sftp-types";

export function compareEntries(a: Entry, b: Entry, key: SortKey, dir: "asc" | "desc"): number {
  if (a.isDir !== b.isDir) return a.isDir ? -1 : 1; // folders always first
  let r = 0;
  if (key === "size") r = a.size - b.size;
  else if (key === "mtime") r = (a.mtime ?? 0) - (b.mtime ?? 0);
  else if (key === "mode") r = (a.mode ?? 0) - (b.mode ?? 0);
  else r = a.name.localeCompare(b.name);
  if (r === 0) r = a.name.localeCompare(b.name);
  return dir === "asc" ? r : -r;
}

function filterEntries(entries: Entry[], filter: string): Entry[] {
  const f = filter.trim().toLowerCase();
  return f ? entries.filter((e) => e.name.toLowerCase().includes(f)) : entries.slice();
}

/** The names the filter leaves on screen — all an operation may reach. */
export function shownNames(entries: Entry[], filter: string): Set<string> {
  return new Set(filterEntries(entries, filter).map((e) => e.name));
}

/** What it takes to show the entry `name` of a listing under `filter`: null
 *  when the listing has no such entry — it is simply not there to point at —
 *  else whether the filter hides it and has to be cleared first. */
export function revealPlan(entries: Entry[], filter: string, name: string): { clearFilter: boolean } | null {
  if (!entries.some((e) => e.name === name)) return null;
  return { clearFilter: !shownNames(entries, filter).has(name) };
}

export function displayEntries(entries: Entry[], filter: string, sort: SortState): Entry[] {
  const list = filterEntries(entries, filter);
  list.sort((a, b) => compareEntries(a, b, sort.key, sort.dir));
  return list;
}
