// Fixed-height file rows: keep the DOM bounded, including after a list shrinks
// while its scroll position still points into the previous directory.
export function visibleRows(count: number, rowHeight: number, top: number, height: number) {
  const overscan = 8;
  const first = Math.min(Math.max(0, count - 1), Math.max(0, Math.floor(top / rowHeight)));
  const start = Math.max(0, first - overscan);
  const end = Math.min(count, Math.max(first + 1, Math.ceil((top + height) / rowHeight)) + overscan);
  return { start, end };
}

/** How many rows PgUp/PgDn move the cursor: the whole rows that fit, at least one. */
export function pageRows(height: number, rowHeight: number): number {
  return Math.max(1, Math.floor(height / rowHeight));
}
