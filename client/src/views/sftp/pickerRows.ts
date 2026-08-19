// What the saved-host picker shows for a query, and how the highlight moves
// through it. Kept out of the component because the rows and the keyboard have
// to agree: Enter opens "the highlighted row", and a filter that computed its
// list one way while the arrow keys counted another would open the wrong host.

/** The fields the picker searches. Structural rather than `ConnectionProfile` so
 *  the rule can be tested without building a whole profile — and so the terminal
 *  and SFTP pickers, which show the same two lines, can't drift apart. */
export interface PickerHost {
  label: string;
  host: string;
  port: number;
  user: string;
}

/** A row as rendered: the optional local-shell entry, then the matching hosts. */
export type PickerRow<T extends PickerHost = PickerHost> =
  | { kind: "local" }
  | { kind: "host"; host: T };

/**
 * @param hosts      saved hosts, in the order they should appear
 * @param query      what the user typed (untrimmed)
 * @param localLabel searchable text of the local-shell row, or null when this
 *                   picker has no local target (SFTP — a local shell would mean
 *                   nothing there)
 */
export function pickerRows<T extends PickerHost>(
  hosts: T[],
  query: string,
  localLabel: string | null,
): PickerRow<T>[] {
  const q = query.trim().toLowerCase();
  const rows: PickerRow<T>[] = [];
  // The local row filters like every other row rather than staying pinned through
  // a search: a list being narrowed that keeps one row regardless reads as a bug.
  if (localLabel !== null && (!q || localLabel.toLowerCase().includes(q))) {
    rows.push({ kind: "local" });
  }
  for (const host of hosts) {
    // Matched against what the row prints, so anything visible is searchable.
    const hay = `${host.label} ${host.user}@${host.host}:${host.port}`.toLowerCase();
    if (!q || hay.includes(q)) rows.push({ kind: "host", host });
  }
  return rows;
}

// The highlight arithmetic is shared with the Hosts screen's search, which has
// the same wrap-and-clamp problem. Re-exported so the picker's callers and its
// tests keep importing it from here.
export { nextRow } from "@/support/listNav";
