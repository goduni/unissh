// What the Hosts screen's search keeps, kept out of the component so the list
// and the keyboard cannot disagree: Enter acts on "the highlighted host", and a
// filter that computed its list one way while the arrows counted another would
// open the wrong machine — the one failure this screen must never have.

/** The fields the search reads. Structural rather than `ConnectionProfile` so the
 *  rule is testable without building a whole profile. */
export interface SearchableHost {
  label: string;
  host: string;
  user: string;
  tags: string[];
}

/** Case-insensitive substring over everything the card shows plus its tags —
 *  anything visible on a host is something people try to search by. */
export function matchesQuery(h: SearchableHost, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    h.label.toLowerCase().includes(q) ||
    h.host.toLowerCase().includes(q) ||
    h.user.toLowerCase().includes(q) ||
    h.tags.some((tag) => tag.toLowerCase().includes(q))
  );
}

/** The hosts a query keeps, in the order they were given. Sorting stays with the
 *  caller: the sort control is a separate axis and applies with or without a query. */
export function filterHosts<T extends SearchableHost>(hosts: T[], query: string): T[] {
  const q = query.trim();
  if (!q) return hosts;
  return hosts.filter((h) => matchesQuery(h, q));
}
