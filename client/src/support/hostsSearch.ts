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

/** The hosts a query keeps, in the order they were given. Always a fresh array, so
 *  a caller that sorts in place cannot reach back into the list it was given.
 *  Sorting stays with the caller: the sort control is a separate axis and applies
 *  with or without a query. */
export function filterHosts<T extends SearchableHost>(hosts: T[], query: string): T[] {
  const q = query.trim();
  if (!q) return hosts.slice();
  return hosts.filter((h) => matchesQuery(h, q));
}

/** Only the fields the decision below reads — so the rule can be tested without a
 *  DOM, which this repo has no harness for. */
export interface SearchKeyEvent {
  key: string;
  metaKey?: boolean;
  ctrlKey?: boolean;
  /** Mid-IME-composition: the Enter that commits a candidate is not a command. */
  isComposing?: boolean;
}

/** What a keystroke in the search box should do. `null` means "leave it alone" —
 *  the box is still a text field, and Escape on an empty one belongs to whatever
 *  is above (the rail, a dialog stack). */
export type SearchAction =
  | { kind: "move"; delta: 1 | -1 }
  | { kind: "open" }
  | { kind: "connect" }
  | { kind: "clear" }
  | null;

/**
 * @param hasQuery whether anything is actually typed (trimmed)
 * @param hasHit   whether the highlight currently points at a host
 *
 * Enter does nothing without a query: `hasQuery` is what keeps a Return on an
 * empty box — the soft keyboard's own key on a phone — from opening whichever
 * host happens to sit first in the list and pushing the user into a detail screen.
 */
export function searchKeyAction(
  e: SearchKeyEvent,
  { hasQuery, hasHit }: { hasQuery: boolean; hasHit: boolean },
): SearchAction {
  if (e.isComposing) return null;
  if (e.key === "ArrowDown") return { kind: "move", delta: 1 };
  if (e.key === "ArrowUp") return { kind: "move", delta: -1 };
  if (e.key === "Enter") {
    if (!hasQuery || !hasHit) return null;
    // Enter OPENS; ⌘/Ctrl+Enter connects. A filter box that starts an SSH session
    // on a stray Enter is a worse failure than one that does nothing, and ⌘K
    // already exists for connect-on-Enter.
    return e.metaKey || e.ctrlKey ? { kind: "connect" } : { kind: "open" };
  }
  if (e.key === "Escape" && hasQuery) return { kind: "clear" };
  return null;
}
