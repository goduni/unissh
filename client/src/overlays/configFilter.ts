// Cutting an ssh config down to the hosts the user ticked.
//
// Only the text-based import needs this: a path-based one is told which aliases
// to take, because filtering text cannot reach a host that lives in another
// file. Kept beside the overlay rather than inside it because getting it wrong
// writes a host to the vault that the user explicitly unticked.

const isWildcard = (a: string) => a.includes("*") || a.includes("?") || a.startsWith("!");

/** Keeps only what `selected` names.
 *
 *  Wildcard blocks (`Host *`, `Host *.example.com`) and the global preamble
 *  before the first `Host` are always kept, so the settings the selected hosts
 *  inherit still resolve. A line naming several aliases is **rewritten** to the
 *  ones that survived: the core creates a profile for every alias in the text it
 *  is handed, so keeping `Host staging prod` whole for the sake of `staging`
 *  would import `prod` too — and dropping it whole for the sake of `prod` would
 *  import neither. */
export function filterConfigToSelected(text: string, selected: Set<string>): string {
  const out: string[] = [];
  let keep = true; // keep the global preamble before the first Host block
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const m = line.match(/^([Hh]ost)\s+(.+)$/);
    if (m && !line.startsWith("#")) {
      const patterns = m[2].trim().split(/\s+/);
      const kept = patterns.filter((p) => isWildcard(p) || selected.has(p));
      keep = kept.length > 0;
      if (keep) {
        const indent = raw.slice(0, raw.length - raw.trimStart().length);
        out.push(kept.length === patterns.length ? raw : `${indent}${m[1]} ${kept.join(" ")}`);
        continue;
      }
    }
    if (keep) out.push(raw);
  }
  return out.join("\n");
}
