// The cheat-sheet resolves every string through tDyn, which takes a runtime key:
// a typo is invisible to TypeScript and renders as the raw dotted path to the
// user. Nothing but this test catches that, and nothing but this test catches a
// row added to one catalog and forgotten in the other.

import { describe, expect, it } from "vitest";
import { shortcutGroups } from "./shortcuts";
import { en } from "@/i18n/locales/en";
import { ru } from "@/i18n/locales/ru";

const CATALOGS = { en, ru } as const;

/** Walk a dotted key into a catalog; undefined when any hop is missing. */
function resolve(catalog: object, key: string): unknown {
  let cur: unknown = catalog;
  for (const part of key.split(".")) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

function keysOf(group: ReturnType<typeof shortcutGroups>[number]) {
  return group.rows.flatMap((r) => [r.labelKey, r.keysKey ?? []].flat());
}

describe("shortcut cheat-sheet", () => {
  for (const mac of [true, false]) {
    const label = mac ? "macOS" : "other platforms";
    const groups = shortcutGroups(mac);

    it(`names every group and row in both catalogs (${label})`, () => {
      const keys = groups.flatMap((g) => [g.titleKey, ...keysOf(g)]);
      expect(keys.length).toBeGreaterThan(0);
      for (const [lang, catalog] of Object.entries(CATALOGS)) {
        for (const key of keys) {
          expect(typeof resolve(catalog, key), `${lang}: ${key}`).toBe("string");
        }
      }
    });

    it(`prints a keycap on every row (${label})`, () => {
      for (const g of groups) {
        for (const r of g.rows) {
          // Exactly one source of the cap: a literal for keyboard chords, a
          // catalog key for the mouse rows (whose caps are words, not symbols).
          expect(!!r.keys !== !!r.keysKey, `${g.titleKey}/${r.labelKey}`).toBe(true);
          if (r.keys) expect(r.keys.trim(), r.labelKey).not.toBe("");
        }
      }
    });

    // A cap printed twice with two meanings is worse than an undocumented
    // shortcut: the reader trusts it. ⌘T is the live example — it goes to the
    // terminal from outside and opens a tab from within, so it is ONE row whose
    // label says both, not two rows that contradict each other.
    it(`prints no keycap twice (${label})`, () => {
      const caps = groups.flatMap((g) => g.rows.map((r) => r.keys).filter(Boolean));
      expect(new Set(caps).size).toBe(caps.length);
    });
  }

  it("uses the platform's own modifier", () => {
    const flat = (mac: boolean) =>
      shortcutGroups(mac)
        .flatMap((g) => g.rows.map((r) => r.keys ?? ""))
        .join(" ");
    expect(flat(true)).toContain("⌘");
    expect(flat(true)).not.toContain("Ctrl+Shift+");
    expect(flat(false)).toContain("Ctrl+Shift+");
    expect(flat(false)).not.toContain("⌘");
  });
});
