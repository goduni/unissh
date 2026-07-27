// The theme-store migration chain.
//
// This exists because the chain broke once in exactly the way that is hard to
// notice: a new step was added below an early return that already excluded
// everyone the step was for. Nothing failed — the migration simply never ran,
// and the symptom would have been a user's chosen theme quietly reverting.
//
// So the cases here are the version boundaries, not the happy path.

import { beforeEach, describe, expect, it } from "vitest";
import { migrateThemeStore } from "./ThemeProvider";

const store = new Map<string, string>();

beforeEach(() => {
  store.clear();
  const mock = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
    key: () => null,
    length: 0,
  };
  Object.defineProperty(globalThis, "localStorage", { value: mock, configurable: true });
});

const seed = (kv: Record<string, string>) => {
  for (const [k, v] of Object.entries(kv)) store.set(k, v);
};

describe("theme store migration", () => {
  it("renames the candy family for someone already on v3", () => {
    // The case the v3 → v4 step exists for, and the one an early return at
    // `v >= 3` would have skipped: everyone running the app was on v3.
    seed({
      "unissh.themeV": "3",
      "unissh.appTheme": "candy",
      "unissh.termOverrideLight": "candy-light",
      "unissh.termOverrideDark": "candy-dark",
    });
    migrateThemeStore();
    expect(store.get("unissh.appTheme")).toBe("barbie");
    expect(store.get("unissh.termOverrideLight")).toBe("barbie-light");
    expect(store.get("unissh.termOverrideDark")).toBe("barbie-dark");
    expect(store.get("unissh.themeV")).toBe("4");
  });

  it("leaves a deliberate nebula choice alone", () => {
    // The regression raising the version ceiling would otherwise introduce: the
    // v2 → v3 step flips nebula to mono, and re-running it on a v3 user would
    // undo a choice they made after that migration.
    seed({ "unissh.themeV": "3", "unissh.appTheme": "nebula" });
    migrateThemeStore();
    expect(store.get("unissh.appTheme")).toBe("nebula");
  });

  it("still flips the old nebula default to mono for a v2 user", () => {
    seed({ "unissh.themeV": "2", "unissh.appTheme": "nebula" });
    migrateThemeStore();
    expect(store.get("unissh.appTheme")).toBe("mono");
  });

  it("carries a v1 store all the way through", () => {
    seed({ "unissh.themeV": "1", "unissh.term": "dracula", "unissh.density": "list" });
    migrateThemeStore();
    // v1 → v2 moved the legacy terminal choice onto the dark side…
    expect(store.get("unissh.termOverrideDark")).toBe("dracula");
    // …v2 → v3 split layout out of density…
    expect(store.get("unissh.hostsLayout")).toBe("list");
    expect(store.get("unissh.density")).toBe("comfortable");
    // …and the unset family took the new default.
    expect(store.get("unissh.appTheme")).toBe("mono");
    expect(store.get("unissh.themeV")).toBe("4");
  });

  it("does nothing at all once the store is current", () => {
    seed({ "unissh.themeV": "4", "unissh.appTheme": "candy" });
    migrateThemeStore();
    // A hand-edited value at the current version is not the migration's business;
    // the family sanitiser at read time is what handles an unknown one.
    expect(store.get("unissh.appTheme")).toBe("candy");
  });
});
