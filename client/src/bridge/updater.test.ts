// The updater's decision logic decides how often UniSSH talks to github.com and
// whether it talks at all. Both are promises made to the user in Settings -> About
// and THREAT_MODEL.md, so they are locked down here rather than left to review.
//
// Everything below is the pure/storage layer. The plugin call itself is not mocked
// and not tested: it needs a real Tauri context, and asserting against a mock of
// `check()` would only test the mock.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AUTO_CHECK_KEY,
  LAST_CHECK_KEY,
  MIN_CHECK_GAP_MS,
  isAutoCheckEnabled,
  lastCheckedAt,
  setAutoCheckEnabled,
  shouldCheckNow,
  updatesSupported,
} from "./updater";

// vitest runs in the node environment here (no jsdom), so localStorage has to be
// supplied. A Map-backed stub exercises the real code path instead of the
// catch-branch fallbacks.
function installStorage() {
  const map = new Map<string, string>();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => map.get(k) ?? null,
      setItem: (k: string, v: string) => void map.set(k, v),
      removeItem: (k: string) => void map.delete(k),
      clear: () => map.clear(),
    },
  });
  return map;
}

describe("updatesSupported", () => {
  it("covers exactly the three desktop platforms", () => {
    expect(updatesSupported("macos")).toBe(true);
    expect(updatesSupported("windows")).toBe(true);
    expect(updatesSupported("linux")).toBe(true);
  });

  it("excludes mobile — sideload artifacts are re-installed by hand", () => {
    expect(updatesSupported("android")).toBe(false);
    expect(updatesSupported("ios")).toBe(false);
  });

  it("treats a non-Tauri context as unsupported, not as a silent failure", () => {
    // osPlatform() yields "unknown" under plain `vite dev`. Counting that as
    // supported would fire a check with no plugin behind it on every reload.
    expect(updatesSupported("unknown")).toBe(false);
  });
});

describe("shouldCheckNow", () => {
  const base = { enabled: true, supported: true, now: 10_000_000, lastCheckedAt: null };

  it("checks when nothing has been checked yet", () => {
    expect(shouldCheckNow(base)).toBe(true);
  });

  it("does not check when the preference is off", () => {
    expect(shouldCheckNow({ ...base, enabled: false })).toBe(false);
  });

  it("does not check on an unsupported platform even when enabled", () => {
    expect(shouldCheckNow({ ...base, supported: false })).toBe(false);
  });

  it("suppresses a second check inside the one-hour floor", () => {
    const now = 10_000_000;
    expect(shouldCheckNow({ ...base, now, lastCheckedAt: now - 1 })).toBe(false);
    expect(shouldCheckNow({ ...base, now, lastCheckedAt: now - (MIN_CHECK_GAP_MS - 1) })).toBe(
      false,
    );
  });

  it("allows a check once the floor has elapsed", () => {
    const now = 10_000_000;
    expect(shouldCheckNow({ ...base, now, lastCheckedAt: now - MIN_CHECK_GAP_MS })).toBe(true);
  });

  it("recovers from a clock that jumped backwards", () => {
    // NTP correction / VM resume / timezone fix leaves a stamp in the future.
    // Without this branch, checks stay wedged off until real time catches up.
    const now = 10_000_000;
    expect(shouldCheckNow({ ...base, now, lastCheckedAt: now + 86_400_000 })).toBe(true);
  });
});

describe("preferences", () => {
  let store: Map<string, string>;

  beforeEach(() => {
    store = installStorage();
  });

  afterEach(() => {
    Reflect.deleteProperty(globalThis, "localStorage");
  });

  it("defaults to on when the user has never touched the setting", () => {
    expect(isAutoCheckEnabled()).toBe(true);
  });

  it("round-trips the toggle", () => {
    setAutoCheckEnabled(false);
    expect(store.get(AUTO_CHECK_KEY)).toBe("0");
    expect(isAutoCheckEnabled()).toBe(false);

    setAutoCheckEnabled(true);
    expect(isAutoCheckEnabled()).toBe(true);
  });

  it("treats only an explicit '0' as off, so an unrelated value cannot disable updates", () => {
    store.set(AUTO_CHECK_KEY, "yes");
    expect(isAutoCheckEnabled()).toBe(true);
  });

  it("reads back a stored check timestamp", () => {
    store.set(LAST_CHECK_KEY, "1234567890");
    expect(lastCheckedAt()).toBe(1234567890);
  });

  it("reports no prior check for absent or corrupt stamps", () => {
    expect(lastCheckedAt()).toBeNull();
    store.set(LAST_CHECK_KEY, "not-a-number");
    expect(lastCheckedAt()).toBeNull();
  });
});
