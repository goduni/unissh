// The OS-lock path ends in the SAME lock as everything else.
//
// The grace decision is pinned in support/systemLock.test.ts; what is pinned
// here is the wiring App.tsx does around it — that a screen lock reaches
// `lockInstance()`, the one action the lock button and the idle timer call, and
// therefore zeroizes exactly as they do. The point is not that a callback ran:
// it is that there is a single place where zeroize can be got wrong, and the
// newest way to trigger a lock did not quietly grow a second one.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const lock = vi.fn();

vi.mock("@/bridge/api", () => ({
  lock: (...a: unknown[]) => lock(...a),
  sessionClose: () => Promise.resolve(),
  sftpClose: () => Promise.resolve(),
}));

const clearSecretKey = vi.fn();
vi.mock("@/bridge/secretKey", () => ({
  clearSecretKey: () => clearSecretKey(),
  rememberSecretKey: () => {},
  readSecretKey: () => null,
}));

import { useApp } from "./app";
import { createSystemLockWatcher } from "@/support/systemLock";

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
}

/** Exactly what App.tsx builds: the watcher, handed the store's lock action. */
const watch = (grace: number | null) =>
  createSystemLockWatcher({
    lock: (cause) => void useApp.getState().lockInstance(cause),
    grace,
    unlocked: useApp.getState().unlocked,
  });

describe("locking because the OS did", () => {
  beforeEach(() => {
    installStorage();
    vi.useFakeTimers();
    lock.mockReset().mockResolvedValue(undefined);
    clearSecretKey.mockReset();
    useApp.setState({
      unlocked: true,
      overlay: null,
      lockReason: null,
      hosts: [],
      items: [],
      terminals: [{ id: "t1", panes: [], activePaneId: null }] as never,
      tunnels: [{ id: "tun1" }] as never,
    });
  });
  afterEach(() => vi.useRealTimers());

  it("tears the instance down through the one lock action", async () => {
    const w = watch(30);
    w.signal("screen-lock");
    vi.advanceTimersByTime(30_000);
    await vi.waitFor(() => expect(useApp.getState().unlocked).toBe(false));

    // The core was told to zeroize, the cached Secret Key is gone, and every
    // live session went with them — the same teardown the lock button performs.
    expect(lock).toHaveBeenCalledTimes(1);
    expect(clearSecretKey).toHaveBeenCalledTimes(1);
    expect(useApp.getState().terminals).toEqual([]);
    expect(useApp.getState().tunnels).toEqual([]);
    expect(useApp.getState().overlay).toBe("unlock");
  });

  it("says on the lock screen which signal took the sessions away", async () => {
    const w = watch(0);
    w.signal("suspend");
    await vi.waitFor(() => expect(useApp.getState().unlocked).toBe(false));
    expect(useApp.getState().lockReason).toBe("suspend");
  });

  it("leaves an already-locked instance alone", () => {
    useApp.setState({ unlocked: false });
    const w = watch(0);
    w.signal("screen-lock");
    w.signal("suspend");
    expect(lock).not.toHaveBeenCalled();
  });
});
