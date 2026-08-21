// What a user would observe, not which timer id got cleared: the screen locked
// and stayed locked past the grace, so the vault locked; it unlocked inside the
// grace, so it did not.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createSystemLockWatcher, handleSystemLockEvent } from "./systemLock";

const make = (grace: number | null, unlocked = true) => {
  const lock = vi.fn();
  const w = createSystemLockWatcher({ lock, grace, unlocked });
  return { lock, w };
};

describe("createSystemLockWatcher", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("locks once the grace has passed with the screen still locked", () => {
    const { lock, w } = make(30);
    w.signal("screen-lock");
    vi.advanceTimersByTime(29_000);
    expect(lock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1_000);
    expect(lock).toHaveBeenCalledExactlyOnceWith("screen-lock");
  });

  it("locks anyway when the user comes back AFTER the grace had expired", () => {
    // A hidden window's timers get throttled by the webview, so the callback
    // can run long after the grace it was armed for. The deadline, not the
    // callback, is what decides: coming back at 45s does not excuse a lock
    // that was owed at 30s.
    const { lock, w } = make(30);
    w.signal("screen-lock");
    vi.setSystemTime(Date.now() + 45_000); // clock moved; the timer did not fire
    w.signal("screen-unlock");
    expect(lock).toHaveBeenCalledExactlyOnceWith("screen-lock");
  });

  it("does not lock when the user comes back inside the grace", () => {
    const { lock, w } = make(30);
    w.signal("screen-lock");
    vi.advanceTimersByTime(20_000);
    w.signal("screen-unlock");
    vi.advanceTimersByTime(60_000);
    expect(lock).not.toHaveBeenCalled();
  });

  it("locks the moment the screen does when the grace is zero", () => {
    const { lock, w } = make(0);
    w.signal("screen-lock");
    expect(lock).toHaveBeenCalledTimes(1); // no timer to advance
  });

  it("locks immediately on suspend, however long the grace is", () => {
    const { lock, w } = make(300);
    w.signal("suspend");
    expect(lock).toHaveBeenCalledExactlyOnceWith("suspend");
  });

  it("lets a suspend overtake a screen lock that is still inside its grace", () => {
    const { lock, w } = make(300);
    w.signal("screen-lock");
    vi.advanceTimersByTime(5_000);
    w.signal("suspend");
    // Blamed on the suspend, not on the screen lock that armed the timer: the
    // machine going down is what actually took the sessions away.
    expect(lock).toHaveBeenCalledExactlyOnceWith("suspend");
    vi.advanceTimersByTime(600_000); // the armed timer must not fire a second one
    expect(lock).toHaveBeenCalledTimes(1);
  });

  it("does nothing at all while the vault is already locked", () => {
    const { lock, w } = make(0, false);
    w.signal("screen-lock");
    w.signal("suspend");
    vi.advanceTimersByTime(600_000);
    expect(lock).not.toHaveBeenCalled();
  });

  it("swallows the second announcement when logind and the screensaver both fire", () => {
    const { lock, w } = make(30);
    w.signal("screen-lock");
    w.signal("screen-lock");
    vi.advanceTimersByTime(60_000);
    expect(lock).toHaveBeenCalledTimes(1);
  });

  it("swallows the doubled announcement with no grace at all", () => {
    const { lock, w } = make(0);
    w.signal("screen-lock");
    w.signal("screen-lock");
    expect(lock).toHaveBeenCalledTimes(1);
  });

  it("does nothing on any signal once the setting is off", () => {
    const { lock, w } = make(null);
    w.signal("screen-lock");
    w.signal("suspend");
    vi.advanceTimersByTime(600_000);
    expect(lock).not.toHaveBeenCalled();
  });

  it("disarms a pending lock when the setting is turned off mid-grace", () => {
    const { lock, w } = make(300);
    w.signal("screen-lock");
    vi.advanceTimersByTime(10_000);
    w.setGrace(null);
    vi.advanceTimersByTime(600_000);
    expect(lock).not.toHaveBeenCalled();
  });

  it("applies a new grace to the next screen lock", () => {
    const { lock, w } = make(300);
    w.setGrace(0);
    w.signal("screen-lock");
    expect(lock).toHaveBeenCalledTimes(1);
  });

  it("hears the next screen lock after the vault has been unlocked again", () => {
    const { lock, w } = make(0);
    w.signal("screen-lock");
    expect(lock).toHaveBeenCalledTimes(1);
    w.setUnlocked(false); // the vault actually locked
    w.signal("screen-lock"); // still nothing to protect
    expect(lock).toHaveBeenCalledTimes(1);
    w.setUnlocked(true); // the user came back and unlocked
    w.signal("screen-lock");
    expect(lock).toHaveBeenCalledTimes(2);
  });

  it("hears the next screen lock after the session unlocked without a vault lock", () => {
    const { lock, w } = make(0);
    w.signal("screen-lock");
    w.signal("screen-unlock");
    w.signal("screen-lock");
    expect(lock).toHaveBeenCalledTimes(2);
  });

  // `settled` is what releases a machine that is being held awake for us: a
  // logind delay inhibitor on Linux, a blocked window proc on Windows. Every
  // suspend must reach an answer, including the ones that lock nothing —
  // otherwise a user who turned the feature off pays a stalled suspend for it.
  describe("releasing a held suspend", () => {
    it("waits for the lock it asked for", async () => {
      let finish = () => {};
      const lock = vi.fn(() => new Promise<void>((r) => (finish = r)));
      const w = createSystemLockWatcher({ lock, grace: 0, unlocked: true });

      w.signal("suspend");
      let released = false;
      void w.settled().then(() => (released = true));

      await Promise.resolve();
      expect(released).toBe(false); // still locking — the machine must wait

      finish();
      await w.settled();
      expect(released).toBe(true);
    });

    it("answers at once when the setting is off and nothing was locked", async () => {
      const { lock, w } = make(null);
      w.signal("suspend");
      await w.settled();
      expect(lock).not.toHaveBeenCalled();
    });

    it("answers at once when the vault was already locked", async () => {
      const { lock, w } = make(0, false);
      w.signal("suspend");
      await w.settled();
      expect(lock).not.toHaveBeenCalled();
    });

    it("answers even when the lock itself failed", async () => {
      const lock = vi.fn(() => Promise.reject(new Error("core is gone")));
      const w = createSystemLockWatcher({ lock, grace: 0, unlocked: true });
      w.signal("suspend");
      await expect(w.settled()).resolves.toBeUndefined();
    });
  });

  it("drops a pending lock on dispose", () => {
    const { lock, w } = make(30);
    w.signal("screen-lock");
    w.dispose();
    vi.advanceTimersByTime(600_000);
    expect(lock).not.toHaveBeenCalled();
  });
});

// Routing the raw event. The case that earns this its own describe is the LAST
// one: a suspend must be answered even when the feature is off, because the
// native side takes its inhibitor before it can know what the user chose. Get
// that wrong and turning the feature off costs the user a stalled suspend every
// time — the one way this feature can make a machine worse, not just no better.
describe("handleSystemLockEvent", () => {
  const setup = (grace: number | null, unlocked = true) => {
    const lock = vi.fn();
    const releaseSuspend = vi.fn(() => Promise.resolve());
    const watcher = createSystemLockWatcher({ lock, grace, unlocked });
    return { lock, releaseSuspend, watcher };
  };

  it("releases the machine even though the feature is switched off", async () => {
    const { lock, releaseSuspend, watcher } = setup(null);
    await handleSystemLockEvent({ signal: "suspend", token: 7 }, { watcher, releaseSuspend });
    expect(lock).not.toHaveBeenCalled(); // nothing to lock — that is the setting
    expect(releaseSuspend).toHaveBeenCalledExactlyOnceWith(7); // but say so anyway
  });

  it("releases the machine when the vault was already locked", async () => {
    const { releaseSuspend, watcher } = setup(0, false);
    await handleSystemLockEvent({ signal: "suspend", token: 8 }, { watcher, releaseSuspend });
    expect(releaseSuspend).toHaveBeenCalledExactlyOnceWith(8);
  });

  it("releases only once the vault is actually shut", async () => {
    const order: string[] = [];
    let finishLock = () => {};
    const watcher = createSystemLockWatcher({
      lock: () =>
        new Promise<void>((r) => {
          finishLock = () => {
            order.push("locked");
            r();
          };
        }),
      grace: 0,
      unlocked: true,
    });
    const releaseSuspend = vi.fn(() => {
      order.push("released");
      return Promise.resolve();
    });

    const routed = handleSystemLockEvent(
      { signal: "suspend", token: 9 },
      { watcher, releaseSuspend },
    );
    await Promise.resolve();
    expect(releaseSuspend).not.toHaveBeenCalled();

    finishLock();
    await routed;
    expect(order).toEqual(["locked", "released"]);
  });

  it("still releases the machine when the lock itself failed", async () => {
    const watcher = createSystemLockWatcher({
      lock: () => Promise.reject(new Error("core is gone")),
      grace: 0,
      unlocked: true,
    });
    const releaseSuspend = vi.fn(() => Promise.resolve());
    await handleSystemLockEvent({ signal: "suspend", token: 10 }, { watcher, releaseSuspend });
    expect(releaseSuspend).toHaveBeenCalledExactlyOnceWith(10);
  });

  it("survives a release that throws — a suspend nobody can answer is not our error", async () => {
    const { watcher } = setup(0);
    const releaseSuspend = vi.fn(() => Promise.reject(new Error("no such command")));
    await expect(
      handleSystemLockEvent({ signal: "suspend", token: 11 }, { watcher, releaseSuspend }),
    ).resolves.toBeUndefined();
  });

  it("releases nothing on a screen lock — no machine is waiting on one", async () => {
    const { releaseSuspend, watcher } = setup(0);
    await handleSystemLockEvent({ signal: "screen-lock" }, { watcher, releaseSuspend });
    expect(releaseSuspend).not.toHaveBeenCalled();
  });

  it("releases nothing when the platform handed out no token (macOS)", async () => {
    const { lock, releaseSuspend, watcher } = setup(0);
    await handleSystemLockEvent({ signal: "suspend" }, { watcher, releaseSuspend });
    expect(lock).toHaveBeenCalledExactlyOnceWith("suspend"); // it still locks
    expect(releaseSuspend).not.toHaveBeenCalled(); // there is just nothing to release
  });

  it("ignores a payload it does not understand", async () => {
    const { lock, releaseSuspend, watcher } = setup(0);
    for (const bad of [null, undefined, {}, { signal: "screen-melted" }, { signal: 3 }]) {
      await handleSystemLockEvent(bad as never, { watcher, releaseSuspend });
    }
    expect(lock).not.toHaveBeenCalled();
    expect(releaseSuspend).not.toHaveBeenCalled();
  });
});
