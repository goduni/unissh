import { describe, it, expect } from "vitest";
import { settleStep, zeroHold } from "./external-edit";

const st = (size: number, mtime: number) => ({ size, mtime });

describe("settleStep", () => {
  const uploaded = st(100, 1000);
  const T0 = 1_000_000;
  /** Comfortably past SETTLE_MS. */
  const later = T0 + 5_000;

  it("does nothing while the copy matches what was uploaded", () => {
    expect(settleStep(uploaded, undefined, st(100, 1000), T0)).toEqual({ action: "none" });
  });

  it("starts the clock on the first changed reading rather than pushing at once", () => {
    expect(settleStep(uploaded, undefined, st(120, 2000), T0)).toEqual({
      action: "wait",
      settling: { size: 120, mtime: 2000, since: T0 },
    });
  });

  it("pushes once the same change has held still long enough", () => {
    const first = settleStep(uploaded, undefined, st(120, 2000), T0);
    if (first.action !== "wait") throw new Error("expected wait");
    expect(settleStep(uploaded, first.settling, st(120, 2000), later)).toEqual({ action: "push" });
  });

  it("keeps waiting while the change is younger than the settle window", () => {
    const first = settleStep(uploaded, undefined, st(120, 2000), T0);
    if (first.action !== "wait") throw new Error("expected wait");
    expect(settleStep(uploaded, first.settling, st(120, 2000), T0 + 50).action).toBe("wait");
  });

  it("restarts the clock while the file is still growing", () => {
    // A large save streaming to disk: every reading is bigger than the last,
    // and none of them may be uploaded — that would push a half-written file.
    let settling: { size: number; mtime: number; since: number } | undefined;
    let t = T0;
    for (const size of [40, 80, 120]) {
      const step = settleStep(uploaded, settling, st(size, 2000), t);
      expect(step.action).toBe("wait");
      if (step.action !== "wait") return;
      expect(step.settling.since).toBe(t);
      settling = step.settling;
      t += 5_000;
    }
    expect(settleStep(uploaded, settling, st(120, 2000), t)).toEqual({ action: "push" });
  });

  it("treats a write-then-rename save as one change", () => {
    // The rename lands atomically, so both readings after it are identical —
    // exactly the case an inode watcher misses.
    const after = st(133, 2500);
    const first = settleStep(uploaded, undefined, after, T0);
    if (first.action !== "wait") throw new Error("expected wait");
    expect(settleStep(uploaded, first.settling, after, later)).toEqual({ action: "push" });
  });

  it("measures the wait in wall-clock, so a throttled poll can't stretch it", () => {
    // Two readings a minute apart — what a hidden window actually gets — must
    // still push on the second one, not on some later tick.
    const changed = st(150, 3000);
    const first = settleStep(uploaded, undefined, changed, T0);
    if (first.action !== "wait") throw new Error("expected wait");
    expect(settleStep(uploaded, first.settling, changed, T0 + 60_000)).toEqual({ action: "push" });
  });

  it("drops the candidate when the file goes back to what we uploaded", () => {
    const first = settleStep(uploaded, undefined, st(120, 2000), T0);
    if (first.action !== "wait") throw new Error("expected wait");
    expect(settleStep(uploaded, first.settling, uploaded, later)).toEqual({ action: "clear" });
  });

  it("notices a same-size edit through mtime alone", () => {
    const touched = st(100, 5000);
    const first = settleStep(uploaded, undefined, touched, T0);
    if (first.action !== "wait") throw new Error("expected wait");
    expect(settleStep(uploaded, first.settling, touched, later)).toEqual({ action: "push" });
  });

  it("notices a same-mtime edit through size alone", () => {
    // Coarse mtime resolution on some filesystems: two saves inside one second.
    const grown = st(140, 1000);
    const first = settleStep(uploaded, undefined, grown, T0);
    if (first.action !== "wait") throw new Error("expected wait");
    expect(settleStep(uploaded, first.settling, grown, later)).toEqual({ action: "push" });
  });
});

describe("zeroHold", () => {
  const T0 = 1_000_000;

  it("ignores a copy that isn't empty", () => {
    expect(zeroHold(120, 100, undefined, T0)).toEqual({ action: "none" });
  });

  it("clears a stale mark once the copy has content again", () => {
    expect(zeroHold(120, 100, T0 - 500, T0)).toEqual({ action: "reset" });
  });

  it("starts the clock the first time the copy reads as empty", () => {
    expect(zeroHold(0, 100, undefined, T0)).toEqual({ action: "hold", since: T0 });
  });

  it("keeps holding while the wait is unserved", () => {
    expect(zeroHold(0, 100, T0, T0 + 1_000)).toEqual({ action: "hold", since: T0 });
  });

  it("lets a deliberate truncation through once the wait is served", () => {
    // The bug this guards: the old tick-counting version reset its own counter
    // on the way out, wiping the settling progress every time, so an emptied
    // file was never pushed at all.
    expect(zeroHold(0, 100, T0, T0 + 60_000)).toEqual({ action: "none" });
  });

  it("measures the wait in wall-clock, so a throttled poll can't stretch it", () => {
    // Two ticks a minute apart are enough; the old version needed twenty of
    // them, which under a hidden window's throttling was twenty minutes.
    const first = zeroHold(0, 100, undefined, T0);
    if (first.action !== "hold") throw new Error("expected hold");
    expect(zeroHold(0, 100, first.since, T0 + 60_000)).toEqual({ action: "none" });
  });

  it("never holds when the file was already empty on the server", () => {
    expect(zeroHold(0, 0, undefined, T0)).toEqual({ action: "none" });
  });
});
