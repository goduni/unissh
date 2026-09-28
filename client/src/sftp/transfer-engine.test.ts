import { describe, expect, it } from "vitest";
import { abortable, Semaphore, Speedometer } from "./transfer-engine";

describe("transfer throughput", () => {
  it("does not inflate speed when progress arrives in a burst", () => {
    const s = new Speedometer();
    s.sample(0, 0);
    s.sample(1000, 999);
    s.sample(2000, 1000);
    expect(s.speed()).toBe(2000);
    expect(s.eta(4000)).toBe(2);
  });
  it("includes simultaneous callbacks and decays to zero without progress", () => {
    const s = new Speedometer();
    s.sample(0, 0);
    s.sample(1000, 1000);
    s.sample(3000, 1000);
    expect(s.speed()).toBe(3000);
    for (let ms = 1250; ms <= 4250; ms += 250) s.sample(3000, ms);
    expect(s.speed()).toBe(0);
    expect(s.eta(100)).toBe(Infinity);
  });
  it("waits for a meaningful measurement interval", () => {
    const s = new Speedometer();
    s.sample(0, 0);
    s.sample(1000000, 1);
    expect(s.speed()).toBe(0);
  });
});

describe("interruptible queue", () => {
  it("removes a cancelled waiter without losing the next permit", async () => {
    const sem = new Semaphore(1);
    let release!: () => void;
    const first = sem.run(() => new Promise<void>((resolve) => { release = resolve; }));
    await Promise.resolve();
    const abort = new AbortController();
    let ran = false;
    const second = sem.run(async () => { ran = true; }, abort.signal);
    const rejected = expect(second).rejects.toThrow();
    abort.abort();
    await rejected;
    release();
    await first;
    expect(await sem.run(async () => 42)).toBe(42);
    expect(ran).toBe(false);
  });
  it("interrupts an unresponsive read-only wait", async () => {
    const abort = new AbortController();
    const result = abortable(new Promise(() => {}), abort.signal);
    const rejected = expect(result).rejects.toThrow();
    abort.abort();
    await rejected;
  });
});
