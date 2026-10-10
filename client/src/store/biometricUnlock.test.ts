// The unlock screen's biometric state machine. One test per transition group:
// what the screen starts with, and every way the prompt can end — for
// biometric unlock and for the Secret-Key-only presence gate.

import { describe, expect, it } from "vitest";
import {
  biometricUnlockReducer as reduce,
  initialBiometricUnlock as initial,
  type BiometricUnlockEvent,
  type BiometricUnlockState,
} from "./biometricUnlock";

const run = (events: BiometricUnlockEvent[], from: BiometricUnlockState = initial) =>
  events.reduce(reduce, from);

const enabled = { type: "status", enabled: true, secretKeyRemembered: true } as const;
const gateOn = { type: "gate", on: true, secretKeyRemembered: true, presenceSupported: true } as const;

// The first prompt of each kind: attempt 1.
const prompting = run([enabled]);
const gate = run([gateOn]);

describe("biometric unlock screen", () => {
  it("prompts at once when enabled, and goes straight to the password when not", () => {
    expect(prompting).toEqual({ phase: "prompting", available: true, notice: null, gate: false, attempt: 1 });
    expect(run([{ type: "status", enabled: false, secretKeyRemembered: true }])).toEqual({
      phase: "password",
      available: false,
      notice: null,
      gate: false,
      attempt: 0,
    });
  });

  it("is done when the prompt unlocks", () => {
    expect(run([{ type: "outcome", outcome: "unlocked", attempt: 1 }], prompting).phase).toBe("done");
  });

  it("falls back to the password on cancel or failure, and can prompt again", () => {
    const cancelled = run([{ type: "outcome", outcome: "cancelled", attempt: 1 }], prompting);
    expect(cancelled).toEqual({ phase: "password", available: true, notice: null, gate: false, attempt: 1 });
    const failed = run([{ type: "error", attempt: 1 }], prompting);
    expect(failed).toEqual({ phase: "password", available: true, notice: "failed", gate: false, attempt: 1 });
    expect(run([{ type: "retry" }], failed)).toEqual({ ...prompting, attempt: 2 });
  });

  it("does not offer the biometric without a remembered Secret Key, and says why", () => {
    const unusable = { phase: "password", available: false, notice: "noSecretKey", gate: false };
    expect(run([{ type: "status", enabled: true, secretKeyRemembered: false }])).toEqual({ ...unusable, attempt: 0 });
    expect(run([{ type: "outcome", outcome: "noSecretKey", attempt: 1 }, { type: "retry" }], prompting)).toEqual({
      ...unusable,
      attempt: 1,
    });
  });

  it("falls back to the password for good when the stored material was invalidated", () => {
    const gone = run([{ type: "outcome", outcome: "invalidated", attempt: 1 }, { type: "retry" }], prompting);
    expect(gone).toEqual({ phase: "password", available: false, notice: "invalidated", gate: false, attempt: 1 });
  });

  it("leaves a prompt that does not answer for the password, and still follows a vault that opened", () => {
    const skipped = run([{ type: "skip" }], prompting);
    expect(skipped).toEqual({ phase: "password", available: true, notice: null, gate: false, attempt: 1 });
    expect(run([{ type: "outcome", outcome: "unlocked", attempt: 1 }], skipped).phase).toBe("done");
  });

  it("opens the password path when the status does not answer in time, and only offers a prompt that turns up late", () => {
    const waitedOut = run([{ type: "timeout" }]);
    expect(waitedOut).toEqual({ phase: "password", available: false, notice: null, gate: false, attempt: 0 });
    expect(run([enabled], waitedOut)).toEqual({ ...waitedOut, available: true });
    expect(run([gateOn], waitedOut)).toEqual({ ...waitedOut, available: true, notice: "gated", gate: true });
    // A view that already knows better is not rewritten by a second answer.
    const gone = run([{ type: "outcome", outcome: "invalidated", attempt: 1 }], prompting);
    expect(run([enabled], gone)).toEqual(gone);
  });

  it("ignores what an earlier prompt reports once a newer one is up", () => {
    const again = run([{ type: "skip" }, { type: "retry" }], prompting);
    expect(again).toEqual({ ...prompting, attempt: 2 });
    expect(run([{ type: "outcome", outcome: "cancelled", attempt: 1 }, { type: "error", attempt: 1 }], again)).toEqual(
      again,
    );
  });

  it("with the presence gate on, prompts before the remembered-key unlock, and not without one to guard or a prompt to show", () => {
    expect(gate).toEqual({ phase: "prompting", available: true, notice: null, gate: true, attempt: 1 });
    expect(run([{ type: "outcome", outcome: "unlocked", attempt: 1 }], gate).phase).toBe("done");
    const manual = { phase: "password", available: false, notice: null, gate: false, attempt: 0 };
    expect(run([{ type: "gate", on: false, secretKeyRemembered: true, presenceSupported: true }])).toEqual(manual);
    expect(run([{ type: "gate", on: true, secretKeyRemembered: false, presenceSupported: true }])).toEqual(manual);
    expect(run([{ type: "gate", on: true, secretKeyRemembered: true, presenceSupported: false }])).toEqual({
      phase: "password",
      available: false,
      notice: "gateUnavailable",
      gate: true,
      attempt: 0,
    });
    expect(run([{ type: "outcome", outcome: "noSecretKey", attempt: 1 }], gate)).toEqual({
      phase: "password",
      available: false,
      notice: "noSecretKey",
      gate: true,
      attempt: 1,
    });
  });

  it("keeps the vault locked when the presence gate is dismissed or fails, with the manual unlock and a retry", () => {
    const dismissed = run([{ type: "outcome", outcome: "cancelled", attempt: 1 }], gate);
    expect(dismissed).toEqual({ phase: "password", available: true, notice: "gated", gate: true, attempt: 1 });
    expect(run([{ type: "retry" }], dismissed)).toEqual({ ...gate, attempt: 2 });
    expect(run([{ type: "error", attempt: 1 }], gate)).toEqual({
      phase: "password",
      available: true,
      notice: "failed",
      gate: true,
      attempt: 1,
    });
  });
});
