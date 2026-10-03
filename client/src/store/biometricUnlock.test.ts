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

const prompting = run([{ type: "status", enabled: true, secretKeyRemembered: true }]);

describe("biometric unlock screen", () => {
  it("prompts at once when enabled, and goes straight to the password when not", () => {
    expect(prompting).toEqual({ phase: "prompting", available: true, notice: null, gate: false });
    expect(run([{ type: "status", enabled: false, secretKeyRemembered: true }])).toEqual({
      phase: "password",
      available: false,
      notice: null,
      gate: false,
    });
  });

  it("is done when the prompt unlocks", () => {
    expect(run([{ type: "outcome", outcome: "unlocked" }], prompting).phase).toBe("done");
  });

  it("falls back to the password on cancel or failure, and can prompt again", () => {
    const cancelled = run([{ type: "outcome", outcome: "cancelled" }], prompting);
    expect(cancelled).toEqual({ phase: "password", available: true, notice: null, gate: false });
    const failed = run([{ type: "error" }], prompting);
    expect(failed).toEqual({ phase: "password", available: true, notice: "failed", gate: false });
    expect(run([{ type: "retry" }], failed)).toEqual(prompting);
  });

  it("does not offer the biometric without a remembered Secret Key, and says why", () => {
    const unusable = { phase: "password", available: false, notice: "noSecretKey", gate: false };
    expect(run([{ type: "status", enabled: true, secretKeyRemembered: false }])).toEqual(unusable);
    expect(run([{ type: "outcome", outcome: "noSecretKey" }, { type: "retry" }], prompting)).toEqual(unusable);
  });

  it("falls back to the password for good when the stored material was invalidated", () => {
    const gone = run([{ type: "outcome", outcome: "invalidated" }, { type: "retry" }], prompting);
    expect(gone).toEqual({ phase: "password", available: false, notice: "invalidated", gate: false });
  });

  it("with the presence gate on, prompts before the remembered-key unlock, and not without one to guard", () => {
    const gate = run([{ type: "gate", on: true, secretKeyRemembered: true }]);
    expect(gate).toEqual({ phase: "prompting", available: true, notice: null, gate: true });
    expect(run([{ type: "outcome", outcome: "unlocked" }], gate).phase).toBe("done");
    const manual = { phase: "password", available: false, notice: null, gate: false };
    expect(run([{ type: "gate", on: false, secretKeyRemembered: true }])).toEqual(manual);
    expect(run([{ type: "gate", on: true, secretKeyRemembered: false }])).toEqual(manual);
  });

  it("keeps the vault locked when the presence gate is dismissed, with the manual unlock and a retry", () => {
    const gate = run([{ type: "gate", on: true, secretKeyRemembered: true }]);
    const dismissed = run([{ type: "outcome", outcome: "cancelled" }], gate);
    expect(dismissed).toEqual({ phase: "password", available: true, notice: "gated", gate: true });
    expect(run([{ type: "retry" }], dismissed)).toEqual(gate);
  });
});
