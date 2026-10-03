// The unlock screen's biometric state machine. One test per transition group:
// what the screen starts with, and every way the prompt can end.

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
    expect(prompting).toEqual({ phase: "prompting", available: true, notice: null });
    expect(run([{ type: "status", enabled: false, secretKeyRemembered: true }])).toEqual({
      phase: "password",
      available: false,
      notice: null,
    });
  });

  it("is done when the prompt unlocks", () => {
    expect(run([{ type: "outcome", outcome: "unlocked" }], prompting).phase).toBe("done");
  });

  it("falls back to the password on cancel or failure, and can prompt again", () => {
    const cancelled = run([{ type: "outcome", outcome: "cancelled" }], prompting);
    expect(cancelled).toEqual({ phase: "password", available: true, notice: null });
    const failed = run([{ type: "error" }], prompting);
    expect(failed).toEqual({ phase: "password", available: true, notice: "failed" });
    expect(run([{ type: "retry" }], failed)).toEqual(prompting);
  });

  it("does not offer the biometric without a remembered Secret Key, and says why", () => {
    const unusable = { phase: "password", available: false, notice: "noSecretKey" };
    expect(run([{ type: "status", enabled: true, secretKeyRemembered: false }])).toEqual(unusable);
    expect(run([{ type: "outcome", outcome: "noSecretKey" }, { type: "retry" }], prompting)).toEqual(unusable);
  });

  it("falls back to the password for good when the stored material was invalidated", () => {
    const gone = run([{ type: "outcome", outcome: "invalidated" }, { type: "retry" }], prompting);
    expect(gone).toEqual({ phase: "password", available: false, notice: "invalidated" });
  });
});
