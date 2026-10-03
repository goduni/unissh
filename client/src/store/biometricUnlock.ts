// The unlock screen's biometric path, as a pure reducer.
//
// The screen asks Rust whether biometric unlock is enabled; if it is, the
// system prompt is requested straight away and the password field waits behind
// it. Every way the prompt can end other than success lands on the password
// field — never on an error state — because the password always works and is
// the obvious way forward. What differs is only what is said there and whether
// the biometric can be offered again:
//
//   checking ──enabled──▶ prompting ──unlocked──▶ done
//      │                     │ cancelled / failed ──▶ password (biometric offered again)
//      │                     │ invalidated ─────────▶ password (biometric gone, say so)
//      │                     │ noSecretKey ─────────▶ password (biometric unusable, say why)
//      ├──enabled, Secret Key not remembered──▶ password (biometric unusable, say why)
//      └──not enabled──▶ password (no biometric)
//
// Kept free of React and of the bridge so that the transitions are tested as
// data (biometricUnlock.test.ts) and the component only performs effects.

import type { BiometricUnlockOutcome } from "@/bridge/types";

export type BiometricPhase = "checking" | "prompting" | "password" | "done";

/** What the password view says about the biometric path, if anything. */
export type BiometricNotice = "invalidated" | "failed" | "noSecretKey" | null;

export interface BiometricUnlockState {
  phase: BiometricPhase;
  /** The biometric can be (re)offered from the password view. */
  available: boolean;
  notice: BiometricNotice;
}

export type BiometricUnlockEvent =
  /** The answer to "is biometric unlock enabled on this device". */
  | { type: "status"; enabled: boolean; secretKeyRemembered: boolean }
  /** How the prompt ended, as reported by `biometric_unlock`. */
  | { type: "outcome"; outcome: BiometricUnlockOutcome }
  /** The prompt could not run at all (a platform or unlock error). */
  | { type: "error" }
  /** "Unlock with Touch ID" pressed on the password view. */
  | { type: "retry" };

export const initialBiometricUnlock: BiometricUnlockState = {
  phase: "checking",
  available: false,
  notice: null,
};

/** Where each prompt outcome leads. */
const AFTER_PROMPT: Record<BiometricUnlockOutcome, BiometricUnlockState> = {
  unlocked: { phase: "done", available: true, notice: null },
  cancelled: { phase: "password", available: true, notice: null },
  invalidated: { phase: "password", available: false, notice: "invalidated" },
  noSecretKey: { phase: "password", available: false, notice: "noSecretKey" },
};

export function biometricUnlockReducer(
  state: BiometricUnlockState,
  event: BiometricUnlockEvent,
): BiometricUnlockState {
  switch (state.phase) {
    case "checking":
      if (event.type !== "status") return state;
      if (!event.enabled) return { phase: "password", available: false, notice: null };
      // Biometric unlock stores only the password; without the remembered
      // Secret Key it cannot open anything, so it is not even prompted for.
      return event.secretKeyRemembered
        ? { phase: "prompting", available: true, notice: null }
        : AFTER_PROMPT.noSecretKey;
    case "prompting":
      if (event.type === "error") return { phase: "password", available: true, notice: "failed" };
      if (event.type !== "outcome") return state;
      return AFTER_PROMPT[event.outcome];
    case "password":
      return event.type === "retry" && state.available
        ? { phase: "prompting", available: true, notice: null }
        : state;
    case "done":
      return state;
  }
}
