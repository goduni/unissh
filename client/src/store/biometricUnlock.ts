// The unlock screen's biometric path, as a pure reducer.
//
// Two uses of the same prompt, told apart by `gate`:
//
// * A password vault with biometric unlock enabled: the prompt releases the
//   stored password (Rust unseals it and unlocks).
// * A Secret-Key-only vault with the startup presence gate on: the prompt is a
//   presence check in front of the remembered Secret Key (Rust unlocks with it
//   only on a match). The remembered key is never put in the field on this
//   path, so a dismissed prompt really leaves the vault locked; the manual
//   unlock — the Secret Key typed from the Emergency Kit — is always there.
//
// The screen asks Rust what applies; if the prompt does, it is requested
// straight away and the fields wait behind it. Every way the prompt can end
// other than success lands on the manual view — never on an error state —
// because typing always works and is the obvious way forward. What differs is
// only what is said there and whether the prompt can be offered again:
//
//   checking ──enabled / gate on──▶ prompting ──unlocked──▶ done
//      │                     │ cancelled / failed ──▶ password (prompt offered again)
//      │                     │ skip ────────────────▶ password (prompt offered again)
//      │                     │ invalidated ─────────▶ password (biometric gone, say so)
//      │                     │ noSecretKey ─────────▶ password (biometric unusable, say why)
//      ├──enabled, Secret Key not remembered──▶ password (biometric unusable, say why)
//      ├──gate on, prompt not available now──▶ password (say so, no prompt)
//      └──not enabled / gate off / nothing remembered to guard──▶ password (no prompt)
//
// "skip" is the way out of a prompt that never answers (a Windows Hello
// dialog behind the window, a hung evaluation): the password view comes
// back at once. The prompt itself may still end later; an outcome arriving
// in the password view is applied like any other, so a late "unlocked" still
// lands on done.
//
// Kept free of React and of the bridge so that the transitions are tested as
// data (biometricUnlock.test.ts) and the component only performs effects.

import type { BiometricUnlockOutcome } from "@/bridge/types";

export type BiometricPhase = "checking" | "prompting" | "password" | "done";

/** What the password view says about the biometric path, if anything.
 *  `gated`: the presence prompt was dismissed, so the remembered Secret Key
 *  stays unused. `gateUnavailable`: the gate is on but its prompt cannot be
 *  shown on this device now, so it is not even tried. */
export type BiometricNotice = "invalidated" | "failed" | "noSecretKey" | "gated" | "gateUnavailable" | null;

export interface BiometricUnlockState {
  phase: BiometricPhase;
  /** The biometric can be (re)offered from the password view. */
  available: boolean;
  notice: BiometricNotice;
  /** The prompt is the Secret-Key-only presence gate, not biometric unlock. */
  gate: boolean;
}

export type BiometricUnlockEvent =
  /** The answer to "is biometric unlock enabled on this device". */
  | { type: "status"; enabled: boolean; secretKeyRemembered: boolean }
  /** A Secret-Key-only vault: is the startup presence gate on, is there a
   *  remembered Secret Key for it to guard, and can its prompt be shown now. */
  | { type: "gate"; on: boolean; secretKeyRemembered: boolean; presenceSupported: boolean }
  /** How the prompt ended, as reported by `biometric_unlock`. */
  | { type: "outcome"; outcome: BiometricUnlockOutcome }
  /** The prompt could not run at all (a platform or unlock error). */
  | { type: "error" }
  /** "Unlock with Touch ID" pressed on the password view. */
  | { type: "retry" }
  /** "Use password" pressed while the prompt is up. */
  | { type: "skip" };

export const initialBiometricUnlock: BiometricUnlockState = {
  phase: "checking",
  available: false,
  notice: null,
  gate: false,
};

type Outcome = Omit<BiometricUnlockState, "gate">;

/** Where each prompt outcome leads, for biometric unlock. */
const AFTER_PROMPT: Record<BiometricUnlockOutcome, Outcome> = {
  unlocked: { phase: "done", available: true, notice: null },
  cancelled: { phase: "password", available: true, notice: null },
  invalidated: { phase: "password", available: false, notice: "invalidated" },
  noSecretKey: { phase: "password", available: false, notice: "noSecretKey" },
};

/** The same for the presence gate. Nothing is stored behind it, so nothing can
 *  be invalidated; a key that vanished — or no longer opens this vault — leaves
 *  only the manual unlock, and the view says so. */
const AFTER_GATE: Record<BiometricUnlockOutcome, Outcome> = {
  unlocked: { phase: "done", available: true, notice: null },
  cancelled: { phase: "password", available: true, notice: "gated" },
  invalidated: { phase: "password", available: false, notice: null },
  noSecretKey: { phase: "password", available: false, notice: "noSecretKey" },
};

const after = (gate: boolean, outcome: BiometricUnlockOutcome): BiometricUnlockState => ({
  ...(gate ? AFTER_GATE : AFTER_PROMPT)[outcome],
  gate,
});

export function biometricUnlockReducer(
  state: BiometricUnlockState,
  event: BiometricUnlockEvent,
): BiometricUnlockState {
  switch (state.phase) {
    case "checking":
      if (event.type === "gate") {
        // Without a remembered Secret Key there is no auto-unlock to guard:
        // the key is typed, as on any device that does not remember it.
        if (!event.on || !event.secretKeyRemembered) {
          return { phase: "password", available: false, notice: null, gate: false };
        }
        // A prompt that cannot be shown would only "cancel" at once.
        return event.presenceSupported
          ? { phase: "prompting", available: true, notice: null, gate: true }
          : { phase: "password", available: false, notice: "gateUnavailable", gate: true };
      }
      if (event.type !== "status") return state;
      if (!event.enabled) return { phase: "password", available: false, notice: null, gate: false };
      // Biometric unlock stores only the password; without the remembered
      // Secret Key it cannot open anything, so it is not even prompted for.
      return event.secretKeyRemembered
        ? { phase: "prompting", available: true, notice: null, gate: false }
        : after(false, "noSecretKey");
    case "prompting":
      if (event.type === "error") return { phase: "password", available: true, notice: "failed", gate: state.gate };
      if (event.type === "skip") return { phase: "password", available: true, notice: null, gate: state.gate };
      if (event.type !== "outcome") return state;
      return after(state.gate, event.outcome);
    case "password":
      // A prompt skipped from the view may still end: its outcome counts.
      if (event.type === "outcome") return after(state.gate, event.outcome);
      return event.type === "retry" && state.available
        ? { phase: "prompting", available: true, notice: null, gate: state.gate }
        : state;
    case "done":
      return state;
  }
}
