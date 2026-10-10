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
//      ├──not enabled / gate off / nothing remembered to guard──▶ password (no prompt)
//      └──no answer within the grace──▶ password (no prompt; see below)
//
// "checking" never stands between the user and the password. Rust answers a
// device with nothing stored without asking the platform, so the wait is only
// ever for someone who turned the feature on — and even then it is bounded:
// after BIOMETRIC_CHECK_GRACE_MS the fields are there. An answer that comes
// later is still used, but only to offer the prompt as a button: it never
// opens a prompt over someone who may be typing.
//
// "skip" is the way out of a prompt that never answers (a Windows Hello
// dialog behind the window, a hung evaluation): the password view comes
// back at once, and the screen tells Rust to end that attempt, so whatever
// the prompt answers later is dropped there and cannot unlock.
//
// Every entry into "prompting" is a new attempt, numbered. A result names the
// attempt it belongs to, and one from an earlier attempt is ignored: a prompt
// given up on must not, when it finally reports "cancelled", knock the next
// one off the screen. The one exception is "unlocked": the vault is open,
// whoever opened it, and the screen follows.
//
// Kept free of React and of the bridge so that the transitions are tested as
// data (biometricUnlock.test.ts) and the component only performs effects.

import type { BiometricUnlockOutcome } from "@/bridge/types";

export type BiometricPhase = "checking" | "prompting" | "password" | "done";

/** How long the unlock screen holds its fields back for the answer to "is
 *  there a prompt to show", so that an enabled biometric does not flash the
 *  password field first. Past it the password path is open, answer or not. */
export const BIOMETRIC_CHECK_GRACE_MS = 800;

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
  /** Which prompt this is: counts the entries into "prompting". */
  attempt: number;
}

export type BiometricUnlockEvent =
  /** The answer to "is biometric unlock enabled on this device". */
  | { type: "status"; enabled: boolean; secretKeyRemembered: boolean }
  /** A Secret-Key-only vault: is the startup presence gate on, is there a
   *  remembered Secret Key for it to guard, and can its prompt be shown now. */
  | { type: "gate"; on: boolean; secretKeyRemembered: boolean; presenceSupported: boolean }
  /** The status did not arrive within the grace. */
  | { type: "timeout" }
  /** How prompt `attempt` ended, as reported by `biometric_unlock`. */
  | { type: "outcome"; outcome: BiometricUnlockOutcome; attempt: number }
  /** Prompt `attempt` could not run at all (a platform or unlock error). */
  | { type: "error"; attempt: number }
  /** "Unlock with Touch ID" pressed on the password view. */
  | { type: "retry" }
  /** "Use password" pressed while the prompt is up. */
  | { type: "skip" };

export const initialBiometricUnlock: BiometricUnlockState = {
  phase: "checking",
  available: false,
  notice: null,
  gate: false,
  attempt: 0,
};

type Outcome = Omit<BiometricUnlockState, "gate" | "attempt">;

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

const after = (state: BiometricUnlockState, gate: boolean, outcome: BiometricUnlockOutcome): BiometricUnlockState => ({
  ...(gate ? AFTER_GATE : AFTER_PROMPT)[outcome],
  gate,
  attempt: state.attempt,
});

const manual = (
  state: BiometricUnlockState,
  to: Pick<BiometricUnlockState, "available" | "notice" | "gate">,
): BiometricUnlockState => ({ phase: "password", ...to, attempt: state.attempt });

/** A new prompt: the next attempt. */
const prompt = (state: BiometricUnlockState, gate: boolean): BiometricUnlockState => ({
  phase: "prompting",
  available: true,
  notice: null,
  gate,
  attempt: state.attempt + 1,
});

/** What the answer to "is there a prompt to show" leads to; "prompting" when
 *  it is yes. Shared by the answer in time and the late one. */
function answered(
  state: BiometricUnlockState,
  event: Extract<BiometricUnlockEvent, { type: "status" | "gate" }>,
): BiometricUnlockState {
  if (event.type === "gate") {
    // Without a remembered Secret Key there is no auto-unlock to guard:
    // the key is typed, as on any device that does not remember it.
    if (!event.on || !event.secretKeyRemembered) {
      return manual(state, { available: false, notice: null, gate: false });
    }
    // A prompt that cannot be shown would only "cancel" at once.
    return event.presenceSupported
      ? prompt(state, true)
      : manual(state, { available: false, notice: "gateUnavailable", gate: true });
  }
  if (!event.enabled) return manual(state, { available: false, notice: null, gate: false });
  // Biometric unlock stores only the password; without the remembered
  // Secret Key it cannot open anything, so it is not even prompted for.
  return event.secretKeyRemembered ? prompt(state, false) : after(state, false, "noSecretKey");
}

export function biometricUnlockReducer(
  state: BiometricUnlockState,
  event: BiometricUnlockEvent,
): BiometricUnlockState {
  // The vault is open, whichever attempt opened it.
  if (event.type === "outcome" && event.outcome === "unlocked") return after(state, state.gate, "unlocked");
  // Anything else an earlier attempt has to say is about a prompt that is gone.
  if ((event.type === "outcome" || event.type === "error") && event.attempt !== state.attempt) return state;
  switch (state.phase) {
    case "checking":
      if (event.type === "timeout") return manual(state, { available: false, notice: null, gate: false });
      return event.type === "status" || event.type === "gate" ? answered(state, event) : state;
    case "prompting":
      if (event.type === "error") return manual(state, { available: true, notice: "failed", gate: state.gate });
      if (event.type === "skip") return manual(state, { available: true, notice: null, gate: state.gate });
      if (event.type !== "outcome") return state;
      return after(state, state.gate, event.outcome);
    case "password":
      // A prompt skipped from the view may still end: its outcome counts.
      if (event.type === "outcome") return after(state, state.gate, event.outcome);
      if (event.type === "status" || event.type === "gate") {
        // The answer came after the grace. Only a view that knows nothing yet
        // takes it, and a "yes" is offered as a button, never opened: the user
        // may be typing. (A dismissed gate reads the same as one not yet tried.)
        if (state.available || state.notice !== null || state.gate) return state;
        const next = answered(state, event);
        return next.phase === "prompting"
          ? manual(state, { available: true, notice: next.gate ? "gated" : null, gate: next.gate })
          : next;
      }
      return event.type === "retry" && state.available ? prompt(state, state.gate) : state;
    case "done":
      return state;
  }
}
