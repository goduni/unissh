// Guided key rotation, the app's own part. The plan (which machines get the
// candidate key), the per-machine state machine deploy → verify → remove →
// confirm and what each step runs live in the core
// (rust-core/crates/ffi/src/key_rotation_plan.rs), shared with the CLI's
// `unissh keys rotation`; the dialog shows them. What stays here is which
// rotation actions a key row offers.

import type { RotationStep } from "@/bridge/types";

/** The steps in order, as the dialog lists them. */
export const ROTATION_STEPS: readonly RotationStep[] = ["deploy", "verify", "remove", "confirm"];

/** The rotation entries of a key row's menu. Finishing is deliberately not one
 *  of them: which machines already take the candidate is known only to a run of
 *  the rotation dialog, and that knowledge is gone once the dialog closes, the
 *  app restarts or the vault locks. So a key in a rotation leads back into the
 *  dialog, which tries every machine again before it offers to finish — and it
 *  offers neither a second rotation nor the in-place replace, which would
 *  discard the key the machines already switched now expect. A rotation started
 *  on another device can only be abandoned here. */
export type KeyRowRotationAction = "start" | "replace" | "continue" | "abandon";
export function keyRowRotationActions(
  rotation: { startedElsewhere: boolean } | null | undefined,
): KeyRowRotationAction[] {
  if (!rotation) return ["start", "replace"];
  return rotation.startedElsewhere ? ["abandon"] : ["continue", "abandon"];
}
