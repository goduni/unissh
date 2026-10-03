// Guided key rotation: the plan (which machines get the candidate key, which
// hosts merely follow, which are out of scope) and the per-target state machine
// deploy → verify → remove. Pure — no I/O. The view runs each step over SSH and
// feeds the result back in; this module decides what may run next.
//
// The safety rule lives here: `remove` (dropping the old public key from a
// machine) is reachable only from a passed `verify` (a login with the candidate
// key) on that same machine, so no machine is ever left accepting neither key.

import type { ConnectionProfile, JumpHost, MultiExecTarget, ProxyConfig } from "@/bridge/types";
import { keyMatcher } from "./keyHygiene";

export type RotationStep = "deploy" | "verify" | "remove";
export const ROTATION_STEPS: readonly RotationStep[] = ["deploy", "verify", "remove"];

/** Why a host is out of a rotation's scope: it does not log in with a vault key. */
export type RotationSkipReason = "personal" | "systemAgent" | "password";

/** A machine whose `authorized_keys` must learn the candidate key: one SSH
 *  login (user@host:port) that authenticates with the rotated key. */
export interface RotationTarget {
  /** `user@host:port` (host lower-cased) — one per authorized_keys file. */
  id: string;
  /** The saved profile when the target is a host of its own, else null (a bare
   *  inline jump hop, which has no profile). */
  profile: ConnectionProfile | null;
  host: string;
  port: number;
  user: string;
  /** The hops in front of it and the outbound proxy: the profile's own chain,
   *  or for an inline hop the chain of the host it came from, up to that hop. */
  jumps: JumpHost[];
  proxy: ProxyConfig | null;
  /** For an inline hop: the host whose chain it was found in. */
  via: ConnectionProfile | null;
}

/** A host that only hops with the key: nothing to deploy on it, it starts
 *  using the new key when the hop target(s) it goes through switch. */
export interface RotationDependent {
  host: ConnectionProfile;
  targetIds: string[];
}

export interface RotationSkip {
  host: ConnectionProfile;
  reason: RotationSkipReason;
}

export interface RotationPlan {
  /** The vault's hosts the plan was made from — hop refs resolve against them. */
  hosts: readonly ConnectionProfile[];
  vaultId: string;
  keyItemId: string;
  targets: RotationTarget[];
  dependents: RotationDependent[];
  skipped: RotationSkip[];
}

const endpointId = (user: string, host: string, port: number) =>
  `${user}@${host.toLowerCase()}:${port}`;

/** Where the candidate's public key has to go for a rotation of `keyItemId`.
 *
 *  The key must be authorized on the machine that authenticates with it:
 *   - a host logging in with the key → the host itself, over its own chain;
 *   - an inline jump hop using the key → that hop's endpoint, reached through
 *     the chain of the host it was found in up to (not including) the hop;
 *   - a `hopRef` hop → the referenced bastion profile, which logs in with the
 *     key itself and so is already a direct target.
 *  Targets are deduplicated by user@host:port (one authorized_keys file), direct
 *  hosts first. Hosts that only hop with the key become dependents of the hop
 *  targets they go through. Hosts not using the key whose login is Personal, the
 *  system agent or a password are listed as skipped with that reason. */
export function planRotation(
  hosts: readonly ConnectionProfile[],
  vaultId: string,
  keyItemId: string,
): RotationPlan {
  const { usesKey, hopUsesKey, refProfile } = keyMatcher(hosts, vaultId, keyItemId);
  const targets = new Map<string, RotationTarget>();
  const addProfile = (h: ConnectionProfile): string => {
    const id = endpointId(h.user, h.host, h.port);
    if (!targets.has(id))
      targets.set(id, {
        id,
        profile: h,
        host: h.host,
        port: h.port,
        user: h.user,
        jumps: h.jumps,
        proxy: h.proxy ?? null,
        via: null,
      });
    return id;
  };
  for (const h of hosts) if (usesKey(h)) addProfile(h);

  const dependents: RotationDependent[] = [];
  const skipped: RotationSkip[] = [];
  for (const h of hosts) {
    const ids: string[] = [];
    h.jumps.forEach((j, i) => {
      if (!hopUsesKey(j)) return;
      const ref = refProfile(j);
      let id: string;
      if (ref) id = addProfile(ref);
      else {
        id = endpointId(j.user, j.host, j.port);
        if (!targets.has(id))
          targets.set(id, {
            id,
            profile: null,
            host: j.host,
            port: j.port,
            user: j.user,
            jumps: h.jumps.slice(0, i),
            proxy: h.proxy ?? null,
            via: h,
          });
      }
      if (!ids.includes(id)) ids.push(id);
    });
    if (usesKey(h)) continue;
    if (ids.length > 0) {
      dependents.push({ host: h, targetIds: ids });
      continue;
    }
    const a = h.auth.type;
    if (a === "personal") skipped.push({ host: h, reason: "personal" });
    else if (a === "systemAgent") skipped.push({ host: h, reason: "systemAgent" });
    else if (a === "vaultPassword" || a === "promptPassword") skipped.push({ host: h, reason: "password" });
  }
  return { hosts, vaultId, keyItemId, targets: [...targets.values()], dependents, skipped };
}

// ── run state machine ──────────────────────────────────────────

/** One target's place in a run:
 *   pending  — waiting to run `step`;
 *   running  — `step` is in flight;
 *   failed   — `step` failed with `error`; the old key is still authorized
 *              (a failed remove is an atomic rewrite that did not happen);
 *   switched — the old key is removed, the candidate is the only one;
 *   keptOld  — the run was cancelled before this target switched; the old key
 *              is still authorized (and the candidate too if it got that far). */
export type TargetState =
  | { kind: "pending"; step: RotationStep }
  | { kind: "running"; step: RotationStep }
  | { kind: "failed"; step: RotationStep; error: string }
  | { kind: "switched" }
  | { kind: "keptOld" };

export interface RotationRun {
  states: Readonly<Record<string, TargetState>>;
  /** Targets where a login with the candidate key passed. Only these may run
   *  `remove`, and only these are reached with the candidate as a hop. */
  verified: Readonly<Record<string, true>>;
  cancelled: boolean;
}

export type StepResult = { ok: true } | { ok: false; error: string };

export function startRun(plan: RotationPlan): RotationRun {
  const states: Record<string, TargetState> = {};
  for (const t of plan.targets) states[t.id] = { kind: "pending", step: "deploy" };
  return { states, verified: {}, cancelled: false };
}

const withState = (run: RotationRun, id: string, s: TargetState, verified = run.verified): RotationRun => ({
  ...run,
  states: { ...run.states, [id]: s },
  verified,
});

/** Steps that may start now. None once cancelled. Removes and the other steps
 *  never overlap: a deploy or verify may route through another target as a
 *  jump hop with the OLD key, which a concurrent remove would pull from under
 *  it. So removes wait until no deploy/verify is waiting or in flight, and a
 *  deploy/verify waits while a remove is in flight. */
export function startableSteps(run: RotationRun): { id: string; step: RotationStep }[] {
  if (run.cancelled) return [];
  const all = Object.entries(run.states);
  const early = all.some(([, s]) => (s.kind === "pending" || s.kind === "running") && s.step !== "remove");
  const removing = all.some(([, s]) => s.kind === "running" && s.step === "remove");
  return all.flatMap(([id, s]) => {
    if (s.kind !== "pending") return [];
    const ok = s.step === "remove" ? !early && run.verified[id] === true : !removing;
    return ok ? [{ id, step: s.step }] : [];
  });
}

/** Mark target `id`'s pending step as in flight. A no-op unless that step is
 *  startable now — in particular `remove` never starts without a passed verify. */
export function beginStep(run: RotationRun, id: string): RotationRun {
  const s = run.states[id];
  if (s?.kind !== "pending" || !startableSteps(run).some((x) => x.id === id)) return run;
  return withState(run, id, { kind: "running", step: s.step });
}

/** Feed back the result of target `id`'s in-flight `step`. Ignored unless that
 *  step is in flight. After a cancel, an in-flight step still lands honestly: a
 *  remove that went through is `switched`, anything else is `keptOld`. */
export function recordStep(run: RotationRun, id: string, step: RotationStep, result: StepResult): RotationRun {
  const s = run.states[id];
  if (s?.kind !== "running" || s.step !== step) return run;
  if (run.cancelled)
    return withState(run, id, result.ok && step === "remove" ? { kind: "switched" } : { kind: "keptOld" });
  if (!result.ok) return withState(run, id, { kind: "failed", step, error: result.error });
  if (step === "deploy") return withState(run, id, { kind: "pending", step: "verify" });
  if (step === "verify")
    return withState(run, id, { kind: "pending", step: "remove" }, { ...run.verified, [id]: true });
  return withState(run, id, { kind: "switched" });
}

/** Put a failed target back in the queue at the step that failed. */
export function retryTarget(run: RotationRun, id: string): RotationRun {
  const s = run.states[id];
  if (run.cancelled || s?.kind !== "failed") return run;
  return withState(run, id, { kind: "pending", step: s.step });
}

/** Stop the run: nothing new starts, every waiting target keeps the old key.
 *  Switched targets stay switched; failed ones keep their error; in-flight
 *  steps land through `recordStep`. The key item itself is not touched here. */
export function cancelRun(run: RotationRun): RotationRun {
  const states: Record<string, TargetState> = {};
  for (const [id, s] of Object.entries(run.states)) states[id] = s.kind === "pending" ? { kind: "keptOld" } : s;
  return { ...run, states, cancelled: true };
}

/** Nothing in flight and nothing left to start. */
export function runSettled(run: RotationRun): boolean {
  return (
    !Object.values(run.states).some((s) => s.kind === "running") && startableSteps(run).length === 0
  );
}

/** How to reach target `id` for `step`. The target itself logs in with the old
 *  key to deploy, and with the candidate to verify and remove (verify is the
 *  proof; remove then runs under that same proven login). A hop in front of it
 *  that uses the rotated key logs in with the candidate once that hop's own
 *  target has verified — it may already have dropped the old key — and with the
 *  old key before. A `hopRef` hop switched that way is written out inline (the
 *  core would resolve it to the old key), carrying the bastion's proxy where
 *  the core would have applied it. */
export function stepConnect(
  plan: RotationPlan,
  run: RotationRun,
  id: string,
  step: RotationStep,
  candidateId: string,
): MultiExecTarget {
  const t = plan.targets.find((x) => x.id === id);
  if (!t) throw new Error(`unknown rotation target ${id}`);
  const { hopUsesKey, refProfile } = keyMatcher(plan.hosts, plan.vaultId, plan.keyItemId);
  const candidate = { type: "agent" as const, vaultId: plan.vaultId, keyItemId: candidateId };
  let proxy = t.proxy;
  const jumps = t.jumps.map((j, i): JumpHost => {
    if (!hopUsesKey(j)) return j;
    const ref = refProfile(j);
    const hopId = ref ? endpointId(ref.user, ref.host, ref.port) : endpointId(j.user, j.host, j.port);
    if (!run.verified[hopId]) return j;
    if (!ref) return { ...j, auth: candidate };
    if (i === 0 && !proxy) proxy = ref.proxy ?? null;
    return { host: ref.host, port: ref.port, user: ref.user, auth: candidate, hopRef: null };
  });
  const auth =
    step === "deploy" ? { type: "agent" as const, vaultId: plan.vaultId, keyItemId: plan.keyItemId } : candidate;
  return { host: t.host, port: t.port, user: t.user, auth, jumps, proxy };
}
