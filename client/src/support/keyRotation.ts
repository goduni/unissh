// Guided key rotation: the plan (which machines get the candidate key, which
// hosts merely follow, which are out of scope), the per-target state machine
// deploy → verify → remove → confirm, and what each step runs and when it
// counts as passed (`runStep`). No I/O of its own: the view hands in the SSH
// exec and feeds each step's result back; this module decides what may run
// next and what a result means.
//
// The safety rule lives here: `remove` (dropping the old public key from a
// machine) is reachable only from a passed `verify` (a login with the candidate
// key) on that same machine, so no machine is ever left accepting neither key.
// And a machine is called switched only after `confirm`: a login with the OLD
// key was attempted and refused. A line gone from `~/.ssh/authorized_keys` does
// not prove that — sshd may accept the key from another file, a command or a CA.

import type { ConnectionProfile, JumpHost, MultiExecResult, MultiExecTarget, ProxyConfig } from "@/bridge/types";
import {
  authorizedKeysAppendCmd,
  authorizedKeysRemoveCmd,
  REMOVE_EXIT_NO_FILE,
  REMOVE_EXIT_STILL_PRESENT,
} from "./authorizedKeys";
import { keyMatcher } from "./keyHygiene";

export type RotationStep = "deploy" | "verify" | "remove" | "confirm";
export const ROTATION_STEPS: readonly RotationStep[] = ["deploy", "verify", "remove", "confirm"];

/** Why a host is out of a rotation's scope: it does not log in with a vault key. */
export type RotationSkipReason = "personal" | "systemAgent" | "password";

/** A machine whose `authorized_keys` must learn the candidate key: one SSH
 *  login (user@host:port, reached over one route) that authenticates with the
 *  rotated key. */
export interface RotationTarget {
  /** The login and the route to it: `user@host:port` (host lower-cased), then
   *  the hops and the proxy in front of it when there are any. The route is
   *  part of the identity because an address means nothing without it:
   *  `root@10.0.0.5` behind two different bastions is two machines. */
  id: string;
  /** The saved profile when the target is a host of its own, else null (a bare
   *  inline jump hop, which has no profile). */
  profile: ConnectionProfile | null;
  host: string;
  port: number;
  user: string;
  /** The hops in front of it: the profile's own chain, or for a hop the chain
   *  of the host it came from, up to that hop. */
  jumps: JumpHost[];
  /** The proxy the first dial of that route goes through (see `firstDialProxy`). */
  proxy: ProxyConfig | null;
  /** `jumps` as the logins they land on (a saved bastion resolved), for display. */
  route: string[];
  /** For a hop: the host whose chain it was found in. */
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

/** Target identities for one vault's hosts: the endpoint plus the route to it. */
function routes(refProfile: (j: JumpHost) => ConnectionProfile | undefined) {
  /** The machine a hop lands on. A `hopRef` resolves to the saved profile's
   *  endpoint, so a ref hop and an inline hop to the same login are one hop;
   *  a ref this vault cannot resolve is identified by the reference itself. */
  const hopEndpoint = (j: JumpHost): string => {
    const ref = refProfile(j);
    if (ref) return endpointId(ref.user, ref.host, ref.port);
    return j.hopRef ? `ref:${j.hopRef.vaultId}/${j.hopRef.profileUid}` : endpointId(j.user, j.host, j.port);
  };
  /** The proxy a connection's first TCP dial goes through: its own, else the
   *  proxy of a saved bastion used as hop #1. Mirrors the core
   *  (rust-core/crates/ffi/src/lib.rs, `connect_with_options`) — keep in step. */
  const firstDialProxy = (jumps: readonly JumpHost[], proxy: ProxyConfig | null | undefined): ProxyConfig | null =>
    proxy ?? (jumps[0] ? refProfile(jumps[0])?.proxy : null) ?? null;
  /** Identity of the login `endpoint` reached through `jumps` behind `proxy`
   *  (the first-dial proxy). No route at all is just the endpoint. */
  const targetId = (endpoint: string, jumps: readonly JumpHost[], proxy: ProxyConfig | null): string =>
    endpoint +
    (jumps.length > 0 ? ` via ${jumps.map(hopEndpoint).join(" > ")}` : "") +
    (proxy
      ? ` proxy ${proxy.kind}://${proxy.username ? `${proxy.username}@` : ""}${proxy.host.toLowerCase()}:${proxy.port}`
      : "");
  /** Identity of hop `i` of the chain `jumps` behind first-dial `proxy`: that
   *  hop's endpoint, reached through the hops before it. */
  const hopTargetId = (jumps: readonly JumpHost[], proxy: ProxyConfig | null, i: number): string =>
    targetId(hopEndpoint(jumps[i]), jumps.slice(0, i), proxy);
  return { hopEndpoint, firstDialProxy, targetId, hopTargetId };
}

/** Where the candidate's public key has to go for a rotation of `keyItemId`.
 *
 *  The key must be authorized on the machine that authenticates with it:
 *   - a host logging in with the key → the host itself, over its own chain;
 *   - a jump hop using the key (inline, or a `hopRef` to a saved bastion that
 *     logs in with it) → that hop's endpoint, reached through the chain of the
 *     host it was found in up to (not including) the hop.
 *  Targets are deduplicated by login AND route (see `RotationTarget.id`), direct
 *  hosts first: two hosts with the same user@host:port behind different
 *  bastions or proxies are two machines and both get the key, while a saved
 *  bastion and a hop that reaches it the same way are one. The same machine
 *  listed twice over two routes is harmless — every step is idempotent — where
 *  a machine dropped from the plan would be locked out. Hosts that only hop
 *  with the key become dependents of the hop targets they go through. Hosts not
 *  using the key whose login is Personal, the system agent or a password are
 *  listed as skipped with that reason. */
export function planRotation(
  hosts: readonly ConnectionProfile[],
  vaultId: string,
  keyItemId: string,
): RotationPlan {
  const { usesKey, hopUsesKey, refProfile } = keyMatcher(hosts, vaultId, keyItemId);
  const { hopEndpoint, firstDialProxy, targetId, hopTargetId } = routes(refProfile);
  const targets = new Map<string, RotationTarget>();
  const add = (id: string, t: Omit<RotationTarget, "id" | "route">) => {
    if (!targets.has(id)) targets.set(id, { id, ...t, route: t.jumps.map(hopEndpoint) });
  };
  for (const h of hosts) {
    if (!usesKey(h)) continue;
    const proxy = firstDialProxy(h.jumps, h.proxy);
    const id = targetId(endpointId(h.user, h.host, h.port), h.jumps, proxy);
    add(id, { profile: h, host: h.host, port: h.port, user: h.user, jumps: h.jumps, proxy, via: null });
  }

  const dependents: RotationDependent[] = [];
  const skipped: RotationSkip[] = [];
  for (const h of hosts) {
    const ids: string[] = [];
    const proxy = firstDialProxy(h.jumps, h.proxy);
    h.jumps.forEach((j, i) => {
      if (!hopUsesKey(j)) return;
      const { host, port, user } = refProfile(j) ?? j;
      const id = hopTargetId(h.jumps, proxy, i);
      add(id, { profile: null, host, port, user, jumps: h.jumps.slice(0, i), proxy, via: h });
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

/** Whether two targets of the plan are the same login reached over different
 *  routes. They may well be one machine (a bastion with two ways in): each
 *  route is then switched and reported on its own, so a route that fails is
 *  listed as not switched although the machine behind it already is. */
export function hasSharedEndpoint(plan: RotationPlan): boolean {
  const endpoints = plan.targets.map((t) => endpointId(t.user, t.host, t.port));
  return new Set(endpoints).size < endpoints.length;
}

// ── run state machine ──────────────────────────────────────────

/** One target's place in a run:
 *   pending  — waiting to run `step`;
 *   running  — `step` is in flight;
 *   failed   — `step` failed with `error`. Up to `remove` the old key has to
 *              be taken as still authorized: a failed remove either did not
 *              rewrite the file at all (the rewrite is atomic), or removed the
 *              plain lines and found the old key's blob still in the file —
 *              behind an options prefix, say (`REMOVE_EXIT_STILL_PRESENT`). On
 *              a host that wants a second factor it means the old key was not
 *              seen refused. A failed `confirm` means the old
 *              line is gone from `~/.ssh/authorized_keys` but the old key was
 *              not seen refused: it still logs in, or the check did not run;
 *   switched — the candidate logs in and the old key was refused;
 *   keptOld  — the run was cancelled before this target's old key was removed;
 *              the old key is still authorized (and the candidate too if it got
 *              that far). `after` is the last step that passed, null for none;
 *   unconfirmed — the run was cancelled after the old line was removed and
 *              before the old key was tried: nobody checked that it is refused. */
export type TargetState =
  | { kind: "pending"; step: RotationStep }
  | { kind: "running"; step: RotationStep }
  | { kind: "failed"; step: RotationStep; error: string }
  | { kind: "switched" }
  | { kind: "keptOld"; after: RotationStep | null }
  | { kind: "unconfirmed" };

export interface RotationRun {
  states: Readonly<Record<string, TargetState>>;
  /** Targets where a login with the candidate key passed. Only these may run
   *  `remove`, and only these are reached with the candidate as a hop. */
  verified: Readonly<Record<string, true>>;
  cancelled: boolean;
}

export type StepResult = { ok: true } | { ok: false; error: string };

/** The step before `step`, null before the first. */
const prevStep = (step: RotationStep): RotationStep | null => ROTATION_STEPS[ROTATION_STEPS.indexOf(step) - 1] ?? null;

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

/** Steps that may start now. None once cancelled. Removes never overlap a
 *  deploy or verify: those may route through another target as a jump hop with
 *  the OLD key, which a concurrent remove would pull from under them. So removes
 *  wait until no deploy/verify is waiting or in flight, and a deploy/verify
 *  waits while a remove is in flight. A confirm starts whenever it is due: its
 *  hops are either verified (and use the candidate) or have not reached remove. */
export function startableSteps(run: RotationRun): { id: string; step: RotationStep }[] {
  if (run.cancelled) return [];
  const all = Object.entries(run.states);
  const early = all.some(
    ([, s]) => (s.kind === "pending" || s.kind === "running") && (s.step === "deploy" || s.step === "verify"),
  );
  const removing = all.some(([, s]) => s.kind === "running" && s.step === "remove");
  return all.flatMap(([id, s]) => {
    if (s.kind !== "pending") return [];
    const ok =
      s.step === "remove" ? !early && run.verified[id] === true : s.step === "confirm" ? true : !removing;
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

/** The state of a target the run stops at, `after` being its last passed step:
 *  the old key is still authorized until the remove went through, and merely
 *  unchecked from then on. */
const stoppedAt = (after: RotationStep | null): TargetState =>
  after === "remove" ? { kind: "unconfirmed" } : { kind: "keptOld", after };

/** Feed back the result of target `id`'s in-flight `step`. Ignored unless that
 *  step is in flight. A passed verify counts as verified whenever it lands.
 *  After a cancel an in-flight step still lands honestly, and nothing follows
 *  it: a passed confirm is `switched`, a failed one keeps its error (the old key
 *  may still log in), a remove that went through is `unconfirmed`, anything
 *  else is `keptOld`. */
export function recordStep(run: RotationRun, id: string, step: RotationStep, result: StepResult): RotationRun {
  const s = run.states[id];
  if (s?.kind !== "running" || s.step !== step) return run;
  const verified = result.ok && step === "verify" ? { ...run.verified, [id]: true as const } : run.verified;
  if (result.ok && step === "confirm") return withState(run, id, { kind: "switched" });
  if (!result.ok && (step === "confirm" || !run.cancelled))
    return withState(run, id, { kind: "failed", step, error: result.error });
  if (run.cancelled) return withState(run, id, stoppedAt(result.ok ? step : prevStep(step)), verified);
  const next = ROTATION_STEPS[ROTATION_STEPS.indexOf(step) + 1];
  return withState(run, id, { kind: "pending", step: next }, verified);
}

/** Put a failed target back in the queue at the step that failed. */
export function retryTarget(run: RotationRun, id: string): RotationRun {
  const s = run.states[id];
  if (run.cancelled || s?.kind !== "failed") return run;
  return withState(run, id, { kind: "pending", step: s.step });
}

/** Stop the run: nothing new starts, every target waiting for a step up to
 *  remove keeps the old key, and one waiting for its confirm is left
 *  `unconfirmed`. Switched targets stay switched; failed ones keep their
 *  error; in-flight steps land through `recordStep`. The key item itself is not
 *  touched here. */
export function cancelRun(run: RotationRun): RotationRun {
  const states: Record<string, TargetState> = {};
  for (const [id, s] of Object.entries(run.states)) states[id] = s.kind === "pending" ? stoppedAt(prevStep(s.step)) : s;
  return { ...run, states, cancelled: true };
}

/** Nothing in flight and nothing left to start. */
export function runSettled(run: RotationRun): boolean {
  return (
    !Object.values(run.states).some((s) => s.kind === "running") && startableSteps(run).length === 0
  );
}

/** What finishing the rotation now would leave behind, machine by machine. */
export interface FinishOutlook {
  /** No login with the candidate passed here: once the key item holds the
   *  candidate, these machines refuse it — a lockout until they get it. */
  unproven: RotationTarget[];
  /** The candidate logs in, but the old key was not seen refused: the machine
   *  keeps working and may still accept the old key. */
  oldNotRefused: RotationTarget[];
}

export function finishOutlook(plan: RotationPlan, run: RotationRun): FinishOutlook {
  return {
    unproven: plan.targets.filter((t) => !run.verified[t.id]),
    oldNotRefused: plan.targets.filter((t) => run.verified[t.id] && run.states[t.id]?.kind !== "switched"),
  };
}

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

/** Whether the key item already holds the candidate's key: a finish was
 *  interrupted after its first write. There is no old key left to move
 *  machines off — a run would deploy and "check" the candidate against itself —
 *  so the only thing to do is complete that finish. Compared by key type and
 *  blob; the comment is not part of a key. */
export function rotationCommitted(keyOpenssh: string, candidateOpenssh: string): boolean {
  const key = (line: string) => line.trim().split(/\s+/).slice(0, 2).join(" ");
  return key(keyOpenssh) === key(candidateOpenssh);
}

/** How a key-only login (`publickeyOnly`) with one key ended:
 *   accepted         — the session was established and the command ran;
 *   acceptedNeedsMore — the server took the key and asked for a second factor;
 *                       the login was not completed, the key is authorized;
 *   refused          — the server does not accept the key;
 *   unknown          — the attempt failed for another reason and says nothing. */
export type KeyLogin = "accepted" | "acceptedNeedsMore" | "refused" | "unknown";

/** Read a key-only login's outcome off the exec result of its target. The two
 *  answers about the key come from the core as a value (`keyLogin`), never from
 *  the error text. Any other error — a hop, the network, a lock, a command that
 *  timed out or could not be run — reads as `unknown`, which claims nothing. */
function keyLoginOutcome(r: Pick<MultiExecResult, "error" | "keyLogin"> | null | undefined): KeyLogin {
  if (!r) return "unknown";
  if (!r.error) return "accepted";
  return r.keyLogin ?? "unknown";
}

/** Why a step did not pass. The view words it. */
export type StepFailure =
  /** Nothing came back for the target. */
  | { kind: "noResult" }
  | { kind: "timedOut" }
  /** The connection or the command failed, in its own words. */
  | { kind: "error"; message: string }
  /** Remove: the old key's blob is still in the file (`REMOVE_EXIT_STILL_PRESENT`). */
  | { kind: "oldKeyStillPresent" }
  | { kind: "noAuthorizedKeys" }
  /** Remove: the candidate cannot get a shell without a second factor, and the
   *  old key is still accepted — its line has to be removed by hand. */
  | { kind: "removeNeedsSecondFactor" }
  /** Confirm: the old key still logs in. */
  | { kind: "oldKeyStillAccepted" }
  /** The old-key login failed for a reason that says nothing about the key. */
  | { kind: "oldKeyCheckFailed"; message: string | null };

export type StepOutcome = { ok: true } | { ok: false; failure: StepFailure };

const PASSED: StepOutcome = { ok: true };
const failed = (failure: StepFailure): StepOutcome => ({ ok: false, failure });

/** A command's result as a step outcome: only a clean exit passes. */
function ran(r: MultiExecResult | null, step: RotationStep): StepOutcome {
  if (!r) return failed({ kind: "noResult" });
  if (r.timedOut) return failed({ kind: "timedOut" });
  if (r.error) return failed({ kind: "error", message: r.error });
  if (step === "remove" && r.exitStatus === REMOVE_EXIT_STILL_PRESENT) return failed({ kind: "oldKeyStillPresent" });
  if (step === "remove" && r.exitStatus === REMOVE_EXIT_NO_FILE) return failed({ kind: "noAuthorizedKeys" });
  if (r.exitStatus !== 0) return failed({ kind: "error", message: r.stderr.trim() || `exit ${r.exitStatus}` });
  return PASSED;
}

/** What `runStep` needs from the view. */
export interface StepIo {
  /** Run `cmd` on the target, connected the way `stepConnect` says for step
   *  `as`. Resolves to null when nothing came back for the target. */
  exec(as: RotationStep, cmd: string): Promise<MultiExecResult | null>;
  /** Continuing a rotation begun earlier (see `runStep`, deploy). */
  resumed: boolean;
}

/** Run one step on one target and say whether it passed.
 *
 *  deploy  — append the candidate, logged in with the old key. When continuing
 *            a rotation, first with the candidate, key-only: a machine an
 *            earlier run got to already takes it — and may no longer take the
 *            old key, which would only earn a password prompt — while one
 *            without it just says no and gets the old-key deploy.
 *  verify  — a key-only login with the candidate. A server that takes the key
 *            and wants a second factor on top has accepted it: the key is
 *            proven, the login is not completed (nothing answers that prompt).
 *  remove  — drop the old line, logged in with the candidate. Where a second
 *            factor stands between the candidate and a shell the line cannot be
 *            removed from here; the step then passes only if the old key is
 *            already refused (it was removed by hand).
 *  confirm — a key-only login with the OLD key, which must be refused. A login
 *            that failed for any other reason proves nothing and is reported
 *            apart from one where the old key was accepted. */
export async function runStep(
  step: RotationStep,
  keys: { old: string; cand: string },
  io: StepIo,
): Promise<StepOutcome> {
  /** Passes only when the machine refuses the old key; `accepted` is the
   *  failure for a machine that still takes it. */
  const oldKeyRefused = async (accepted: StepFailure): Promise<StepOutcome> => {
    const r = await io.exec("confirm", "true");
    const login = keyLoginOutcome(r);
    if (login === "refused") return PASSED;
    return failed(login === "unknown" ? { kind: "oldKeyCheckFailed", message: r?.error ?? null } : accepted);
  };

  if (step === "verify") {
    const r = await io.exec("verify", "true");
    return keyLoginOutcome(r) === "acceptedNeedsMore" ? PASSED : ran(r, step);
  }
  if (step === "remove") {
    const r = await io.exec("remove", authorizedKeysRemoveCmd(keys.old, keys.cand));
    if (keyLoginOutcome(r) !== "acceptedNeedsMore") return ran(r, step);
    return oldKeyRefused({ kind: "removeNeedsSecondFactor" });
  }
  if (step === "confirm") return oldKeyRefused({ kind: "oldKeyStillAccepted" });

  const append = authorizedKeysAppendCmd(keys.cand);
  if (io.resumed) {
    const r = await io.exec("verify", append);
    if (keyLoginOutcome(r) === "acceptedNeedsMore" || ran(r, step).ok) return PASSED;
  }
  return ran(await io.exec("deploy", append), step);
}

/** How to reach target `id` for `step`. The target itself logs in with the old
 *  key to deploy, with the candidate to verify and remove (verify is the proof;
 *  remove then runs under that same proven login), and with the old key again
 *  to confirm — a login that must be refused. A hop in front of it that uses
 *  the rotated key logs in with the candidate once that hop's own target has
 *  verified — it may already have dropped the old key — and with the old key
 *  before. A `hopRef` hop switched that way is written out inline (the core
 *  would resolve it to the old key); the proxy the core would have taken from
 *  that bastion is already the target's own (`firstDialProxy`). That inline
 *  copy mirrors the core's hop_ref resolution (rust-core/crates/ffi/src/lib.rs,
 *  `connect_with_options`: a ref hop takes the referenced profile's
 *  host/port/user/auth) — keep the two in step. */
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
  const { hopTargetId } = routes(refProfile);
  const candidate = { type: "agent" as const, vaultId: plan.vaultId, keyItemId: candidateId };
  const old = { type: "agent" as const, vaultId: plan.vaultId, keyItemId: plan.keyItemId };
  const jumps = t.jumps.map((j, i): JumpHost => {
    if (!hopUsesKey(j) || !run.verified[hopTargetId(t.jumps, t.proxy, i)]) return j;
    const ref = refProfile(j);
    if (!ref) return { ...j, auth: candidate };
    return { host: ref.host, port: ref.port, user: ref.user, auth: candidate, hopRef: null };
  });
  const auth = step === "deploy" || step === "confirm" ? old : candidate;
  // Verify, remove and confirm must log in with that one key and nothing else: a
  // keyboard-interactive fallback would let a typed password pass for the key.
  // Deploy logs in with the old key the user already uses, prompts and all.
  return { host: t.host, port: t.port, user: t.user, auth, jumps, proxy: t.proxy, publickeyOnly: step !== "deploy" };
}
