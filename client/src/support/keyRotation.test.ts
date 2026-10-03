import { describe, it, expect } from "vitest";
import {
  beginStep,
  cancelRun,
  planRotation,
  recordStep,
  retryTarget,
  runSettled,
  startableSteps,
  startRun,
  stepConnect,
  type RotationRun,
  type RotationStep,
  type StepResult,
} from "./keyRotation";
import type { ConnectionProfile, JumpHost, ProfileAuth } from "@/bridge/types";

const KEY: ProfileAuth = { type: "key", keyItemId: "k" };

const host = (name: string, auth: ProfileAuth, jumps: JumpHost[] = []): ConnectionProfile => ({
  profileId: name,
  uid: name,
  label: name,
  host: `${name}.example`,
  port: 22,
  user: "root",
  auth,
  jumps,
  tags: [],
  startupSnippetIds: [],
  recordSessions: false,
  agentForward: false,
});

const inlineHop = (name: string, keyItemId: string): JumpHost => ({
  host: `${name}.example`,
  port: 22,
  user: "ops",
  auth: { type: "agent", vaultId: "v", keyItemId },
});

const refHop = (profileUid: string): JumpHost => ({ ...inlineHop("ignored", ""), hopRef: { vaultId: "v", profileUid } });

const OK: StepResult = { ok: true };

/** Run every startable step until the run settles, answering each from `answer`. */
function drive(run: RotationRun, answer: (id: string, step: RotationStep) => StepResult): RotationRun {
  for (let steps = startableSteps(run); steps.length > 0; steps = startableSteps(run)) {
    for (const { id } of steps) run = beginStep(run, id);
    for (const { id, step } of steps) run = recordStep(run, id, step, answer(id, step));
  }
  return run;
}

const kinds = (run: RotationRun) =>
  Object.fromEntries(Object.entries(run.states).map(([id, s]) => [id, "step" in s ? `${s.kind}:${s.step}` : s.kind]));

const twoHosts = () => planRotation([host("a", KEY), host("b", KEY)], "v", "k");
const A = "root@a.example:22";
const B = "root@b.example:22";

describe("planRotation", () => {
  it("targets the machines that log in with the key and makes hop-only hosts follow them", () => {
    const plan = planRotation(
      [
        host("bastion", KEY),
        // hop-only through the saved bastion profile → follows the bastion
        host("db", { type: "promptPassword" }, [refHop("bastion")]),
        // inline hop with the key, behind an unrelated first hop → that endpoint, over the prefix
        host("app", { type: "vaultPassword", passwordItemId: "p" }, [inlineHop("edge", "x"), inlineHop("jump", "k")]),
        // the same inline endpoint again → one target
        host("cache", { type: "personal" }, [inlineHop("jump", "k")]),
        // a direct host that also hops with the key is a target, not a dependent
        host("web", KEY, [inlineHop("jump", "k")]),
      ],
      "v",
      "k",
    );
    const J = "ops@jump.example:22";
    expect(plan.targets.map((t) => [t.id, t.profile?.label ?? null, t.jumps.map((j) => j.host)])).toEqual([
      ["root@bastion.example:22", "bastion", []],
      ["root@web.example:22", "web", ["jump.example"]],
      [J, null, ["edge.example"]],
    ]);
    expect(plan.dependents.map((d) => [d.host.label, d.targetIds])).toEqual([
      ["db", ["root@bastion.example:22"]],
      ["app", [J]],
      ["cache", [J]],
    ]);
  });

  it("skips hosts that log in with Personal, the system agent or a password, naming the reason", () => {
    const plan = planRotation(
      [
        host("a", KEY),
        host("p", { type: "personal" }),
        host("s", { type: "systemAgent", publicKey: "ssh-ed25519 AAAA" }),
        host("vp", { type: "vaultPassword", passwordItemId: "x" }),
        host("ask", { type: "promptPassword" }),
        host("other", { type: "key", keyItemId: "other" }),
      ],
      "v",
      "k",
    );
    expect(plan.skipped.map((s) => [s.host.label, s.reason])).toEqual([
      ["p", "personal"],
      ["s", "systemAgent"],
      ["vp", "password"],
      ["ask", "password"],
    ]);
  });
});

describe("rotation run", () => {
  it("switches every target through deploy, verify and remove", () => {
    const run = drive(startRun(twoHosts()), () => OK);
    expect([kinds(run), runSettled(run)]).toEqual([{ [A]: "switched", [B]: "switched" }, true]);
  });

  it("never verifies or removes on a host whose deploy failed", () => {
    const seen: string[] = [];
    const run = drive(startRun(twoHosts()), (id, step) => {
      seen.push(`${id}:${step}`);
      return id === A ? { ok: false, error: "denied" } : OK;
    });
    expect(seen.filter((s) => s.startsWith(A))).toEqual([`${A}:deploy`]);
    expect(run.states[A]).toEqual({ kind: "failed", step: "deploy", error: "denied" });
    expect(run.states[B]).toEqual({ kind: "switched" });
  });

  it("keeps the old key where verify failed", () => {
    const run = drive(startRun(twoHosts()), (id, step) =>
      id === A && step === "verify" ? { ok: false, error: "Permission denied" } : OK,
    );
    expect([run.states[A], run.verified[A]]).toEqual([
      { kind: "failed", step: "verify", error: "Permission denied" },
      undefined,
    ]);
  });

  it("leaves switched targets switched and every other one on the old key after a cancel", () => {
    const plan = planRotation([host("a", KEY), host("b", KEY), host("c", KEY), host("d", KEY)], "v", "k");
    const [a, b, c, d] = plan.targets.map((t) => t.id);
    // a switches; c fails deploy; b's remove and d's verify fail and are retried
    let run = drive(startRun(plan), (id, step) =>
      (id === c && step === "deploy") || (id === b && step === "remove") || (id === d && step === "verify")
        ? { ok: false, error: "x" }
        : OK,
    );
    run = retryTarget(retryTarget(run, b), d);
    run = beginStep(run, d); // d's verify in flight; b's remove waits for it
    run = cancelRun(run);
    expect(startableSteps(run)).toEqual([]);
    run = recordStep(run, d, "verify", OK);
    expect(kinds(run)).toEqual({ [a]: "switched", [b]: "keptOld", [c]: "failed:deploy", [d]: "keptOld" });
    expect([runSettled(run), retryTarget(run, c)]).toEqual([true, run]);
  });

  it("resumes a retried host at the step that failed", () => {
    let failVerify = true;
    const seen: string[] = [];
    const answer = (id: string, step: RotationStep): StepResult => {
      seen.push(`${id}:${step}`);
      if (id === A && step === "verify" && failVerify) return { ok: false, error: "timeout" };
      return OK;
    };
    let run = drive(startRun(twoHosts()), answer);
    failVerify = false;
    seen.length = 0;
    run = drive(retryTarget(run, A), answer);
    expect([seen, run.states[A]]).toEqual([[`${A}:verify`, `${A}:remove`], { kind: "switched" }]);
  });

  it("never lets a host reach remove without a passed verify, whatever the results", () => {
    // mulberry32: a seeded PRNG so a failure reproduces.
    let seed = 0x5eed;
    const rand = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const pick = <T,>(xs: T[]) => xs[Math.floor(rand() * xs.length)];
    const plan = planRotation(["a", "b", "c", "d", "e"].map((n) => host(n, KEY)), "v", "k");
    let switched = 0;
    for (let iter = 0; iter < 300; iter++) {
      let run = startRun(plan);
      const passedVerify = new Set<string>();
      for (let op = 0; op < 60; op++) {
        const running = Object.entries(run.states).filter(([, s]) => s.kind === "running");
        const failed = Object.entries(run.states).filter(([, s]) => s.kind === "failed");
        const r = rand();
        if (r < 0.4 && startableSteps(run).length) run = beginStep(run, pick(startableSteps(run)).id);
        else if (r < 0.85 && running.length) {
          const [id, s] = pick(running);
          const step = (s as { step: RotationStep }).step;
          const ok = rand() < 0.7;
          if (ok && step === "verify" && !run.cancelled) passedVerify.add(id);
          run = recordStep(run, id, step, ok ? OK : { ok: false, error: "e" });
        } else if (r < 0.95 && failed.length) run = retryTarget(run, pick(failed)[0]);
        else if (r >= 0.99) run = cancelRun(run);
        // an arbitrary begin, allowed or not
        else run = beginStep(run, pick(Object.keys(run.states)));
        for (const [id, s] of Object.entries(run.states))
          if ((s.kind === "running" && s.step === "remove") || s.kind === "switched")
            expect(passedVerify.has(id), `${id} reached ${s.kind} without a passed verify`).toBe(true);
      }
      switched += Object.values(run.states).filter((s) => s.kind === "switched").length;
    }
    expect(switched).toBeGreaterThan(0); // the sweep did exercise remove
  });
});

describe("stepConnect", () => {
  it("reaches a target through hops that already verified with the candidate, and proves the candidate key-only", () => {
    const bastion = { ...host("bastion", KEY), proxy: { kind: "socks5" as const, host: "px", port: 1080 } };
    const plan = planRotation(
      [bastion, host("db", KEY, [refHop("bastion"), inlineHop("mid", "k")])],
      "v",
      "k",
    );
    const DB = "root@db.example:22";
    let run = startRun(plan);
    run = { ...run, verified: { "root@bastion.example:22": true } };
    const old = { type: "agent", vaultId: "v", keyItemId: "k" };
    const cand = { type: "agent", vaultId: "v", keyItemId: "cand" };
    const deploy = stepConnect(plan, run, DB, "deploy", "cand");
    expect([
      deploy.auth,
      deploy.publickeyOnly,
      deploy.proxy,
      deploy.jumps.map((j) => [j.host, j.auth, j.hopRef ?? null]),
    ]).toEqual([
      old,
      false,
      bastion.proxy,
      [
        ["bastion.example", cand, null],
        ["mid.example", old, null],
      ],
    ]);
    const verify = stepConnect(plan, run, DB, "verify", "cand");
    expect([verify.auth, verify.publickeyOnly]).toEqual([cand, true]);
  });
});
