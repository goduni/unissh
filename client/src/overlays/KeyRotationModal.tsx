// Guided key rotation: show the plan, then on each machine deploy the candidate
// key, verify a login with it, and remove the old key only where that login
// passed; finish (commit the candidate into the key item) when satisfied. The
// plan and the per-machine state machine are the pure `support/keyRotation`;
// this view runs each step over SSH and feeds the result back.

import { useRef, useState } from "react";
import { useTranslation } from "@/i18n";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { Btn, Icon, Spinner } from "@/components/primitives";
import { Modal } from "@/components/Modal";
import { useApp } from "@/store/app";
import { useCtx } from "@/store/ctx";
import { useIsMobile } from "@/store/responsive";
import * as api from "@/bridge/api";
import { apiErrorMessage, type MultiExecTarget } from "@/bridge/types";
import {
  authorizedKeysAppendCmd,
  authorizedKeysRemoveCmd,
  REMOVE_EXIT_NO_FILE,
  REMOVE_EXIT_STILL_PRESENT,
} from "@/support/authorizedKeys";
import { EXEC_CONCURRENCY, EXEC_TIMEOUT_SECS } from "@/support/execLimits";
import { confirmFinishRotation } from "./finishRotation";
import {
  beginStep,
  cancelRun,
  planRotation,
  recordStep,
  retryTarget,
  ROTATION_STEPS,
  runSettled,
  startableSteps,
  startRun,
  stepConnect,
  type RotationRun,
  type RotationSkipReason,
  type RotationStep,
  type RotationTarget,
  type StepResult,
  type TargetState,
} from "@/support/keyRotation";

const STEP_KEY = { deploy: "keyRotation.stepDeploy", verify: "keyRotation.stepVerify", remove: "keyRotation.stepRemove" } as const;
const SKIP_KEY: Record<RotationSkipReason, "keyRotation.skipPersonal" | "keyRotation.skipSystemAgent" | "keyRotation.skipPassword"> = {
  personal: "keyRotation.skipPersonal",
  systemAgent: "keyRotation.skipSystemAgent",
  password: "keyRotation.skipPassword",
};

type StepView = "waiting" | "running" | "done" | "failed";

/** How one step of a target reads, from the target's state. */
function stepView(s: TargetState, step: RotationStep): StepView {
  const i = ROTATION_STEPS.indexOf(step);
  if (s.kind === "switched") return "done";
  if (s.kind === "keptOld") return s.after !== null && i <= ROTATION_STEPS.indexOf(s.after) ? "done" : "waiting";
  const at = ROTATION_STEPS.indexOf(s.step);
  if (i < at) return "done";
  if (i > at) return "waiting";
  return s.kind === "running" ? "running" : s.kind === "failed" ? "failed" : "waiting";
}

const targetLabel = (tg: RotationTarget) =>
  tg.profile ? tg.profile.label : `${tg.user}@${tg.host}${tg.port !== 22 ? `:${tg.port}` : ""}`;

export function KeyRotationModal({
  keyItemId,
  hasCertificate,
  candidateId: resumeCandidate,
  onClose,
}: {
  keyItemId: string;
  hasCertificate: boolean;
  /** Set when continuing a rotation already begun on this device. */
  candidateId?: string;
  onClose: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const isMobile = useIsMobile();
  const liveVault = useApp((s) => s.vaultId) ?? "";
  const hosts = useApp((s) => s.hosts);
  // Frozen at open: the run works off this snapshot even if hosts sync or the
  // active vault changes meanwhile — the key, its candidate and the plan all
  // belong to the vault the dialog was opened for.
  const [vault] = useState(liveVault);
  const [plan] = useState(() => planRotation(hosts, vault, keyItemId));
  const [candidateId, setCandidateId] = useState<string | null>(resumeCandidate ?? null);
  const [run, setRun] = useState<RotationRun | null>(null);
  const runRef = useRef<RotationRun | null>(null);
  const keysRef = useRef<{ old: string; cand: string } | null>(null);
  const [starting, setStarting] = useState(false);
  const [driving, setDriving] = useState(false);

  const apply = (f: (r: RotationRun) => RotationRun) => {
    if (!runRef.current) return;
    runRef.current = f(runRef.current);
    setRun(runRef.current);
  };

  const exec = async (args: MultiExecTarget, cmd: string, step: RotationStep): Promise<StepResult> => {
    try {
      const r = (await api.sshExecMulti([args], cmd, 0, EXEC_TIMEOUT_SECS))[0];
      if (!r) return { ok: false, error: t("error.generic") };
      if (r.timedOut) return { ok: false, error: t("keyRotation.timedOut") };
      if (r.error) return { ok: false, error: r.error };
      if (step === "remove" && r.exitStatus === REMOVE_EXIT_STILL_PRESENT)
        return { ok: false, error: t("keyRotation.oldKeyStillPresent") };
      if (step === "remove" && r.exitStatus === REMOVE_EXIT_NO_FILE)
        return { ok: false, error: t("keyRotation.noAuthorizedKeys") };
      if (r.exitStatus !== 0) return { ok: false, error: r.stderr.trim() || `exit ${r.exitStatus}` };
      return { ok: true };
    } catch (e) {
      return { ok: false, error: apiErrorMessage(e) };
    }
  };

  const execStep = async (cid: string, id: string, step: RotationStep): Promise<StepResult> => {
    const r = runRef.current;
    const keys = keysRef.current;
    if (!r || !keys) return { ok: false, error: t("error.generic") };
    if (step === "verify") return exec(stepConnect(plan, r, id, "verify", cid), "true", step);
    if (step === "remove")
      return exec(stepConnect(plan, r, id, "remove", cid), authorizedKeysRemoveCmd(keys.old, keys.cand), step);
    const append = authorizedKeysAppendCmd(keys.cand);
    const res = await exec(stepConnect(plan, r, id, "deploy", cid), append, step);
    // Continuing a rotation: a machine switched by an earlier run no longer takes
    // the old key, but the candidate already there logs in just as well.
    if (res.ok || !resumeCandidate) return res;
    const again = await exec(stepConnect(plan, r, id, "verify", cid), append, step);
    return again.ok ? again : res;
  };

  // Round after round of whatever may start now, a bounded pool per round, until
  // the run settles. Stop cuts the queue; in-flight steps land through recordStep.
  const drive = async (cid: string) => {
    setDriving(true);
    for (let steps = startableSteps(runRef.current!); steps.length > 0; steps = startableSteps(runRef.current!)) {
      const queue = [...steps];
      const worker = async () => {
        for (let next = queue.shift(); next; next = queue.shift()) {
          const { id, step } = next;
          apply((r) => beginStep(r, id));
          const s = runRef.current!.states[id];
          if (s.kind !== "running" || s.step !== step) continue;
          const res = await execStep(cid, id, step);
          apply((r) => recordStep(r, id, step, res));
        }
      };
      await Promise.all(Array.from({ length: Math.min(EXEC_CONCURRENCY, queue.length) }, worker));
    }
    setDriving(false);
  };

  const start = async () => {
    setStarting(true);
    try {
      let cid = candidateId;
      if (!cid) {
        cid = await api.beginKeyRotation(vault, keyItemId);
        setCandidateId(cid);
        await useApp.getState().reloadVault();
      }
      const [o, c] = await Promise.all([api.getPublicKey(vault, keyItemId), api.getPublicKey(vault, cid)]);
      keysRef.current = { old: o.openssh, cand: c.openssh };
      runRef.current = startRun(plan);
      setRun(runRef.current);
      setStarting(false);
      await drive(cid);
    } catch (e) {
      setStarting(false);
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  const retry = (id: string) => {
    if (!candidateId || driving) return;
    apply((r) => retryTarget(r, id));
    void drive(candidateId);
  };

  const busy = starting || driving;
  const settled = run !== null && runSettled(run);
  // Machines the new key has not been proven on: after finish they refuse the
  // key until they get it. Separately, machines where it was proven but the old
  // line was not removed: they keep working and still accept the old key.
  const notSwitched = run ? plan.targets.filter((tg) => !run.verified[tg.id]) : [];
  const stillOld = run
    ? plan.targets.filter((tg) => run.verified[tg.id] && run.states[tg.id]?.kind !== "switched")
    : [];
  const finish = () => {
    if (!candidateId) return;
    confirmFinishRotation(ctx, {
      vault,
      keyId: keyItemId,
      candidateId,
      danger: notSwitched.length > 0,
      onDone: onClose,
    });
  };
  const outcome = (tg: RotationTarget) => {
    const s = run?.states[tg.id];
    return s?.kind === "failed"
      ? t("keyRotation.failedAt", { step: t(STEP_KEY[s.step]), error: s.error })
      : t("keyRotation.keptOld");
  };
  // Hosts that reach the key only through target `id` as a hop: they follow it.
  const dependentsOf = (id: string) =>
    plan.dependents.filter((d) => d.targetIds.includes(id)).map((d) => d.host.label);
  const labelOf = (id: string) => {
    const tg = plan.targets.find((x) => x.id === id);
    return tg ? targetLabel(tg) : id;
  };
  const mobileBtn = isMobile ? { minHeight: rem(44), flex: 1 } : undefined;
  const sectionLabel = {
    fontSize: TEXT.micro,
    fontWeight: 700,
    color: p.txt3,
    textTransform: "uppercase",
    margin: `${rem(4)} 0`,
  } as const;
  const note = { fontSize: TEXT.small, color: p.txt2, lineHeight: 1.5, margin: 0 } as const;

  return (
    <Modal
      position="absolute"
      zIndex={150}
      icon="refresh"
      title={t("keyRotation.title", { item: keyItemId })}
      subtitle={t("keyRotation.subtitle")}
      // Mid-run the dialog stays: closing would orphan steps in flight. Stop first.
      onClose={
        busy
          ? () => ctx.toast(t(run?.cancelled ? "keyRotation.busyCloseStopped" : "keyRotation.busyClose"), "warn")
          : onClose
      }
      w={600}
      footer={
        <>
          <div style={{ flex: isMobile ? "1 1 100%" : 1 }} />
          {!run && (
            <>
              <Btn variant="ghost" onClick={onClose} disabled={starting} style={mobileBtn}>
                {t("common.cancel")}
              </Btn>
              <Btn icon="refresh" onClick={start} disabled={starting} style={mobileBtn}>
                {t("keyRotation.start")}
              </Btn>
            </>
          )}
          {run && driving && !run.cancelled && (
            <Btn variant="ghost" icon="stop" onClick={() => apply(cancelRun)} style={mobileBtn}>
              {t("keyRotation.stop")}
            </Btn>
          )}
          {run && settled && !driving && (
            <>
              <Btn variant="ghost" onClick={onClose} style={mobileBtn}>
                {t("common.close")}
              </Btn>
              <Btn icon="check" onClick={finish} style={mobileBtn}>
                {t("keyRotation.finish")}
              </Btn>
            </>
          )}
        </>
      }
    >
      <p style={note}>{t("keyRotation.stepsIntro")}</p>
      {resumeCandidate && <p style={note}>{t("keyRotation.resumeNote", { candidate: resumeCandidate })}</p>}
      {hasCertificate && (
        <p role="note" style={{ ...note, color: p.amber, display: "flex", gap: rem(6) }}>
          <Icon name="alert" size={14} color={p.amber} style={{ marginTop: rem(2) }} />
          {t("keyRotation.certNote")}
        </p>
      )}

      <div style={sectionLabel}>{t("keyRotation.targetsLabel")}</div>
      {plan.targets.length === 0 ? (
        <p style={note}>{t("keyRotation.noTargets")}</p>
      ) : (
        <ul aria-live="polite" style={{ listStyle: "none", margin: 0, padding: 0 }}>
          {plan.targets.map((tg, i) => {
            const s: TargetState = run?.states[tg.id] ?? { kind: "pending", step: "deploy" };
            return (
              <li
                key={tg.id}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: rem(6),
                  padding: `${rem(9)} ${rem(2)}`,
                  borderTop: i === 0 ? undefined : `1px solid ${p.line}`,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: rem(10), flexWrap: "wrap" }}>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ fontSize: TEXT.base, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {targetLabel(tg)}
                    </div>
                    <div style={{ fontFamily: MONO, fontSize: TEXT.micro, color: p.txt3 }}>
                      {tg.user}@{tg.host}
                      {tg.port !== 22 ? `:${tg.port}` : ""}
                      {tg.via ? ` · ${t("keyRotation.hopOf", { host: tg.via.label })}` : ""}
                    </div>
                  </div>
                  {s.kind === "switched" && (
                    <span style={{ fontSize: TEXT.small, fontWeight: 600, color: p.green }}>{t("keyRotation.switched")}</span>
                  )}
                  {s.kind === "keptOld" && (
                    <span style={{ fontSize: TEXT.small, fontWeight: 600, color: p.amber }}>{t("keyRotation.keptOld")}</span>
                  )}
                  {s.kind === "failed" && !run?.cancelled && (
                    <Btn
                      size="sm"
                      variant="ghost"
                      icon="refresh"
                      onClick={() => retry(tg.id)}
                      disabled={driving}
                      aria-label={t("keyRotation.retryAria", { host: targetLabel(tg), step: t(STEP_KEY[s.step]) })}
                    >
                      {t("keyRotation.retry")}
                    </Btn>
                  )}
                </div>
                <ol style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", gap: rem(14), flexWrap: "wrap" }}>
                  {ROTATION_STEPS.map((step) => {
                    const v = run ? stepView(s, step) : "waiting";
                    const color = v === "done" ? p.green : v === "failed" ? p.red : v === "running" ? p.txt : p.txt3;
                    const stateLabel = t(
                      v === "done"
                        ? "keyRotation.stateDone"
                        : v === "failed"
                          ? "keyRotation.stateFailed"
                          : v === "running"
                            ? "keyRotation.stateRunning"
                            : "keyRotation.stateWaiting",
                    );
                    return (
                      <li
                        key={step}
                        aria-label={t("keyRotation.stepAria", { step: t(STEP_KEY[step]), state: stateLabel })}
                        style={{ display: "inline-flex", alignItems: "center", gap: rem(5), fontSize: TEXT.small, color }}
                      >
                        {v === "running" ? (
                          <Spinner size={11} />
                        ) : (
                          <Icon name={v === "done" ? "check" : v === "failed" ? "x" : "dot"} size={12} color={color} />
                        )}
                        {t(STEP_KEY[step])}
                      </li>
                    );
                  })}
                </ol>
                {s.kind === "failed" && (
                  <div style={{ fontFamily: MONO, fontSize: TEXT.micro, color: p.red, wordBreak: "break-word" }}>
                    {t("keyRotation.failedAt", { step: t(STEP_KEY[s.step]), error: s.error })}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {plan.dependents.length > 0 && (
        <>
          <div style={sectionLabel}>{t("keyRotation.dependentsLabel")}</div>
          <ul style={{ ...note, paddingLeft: rem(18) }}>
            {plan.dependents.map((d) => (
              <li key={d.host.profileId}>
                {d.host.label}{" "}
                <span style={{ color: p.txt3 }}>
                  {t("keyRotation.dependentVia", { targets: d.targetIds.map(labelOf).join(", ") })}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}

      {plan.skipped.length > 0 && (
        <details>
          <summary style={{ ...sectionLabel, cursor: "pointer" }}>
            {t("keyRotation.skippedLabel", { count: plan.skipped.length })}
          </summary>
          <ul style={{ ...note, paddingLeft: rem(18) }}>
            {plan.skipped.map((s) => (
              <li key={s.host.profileId}>
                {s.host.label} <span style={{ color: p.txt3 }}>— {t(SKIP_KEY[s.reason])}</span>
              </li>
            ))}
          </ul>
        </details>
      )}

      {run?.cancelled && <p style={{ ...note, color: p.amber }}>{t("keyRotation.stopped")}</p>}
      {settled && !driving && (
        <>
          {notSwitched.length > 0 && (
            <div style={{ ...note, color: p.amber }}>
              {t("keyRotation.notSwitchedLabel")}
              <ul style={{ margin: `${rem(4)} 0 0`, paddingLeft: rem(18) }}>
                {notSwitched.map((tg) => {
                  const deps = dependentsOf(tg.id);
                  return (
                    <li key={tg.id}>
                      {targetLabel(tg)} — {outcome(tg)}
                      {deps.length > 0 && (
                        <div style={{ color: p.txt3 }}>{t("keyRotation.notSwitchedWith", { hosts: deps.join(", ") })}</div>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
          {stillOld.length > 0 && (
            <div style={note}>
              {t("keyRotation.stillOldLabel")}
              <ul style={{ margin: `${rem(4)} 0 0`, paddingLeft: rem(18) }}>
                {stillOld.map((tg) => (
                  <li key={tg.id}>
                    {targetLabel(tg)} — {outcome(tg)}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p style={note}>{t("keyRotation.finishNote", { item: keyItemId })}</p>
        </>
      )}
    </Modal>
  );
}
