import { useId, useState } from "react";
import { Btn, Icon } from "@/components/primitives";
import { useTranslation, tDyn } from "@/i18n";
import type { McpRun, McpSession } from "@/bridge/mcp";
import { commandText, elapsed, isActiveRun, isFailedRun, sortRuns } from "./activity";
import { McpCommandDetails } from "./McpCommandDetails";
import "./activity.css";

type Actions = { busy: boolean; onCancel: (id: string) => void; onRecording: (run: McpRun) => void };
function RunRow({ run, busy, onCancel, onRecording }: Actions & { run: McpRun }) {
  const { t, i18n } = useTranslation();
  const [expanded, setExpanded] = useState(false);
  const id = useId();
  const active = isActiveRun(run);
  const failed = isFailedRun(run);
  const success = run.state === "completed" && run.exit_code === 0;
  const unknown = run.error === "outcome_unknown" || (run.state === "completed" && run.exit_code == null);
  const timestamp = run.started_unix_ms ?? run.created_unix_ms;
  const date = timestamp ? new Date(timestamp) : null;
  const tone = failed ? "error" : success ? "success" : active ? "active" : "neutral";
  const state = unknown ? t("mcp.activityDetails.unknownExit") : failed && run.state === "completed" ? t("mcp.activityDetails.nonzeroExit") : tDyn(`mcp.state.${run.state}`);
  return <article className={`mcp-command-row${expanded ? " is-open" : ""}`}>
    <div className="mcp-command-heading">
      <button type="button" className="mcp-command-toggle" aria-expanded={expanded} aria-controls={id} onClick={() => setExpanded(value => !value)}>
        <span className="mcp-command-chevron"><Icon name="cr" size={14} /></span>
        <span className="mcp-command-title"><code>{commandText(run.command_preview ?? run.command ?? t("mcp.command"))}</code>
          <span className="mcp-command-context"><span>{run.target?.label ?? t("mcp.command")}</span>
            {run.target && <span>{run.target.user}@{run.target.host}{run.target.port !== 22 ? `:${run.target.port}` : ""}</span>}
            {run.cwd && <span className="mcp-command-directory">{commandText(run.cwd)}</span>}
            {date && <time dateTime={date.toISOString()} title={date.toLocaleString(i18n.language)}>{date.toLocaleTimeString(i18n.language, { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time>}
          </span>
        </span>
        <span className="mcp-command-result"><span className={`mcp-run-state is-${tone}`}><span className="mcp-state-dot" />{state}{run.state === "completed" && run.exit_code != null && <span className="mcp-exit-code"> · exit {run.exit_code}</span>}</span><span className="mcp-command-duration">{elapsed(run.elapsed_ms, i18n.language)}</span></span>
      </button>
      {active && <Btn variant="ghost" size="sm" disabled={busy || run.state === "cancelling"} onClick={() => onCancel(run.run_id)}>{t("mcp.activityDetails.stop")}</Btn>}
    </div>
    {run.recording?.status === "failed" && <p className="mcp-recording-warning">{t("recordings.saveFailed")}</p>}
    <div id={id} hidden={!expanded}>{expanded && <>
      <div className="mcp-command-kind"><span>{t(run.session_id ? "mcp.sessionCommand" : "mcp.oneShot")}</span>{run.recording?.status === "saved" && <Btn variant="ghost" size="sm" icon="play" disabled={busy} onClick={() => onRecording(run)}>{t("recordings.open")}</Btn>}{run.recording?.status === "recording" && <span>{t("recordings.capturing")}</span>}</div>
      <McpCommandDetails run={run} />
    </>}</div>
  </article>;
}

export function McpActivity({ sessions, runs, busy, onClose, onCancel, onRecording }: Actions & { sessions: McpSession[]; runs: McpRun[]; onClose: (id: string) => void }) {
  const { t, i18n } = useTranslation();
  const [filter, setFilter] = useState<"all" | "active" | "failed">("all");
  const counts = { all: runs.length, active: runs.filter(isActiveRun).length, failed: runs.filter(isFailedRun).length };
  const visible = sortRuns(runs).filter(run => filter === "all" || (filter === "active" ? isActiveRun(run) : isFailedRun(run)));
  const orderedSessions = [...sessions].sort((a,b) => Number(b.state !== "closed") - Number(a.state !== "closed") || (b.created_unix_ms ?? 0) - (a.created_unix_ms ?? 0));
  return <section className="mcp-section mcp-activity-section" aria-label={t("mcp.activity")}>
    <h3>{t("mcp.activity")}</h3>
    <p className="mcp-activity-hint">{t("mcp.activityDetails.historyHint")}</p>
    {sessions.length > 0 && <div className="mcp-connections"><h4>{t("mcp.activityDetails.connections")} <span>{sessions.filter(s => s.state !== "closed").length}</span></h4>
      {orderedSessions.map(session => {
        const current = runs.find(run => run.session_id === session.session_id && isActiveRun(run));
        return <div className="mcp-connection" key={session.session_id}>
          <Icon name="terminal" size={16} />
          <div className="mcp-connection-info"><strong>{session.target?.label ?? t("mcp.session")}</strong><span>{session.target && `${session.target.user}@${session.target.host}:${session.target.port}`}</span>
            {current && <code>{commandText(current.command_preview ?? current.command ?? t("mcp.command"))}</code>}
            {session.error && <span className="mcp-connection-error">{tDyn(`mcp.errors.${session.error}`)}</span>}
          </div>
          <div className="mcp-connection-state"><span>{tDyn(`mcp.state.${session.state}`)}</span>{session.connected_elapsed_ms != null && <span>{t("mcp.activityDetails.connectedFor", { duration: elapsed(session.connected_elapsed_ms, i18n.language) })}</span>}{session.state === "ready" && !current && <span>{t("mcp.idle", { seconds: session.idle_seconds })}</span>}</div>
          {session.state !== "closed" && <Btn variant="ghost" size="sm" disabled={busy} onClick={() => onClose(session.session_id)}>{t("common.close")}</Btn>}
        </div>;
      })}
    </div>}
    <div className="mcp-command-toolbar"><h4>{t("mcp.activityDetails.commands")}</h4><div className="mcp-activity-filters" role="group" aria-label={t("mcp.activityDetails.filter")}>
      {(["all", "active", "failed"] as const).map(value => <button type="button" key={value} aria-pressed={filter === value} onClick={() => setFilter(value)}>{t(`mcp.activityDetails.filters.${value}`)} <span>{counts[value]}</span></button>)}
    </div></div>
    {visible.length ? <div className="mcp-command-list">{visible.map(run => <RunRow key={run.run_id} run={run} busy={busy} onCancel={onCancel} onRecording={onRecording} />)}</div> : <p className="mcp-activity-empty">{t(runs.length ? "mcp.activityDetails.noMatches" : "mcp.noActivity")}</p>}
  </section>;
}
