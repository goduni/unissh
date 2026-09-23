import { useEffect, useId, useMemo, useState } from "react";
import { Btn, Spinner } from "@/components/primitives";
import { useTranslation, tDyn } from "@/i18n";
import { mcpInspectCommand, type McpCommandDetails as CommandDetails, type McpOutputChunk, type McpRun } from "@/bridge/mcp";
import { commandText, elapsed, isActiveState, mergeOutput, outputGroups, readableOutput } from "./activity";

export function McpCommandDetails({ run }: { run: McpRun }) {
  const { t, i18n } = useTranslation();
  const id = useId();
  const [details, setDetails] = useState<CommandDetails | null>(null);
  const [chunks, setChunks] = useState<McpOutputChunk[]>([]);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [stream, setStream] = useState<"all" | "stdout" | "stderr">("all");
  useEffect(() => {
    let alive = true;
    let cursor: string | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setDetails(null); setChunks([]); setError(false);
    const poll = async () => {
      try {
        const result = await mcpInspectCommand(run.integration_id, run.run_id, cursor);
        if (!alive) return;
        setDetails(result);
        setChunks(previous => result.output_error ? [] : mergeOutput(previous, result.chunks));
        cursor = result.next_cursor;
        if (!result.output_error) timer = setTimeout(() => { void poll(); }, result.has_more ? 50 : isActiveState(result.state) ? 1000 : 5000);
      } catch {
        if (alive) { setDetails(null); setChunks([]); setError(true); }
      }
    };
    void poll();
    return () => { alive = false; clearTimeout(timer); };
  }, [run.integration_id, run.run_id, retry]);
  const groups = useMemo(() => outputGroups(chunks, stream).map(group => ({ ...group, data: group.encoding === "base64" ? group.data : readableOutput(group.data) })), [chunks, stream]);
  if (error) return <div className="mcp-inspect-error" role="alert"><p>{t("mcp.activityDetails.readFailed")}</p><Btn variant="outline" size="sm" onClick={() => setRetry(n => n + 1)}>{t("mcp.activityDetails.retry")}</Btn></div>;
  if (!details) return <div className="mcp-inspect-loading" role="status"><Spinner />{t("mcp.activityDetails.loading")}</div>;
  return <div className="mcp-command-inspector">
    <div className="mcp-inspect-command"><span className="mcp-field-label">{t("mcp.command")}</span><pre>{commandText(details.command)}</pre></div>
    <dl className="mcp-inspect-meta">
      <div><dt>{t("mcp.cwd")}</dt><dd><code>{details.cwd ? commandText(details.cwd) : t("mcp.activityDetails.defaultDirectory")}</code></dd></div>
      <div><dt>{t("mcp.commandLimit")}</dt><dd>{elapsed(details.timeout_ms, i18n.language)}</dd></div>
    </dl>
    {(details.error && details.error !== "output_expired") && <p className="mcp-inspect-reason">{tDyn(`mcp.errors.${details.error}`)}</p>}
    {(details.stdin !== null || Object.keys(details.env).length > 0) && <div className="mcp-inspect-inputs">
      {details.stdin !== null && <details><summary>{t("mcp.standardInput")}</summary><pre>{commandText(details.stdin)}</pre></details>}
      {Object.keys(details.env).length > 0 && <details><summary>{t("mcp.environment")}</summary><pre>{Object.entries(details.env).map(([name, value]) => `${name}=${commandText(value)}`).join("\n")}</pre></details>}
    </div>}
    <div className="mcp-output-heading"><h5>{t("mcp.activityDetails.output")}</h5>
      <div className="mcp-streams" role="group" aria-label={t("mcp.activityDetails.outputStream")}>{(["all", "stdout", "stderr"] as const).map(value => <label key={value}>
        <input type="radio" name={`${id}-stream`} value={value} checked={stream === value} onChange={() => setStream(value)} />
        <span>{value === "all" ? t("mcp.activityDetails.allOutput") : value}</span>
      </label>)}</div>
    </div>
    {details.output_error ? <p className="mcp-output-notice" role="status">{t("mcp.activityDetails.outputExpired")}</p> : <>
      {details.truncated && <p className="mcp-output-notice" role="status">{t("mcp.activityDetails.truncated")}</p>}
      <div className="mcp-command-output" tabIndex={0} role="region" aria-label={t("mcp.activityDetails.output")}>
        {groups.length ? groups.map(group => <div key={group.cursor} className="mcp-output-part">
          <span className="mcp-output-stream">{group.stream}{group.encoding === "base64" && ` · ${t("mcp.activityDetails.binary")}`}</span>
          <pre>{group.data}</pre>
        </div>) : <p>{t(isActiveState(details.state) ? "mcp.activityDetails.waitingOutput" : "mcp.activityDetails.noOutput")}</p>}
      </div>
    </>}
  </div>;
}
