/** Versioned native extension in an otherwise standard asciicast v2 header. */
export interface McpRecordingDetails {
  application: string;
  destination: string | null;
  command: string;
  stdin?: string;
  env?: Record<string, string>;
  cwd: string | null;
  outcome: "completed" | "failed" | "cancelled" | "interrupted";
  exitCode: number | null;
  truncated: boolean;
}
export function mcpRecordingDetails(cast: string): McpRecordingDetails | null {
  try {
    const header = JSON.parse(cast.slice(0, cast.indexOf("\n") < 0 ? undefined : cast.indexOf("\n")));
    const m = header?.unissh_mcp;
    if (m?.version !== 1 || typeof m.application !== "string" || typeof m.command !== "string" ||
        !(m.cwd === null || typeof m.cwd === "string") ||
        !["completed", "failed", "cancelled", "interrupted"].includes(m.outcome)) return null;
    return { application: m.application,
      ...(typeof m.stdin === "string" ? { stdin: m.stdin } : {}),
      ...(m.env && typeof m.env === "object" && !Array.isArray(m.env) && Object.values(m.env).every(v => typeof v === "string") ? { env: m.env as Record<string, string> } : {}),
      destination: typeof m.host === "string" && typeof m.user === "string" && Number.isInteger(m.port) ? `${m.user}@${m.host}:${m.port}` : null, command: m.command, cwd: m.cwd, outcome: m.outcome,
      exitCode: Number.isInteger(m.exit_code) && m.exit_code >= 0 ? m.exit_code : null,
      truncated: m.truncated === true };
  } catch { return null; }
}

export type RecordingExportFormat = "cast" | "txt" | "json";

/** Presentation-only exports. The original cast preserves all raw MCP bytes. */
export function exportRecording(cast: string, format: RecordingExportFormat): string {
  if (format === "cast") return cast;
  const lines = cast.trimEnd().split("\n");
  const header = JSON.parse(lines[0]);
  const events: unknown[] = lines.slice(1).filter(Boolean).map(line => JSON.parse(line));
  if (format === "json") return JSON.stringify({ header, events }, null, 2) + "\n";
  const details = mcpRecordingDetails(cast);
  const preamble = details ? [
    `Application: ${details.application}`, `Target: ${details.destination ?? ""}`,
    `Command: ${details.command}`, `Directory: ${details.cwd ?? ""}`,
    ...(details.stdin === undefined ? [] : [`Standard input: ${JSON.stringify(details.stdin)}`]),
    ...(details.env === undefined ? [] : [`Environment: ${JSON.stringify(details.env)}`]),
    `Outcome: ${details.outcome}`, `Exit code: ${details.exitCode ?? "unknown"}`,
    `Truncated: ${details.truncated}`, "", "Output:", "",
  ].join("\n") : "";
  // The cast preview already handles split UTF-8, binary bytes and terminal controls.
  // Strip terminal escape sequences for readable exports of interactive recordings.
  const output = events.filter((e): e is [number, string, string] =>
    Array.isArray(e) && e[1] === "o" && typeof e[2] === "string").map(e => e[2]).join("");
  return preamble + output.replace(/\x1b\[[0-?]*[ -/]*[@-~]|\x1b\](?:[^\x07\x1b]|\x1b(?!\\))*(?:\x07|\x1b\\)/g, "");
}
