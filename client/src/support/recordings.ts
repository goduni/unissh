/** Versioned native extension in an otherwise standard asciicast v2 header. */
export interface McpRecordingDetails {
  application: string;
  destination: string | null;
  command: string;
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
      destination: typeof m.host === "string" && typeof m.user === "string" && Number.isInteger(m.port) ? `${m.user}@${m.host}:${m.port}` : null, command: m.command, cwd: m.cwd, outcome: m.outcome,
      exitCode: Number.isInteger(m.exit_code) && m.exit_code >= 0 ? m.exit_code : null,
      truncated: m.truncated === true };
  } catch { return null; }
}
