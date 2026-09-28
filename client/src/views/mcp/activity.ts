import type { McpOutputChunk, McpRun } from "@/bridge/mcp";
import { visibleCommand } from "@/bridge/mcp";

export const isActiveState = (state: string) => ["awaiting_approval", "queued", "connecting", "running", "cancelling"].includes(state);
export const isActiveRun = (run: McpRun) => isActiveState(run.state);
export const isFailedRun = (run: McpRun) => run.state === "failed" || (run.state === "completed" && run.exit_code != null && run.exit_code !== 0);
export function sortRuns(runs: McpRun[]): McpRun[] {
  return [...runs].sort((a, b) => Number(isActiveRun(b)) - Number(isActiveRun(a)) || (b.started_unix_ms ?? b.created_unix_ms ?? 0) - (a.started_unix_ms ?? a.created_unix_ms ?? 0) || a.run_id.localeCompare(b.run_id));
}
export const commandText = (text: string) => visibleCommand(text).slice(1, -1);
export function elapsed(ms: number | null | undefined, locale = "en"): string {
  if (ms == null) return "—";
  const seconds = Math.floor(ms / 1000);
  const unit = (value: number, name: string) => new Intl.NumberFormat(locale, { style: "unit", unit: name, unitDisplay: "narrow" }).format(value);
  if (seconds < 1) return `<${unit(1, "second")}`;
  if (seconds < 60) return unit(seconds, "second");
  if (seconds < 3600) return `${unit(Math.floor(seconds / 60), "minute")} ${unit(seconds % 60, "second")}`;
  return `${unit(Math.floor(seconds / 3600), "hour")} ${unit(Math.floor((seconds % 3600) / 60), "minute")}`;
}
export function mergeOutput(previous: McpOutputChunk[], incoming: McpOutputChunk[]): McpOutputChunk[] {
  const known = new Set(previous.map(c => c.cursor));
  const added = incoming.filter(c => { if (known.has(c.cursor)) return false; known.add(c.cursor); return true; });
  return added.length ? [...previous, ...added] : previous;
}
/** Plain text only: never feed remote output into HTML or a terminal interpreter. */
export function readableOutput(text: string): string {
  return text.replace(/\x1b\[[0-?]*[ -/]*[@-~]|\x1b\](?:[^\x07\x1b]|\x1b(?!\\))*(?:\x07|\x1b\\)/g, "")
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
export function outputGroups(chunks: McpOutputChunk[], stream: "all" | "stdout" | "stderr") {
  const groups: McpOutputChunk[] = [];
  for (const chunk of chunks) {
    if (stream !== "all" && chunk.stream !== stream) continue;
    const last = groups[groups.length - 1];
    if (last && last.stream === chunk.stream && last.encoding === "utf8" && chunk.encoding === "utf8") last.data += chunk.data;
    else groups.push({ ...chunk });
  }
  return groups;
}
