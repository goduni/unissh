import { describe, expect, it } from "vitest";
import { mcpRecordingDetails } from "./recordings";

describe("MCP recording extension", () => {
  const m = { version: 1, application: "Agent", command: "printf '\\0'", cwd: "/tmp", outcome: "completed", exit_code: 7, truncated: false };
  it("reads native metadata without treating command text as markup", () => {
    const cast = JSON.stringify({ version: 2, unissh_mcp: { ...m, command: "<script>bad</script>\n" } }) + '\n[0,"o","hello"]';
    expect(mcpRecordingDetails(cast)).toEqual({ application: "Agent", destination: null, command: "<script>bad</script>\n", cwd: "/tmp", outcome: "completed", exitCode: 7, truncated: false });
  });
  it("leaves old, invalid and future recordings playable without MCP details", () => {
    for (const cast of ['{"version":2}\n', "broken", JSON.stringify({ unissh_mcp: { ...m, version: 2 } }), JSON.stringify({ unissh_mcp: { ...m, command: {} } })]) {
      expect(mcpRecordingDetails(cast)).toBeNull();
    }
  });
  it("preserves partial and interrupted outcomes", () => {
    expect(mcpRecordingDetails(JSON.stringify({ unissh_mcp: { ...m, cwd: null, outcome: "interrupted", exit_code: null, truncated: true } })))
      .toMatchObject({ cwd: null, outcome: "interrupted", exitCode: null, truncated: true });
  });
});
