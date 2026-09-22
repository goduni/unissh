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

import { exportRecording } from "./recordings";

describe("recording exports", () => {
  const cast = JSON.stringify({ version: 2, unissh_mcp: { version: 1, application: "Agent", command: "printf hi", cwd: null, outcome: "completed", exit_code: 0, truncated: false } }) + '\n[0,"o","hello"]\n[1,"o"," world\\n"]\n';
  it("preserves raw JSON events and leaves cast exports byte-identical", () => {
    expect(exportRecording(cast, "cast")).toBe(cast);
    const json = JSON.parse(exportRecording(cast, "json"));
    expect(json.header.unissh_mcp.command).toBe("printf hi");
    expect(json.events).toHaveLength(2);
  });
  it("exports readable command context and output without terminal escapes", () => {
    const text = exportRecording(cast, "txt");
    expect(text).toContain("Command: printf hi");
    expect(text).toContain("hello world\n");
    expect(exportRecording('{"version":2}\n[0,"o","\\u001b[31mred\\u001b[0m"]\n', "txt")).toBe("red");
  });
});
