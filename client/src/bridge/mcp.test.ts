import { describe, expect, it } from "vitest";
import { mcpConfiguration, visibleCommand } from "./mcp";

describe("MCP command review", () => {
  it("shows newlines, escapes, bidirectional and terminal controls unambiguously", () => {
    const command = 'printf "ok"\n\\n\x1b[2J\u202e\u0085\u2066';
    const shown = visibleCommand(command);
    expect(shown).not.toContain("\n");
    expect(shown).not.toContain("\u202e");
    expect(shown).toContain("\\u001b");
    expect(shown).toContain("\\u202e");
    expect(shown).toContain("\\u0085");
    expect(JSON.parse(shown)).toBe(command);
  });
  it("copies a header placeholder rather than a URL token", () => {
    const config = JSON.parse(mcpConfiguration("http://127.0.0.1:12345/mcp"));
    expect(config.mcpServers.UniSSH).toEqual({ type: "http", url: "http://127.0.0.1:12345/mcp", headers: { Authorization: "Bearer <TOKEN>" } });
  });
});
