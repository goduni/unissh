import { describe, expect, it } from "vitest";
import { connectionSnippet, MCP_CLIENTS } from "./connections";

const endpoint = "http://127.0.0.1:54321/mcp";

describe("MCP connection instructions", () => {
  it("uses the current endpoint and a replaceable token in every template", () => {
    for (const client of MCP_CLIENTS) {
      expect(connectionSnippet(client, endpoint)).toContain(endpoint);
      expect(connectionSnippet(client, endpoint)).toContain("Bearer <TOKEN>");
    }
  });

  it("uses each client's HTTP configuration shape and disables OAuth for OpenCode", () => {
    const cursor = JSON.parse(connectionSnippet("cursor", endpoint));
    expect(cursor.mcpServers.UniSSH).toEqual({
      url: endpoint,
      headers: { Authorization: "Bearer <TOKEN>" },
    });
    const v1 = JSON.parse(connectionSnippet("opencode", endpoint, "1"));
    const v2 = JSON.parse(connectionSnippet("opencode", endpoint, "2"));
    expect(v1.mcp.UniSSH.oauth).toBe(false);
    expect(v1.mcp.UniSSH.type).toBe("remote");
    expect(v2.mcp.servers.UniSSH).toEqual(v1.mcp.UniSSH);
    expect(v2.mcp.UniSSH).toBeUndefined();
    expect(
      JSON.parse(connectionSnippet("other", endpoint)).mcpServers.UniSSH.type,
    ).toBe("http");
  });

  it("keeps Claude configuration in user scope and uses Codex's header field", () => {
    expect(connectionSnippet("claude", endpoint)).toContain("--scope user");
    expect(connectionSnippet("claude", endpoint)).toContain(
      '--header "Authorization: Bearer <TOKEN>"',
    );
    expect(connectionSnippet("codex", endpoint)).toContain(
      "[mcp_servers.UniSSH]\n",
    );
    expect(connectionSnippet("codex", endpoint)).toContain(
      'http_headers = { Authorization = "Bearer <TOKEN>" }',
    );
  });
});
