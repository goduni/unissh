import { mcpConfiguration } from "@/bridge/mcp";

export const MCP_CLIENTS = [
  "claude",
  "codex",
  "opencode",
  "cursor",
  "other",
] as const;
export type McpClient = (typeof MCP_CLIENTS)[number];
export type OpenCodeVersion = "1" | "2";

// These templates intentionally never accept a token. Copying instructions must
// not accidentally expose the one-time secret displayed elsewhere in the UI.
export function connectionSnippet(
  client: McpClient,
  endpoint: string,
  version: OpenCodeVersion = "1",
): string {
  const headers = { Authorization: "Bearer <TOKEN>" };
  switch (client) {
    case "claude":
      // The endpoint comes from the native loopback listener (not a user label).
      return `claude mcp add --transport http --scope user UniSSH "${endpoint}" --header "Authorization: Bearer <TOKEN>"`;
    case "codex":
      return `[mcp_servers.UniSSH]\nurl = ${JSON.stringify(endpoint)}\nhttp_headers = { Authorization = "Bearer <TOKEN>" }`;
    case "opencode": {
      const server = { type: "remote", url: endpoint, oauth: false, headers };
      return JSON.stringify(
        {
          $schema: "https://opencode.ai/config.json",
          mcp:
            version === "2"
              ? { servers: { UniSSH: server } }
              : { UniSSH: server },
        },
        null,
        2,
      );
    }
    case "cursor":
      return JSON.stringify(
        { mcpServers: { UniSSH: { url: endpoint, headers } } },
        null,
        2,
      );
    case "other":
      return mcpConfiguration(endpoint);
  }
}

export const CONNECTION_DOCS: Record<Exclude<McpClient, "other">, string> = {
  claude: "https://code.claude.com/docs/en/mcp",
  codex: "https://developers.openai.com/codex/mcp",
  opencode: "https://opencode.ai/docs/mcp-servers/",
  cursor: "https://cursor.com/docs/mcp",
};
