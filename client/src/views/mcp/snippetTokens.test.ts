import { describe, expect, it } from "vitest";
import { connectionSnippet, MCP_CLIENTS } from "./connections";
import { snippetTokens } from "./snippetTokens";

describe("connection snippet highlighting", () => {
  it("preserves every byte of every client template, including both OpenCode versions", () => {
    for (const client of MCP_CLIENTS) {
      for (const version of ["1", "2"] as const) {
        const source = connectionSnippet(client, "http://127.0.0.1:12345/mcp", version);
        const language = client === "claude" ? "Shell" : client === "codex" ? "TOML" : "JSON";
        const tokens = snippetTokens(source, language);
        expect(tokens.map((token) => token.text).join("")).toBe(source);
        expect(tokens.filter((token) => token.kind === "placeholder")).toEqual([
          { text: "<TOKEN>", kind: "placeholder" },
        ]);
      }
    }
  });

  it("distinguishes JSON keys, escaped string values and booleans", () => {
    const source = '{"key": "say \\"hello\\" <script>", "enabled": false}';
    const tokens = snippetTokens(source, "JSON");
    expect(tokens.map((token) => token.text).join("")).toBe(source);
    expect(tokens).toContainEqual({ text: '"key"', kind: "key" });
    expect(tokens).toContainEqual({ text: '"say \\"hello\\" <script>"', kind: "string" });
    expect(tokens).toContainEqual({ text: "false", kind: "keyword" });
  });

  it("recognizes TOML sections and keys and shell flags without coloring quoted content as options", () => {
    expect(snippetTokens('[mcp_servers.UniSSH]\nurl = "http://localhost"', "TOML"))
      .toEqual(expect.arrayContaining([
        { text: "mcp_servers.UniSSH", kind: "key" },
        { text: "url", kind: "key" },
      ]));
    expect(snippetTokens('claude --header "--literal"', "Shell"))
      .toEqual(expect.arrayContaining([
        { text: "claude", kind: "keyword" },
        { text: "--header", kind: "keyword" },
        { text: '"--literal"', kind: "string" },
      ]));
  });
});
