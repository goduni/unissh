import type { CSSProperties } from "react";
import { Icon } from "@/components/primitives";
import type { McpClient } from "./connections";
import claude from "./logos/claude.svg";
import codex from "./logos/codex.svg";
import opencode from "./logos/opencode.svg";
import cursor from "./logos/cursor.svg";

const logos = { claude, codex, opencode, cursor };

export function McpAgentLogo({ client }: { client: McpClient }) {
  return client === "other" ? (
    <Icon name="link" size={18} />
  ) : (
    <span
      aria-hidden="true"
      className="mcp-agent-logo"
      style={{ "--mcp-agent-logo": `url("${logos[client]}")` } as CSSProperties}
    />
  );
}
