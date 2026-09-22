import { useId, useState } from "react";
import { Btn } from "@/components/primitives";
import { useTranslation } from "@/i18n";
import {
  CONNECTION_DOCS,
  MCP_CLIENTS,
  connectionSnippet,
  type McpClient,
  type OpenCodeVersion,
} from "./connections";

export function McpConnectionGuide({
  endpoint,
  enabled,
  busy,
  copied,
  onCopy,
  onOpenDocs,
}: {
  endpoint: string;
  enabled: boolean;
  busy: boolean;
  copied: string | null;
  onCopy: (kind: string, text: string) => void;
  onOpenDocs: (url: string) => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const [client, setClient] = useState<McpClient>("claude");
  const [version, setVersion] = useState<OpenCodeVersion>("1");
  const names = {
    claude: "Claude Code",
    codex: "Codex",
    opencode: "OpenCode",
    cursor: "Cursor",
    other: t("mcp.guide.other"),
  };
  const files = {
    claude: t("mcp.guide.terminal"),
    codex: "~/.codex/config.toml",
    opencode: "~/.config/opencode/opencode.json",
    cursor: "~/.cursor/mcp.json",
    other: "JSON",
  };
  const copyKey = `guide-${client}-${version}-${endpoint}`;
  const docs =
    client === "other"
      ? null
      : client === "opencode" && version === "2"
        ? "https://opencode.ai/v2/docs/mcp-servers"
        : CONNECTION_DOCS[client];
  return (
    <div className="mcp-connection-guide">
      <fieldset>
        <legend className="mcp-field-label">{t("mcp.guide.client")}</legend>
        <div className="mcp-choice-group">
          {MCP_CLIENTS.map((option) => (
            <label className="mcp-choice" key={option}>
              <input
                type="radio"
                name={id}
                checked={client === option}
                onChange={() => setClient(option)}
              />
              <span>{names[option]}</span>
            </label>
          ))}
        </div>
      </fieldset>
      {client === "opencode" && (
        <fieldset className="mcp-guide-version">
          <legend className="mcp-field-label">{t("mcp.guide.version")}</legend>
          <div className="mcp-choice-group">
            {(["1", "2"] as const).map((v) => (
              <label className="mcp-choice" key={v}>
                <input
                  type="radio"
                  name={`${id}-version`}
                  checked={version === v}
                  onChange={() => setVersion(v)}
                />
                <span>OpenCode {v}.x</span>
              </label>
            ))}
          </div>
        </fieldset>
      )}
      <p>{t(`mcp.guide.instructions.${client}`)}</p>
      {!enabled ? (
        <p className="mcp-guide-disabled" role="status">
          {t("mcp.guide.enableFirst")}
        </p>
      ) : (
        <>
          <div className="mcp-guide-code">
            <div className="mcp-guide-code-heading">
              <code>{files[client]}</code>
              <Btn
                type="button"
                variant="ghost"
                icon="copy"
                disabled={busy}
                onClick={() =>
                  onCopy(copyKey, connectionSnippet(client, endpoint, version))
                }
              >
                {t(copied === copyKey ? "mcp.copied" : "mcp.guide.copy")}
              </Btn>
            </div>
            <pre
              tabIndex={0}
              aria-label={t("mcp.guide.snippet", { client: names[client] })}
            >
              <code>{connectionSnippet(client, endpoint, version)}</code>
            </pre>
          </div>
          <p>{t("mcp.guide.replaceToken")}</p>
          <p>{t(`mcp.guide.verify.${client}`)}</p>
        </>
      )}
      <p>{t("mcp.guide.local")}</p>
      {docs && (
        <Btn type="button" variant="ghost" onClick={() => onOpenDocs(docs)}>
          {t("mcp.guide.docs", { client: names[client] })}
        </Btn>
      )}
    </div>
  );
}
