import type { CSSProperties } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { contrastRatio } from "@/theme/tokens";
import { snippetTokens, type SnippetLanguage } from "./snippetTokens";

export function McpSnippet({
  source,
  language,
}: {
  source: string;
  language: SnippetLanguage;
}) {
  const p = usePalette();
  const textColor = (color: string) =>
    contrastRatio(color, p.bg1) >= 4.5 ? color : p.accentText;
  const style = {
    "--mcp-code-key": p.accentText,
    "--mcp-code-string": textColor(p.green),
    "--mcp-code-keyword": textColor(p.purple),
  } as CSSProperties;
  return (
    <code style={style}>
      {snippetTokens(source, language).map((token, index) => (
        <span
          key={index}
          className={token.kind === "plain" ? undefined : `mcp-code-${token.kind}`}
        >
          {token.text}
        </span>
      ))}
    </code>
  );
}
