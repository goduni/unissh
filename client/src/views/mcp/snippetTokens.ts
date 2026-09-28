export type SnippetLanguage = "JSON" | "TOML" | "Shell";
type TokenKind = "plain" | "key" | "string" | "keyword" | "placeholder";

// A lossless highlighter for our generated connection examples, not a parser
// for arbitrary config files. Tokens remain React text nodes, never HTML.
export function snippetTokens(source: string, language: SnippetLanguage) {
  const pattern = /"(?:\\.|[^"\\])*"|--[\w-]+|\b[\w.-]+\b|\s+|./g;
  const tokens: { text: string; kind: TokenKind }[] = [];
  let offset = 0;
  for (const match of source.matchAll(pattern)) {
    if (match.index > offset) {
      tokens.push({ text: source.slice(offset, match.index), kind: "plain" });
    }
    const text = match[0];
    const next = source.slice(match.index + text.length);
    let kind: TokenKind = "plain";
    if (text.startsWith('"')) {
      kind = language === "JSON" && /^\s*:/.test(next) ? "key" : "string";
    } else if (language === "TOML" && /^[\w.-]+$/.test(text) &&
      (source[match.index - 1] === "[" || /^\s*=/.test(next))) {
      kind = "key";
    } else if (language === "Shell" && (text.startsWith("--") || match.index === 0)) {
      kind = "keyword";
    } else if (language !== "Shell" && /^(true|false|null|-?\d+(\.\d+)?)$/.test(text)) {
      kind = "keyword";
    }
    for (const part of text.split(/(<TOKEN>)/)) {
      if (part) tokens.push({ text: part, kind: part === "<TOKEN>" ? "placeholder" : kind });
    }
    offset = match.index + text.length;
  }
  if (offset < source.length) tokens.push({ text: source.slice(offset), kind: "plain" });
  return tokens;
}
