// snippetParams — the one place that reads `{{name}}` / `{{name:default}}` in
// a snippet's command text. The palette, Fleet and the startup path all go
// through here, so they cannot disagree about the syntax.
//
// Syntax: a name is `[A-Za-z_][A-Za-z0-9_]*`; a default runs to the first
// closing `}}`. `\{{` is a literal `{{`. Anything else — `{{ spaced }}`, a
// stray brace, an unterminated placeholder — is literal text, so there is no
// error case: a shell command full of braces still goes through untouched.

/** A parameter in order of first appearance. `default` is null for `{{name}}`
 *  and a (possibly empty) string for `{{name:...}}`; a repeated name keeps the
 *  default and position of its first occurrence. */
export interface SnippetParam {
  name: string;
  default: string | null;
  /** Offset of the first occurrence in the command text. */
  position: number;
}

/** Names that come from the connect target rather than from the user. */
export const BUILTIN_PARAMS = ["host", "user", "port"] as const;
export type BuiltinParam = (typeof BUILTIN_PARAMS)[number];
export type BuiltinValues = Partial<Record<BuiltinParam, string>>;

type Token =
  | { kind: "text"; text: string }
  | { kind: "param"; raw: string; name: string; default: string | null; position: number };

const PLACEHOLDER = /\{\{([A-Za-z_][A-Za-z0-9_]*)(?::([\s\S]*?))?\}\}/y;

function tokenize(command: string): Token[] {
  const tokens: Token[] = [];
  let text = "";
  let i = 0;
  while (i < command.length) {
    if (command.startsWith("\\{{", i)) {
      text += "{{";
      i += 3;
      continue;
    }
    if (command.startsWith("{{", i)) {
      PLACEHOLDER.lastIndex = i;
      const m = PLACEHOLDER.exec(command);
      if (m) {
        if (text) tokens.push({ kind: "text", text });
        text = "";
        tokens.push({ kind: "param", raw: m[0], name: m[1], default: m[2] ?? null, position: i });
        i += m[0].length;
        continue;
      }
    }
    text += command[i];
    i += 1;
  }
  if (text) tokens.push({ kind: "text", text });
  return tokens;
}

/** The parameters a command takes, each name once, in order of first appearance. */
export function parseParams(command: string): SnippetParam[] {
  const seen = new Map<string, SnippetParam>();
  for (const tk of tokenize(command)) {
    if (tk.kind === "param" && !seen.has(tk.name)) {
      seen.set(tk.name, { name: tk.name, default: tk.default, position: tk.position });
    }
  }
  return [...seen.values()];
}

/** Split a parameter list into what the form asks and what the target already
 *  answers. A built-in with a value shadows a user parameter of the same name;
 *  one without a value (a local terminal) is asked like any other. */
export function splitBuiltins(
  params: SnippetParam[],
  builtins: BuiltinValues,
): { ask: SnippetParam[]; fromHost: { name: BuiltinParam; value: string }[] } {
  const ask: SnippetParam[] = [];
  const fromHost: { name: BuiltinParam; value: string }[] = [];
  for (const prm of params) {
    const value = (BUILTIN_PARAMS as readonly string[]).includes(prm.name)
      ? builtins[prm.name as BuiltinParam]
      : undefined;
    if (value !== undefined) fromHost.push({ name: prm.name as BuiltinParam, value });
    else ask.push(prm);
  }
  return { ask, fromHost };
}

/** The command with every placeholder replaced from `values`. A placeholder
 *  with no value is left as written, so a gap shows up in the pane instead of
 *  silently becoming an empty string. */
export function substituteParams(command: string, values: Record<string, string>): string {
  return tokenize(command)
    .map((tk) =>
      tk.kind === "text" ? tk.text : Object.prototype.hasOwnProperty.call(values, tk.name) ? values[tk.name] : tk.raw,
    )
    .join("");
}
