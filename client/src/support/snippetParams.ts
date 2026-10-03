// snippetParams — the one place that reads `{{name}}` / `{{name:default}}` in
// a snippet's command text. The palette, Fleet and the startup path all go
// through here, so they cannot disagree about the syntax.
//
// Syntax: a name is `[A-Za-z_][A-Za-z0-9_]*`; a default runs to the first
// closing `}}`. `\{{` is a literal `{{`. Anything else — `{{ spaced }}`, a
// stray brace, an unterminated placeholder — is literal text, so there is no
// error case: a shell command full of braces still goes through untouched.

import type { ConnectionProfile } from "@/bridge/types";

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

export function isBuiltinParam(name: string): name is BuiltinParam {
  return (BUILTIN_PARAMS as readonly string[]).includes(name);
}

/** The built-ins a host answers. None for a local shell (null), and no `user`
 *  when the profile leaves it empty (an identity-bound login) — those are
 *  then asked like any other parameter. */
export function builtinsFromProfile(profile: ConnectionProfile | null): BuiltinValues {
  if (!profile) return {};
  return { host: profile.host, port: String(profile.port), ...(profile.user ? { user: profile.user } : null) };
}

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
function splitBuiltins(
  params: SnippetParam[],
  builtins: BuiltinValues,
): { ask: SnippetParam[]; fromHost: { name: BuiltinParam; value: string }[] } {
  const ask: SnippetParam[] = [];
  const fromHost: { name: BuiltinParam; value: string }[] = [];
  for (const prm of params) {
    const name = prm.name;
    const value = isBuiltinParam(name) ? builtins[name] : undefined;
    if (isBuiltinParam(name) && value !== undefined) fromHost.push({ name, value });
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

/** The command as it should run: the user's answers, with built-ins winning
 *  over a user parameter of the same name. */
export function resolveCommand(
  command: string,
  userValues: Record<string, string>,
  builtins: BuiltinValues,
): string {
  return substituteParams(command, { ...userValues, ...builtins });
}

/** What running a snippet on one target needs: the form's fields, the
 *  built-ins shown as answered, and — when nothing is left to ask — the command
 *  ready to type, so the caller skips the form. */
export function planSnippet(
  command: string,
  builtins: BuiltinValues,
): { ask: SnippetParam[]; fromHost: { name: BuiltinParam; value: string }[]; ready: string | null } {
  const { ask, fromHost } = splitBuiltins(parseParams(command), builtins);
  return { ask, fromHost, ready: ask.length === 0 ? resolveCommand(command, {}, builtins) : null };
}

/** A Fleet target as the resolver sees it: the key its result is filed under
 *  and the built-ins its profile answers (`builtinsFromProfile`). */
export interface FleetTarget {
  id: string;
  builtins: BuiltinValues;
}

/** What a Fleet run asks once, for every target. A built-in that every target
 *  answers shadows a user parameter of the same name and comes from each host;
 *  one that some target lacks (a profile with no user) is asked, and the answer
 *  fills only the targets that lack it — built-ins still win where present. */
export function splitFleetParams(
  command: string,
  targets: FleetTarget[],
): { ask: SnippetParam[]; fromHost: { name: BuiltinParam }[] } {
  const everyHost: string[] = BUILTIN_PARAMS.filter(
    (b) => targets.length > 0 && targets.every((tg) => tg.builtins[b] !== undefined),
  );
  const params = parseParams(command);
  return {
    ask: params.filter((prm) => !everyHost.includes(prm.name)),
    fromHost: params.filter((prm) => everyHost.includes(prm.name)).map((prm) => ({ name: prm.name as BuiltinParam })),
  };
}

/** The command each target runs, keyed by target id: the user's answers once,
 *  the built-ins from that target. */
export function fleetCommands(
  command: string,
  userValues: Record<string, string>,
  targets: FleetTarget[],
): Record<string, string> {
  return Object.fromEntries(targets.map((tg) => [tg.id, resolveCommand(command, userValues, tg.builtins)]));
}
