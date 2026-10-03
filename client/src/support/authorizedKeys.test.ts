import { describe, expect, it } from "vitest";
import { authorizedKeysAppendCmd } from "./authorizedKeys";

// Node built-ins, typed locally: the client deliberately has no @types/node (see
// src/vite-env.d.ts — Node globals would typecheck in webview code). A non-literal
// specifier keeps these imports out of typechecking; vitest runs them under Node.
const nodeModule = (name: string): Promise<unknown> => import(/* @vite-ignore */ `node:${name}`);
const fs = (await nodeModule("fs")) as {
  existsSync(p: string): boolean;
  mkdirSync(p: string): void;
  mkdtempSync(prefix: string): string;
  readFileSync(p: string, enc: "utf8"): string;
  rmSync(p: string, o: { recursive: boolean; force: boolean }): void;
  writeFileSync(p: string, data: string): void;
};
const { execFileSync } = (await nodeModule("child_process")) as {
  execFileSync(file: string, args: string[], o: { env: Record<string, string | undefined> }): unknown;
};
const { tmpdir } = (await nodeModule("os")) as { tmpdir(): string };
const { join } = (await nodeModule("path")) as { join(...parts: string[]): string };
const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env;

const SH = "/bin/sh";
const hasSh = fs.existsSync(SH);
if (!hasSh) console.warn(`authorizedKeys.test: ${SH} not found, skipping the shell run`);

describe.skipIf(!hasSh)("authorizedKeysAppendCmd under /bin/sh", () => {
  it("puts the key on its own line when the file has no trailing newline", () => {
    const home = fs.mkdtempSync(join(tmpdir(), "unissh-ak-"));
    try {
      fs.mkdirSync(join(home, ".ssh"));
      const file = join(home, ".ssh", "authorized_keys");
      fs.writeFileSync(file, "ssh-ed25519 AAAAOLD old");

      execFileSync(SH, ["-c", authorizedKeysAppendCmd("ssh-ed25519 AAAACAND cand")], { env: { ...env, HOME: home } });

      expect(fs.readFileSync(file, "utf8")).toBe("ssh-ed25519 AAAAOLD old\nssh-ed25519 AAAACAND cand\n");
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
