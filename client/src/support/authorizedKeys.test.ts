import { describe, expect, it } from "vitest";
import {
  authorizedKeysAppendCmd,
  authorizedKeysRemoveCmd,
  REMOVE_EXIT_STILL_PRESENT,
} from "./authorizedKeys";

// Node built-ins, typed locally: the client deliberately has no @types/node (see
// src/vite-env.d.ts — Node globals would typecheck in webview code). A non-literal
// specifier keeps these imports out of typechecking; vitest runs them under Node.
const nodeModule = (name: string): Promise<unknown> => import(/* @vite-ignore */ `node:${name}`);
const fs = (await nodeModule("fs")) as {
  chmodSync(p: string, mode: number): void;
  existsSync(p: string): boolean;
  lstatSync(p: string): { isSymbolicLink(): boolean };
  mkdirSync(p: string): void;
  mkdtempSync(prefix: string): string;
  readFileSync(p: string, enc: "utf8"): string;
  rmSync(p: string, o: { recursive: boolean; force: boolean }): void;
  statSync(p: string): { mode: number };
  symlinkSync(target: string, p: string): void;
  writeFileSync(p: string, data: string): void;
};
const { spawnSync } = (await nodeModule("child_process")) as {
  spawnSync(
    file: string,
    args: string[],
    o: { env: Record<string, string | undefined>; encoding: "utf8" },
  ): { status: number | null; stderr: string };
};
const { tmpdir } = (await nodeModule("os")) as { tmpdir(): string };
const { join } = (await nodeModule("path")) as { join(...parts: string[]): string };
const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env;

const SH = "/bin/sh";
const hasSh = fs.existsSync(SH);
if (!hasSh) console.warn(`authorizedKeys.test: ${SH} not found, skipping the shell run`);

const OLD = "ssh-ed25519 AAAAC3OLD";
const CAND = "ssh-ed25519 AAAAC3CAND rotation";
const OTHER = "ssh-rsa AAAAB3OTHER someone@else";

/** A throwaway HOME — with a space in its path, as a real one may have — holding
 *  `~/.ssh/authorized_keys` with `content` (none when null). */
function withHome(content: string | null, body: (home: string, file: string) => void) {
  const home = fs.mkdtempSync(join(tmpdir(), "unissh ak-"));
  try {
    fs.mkdirSync(join(home, ".ssh"));
    const file = join(home, ".ssh", "authorized_keys");
    if (content !== null) fs.writeFileSync(file, content);
    body(home, file);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
}

/** Run a built command the way the exec channel does, with HOME pointed at `home`. */
const run = (home: string, cmd: string) => spawnSync(SH, ["-c", cmd], { env: { ...env, HOME: home }, encoding: "utf8" });

const mode = (p: string) => fs.statSync(p).mode & 0o777;

describe.skipIf(!hasSh)("authorizedKeysAppendCmd under /bin/sh", () => {
  it("puts the key on its own line when the file has no trailing newline", () => {
    withHome("ssh-ed25519 AAAAOLD old", (home, file) => {
      expect(run(home, authorizedKeysAppendCmd("ssh-ed25519 AAAACAND cand")).status).toBe(0);
      expect(fs.readFileSync(file, "utf8")).toBe("ssh-ed25519 AAAAOLD old\nssh-ed25519 AAAACAND cand\n");
    });
  });

  it("leaves the modes of an existing ~/.ssh and authorized_keys alone", () => {
    withHome(`${OTHER}\n`, (home, file) => {
      fs.chmodSync(join(home, ".ssh"), 0o750);
      fs.chmodSync(file, 0o640);
      expect(run(home, authorizedKeysAppendCmd(CAND)).status).toBe(0);
      expect([mode(join(home, ".ssh")), mode(file), fs.readFileSync(file, "utf8")]).toEqual([
        0o750,
        0o640,
        `${OTHER}\n${CAND}\n`,
      ]);
    });
  });
});

describe.skipIf(!hasSh)("authorizedKeysRemoveCmd under /bin/sh", () => {
  it("removes the old key's plain lines whatever their comment and line ending, and nothing else", () => {
    withHome(`${OLD}\n${OTHER}\r\n${OLD} user@laptop\r\n\t${OLD} second copy\n${OLD}\r\n${CAND}\n`, (home, file) => {
      const r = run(home, authorizedKeysRemoveCmd(`${OLD} vault comment`, CAND));
      expect([r.status, fs.readFileSync(file, "utf8")]).toEqual([0, `${OTHER}\r\n${CAND}\n`]);
    });
  });

  it("leaves an old-key line with an options prefix in place and reports it", () => {
    const restricted = `from="10.0.0.0/8",command="/usr/bin/backup" ${OLD} backup`;
    withHome(`${OLD} user@laptop\n${restricted}\n${CAND}\n`, (home, file) => {
      const r = run(home, authorizedKeysRemoveCmd(OLD, CAND));
      expect([r.status, fs.readFileSync(file, "utf8")]).toEqual([
        REMOVE_EXIT_STILL_PRESENT,
        `${restricted}\n${CAND}\n`,
      ]);
    });
  });

  it("touches nothing unless the new key is there as a plain line", () => {
    // The candidate behind an options prefix is a restricted login, not a replacement.
    const before = `${OLD} user@laptop\ncommand="/bin/false" ${CAND}\n`;
    withHome(before, (home, file) => {
      const r = run(home, authorizedKeysRemoveCmd(OLD, CAND));
      expect([r.status, fs.readFileSync(file, "utf8")]).toEqual([1, before]);
    });
  });

  it("rewrites a symlinked authorized_keys through the link, keeping the link and the file's mode", () => {
    withHome(null, (home, file) => {
      const real = join(home, "keys of mine");
      fs.writeFileSync(real, `${OLD} user@laptop\n${CAND}\n`);
      fs.chmodSync(real, 0o640);
      // Relative, as a dotfiles manager links it: resolved against ~/.ssh.
      fs.symlinkSync("../keys of mine", file);
      const r = run(home, authorizedKeysRemoveCmd(OLD, CAND));
      expect([r.status, fs.lstatSync(file).isSymbolicLink(), mode(real), fs.readFileSync(real, "utf8")]).toEqual([
        0,
        true,
        0o640,
        `${CAND}\n`,
      ]);
    });
  });
});
