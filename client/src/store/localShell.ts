// Local-terminal settings, and turning them into something concrete enough to
// start a shell with.
//
// These live in localStorage rather than the vault: a shell path is a fact about
// one machine, and syncing "/opt/homebrew/bin/fish" to a Windows laptop would be
// worse than useless. They are read once per pane (not per session), so a
// Restart brings up the same shell and editing the settings never rewrites a
// pane that is already running.

import { useEffect, useState } from "react";
import * as api from "@/bridge/api";
import type { RecordingRequest } from "@/bridge/api";
import type { LocalPaneSpec, LocalShellInfo } from "@/bridge/types";

export const LOCAL_KEYS = {
  shell: "unissh.local.shell",
  args: "unissh.local.args",
  cwd: "unissh.local.cwd",
  record: "unissh.local.record",
} as const;

/** What the user typed in Settings. Empty strings mean "auto". */
export interface LocalShellSettings {
  shell: string;
  args: string;
  cwd: string;
  /** Record local sessions into the vault. Off by default — a local pane has no
   *  profile to carry `recordSessions`, so this is one global choice. */
  record: boolean;
}

function read(key: string): string {
  try {
    return localStorage.getItem(key) ?? "";
  } catch {
    return ""; // private mode / disabled storage — behave as "auto"
  }
}

export function localShellSettings(): LocalShellSettings {
  return {
    shell: read(LOCAL_KEYS.shell).trim(),
    args: read(LOCAL_KEYS.args),
    cwd: read(LOCAL_KEYS.cwd).trim(),
    record: read(LOCAL_KEYS.record) === "1",
  };
}

export function setLocalShellSetting(key: keyof typeof LOCAL_KEYS, value: string): void {
  try {
    localStorage.setItem(LOCAL_KEYS[key], value);
  } catch {
    /* ignore (private mode / quota) */
  }
}

/** The bare program name a tab shows: "zsh", "pwsh". Mirrors the core's
 *  `program_label` — both separators, `.exe` trimmed, nothing else. */
export function programLabel(program: string): string {
  const tail = program.replace(/[/\\]+$/, "").split(/[/\\]/).pop() ?? program;
  const stem = /\.exe$/i.test(tail) ? tail.slice(0, -4) : tail;
  return stem || program;
}

let machinePromise: Promise<LocalShellInfo> | null = null;

/** Who and where this machine is, plus its default shell.
 *
 *  Cached for the life of the process: neither the hostname nor the OS account
 *  changes while the app runs, and the local pane's status line asks for this on
 *  every render. A failed call is not cached, so a transient error doesn't
 *  poison the rest of the session. */
export function localMachine(): Promise<LocalShellInfo> {
  machinePromise ??= api.localShellDefault().catch((e) => {
    machinePromise = null;
    throw e;
  });
  return machinePromise;
}

/** `null` until the first answer arrives — callers render nothing until then
 *  rather than a placeholder identity, which is the one thing a status line
 *  that exists to say "this is your machine" must not show. */
export function useLocalMachine(): LocalShellInfo | null {
  const [info, setInfo] = useState<LocalShellInfo | null>(null);
  useEffect(() => {
    let alive = true;
    localMachine()
      .then((i) => {
        if (alive) setInfo(i);
      })
      .catch(() => {
        /* the status line simply stays quiet */
      });
    return () => {
      alive = false;
    };
  }, []);
  return info;
}

/** Resolve the settings into a spec with a concrete program and a real label.
 *
 *  Done here, before the pane exists, and that ordering is the point: a pane
 *  holding "" as its shell would have nothing to put in the tab, nothing to
 *  restart, and nothing to name in an error — the title, the Restart button and
 *  the failure message all read from this spec.
 *
 *  Throws whatever the bridge throws (e.g. the core is unreachable); the caller
 *  surfaces that instead of opening a pane that cannot work. */
export async function resolveLocalPaneSpec(): Promise<LocalPaneSpec> {
  const s = localShellSettings();
  const fallback = await localMachine();
  const shell = s.shell || fallback.program;
  // An empty argument field means the platform default (`-l` on macOS); a
  // non-empty one is the user's, split the way a shell would. An unparsable
  // string (unbalanced quote) falls back to no arguments rather than guessing —
  // Settings shows the same string as invalid.
  const args = s.args.trim()
    ? ((await api.localShellSplitArgs(s.args)) ?? [])
    : s.shell
      ? [] // a custom shell with no arguments given: don't inherit the default's
      : fallback.args;
  return {
    shell,
    args,
    cwd: s.cwd || undefined,
    label: programLabel(shell),
  };
}

/** Where a local session's recording goes, if the user asked for one at all.
 *
 *  The **personal** vault when there is one, and the selected vault otherwise. A
 *  recording of your own machine is yours; putting it in a shared team vault
 *  would sync it to your colleagues, which is not what "record my local
 *  sessions" asks for. Settings names the recipient vault so this is never a
 *  surprise — and it lives here, tested, rather than inline in a React effect,
 *  because "which vault does this land in" is not a rule to verify by reading.
 *
 *  `undefined` means "do not record": the toggle is off, or there is no vault to
 *  write to at all. Never falls back to *some* vault just to have one.
 *
 *  `now` is injected so the caller — and the test — decides the clock. */
export async function localRecordingRequest(
  spec: LocalPaneSpec,
  selectedVaultId: string,
  now: number = Date.now(),
): Promise<RecordingRequest | undefined> {
  if (!localShellSettings().record) return undefined;
  // A personal vault that cannot be read is not a reason to quietly record into
  // the shared one instead — treat it as "none configured" and fall through to
  // the vault Settings already named.
  const personal = await api.getPersonalVault().catch(() => null);
  const vaultId = personal || selectedVaultId;
  if (!vaultId) return undefined;
  // One recording per session, not per pane: a restart is a new session with its
  // own start time, and appending to the previous document would produce one
  // recording whose timeline lies.
  return { vaultId, recordingId: `rec-local-${now}`, label: spec.label };
}
