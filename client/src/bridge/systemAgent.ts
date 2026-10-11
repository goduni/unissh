import { invoke } from "@tauri-apps/api/core";

export type SystemAgentError =
  | "in_use"
  | "bind_failed"
  | "path_too_long"
  | "save_failed"
  | "listener_failed";

/**
 * Desktop-only. `supported` is false when the endpoint could not be worked
 * out (no app data directory; on Windows, no user SID for the pipe name):
 * nothing can listen then, and `error` is `bind_failed` from the start.
 */
export interface SystemAgentStatus {
  supported: boolean;
  enabled: boolean;
  running: boolean;
  endpoint: string | null;
  error: SystemAgentError | null;
}

export interface SharedAgentKey {
  vaultId: string;
  itemId: string;
}

export const systemAgentStatus = () => invoke<SystemAgentStatus>("system_agent_status");
export const systemAgentSetEnabled = (enabled: boolean) =>
  invoke<void>("system_agent_set_enabled", { enabled });
export const systemAgentSharedKeys = () => invoke<SharedAgentKey[]>("system_agent_shared_keys");
export const systemAgentSetShared = (vaultId: string, itemId: string, shared: boolean) =>
  invoke<void>("system_agent_set_shared", { vaultId, itemId, shared });

/** Single-quoted for a POSIX shell: the macOS path contains a space. */
function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * What Git for Windows must run instead of its bundled ssh; see below. The
 * usual place, not a certain one: Windows may live on another drive, and an
 * OpenSSH installed with winget or the MSI is under Program Files. The
 * webview cannot ask, so the UI says to adjust it (`setupDescWindows`).
 */
const WINDOWS_OPENSSH = "C:/Windows/System32/OpenSSH/ssh.exe";

export interface SystemAgentSetup {
  /** Sets SSH_AUTH_SOCK for the current shell session. */
  shell: string;
  /** The `IdentityAgent` line for a Host block. */
  sshConfig: string;
  /** Windows: saves SSH_AUTH_SOCK for the user account (cmd or PowerShell). */
  persist?: string;
  /** Windows: points Git for Windows at Windows OpenSSH. */
  git?: string;
}

/**
 * The copy-ready setup lines for the agent's endpoint: a Unix socket path, or
 * on Windows (`windows`) the named pipe.
 *
 * Windows, for Win32-OpenSSH (the ssh in C:\Windows\System32\OpenSSH):
 * - SSH_AUTH_SOCK takes the pipe path as is (`\\.\pipe\…`): an environment
 *   value is not parsed, only handed to CreateFile.
 * - ssh_config spells it with forward slashes, in quotes. Since 8.9
 *   Win32-OpenSSH reads `\\` in ssh_config as an escaped backslash, so
 *   `\\.\pipe\…` there names `\.\pipe\…`, which is not a pipe; the doubled
 *   form that fixes it breaks the older ssh still shipped with Windows 10.
 *   `//./pipe/…` is read the same by both and Windows resolves it to the same
 *   pipe. (JGit's ssh-agent notes recommend forward slashes in ~/.ssh/config
 *   for the same reason. None of this was run against a Windows ssh here.)
 * - Git for Windows bundles an MSYS2 ssh, which speaks Unix sockets only and
 *   cannot open a named pipe at all; `core.sshCommand` hands git the Windows
 *   one.
 */
export function systemAgentSetup(endpoint: string, windows = false): SystemAgentSetup {
  if (windows) {
    return {
      shell: `$env:SSH_AUTH_SOCK = '${endpoint.replace(/'/g, "''")}'`,
      persist: `setx SSH_AUTH_SOCK "${endpoint}"`,
      sshConfig: `IdentityAgent "${endpoint.replace(/\\/g, "/")}"`,
      git: `git config --global core.sshCommand "${WINDOWS_OPENSSH}"`,
    };
  }
  return {
    shell: `export SSH_AUTH_SOCK=${shellQuote(endpoint)}`,
    // ssh_config takes a double-quoted argument; a path with a quote in it
    // cannot be expressed there, and an app data directory never has one.
    sshConfig: `IdentityAgent "${endpoint}"`,
  };
}
