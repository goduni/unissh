import { invoke } from "@tauri-apps/api/core";

export type SystemAgentError =
  | "unsupported"
  | "in_use"
  | "bind_failed"
  | "path_too_long"
  | "save_failed"
  | "listener_failed";

/** Desktop-only. `supported` is false where the platform has no listener yet. */
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

/** The copy-ready setup lines for a socket path. */
export function systemAgentSetup(socket: string): { shell: string; sshConfig: string } {
  return {
    shell: `export SSH_AUTH_SOCK=${shellQuote(socket)}`,
    // ssh_config takes a double-quoted argument; a path with a quote in it
    // cannot be expressed there, and an app data directory never has one.
    sshConfig: `IdentityAgent "${socket}"`,
  };
}
