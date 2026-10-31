import { invoke } from "@tauri-apps/api/core";

export interface CliToolsStatus {
  available: boolean;
  installed: boolean;
  updateAvailable: boolean;
  pathConfigured: boolean;
  installPath: string;
}

export const cliToolsStatus = () => invoke<CliToolsStatus>("cli_tools_status");
export const cliToolsInstall = () => invoke<CliToolsStatus>("cli_tools_install");
export const cliToolsRemove = () => invoke<CliToolsStatus>("cli_tools_remove");
