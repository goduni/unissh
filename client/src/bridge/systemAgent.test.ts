import { describe, expect, it } from "vitest";
import { systemAgentSetup } from "./systemAgent";

describe("system agent setup lines", () => {
  it("quotes a socket path with a space and a quote so the shell reads it whole", () => {
    const socket = "/Users/o'neil/Library/Application Support/me.goduni.unissh/agent/agent.sock";
    const { shell, sshConfig } = systemAgentSetup(socket);
    expect(shell).toBe(
      "export SSH_AUTH_SOCK='/Users/o'\\''neil/Library/Application Support/me.goduni.unissh/agent/agent.sock'",
    );
    expect(sshConfig).toBe(`IdentityAgent "${socket}"`);
  });

  it("gives Windows a PowerShell line and a forward-slash pipe path for ssh_config", () => {
    const { shell, sshConfig } = systemAgentSetup("\\\\.\\pipe\\unissh-agent", true);
    expect(shell).toBe("$env:SSH_AUTH_SOCK = '\\\\.\\pipe\\unissh-agent'");
    expect(sshConfig).toBe("IdentityAgent //./pipe/unissh-agent");
  });
});
