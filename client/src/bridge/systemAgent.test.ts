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

  it("gives Windows the pipe as is for SSH_AUTH_SOCK, with forward slashes for ssh_config, and the git override", () => {
    const pipe = "\\\\.\\pipe\\unissh-agent-S-1-5-21-1-2-3-1001";
    expect(systemAgentSetup(pipe, true)).toEqual({
      shell: "$env:SSH_AUTH_SOCK = '\\\\.\\pipe\\unissh-agent-S-1-5-21-1-2-3-1001'",
      persist: 'setx SSH_AUTH_SOCK "\\\\.\\pipe\\unissh-agent-S-1-5-21-1-2-3-1001"',
      sshConfig: 'IdentityAgent "//./pipe/unissh-agent-S-1-5-21-1-2-3-1001"',
      git: 'git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"',
    });
  });
});
