// The local-terminal settings layer. What is pinned here is the resolution
// rule — what a pane actually gets when a field is left on "auto" — because
// every downstream promise depends on it: a pane must never be born holding ""
// as its shell, and a custom shell must not silently inherit another shell's
// arguments (`-l` on a program that has no such flag would fail to start).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const localShellDefault = vi.fn();
const localShellSplitArgs = vi.fn();
const getPersonalVault = vi.fn();

vi.mock("@/bridge/api", () => ({
  localShellDefault: (...a: unknown[]) => localShellDefault(...a),
  localShellSplitArgs: (...a: unknown[]) => localShellSplitArgs(...a),
  getPersonalVault: (...a: unknown[]) => getPersonalVault(...a),
}));

// vitest runs in the node environment here (no jsdom), so localStorage has to be
// supplied. A Map-backed stub exercises the real code path rather than the
// catch-branch fallbacks.
function installStorage(): Map<string, string> {
  const map = new Map<string, string>();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => map.get(k) ?? null,
      setItem: (k: string, v: string) => void map.set(k, v),
      removeItem: (k: string) => void map.delete(k),
      clear: () => map.clear(),
    },
  });
  return map;
}

const MACHINE = {
  program: "/bin/zsh",
  args: ["-l"],
  user: "jane",
  hostname: "workbench",
};

let store: Map<string, string>;

beforeEach(async () => {
  store = installStorage();
  localShellDefault.mockReset().mockResolvedValue(MACHINE);
  localShellSplitArgs.mockReset();
  getPersonalVault.mockReset().mockResolvedValue(null);
  // The machine info is cached per module instance; a fresh registry per test
  // keeps one test's stub from being the next test's answer.
  vi.resetModules();
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function mod() {
  return await import("./localShell");
}

describe("programLabel", () => {
  it("reduces a path to the bare program name", async () => {
    const { programLabel } = await mod();
    expect(programLabel("/bin/zsh")).toBe("zsh");
    expect(programLabel("zsh")).toBe("zsh");
  });

  it("handles a Windows path and trims .exe, on any platform", async () => {
    // The string being labelled is a path the *user* typed, so a Windows path
    // pasted into the settings on any machine still labels as `pwsh`.
    const { programLabel } = await mod();
    expect(programLabel("C:\\Program Files\\PowerShell\\pwsh.exe")).toBe("pwsh");
    expect(programLabel("cmd.EXE")).toBe("cmd");
  });

  it("leaves a version suffix alone — that is the program's name", async () => {
    const { programLabel } = await mod();
    expect(programLabel("/usr/bin/python3.11")).toBe("python3.11");
  });
});

describe("resolveLocalPaneSpec", () => {
  it("falls back to the system shell and its platform arguments", async () => {
    const { resolveLocalPaneSpec } = await mod();
    const spec = await resolveLocalPaneSpec();
    expect(spec).toEqual({ shell: "/bin/zsh", args: ["-l"], cwd: undefined, label: "zsh" });
  });

  it("never yields an empty shell — the pane's title and restart depend on it", async () => {
    const { resolveLocalPaneSpec, setLocalShellSetting } = await mod();
    setLocalShellSetting("shell", "   ");
    const spec = await resolveLocalPaneSpec();
    expect(spec.shell).toBe("/bin/zsh");
    expect(spec.label).toBe("zsh");
  });

  it("does not give a custom shell the default's arguments", async () => {
    // `-l` belongs to the shell it was resolved for. Handing it to whatever the
    // user chose could stop that program from starting at all.
    const { resolveLocalPaneSpec, setLocalShellSetting } = await mod();
    setLocalShellSetting("shell", "/usr/bin/fish");
    const spec = await resolveLocalPaneSpec();
    expect(spec).toEqual({
      shell: "/usr/bin/fish",
      args: [],
      cwd: undefined,
      label: "fish",
    });
    expect(localShellSplitArgs).not.toHaveBeenCalled();
  });

  it("splits a non-empty argument string through the core, not by hand", async () => {
    const { resolveLocalPaneSpec, setLocalShellSetting } = await mod();
    localShellSplitArgs.mockResolvedValue(["-c", "echo hi"]);
    setLocalShellSetting("args", '-c "echo hi"');
    const spec = await resolveLocalPaneSpec();
    expect(localShellSplitArgs).toHaveBeenCalledWith('-c "echo hi"');
    expect(spec.args).toEqual(["-c", "echo hi"]);
  });

  it("passes no arguments at all when the string does not parse", async () => {
    // An unbalanced quote is reported as invalid in Settings; guessing at what
    // the user meant and running it would be worse than running the bare shell.
    const { resolveLocalPaneSpec, setLocalShellSetting } = await mod();
    localShellSplitArgs.mockResolvedValue(null);
    setLocalShellSetting("args", '"oops');
    const spec = await resolveLocalPaneSpec();
    expect(spec.args).toEqual([]);
  });

  it("carries a starting directory through, and treats empty as home", async () => {
    const { resolveLocalPaneSpec, setLocalShellSetting } = await mod();
    setLocalShellSetting("cwd", "/srv/app");
    expect((await resolveLocalPaneSpec()).cwd).toBe("/srv/app");
    setLocalShellSetting("cwd", "");
    expect((await resolveLocalPaneSpec()).cwd).toBeUndefined();
  });
});

describe("localShellSettings", () => {
  it("reads recording as an explicit opt-in", async () => {
    const { localShellSettings, setLocalShellSetting } = await mod();
    expect(localShellSettings().record).toBe(false);
    setLocalShellSetting("record", "1");
    expect(localShellSettings().record).toBe(true);
    setLocalShellSetting("record", "0");
    expect(localShellSettings().record).toBe(false);
  });

  it("keeps its keys under the unissh.local namespace", async () => {
    const { setLocalShellSetting } = await mod();
    setLocalShellSetting("shell", "/bin/dash");
    expect(store.get("unissh.local.shell")).toBe("/bin/dash");
  });
});

describe("localRecordingRequest", () => {
  const SPEC = { shell: "/bin/zsh", args: [], label: "zsh" };

  it("records nothing while the toggle is off", async () => {
    const { localRecordingRequest } = await mod();
    expect(await localRecordingRequest(SPEC, "team-vault")).toBeUndefined();
    // And does not even ask which vault it would have used.
    expect(getPersonalVault).not.toHaveBeenCalled();
  });

  it("prefers the personal vault — a recording of your machine is yours", async () => {
    // The whole point of the rule: a local session pushed into a shared team
    // vault would sync a recording of the user's own machine to colleagues.
    const { localRecordingRequest, setLocalShellSetting } = await mod();
    setLocalShellSetting("record", "1");
    getPersonalVault.mockResolvedValue("personal-vault");
    const req = await localRecordingRequest(SPEC, "team-vault", 1234);
    expect(req).toEqual({
      vaultId: "personal-vault",
      recordingId: "rec-local-1234",
      label: "zsh",
    });
  });

  it("falls back to the selected vault when there is no personal one", async () => {
    const { localRecordingRequest, setLocalShellSetting } = await mod();
    setLocalShellSetting("record", "1");
    getPersonalVault.mockResolvedValue(null);
    expect((await localRecordingRequest(SPEC, "team-vault"))?.vaultId).toBe("team-vault");
  });

  it("treats an unreadable personal vault as none, not as an error", async () => {
    const { localRecordingRequest, setLocalShellSetting } = await mod();
    setLocalShellSetting("record", "1");
    getPersonalVault.mockRejectedValue(new Error("locked"));
    expect((await localRecordingRequest(SPEC, "team-vault"))?.vaultId).toBe("team-vault");
  });

  it("records nothing when there is no vault at all", async () => {
    // Rather than inventing a destination just to have one.
    const { localRecordingRequest, setLocalShellSetting } = await mod();
    setLocalShellSetting("record", "1");
    getPersonalVault.mockResolvedValue(null);
    expect(await localRecordingRequest(SPEC, "")).toBeUndefined();
  });

  it("mints a fresh recording id per session, so a restart is its own document", async () => {
    const { localRecordingRequest, setLocalShellSetting } = await mod();
    setLocalShellSetting("record", "1");
    getPersonalVault.mockResolvedValue("v");
    const a = await localRecordingRequest(SPEC, "v", 1);
    const b = await localRecordingRequest(SPEC, "v", 2);
    expect(a?.recordingId).not.toBe(b?.recordingId);
  });
});

describe("localMachine", () => {
  it("asks the core once and reuses the answer", async () => {
    const { localMachine } = await mod();
    await localMachine();
    await localMachine();
    expect(localShellDefault).toHaveBeenCalledTimes(1);
  });

  it("does not cache a failure", async () => {
    // A transient error must not leave the status line and the Settings
    // placeholder permanently blank for the rest of the session.
    const { localMachine } = await mod();
    localShellDefault.mockRejectedValueOnce(new Error("core is busy"));
    await expect(localMachine()).rejects.toThrow();
    await expect(localMachine()).resolves.toEqual(MACHINE);
    expect(localShellDefault).toHaveBeenCalledTimes(2);
  });
});
