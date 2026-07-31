// The pane target model. `PaneTarget` is a tagged union rather than an optional
// field precisely so that split, duplicate and every reader take an explicit
// branch — these tests pin the behaviour that shape was chosen to guarantee.

import { beforeEach, describe, expect, it, vi } from "vitest";

// The store closes backend sessions on its own as panes come and go; none of
// that is what is under test here, and a real invoke has nothing to talk to.
vi.mock("@/bridge/api", () => ({
  sessionClose: () => Promise.resolve(),
  sftpClose: () => Promise.resolve(),
}));

import {
  makeLocalPane,
  makePane,
  makeTargetPane,
  paneProfile,
  useApp,
  type TerminalTab,
} from "./app";
import type { ConnectionProfile, LocalPaneSpec } from "@/bridge/types";

const HOST = {
  profileId: "p1",
  label: "web-prod-01",
  host: "10.0.0.9",
  port: 22,
  user: "deploy",
  tags: [],
  jumps: [],
  auth: { type: "agent", vaultId: "v", keyItemId: "k" },
  startupSnippetIds: [],
} as unknown as ConnectionProfile;

const SHELL: LocalPaneSpec = { shell: "/bin/zsh", args: ["-l"], label: "zsh" };

function tabWith(paneTarget: "ssh" | "local"): TerminalTab {
  const pane = paneTarget === "ssh" ? makePane(HOST) : makeLocalPane(SHELL);
  return {
    id: `tab-${paneTarget}`,
    title: pane.title,
    panes: [pane],
    layout: { kind: "pane", paneId: pane.id },
    activePaneId: pane.id,
  };
}

beforeEach(() => {
  useApp.setState({ terminals: [], activeTermId: null });
});

describe("pane targets", () => {
  it("names an SSH pane after its host and a local pane after its program", () => {
    expect(makePane(HOST).title).toBe("web-prod-01");
    expect(makeLocalPane(SHELL).title).toBe("zsh");
  });

  it("gives every pane a target, so no reader can forget to branch", () => {
    expect(makePane(HOST).target).toEqual({ kind: "ssh", profile: HOST });
    expect(makeLocalPane(SHELL).target).toEqual({ kind: "local", spec: SHELL });
  });

  it("resolves a profile only for SSH panes", () => {
    expect(paneProfile(makePane(HOST))).toBe(HOST);
    expect(paneProfile(makeLocalPane(SHELL))).toBeNull();
  });

  it("snapshots the spec, so editing the settings cannot rewrite a live pane", () => {
    const pane = makeLocalPane(SHELL);
    const target = pane.target;
    expect(target.kind).toBe("local");
    if (target.kind !== "local") return;
    expect(target.spec.shell).toBe("/bin/zsh");
    expect(target.spec.args).toEqual(["-l"]);
  });
});

describe("splitPane", () => {
  it("splits a host pane into another connection to the same host", () => {
    const tab = tabWith("ssh");
    useApp.setState({ terminals: [tab], activeTermId: tab.id });
    useApp.getState().splitPane(tab.id, tab.panes[0].id, "row");

    const panes = useApp.getState().terminals[0].panes;
    expect(panes).toHaveLength(2);
    expect(paneProfile(panes[1])).toBe(HOST);
  });

  it("splits a local pane into another local shell", () => {
    // Before the tagged union this was the silent failure: the split guard
    // tested for a profile, found none, and returned the tab untouched.
    const tab = tabWith("local");
    useApp.setState({ terminals: [tab], activeTermId: tab.id });
    useApp.getState().splitPane(tab.id, tab.panes[0].id, "col");

    const panes = useApp.getState().terminals[0].panes;
    expect(panes).toHaveLength(2);
    expect(panes[1].target).toEqual({ kind: "local", spec: SHELL });
  });

  it("puts a local shell beside a host pane when given that target", () => {
    const tab = tabWith("ssh");
    useApp.setState({ terminals: [tab], activeTermId: tab.id });
    useApp
      .getState()
      .splitPane(tab.id, tab.panes[0].id, "row", { kind: "local", spec: SHELL });

    const panes = useApp.getState().terminals[0].panes;
    expect(panes).toHaveLength(2);
    expect(paneProfile(panes[0])).toBe(HOST);
    expect(panes[1].target.kind).toBe("local");
    // The new pane takes focus, and the layout grew a split around the old one.
    expect(useApp.getState().terminals[0].activePaneId).toBe(panes[1].id);
    expect(useApp.getState().terminals[0].layout.kind).toBe("split");
  });
});

describe("duplicateTerminal", () => {
  it("duplicates a local tab as another local shell", () => {
    const tab = tabWith("local");
    useApp.setState({ terminals: [tab], activeTermId: tab.id });
    useApp.getState().duplicateTerminal(tab.id);

    const tabs = useApp.getState().terminals;
    expect(tabs).toHaveLength(2);
    expect(tabs[1].panes[0].target).toEqual({ kind: "local", spec: SHELL });
    expect(tabs[1].title).toBe("zsh");
  });

  it("duplicates a host tab as another connection to that host", () => {
    const tab = tabWith("ssh");
    useApp.setState({ terminals: [tab], activeTermId: tab.id });
    useApp.getState().duplicateTerminal(tab.id);

    const tabs = useApp.getState().terminals;
    expect(tabs).toHaveLength(2);
    expect(paneProfile(tabs[1].panes[0])).toBe(HOST);
  });
});

describe("setPaneTitle", () => {
  it("renames the pane and, with it, the tab", () => {
    const tab = tabWith("local");
    useApp.setState({ terminals: [tab], activeTermId: tab.id });
    useApp.getState().setPaneTitle(tab.panes[0].id, "~/src/unissh");

    expect(useApp.getState().terminals[0].panes[0].title).toBe("~/src/unissh");
    expect(useApp.getState().terminals[0].title).toBe("~/src/unissh");
  });

  it("never overrides a name the user chose", () => {
    const tab = { ...tabWith("local"), title: "build box", customTitle: true };
    useApp.setState({ terminals: [tab], activeTermId: tab.id });
    useApp.getState().setPaneTitle(tab.panes[0].id, "~/src/unissh");

    expect(useApp.getState().terminals[0].title).toBe("build box");
    // The pane still knows what the shell called itself; only the tab is pinned.
    expect(useApp.getState().terminals[0].panes[0].title).toBe("~/src/unissh");
  });

  it("leaves the tab alone when the renamed pane is not the focused one", () => {
    const tab = tabWith("local");
    useApp.setState({ terminals: [tab], activeTermId: tab.id });
    useApp.getState().splitPane(tab.id, tab.panes[0].id, "row");
    const [first, second] = useApp.getState().terminals[0].panes;
    // The split focused the second pane; a title from the first must not win.
    useApp.getState().setPaneTitle(first.id, "background job");

    expect(useApp.getState().terminals[0].title).toBe(tab.title);
    expect(useApp.getState().terminals[0].panes[1].id).toBe(second.id);
  });
});

describe("makeTargetPane", () => {
  it("starts every pane connecting, with a fresh reconnect budget", () => {
    const pane = makeTargetPane({ kind: "local", spec: SHELL });
    expect(pane.status).toBe("connecting");
    expect(pane.sessionId).toBeNull();
    expect(pane.gen).toBe(0);
    expect(pane.reconnects).toBe(0);
    expect(pane.lastOnlineAt).toBe(0);
  });

  it("gives panes distinct ids", () => {
    const a = makeLocalPane(SHELL);
    const b = makeLocalPane(SHELL);
    expect(a.id).not.toBe(b.id);
  });
});
