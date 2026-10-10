import { describe, expect, it } from "vitest";
// `?raw` through Vite rather than node:fs: the client has no node types.
import source from "./App.tsx?raw";

// vitest runs in the node environment here (no jsdom), and App pulls in every
// view, so the shells are checked structurally: the phone shell is the block
// under `device === "mobile"`, the desktop shell is everything after it.
const fork = source.indexOf('if (device === "mobile") {');
const forkEnd = source.indexOf("\n  }\n", fork);
const shells = {
  phone: source.slice(fork, forkEnd),
  desktop: source.slice(forkEnd),
};

describe("app shells", () => {
  // The desktop shell once lost this host in a de-duplication: every agent
  // signature request then timed out with no prompt on screen.
  it.each(["phone", "desktop"] as const)(
    "the %s shell mounts the agent approval prompt whenever the vault is unlocked",
    (shell) => {
      expect(fork).toBeGreaterThan(0);
      expect(shells[shell]).toContain("{unlocked && <AgentApproval />}");
    },
  );
});
