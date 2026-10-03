// The inline-images setting: on by default on desktop, off on phones, and the
// user's choice survives a restart. The store reads it once at module load, so
// each case loads a fresh store under a mocked platform.

import { beforeEach, describe, expect, it, vi } from "vitest";

let phone = false;
vi.mock("@/bridge/platform", async (orig) => ({
  ...(await orig<typeof import("@/bridge/platform")>()),
  isPhoneOs: () => phone,
}));

function installStorage() {
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
}

const freshStore = async () => {
  vi.resetModules();
  return (await import("./app")).useApp;
};

describe("terminalImages setting", () => {
  beforeEach(installStorage);

  it("defaults on for desktop and off for phones", async () => {
    phone = false;
    expect((await freshStore()).getState().terminalImages).toBe(true);
    phone = true;
    expect((await freshStore()).getState().terminalImages).toBe(false);
  });

  it("persists the user's choice across a restart", async () => {
    phone = false;
    (await freshStore()).getState().setTerminalImages(false);
    expect((await freshStore()).getState().terminalImages).toBe(false);
  });
});
