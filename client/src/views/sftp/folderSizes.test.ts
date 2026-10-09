import { describe, expect, it } from "vitest";
import { FolderSizeRegistry, NO_FOLDER_SIZES, type FolderSizeSnapshot } from "./folderSizes";

type Total = { bytes: number; partial: boolean };

function deferred() {
  let resolve!: (total: Total) => void;
  const promise = new Promise<Total>((r) => { resolve = r; });
  return { promise, resolve };
}

function registry() {
  const shown = { current: NO_FOLDER_SIZES as FolderSizeSnapshot };
  return { shown, reg: new FolderSizeRegistry((snapshot) => { shown.current = snapshot; }) };
}

const settled = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("folder size registry", () => {
  it("takes nothing from a walk that was stopped or started over", async () => {
    const { reg, shown } = registry();
    const stopped = deferred();
    const replaced = deferred();
    reg.start(["stopped", "again"], (name) => (name === "stopped" ? stopped : replaced).promise, 0);
    reg.cancel(["stopped"]);
    reg.start(["again"], () => new Promise<Total>(() => {}), 0);
    stopped.resolve({ bytes: 1, partial: false });
    replaced.resolve({ bytes: 2, partial: false });
    await settled();
    expect([...shown.current.sizes]).toEqual([["again", { state: "pending", bytes: 0 }]]);
  });

  it("takes nothing from a walk asked for on the rows of an earlier listing", async () => {
    const { reg, shown } = registry();
    reg.reset(); // a new listing was applied; the caller below still saw the old rows
    reg.start(["same-name"], async () => ({ bytes: 5, partial: false }), 0);
    await settled();
    expect(shown.current).toEqual({ generation: 1, sizes: new Map() });
  });
});
