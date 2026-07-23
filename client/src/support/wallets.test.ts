// The addresses are published on three independent surfaces — this app, the README and
// unissh.dev/support — for one reason: so a reader can compare two before sending. That
// defence only works if the three actually agree, and nothing but this test makes them.
// A copy-paste slip in a Markdown table is invisible in review and unrecoverable for
// whoever sends to it.

import { describe, expect, it } from "vitest";
import readme from "../../../README.md?raw";
import page from "../../../website/src/pages/support.astro?raw";
import { CONTACT_EMAIL, WALLETS } from "./wallets";

describe("wallets", () => {
  it("publishes exactly the six authored networks, in order", () => {
    expect(WALLETS.map((w) => w.label)).toEqual(["BTC", "BEP20", "ERC20", "TRC20", "TON", "SOL"]);
  });

  it("has no address with stray whitespace", () => {
    for (const w of WALLETS) {
      expect(w.address, w.label).toBe(w.address.trim());
      expect(w.address, w.label).not.toMatch(/\s/);
    }
  });

  // ERC20 and BEP20 intentionally share one EVM address; every OTHER pair must differ,
  // which catches a row duplicated by accident during an edit.
  it("only ERC20 and BEP20 share an address", () => {
    const shared = new Map<string, string[]>();
    for (const w of WALLETS) shared.set(w.address, [...(shared.get(w.address) ?? []), w.label]);
    const dupes = [...shared.values()].filter((labels) => labels.length > 1);
    expect(dupes).toEqual([["BEP20", "ERC20"]]);
  });

  describe("README.md", () => {
    it.each(WALLETS.map((w) => [w.label, w.address] as const))(
      "pairs %s with its address on one row",
      (label, address) => {
        const paired = readme
          .split("\n")
          .some((line) => line.includes(`**${label}**`) && line.includes(address));
        expect(paired, `README.md has no row pairing ${label} with ${address}`).toBe(true);
      },
    );

    it("names the contact address", () => {
      expect(readme).toContain(CONTACT_EMAIL);
    });

    it("links the Telegram community", () => {
      expect(readme).toContain("https://t.me/unissh");
    });
  });

  describe("website /support", () => {
    it.each(WALLETS.map((w) => [w.label, w.address] as const))(
      "pairs %s with its address",
      (label, address) => {
        const paired = page
          .split("\n")
          .some((line) => line.includes(`'${label}'`) && line.includes(address));
        expect(paired, `support.astro has no entry pairing ${label} with ${address}`).toBe(true);
      },
    );

    it("names the contact address", () => {
      expect(page).toContain(CONTACT_EMAIL);
    });
  });
});
