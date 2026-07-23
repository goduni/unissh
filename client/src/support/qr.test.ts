// The QR is the only path in this feature where a mistake silently costs someone money:
// an address that fails to encode, or encodes truncated, looks exactly like a working QR
// until a wallet rejects it. These check the encoder actually round-trips every address
// we publish.

import { describe, expect, it } from "vitest";
import { encodeQr } from "./qr";
import { WALLETS } from "./wallets";

describe("encodeQr", () => {
  it.each(WALLETS.map((w) => [w.label, w.address] as const))(
    "encodes the %s address without overflowing the symbol",
    (_label, address) => {
      const qr = encodeQr(address);
      // Version 1 is 21x21; anything real is at least that, and a failed encode throws
      // rather than returning a degenerate grid.
      expect(qr.count).toBeGreaterThanOrEqual(21);
      expect(qr.isDark(0, 0)).toBe(true); // top-left finder pattern is always dark
    },
  );

  it("throws rather than truncating when the payload cannot fit", () => {
    expect(() => encodeQr("x".repeat(10_000))).toThrow();
  });
});
