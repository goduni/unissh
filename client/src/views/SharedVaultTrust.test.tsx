import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import "@/i18n";
import type { PendingSharedVault } from "@/bridge/types";
import { ThemeProvider } from "@/theme/ThemeProvider";
import { SharedWithYou } from "./SharedVaultTrust";

const vault: PendingSharedVault = {
  vaultId: "ab".repeat(16),
  state: "ownerChanged",
  fingerprint: "0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567 89ab cdef",
  role: "editor",
  claimedHandle: "alice",
  claimedName: null,
  error: null,
};

describe("shared with you", () => {
  // The server now names a different owner than the one pinned here: the row is
  // a loud warning and offers no way to trust the new one.
  it("shows a vault whose owner changed as a warning with no verify action", () => {
    const markup = renderToStaticMarkup(
      <ThemeProvider>
        <SharedWithYou vaults={[vault]} serverId={null} onChanged={() => {}} />
      </ThemeProvider>,
    );
    expect(markup).toContain('role="alert"');
    expect(markup).toContain("Owner changed — do not trust this vault");
    expect(markup).not.toContain("Verify owner…");
  });
});
