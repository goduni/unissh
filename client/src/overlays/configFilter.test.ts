import { describe, it, expect } from "vitest";
import { filterConfigToSelected } from "./configFilter";

const sel = (...a: string[]) => new Set(a);

describe("filterConfigToSelected", () => {
  it("keeps a selected host and drops an unselected one", () => {
    const text = "Host web\n  HostName w\n\nHost db\n  HostName d\n";
    expect(filterConfigToSelected(text, sel("web"))).toContain("Host web");
    expect(filterConfigToSelected(text, sel("web"))).not.toContain("Host db");
  });

  it("keeps wildcard blocks so inherited settings still resolve", () => {
    // Dropping `Host *` would change the user/port/key the kept host resolves to.
    const text = "Host *\n  User fallback\n\nHost web\n  HostName w\n";
    const got = filterConfigToSelected(text, sel("web"));
    expect(got).toContain("Host *");
    expect(got).toContain("User fallback");
  });

  it("keeps the preamble before the first Host block", () => {
    const text = "# comment\nCompression yes\n\nHost web\n";
    expect(filterConfigToSelected(text, sel("web"))).toContain("Compression yes");
  });

  it("rewrites a multi-alias line down to the aliases that were ticked", () => {
    // The core creates a profile for every alias in the text it is handed, so
    // keeping the line whole would import a host the user unticked.
    const text = "Host staging prod\n  HostName x\n";
    expect(filterConfigToSelected(text, sel("staging"))).toBe("Host staging\n  HostName x\n");
    expect(filterConfigToSelected(text, sel("prod"))).toBe("Host prod\n  HostName x\n");
  });

  it("keeps a multi-alias line verbatim when every alias survived", () => {
    const text = "Host staging prod\n  HostName x\n";
    expect(filterConfigToSelected(text, sel("staging", "prod"))).toBe(text);
  });

  it("drops a multi-alias block when none of its aliases was ticked", () => {
    const text = "Host staging prod\n  HostName x\nHost web\n";
    expect(filterConfigToSelected(text, sel("web"))).toBe("Host web\n");
  });

  it("keeps the wildcards of a mixed line whose concrete alias was dropped", () => {
    // `*.internal` sets things other hosts inherit; only `web` was deselected.
    const text = "Host web *.internal\n  User admin\nHost db\n";
    const got = filterConfigToSelected(text, sel("db"));
    expect(got).toContain("Host *.internal");
    expect(got).toContain("User admin");
  });

  it("preserves the indentation of a rewritten line", () => {
    expect(filterConfigToSelected("  Host a b\n", sel("b"))).toBe("  Host b\n");
  });
});
