// ViewRun — the merged "Run a command across hosts" destination: Broadcast (type
// once → many live PTYs) and Fleet exec (run once → collect results) as two modes of
// one screen. Both ViewBroadcast and ViewFleet stay MOUNTED and are toggled by
// visibility, so switching modes never tears down live broadcast sessions (spec A13
// — keep the broadcast pane alive across the switch); the route-level teardown guard
// that ViewBroadcast registers still fires when leaving the Run route entirely. The
// two views share store.fleetSelection (the host selection applies to both modes),
// and their selection-clear effects are unmount-only, so dual-mounting is safe.

import { useState } from "react";
import { useApp } from "@/store/app";
import { usePalette } from "@/theme/ThemeProvider";
import { useTranslation } from "@/i18n";
import { UnderlineTabs } from "@/components/mono";
import { ViewBroadcast } from "@/views/ViewBroadcast";
import { ViewFleet } from "@/views/ViewFleet";

type RunMode = "broadcast" | "fleet";

export function ViewRun() {
  const p = usePalette();
  const { t } = useTranslation();
  // Initial mode follows the entry route so a deep-link / ⌘K jump to "fleet" or
  // "broadcast" opens the matching mode; a plain "run" defaults to Broadcast.
  const route = useApp((s) => s.route);
  const [mode, setMode] = useState<RunMode>(route === "fleet" ? "fleet" : "broadcast");

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
      <div style={{ padding: "12px 22px 0", borderBottom: `1px solid ${p.line}`, flexShrink: 0 }}>
        <UnderlineTabs<RunMode>
          ariaLabel={t("nav.run")}
          value={mode}
          onChange={setMode}
          tabs={[
            { value: "broadcast", label: t("nav.broadcast") },
            { value: "fleet", label: t("nav.fleetExec") },
          ]}
        />
      </div>
      <div style={{ flex: 1, minHeight: 0, display: mode === "broadcast" ? "flex" : "none" }}>
        <ViewBroadcast />
      </div>
      <div style={{ flex: 1, minHeight: 0, display: mode === "fleet" ? "flex" : "none" }}>
        <ViewFleet />
      </div>
    </div>
  );
}
