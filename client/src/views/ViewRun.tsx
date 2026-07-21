// ViewRun — the merged "Run a command across hosts" destination: Broadcast (type
// once → many live PTYs) and Fleet exec (run once → collect results) as two modes of
// one screen. Both ViewBroadcast and ViewFleet stay MOUNTED and are toggled by
// visibility, so switching modes never tears down live broadcast sessions (spec A13
// — keep the broadcast pane alive across the switch); the route-level teardown guard
// that ViewBroadcast registers still fires when leaving the Run route entirely. The
// two views share store.fleetSelection (the host selection applies to both modes),
// and their selection-clear effects are unmount-only, so dual-mounting is safe.

import { useEffect, useState } from "react";
import { useApp } from "@/store/app";
import { usePalette } from "@/theme/ThemeProvider";
import { useTranslation } from "@/i18n";
import { useNarrow } from "@/store/responsive";
import { SPACE } from "@/theme/tokens";
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
  // Follow the route, don't just seed from it. A useState initialiser runs once,
  // so a ⌘K / bulk-bar jump to "Fleet exec" landed on whatever mode this screen
  // happened to mount with — Broadcast on the phone, where it is now mounted for
  // the whole session, and the previous mode on the desktop, which keeps it
  // mounted across run/fleet/broadcast too.
  useEffect(() => {
    if (route === "fleet") setMode("fleet");
    else if (route === "broadcast") setMode("broadcast");
  }, [route]);
  // Match the gutter of the mode it wraps, or the tabs sit inset from their content.
  const gutter = useNarrow() ? SPACE.gutterNarrow : SPACE.gutter;

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
      <div style={{ padding: `12px ${gutter}px 0`, borderBottom: `1px solid ${p.line}`, flexShrink: 0 }}>
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
