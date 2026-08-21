// Dropped/failed-session banner, shared by the desktop terminal pane (a floating
// card over the xterm) and the mobile terminal (a bottom strip). One source of
// truth for the message + reconnect affordance so the two shells can't drift.

import { type CSSProperties } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { rem, rgba, TEXT } from "@/theme/tokens";
import { Btn, Icon } from "@/components/primitives";
import { useTranslation } from "@/i18n";
import { useApp, type TerminalPaneState } from "@/store/app";

export function ReconnectBanner({
  pane,
  onReconnect,
  variant,
}: {
  pane: TerminalPaneState;
  onReconnect: () => void;
  variant: "float" | "strip";
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const isError = pane.status === "error";
  const message = isError ? pane.error || t("terminal.status.closed") : t("terminal.status.closed");
  const float = variant === "float";
  // A local shell did not lose a connection — it exited, or never started. The
  // action is the same one (re-open in this pane, keeping the scrollback); the
  // word for it is not, and calling it "Reconnect" would describe a network
  // event that never happened.
  const local = pane.target.kind === "local";

  const floatStyle: CSSProperties = {
    position: "absolute",
    left: rem(8),
    right: rem(8),
    bottom: rem(8),
    borderRadius: 10,
    background: p.bg3,
    border: `1px solid ${isError ? p.red : p.line2}`,
    boxShadow: p.shadow,
    zIndex: 6,
  };
  const stripStyle: CSSProperties = {
    flexShrink: 0,
    background: rgba(p.red, 0.12),
    borderTop: `1px solid ${rgba(p.red, 0.3)}`,
  };

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: rem(10),
        padding: float ? `${rem(9)} ${rem(12)}` : `${rem(10)} ${rem(14)}`,
        ...(float ? floatStyle : stripStyle),
      }}
    >
      <Icon name="alert" size={16} color={isError || !float ? p.red : p.txt3} />
      <span
        style={{
          flex: 1,
          minWidth: 0,
          fontSize: TEXT.base,
          color: p.txt2,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {message}
      </span>
      {/* A local shell that would not start failed for a reason the settings
          hold — a wrong path, no execute permission, a directory that isn't
          there. Point at the place that fixes it, next to the retry that won't. */}
      {local && isError && (
        <Btn size="sm" variant="ghost" icon="sliders" onClick={() => useApp.getState().go("settings")}>
          {t("nav.settings")}
        </Btn>
      )}
      <Btn size="sm" icon="refresh" onClick={onReconnect}>
        {t(local ? "terminal.restart" : "terminal.reconnect")}
      </Btn>
    </div>
  );
}
