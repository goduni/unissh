// Settings, over the current view instead of instead of it.
//
// It used to be a route like any other, which meant opening it while a session
// was running blanked the terminal behind a full-screen page — reported twice,
// once as "settings don't open next to the terminal" and once as "⌘, does
// nothing". The sessions themselves always survived (ViewTerminal stays mounted
// under display:none), but the screen, the focus and a re-fit round trip did not.
//
// Desktop only. A phone has no room to show a session behind a panel, so there
// Settings stays the screen it was — the interception lives in `go()`.

import { useApp } from "@/store/app";
import { useDialogFocus, useDialogKeys } from "@/components/a11y";
import { Icon } from "@/components/primitives";
import { usePalette } from "@/theme/ThemeProvider";
import { rem } from "@/theme/tokens";
import { useTranslation } from "@/i18n";
import { ViewSettings } from "@/views/ViewSettings";

export function SettingsOverlay() {
  const open = useApp((s) => s.settingsOpen);
  if (!open) return null;
  return <SettingsPanel />;
}

/** Split out so the dialog hooks mount only while the panel is actually open —
 *  `useDialogKeys` registers on the Escape stack for as long as it lives. */
function SettingsPanel() {
  const p = usePalette();
  const { t } = useTranslation();
  const close = useApp((s) => s.setSettingsOpen);
  useDialogKeys(() => close(false));
  // The panel itself, not an input: Settings opens on a tab list, and yanking
  // focus into the first text field would land the caret in some arbitrary
  // setting on every open.
  const cardRef = useDialogFocus<HTMLDivElement>("[role='dialog']");

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        // BELOW the global modal host, not above it. Settings opens ordinary
        // modals of its own — "New terminal theme", "Edit vault" — and those
        // render into that host at 150; at 250 the panel covered them, so the
        // button appeared to do nothing while an invisible dialog ate Escape.
        // The ladder: Entry 100 (never co-mounted) < THIS < Groups/Import 130 <
        // Modals 150 < Modal 200 < palette 300 < confirm 350 < prompts 400+.
        zIndex: 120,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: rem(32),
        boxSizing: "border-box",
      }}
    >
      <div
        onClick={() => close(false)}
        style={{ position: "absolute", inset: 0, background: "rgba(6,7,11,0.55)", backdropFilter: "blur(3px)" }}
      />
      <div
        ref={cardRef}
        role="dialog"
        aria-modal="true"
        aria-label={t("nav.settings")}
        tabIndex={-1}
        className="uh-view"
        style={{
          position: "relative",
          // Design pixels: the panel holds Settings' own two columns, and at 150 %
          // a 1080 CSS-px box makes the label column crush the control beside it.
          // The `100%` half of each clamp keeps it on screen at any window size —
          // grow, then fall back to the viewport, never overflow it.
          width: `min(${rem(1080)}, 100%)`,
          height: `min(${rem(760)}, 100%)`,
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          background: p.bg0,
          border: `1px solid ${p.line2}`,
          borderRadius: 16,
          boxShadow: p.shadow,
          outline: "none",
        }}
      >
        {/* ViewSettings draws its own heading, so the close control floats over
            the panel rather than adding a second title bar above it. */}
        <button
          onClick={() => close(false)}
          title={t("common.close")}
          aria-label={t("common.close")}
          style={{
            position: "absolute",
            top: rem(10),
            right: rem(10),
            zIndex: 1,
            width: rem(30),
            height: rem(30),
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            border: "none",
            borderRadius: 8,
            background: "transparent",
            color: p.txt3,
            cursor: "pointer",
          }}
        >
          <Icon name="x" size={16} />
        </button>
        {/* `flex: 1` alone is not enough: as a column-flex item ViewSettings'
            automatic min-height is its CONTENT height, so a tall tab would push
            past the card and get clipped instead of scrolling in its own pane. */}
        <div style={{ flex: 1, minHeight: 0, display: "flex" }}>
          <ViewSettings />
        </div>
      </div>
    </div>
  );
}
