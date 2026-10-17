// AppearancePicker — the colour tag + icon pickers of the host and group editors
// (#134). Both radio groups follow the ARIA radio pattern: one tab stop, arrows
// move AND select, Home/End jump — the same keys as UnderlineTabs.

import React, { useId, useRef } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { RADIUS, rem, SIZE, TEXT } from "@/theme/tokens";
import { BTN_RESET, Icon, type IconName } from "@/components/primitives";
import { useIsMobile } from "@/store/responsive";
import { useTranslation, tDyn } from "@/i18n";
import { APPEARANCE_ICONS, TAG_COLORS, isKnownColor, isKnownIcon, type TagColor } from "@/components/appearance";
import { ColorTick, colorName } from "@/components/ColorTick";

/** Roving-tabindex radio keys over the `[role="radio"]` children of `ref`. */
function useRadioKeys<T>(options: readonly T[], value: T, onChange: (v: T) => void) {
  const ref = useRef<HTMLDivElement>(null);
  const onKeyDown = (e: React.KeyboardEvent) => {
    const keys = ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"];
    if (!keys.includes(e.key)) return;
    e.preventDefault();
    const i = Math.max(0, options.indexOf(value));
    const last = options.length - 1;
    const n =
      e.key === "Home"
        ? 0
        : e.key === "End"
          ? last
          : e.key === "ArrowRight" || e.key === "ArrowDown"
            ? (i + 1) % options.length
            : (i - 1 + options.length) % options.length;
    onChange(options[n]);
    ref.current?.querySelectorAll<HTMLElement>('[role="radio"]')[n]?.focus();
  };
  return { ref, onKeyDown };
}

const COLOR_OPTIONS: readonly (TagColor | null)[] = [null, ...TAG_COLORS];
const ICON_OPTIONS: readonly (IconName | null)[] = [null, ...APPEARANCE_ICONS];

/** The "Appearance" section body: a colour row and an icon grid.
 *
 *  `inheritedColor` is what the host would show with no colour of its own (its
 *  groups'), so "None" is not mistaken for "no colour on the tab". Unknown ids
 *  (a newer client's) show as the None/Default choice and are kept until the
 *  user picks something — the picker never rewrites a value on its own. */
export function AppearancePicker({
  color,
  icon,
  onColor,
  onIcon,
  inheritedColor,
}: {
  color: string | null | undefined;
  icon: string | null | undefined;
  onColor: (c: TagColor | null) => void;
  onIcon: (i: IconName | null) => void;
  inheritedColor?: TagColor | null;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const touch = useIsMobile();
  const uid = useId();
  const colorValue = isKnownColor(color) ? color : null;
  const iconValue = isKnownIcon(icon) ? icon : null;
  const colorKeys = useRadioKeys(COLOR_OPTIONS, colorValue, onColor);
  const iconKeys = useRadioKeys(ICON_OPTIONS, iconValue, onIcon);
  // Touch floors every option at the tap minimum; the drawn swatch stays small.
  const cell = touch ? SIZE.tapMin : 30;
  const swatch = touch ? 26 : 20;

  const caption = (text: string, id: string) => (
    <div id={id} style={{ fontSize: TEXT.small, fontWeight: 600, color: p.txt2, marginBottom: rem(6) }}>
      {text}
    </div>
  );
  const cellStyle = (on: boolean): React.CSSProperties => ({
    ...BTN_RESET,
    width: rem(cell),
    height: rem(cell),
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: RADIUS.chip,
    cursor: "pointer",
    // Selection is a frame, never a fill (mono Card rule) — and a shape change,
    // so it does not ride on the swatch's own colour.
    boxShadow: on ? `inset 0 0 0 1.5px ${p.txt}` : "none",
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: rem(14) }}>
      <div>
        {caption(t("appearance.color"), `${uid}-color`)}
        <div
          ref={colorKeys.ref}
          role="radiogroup"
          aria-labelledby={`${uid}-color`}
          onKeyDown={colorKeys.onKeyDown}
          style={{ display: "flex", flexWrap: "wrap", gap: rem(4) }}
        >
          {COLOR_OPTIONS.map((c) => {
            const on = c === colorValue;
            const name = c ? colorName(c) : t("appearance.none");
            return (
              <button
                key={c ?? "none"}
                type="button"
                role="radio"
                aria-checked={on}
                aria-label={name}
                title={name}
                tabIndex={on ? 0 : -1}
                onClick={() => onColor(c)}
                style={cellStyle(on)}
              >
                <span
                  aria-hidden
                  style={{
                    width: rem(swatch),
                    height: rem(swatch),
                    borderRadius: "50%",
                    boxSizing: "border-box",
                    background: c ? p.tags[c] : "transparent",
                    border: c ? "none" : `1.5px solid ${p.line2}`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    color: p.txt3,
                  }}
                >
                  {!c && <Icon name="minus" size={12} style={{ transform: "rotate(-45deg)" }} />}
                </span>
              </button>
            );
          })}
        </div>
        {!colorValue && inheritedColor && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: rem(6),
              marginTop: rem(6),
              fontSize: TEXT.small,
              color: p.txt3,
            }}
          >
            <ColorTick color={inheritedColor} height={12} />
            {t("appearance.inheritFrom", { color: colorName(inheritedColor) })}
          </div>
        )}
      </div>
      <div>
        {caption(t("appearance.icon"), `${uid}-icon`)}
        <div
          ref={iconKeys.ref}
          role="radiogroup"
          aria-labelledby={`${uid}-icon`}
          onKeyDown={iconKeys.onKeyDown}
          style={{ display: "flex", flexWrap: "wrap", gap: rem(4) }}
        >
          {ICON_OPTIONS.map((ic) => {
            const on = ic === iconValue;
            const name = ic ? tDyn(`appearance.icons.${ic}`) : t("appearance.defaultIcon");
            return (
              <button
                key={ic ?? "default"}
                type="button"
                role="radio"
                aria-checked={on}
                aria-label={name}
                title={name}
                tabIndex={on ? 0 : -1}
                onClick={() => onIcon(ic)}
                style={{ ...cellStyle(on), color: on ? p.txt : p.txt2 }}
              >
                {ic ? (
                  <Icon name={ic} size={16} />
                ) : (
                  <Icon name="minus" size={12} color={p.txt3} style={{ transform: "rotate(-45deg)" }} />
                )}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
