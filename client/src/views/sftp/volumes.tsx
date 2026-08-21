// Volume (drive) picker for the SFTP local pane. A machine with more than one
// disk had no way to reach the others: the pane opens in the home directory and
// "up" bottoms out at that volume's root, so D:\ or a mounted USB stick was
// reachable only by typing its path into the breadcrumb editor.
//
// Shown only when there is a choice to make — one volume, no button.

import { useCallback, useEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { Icon } from "@/components/primitives";
import { fmtSize } from "@/i18n/format";
import { useTranslation } from "@/i18n";
import * as api from "@/bridge/api";
import { trimTrailing, volumeName, volumeOf } from "@/sftp/volumes";
import type { LocalVolume } from "@/bridge/types";

/** Fetch the mounted volumes. `enabled` is false for a remote slot (and on
 *  mobile, where the command answers empty anyway) so no IPC is spent on a
 *  pane that can never show the picker. */
export function useVolumes(enabled: boolean): { volumes: LocalVolume[]; reload: () => void } {
  const [volumes, setVolumes] = useState<LocalVolume[]>([]);
  const reload = useCallback(() => {
    if (!enabled) {
      setVolumes([]);
      return;
    }
    void (async () => {
      try {
        setVolumes(await api.localVolumes());
      } catch {
        // A volume list we couldn't read is a missing button, not an error to
        // put in the user's way: the breadcrumb editor still goes anywhere.
        setVolumes([]);
      }
    })();
  }, [enabled]);
  useEffect(reload, [reload]);
  return { volumes, reload };
}

export function VolumePicker({
  volumes,
  cwd,
  onPick,
  onOpen,
}: {
  volumes: LocalVolume[];
  cwd: string;
  onPick: (path: string) => void;
  /** Re-read the list as the menu opens, so a stick plugged in after the pane
   *  was built shows up without a restart. */
  onOpen: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const current = volumeOf(volumes, cwd);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={ref} style={{ position: "relative", flexShrink: 0 }}>
      <button
        onClick={() => {
          if (!open) onOpen();
          setOpen((v) => !v);
        }}
        title={t("sftp.drives")}
        aria-label={t("sftp.drives")}
        aria-haspopup="menu"
        aria-expanded={open}
        style={{
          display: "flex",
          alignItems: "center",
          gap: rem(4),
          maxWidth: rem(130),
          padding: `${rem(3)} ${rem(7)}`,
          borderRadius: 7,
          border: `1px solid ${p.line}`,
          background: p.bg2,
          color: p.txt2,
          fontFamily: MONO,
          fontSize: rem(11.5),
          cursor: "pointer",
        }}
      >
        <Icon name="drive" size={12} color={p.txt3} />
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {current ? volumeName(current) : t("sftp.drives")}
        </span>
        <span style={{ color: p.txt3 }}>▾</span>
      </button>
      {open && (
        <div
          role="menu"
          style={{
            position: "absolute",
            top: "calc(100% + 5px)",
            left: 0,
            zIndex: 40,
            minWidth: rem(230),
            maxHeight: rem(300),
            overflow: "auto",
            background: p.bg1,
            border: `1px solid ${p.line2}`,
            borderRadius: 12,
            boxShadow: p.shadow,
            padding: rem(5),
          }}
        >
          {volumes.map((v) => {
            const on = current?.path === v.path;
            return (
              <button
                key={v.path}
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  onPick(v.path);
                }}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: rem(9),
                  width: "100%",
                  padding: `${rem(7)} ${rem(9)}`,
                  borderRadius: 8,
                  border: "1px solid transparent",
                  background: on ? p.bg2 : "transparent",
                  color: p.txt,
                  cursor: "pointer",
                  textAlign: "left",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = p.bg2)}
                onMouseLeave={(e) => (e.currentTarget.style.background = on ? p.bg2 : "transparent")}
              >
                <Icon name="drive" size={15} color={on ? p.accentText : p.txt3} />
                <span style={{ flex: 1, minWidth: 0 }}>
                  <span
                    style={{
                      display: "block",
                      fontSize: TEXT.base,
                      fontWeight: on ? 700 : 600,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {volumeName(v)}
                  </span>
                  {/* The path only earns a line when it isn't already the name
                      ("C:" says it; "/media/me/USB" behind "USB" does not). */}
                  {volumeName(v) !== trimTrailing(v.path) && (
                    <span
                      style={{
                        display: "block",
                        fontFamily: MONO,
                        fontSize: TEXT.micro,
                        color: p.txt3,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {v.path}
                    </span>
                  )}
                </span>
                {/* Capacity tells two same-named volumes apart, and it is what
                    you want to know before sending a folder to one of them. */}
                {v.totalBytes > 0 && (
                  <span style={{ flexShrink: 0, fontFamily: MONO, fontSize: rem(10.5), color: p.txt3 }}>
                    {t("sftp.driveFree", { free: fmtSize(v.freeBytes), total: fmtSize(v.totalBytes) })}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
