// One file/dir row. Presentational: selection highlight, optional metadata
// columns (size / modified / permissions), a hover/touch "send" action, and the
// drag source hooks. FileList owns selection/drag/context logic; drops bubble
// to the pane and always target its currently open directory.

import { useEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT, UI } from "@/theme/tokens";
import { Icon, Spinner, type IconName } from "@/components/primitives";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import { useFmt } from "@/i18n/format";
import type { Entry } from "@/store/sftp-types";
import type { FolderSizeState } from "./useFolderSizes";

/** Unix mode bits → "rwxr-xr-x" (only the low 9 permission bits). */
export function modeString(mode?: number): string {
  if (mode == null) return "";
  const rwx = (m: number) => `${m & 4 ? "r" : "-"}${m & 2 ? "w" : "-"}${m & 1 ? "x" : "-"}`;
  return rwx((mode >> 6) & 7) + rwx((mode >> 3) & 7) + rwx(mode & 7);
}

export function FileRow({
  entry,
  id,
  position,
  total,
  isUp,
  selected,
  focused,
  showModified,
  showPerms,
  folderSize,
  actionIcon,
  onClick,
  onDoubleClick,
  onContextAt,
  onActivate,
  onDragStart,
}: {
  entry: Entry;
  id?: string;
  position?: number;
  total?: number;
  isUp?: boolean;
  selected?: boolean;
  focused?: boolean;
  showModified?: boolean;
  showPerms?: boolean;
  /** The folder's on-demand total, once one was asked for. */
  folderSize?: FolderSizeState;
  actionIcon?: IconName;
  onClick?: (e: React.MouseEvent) => void;
  onDoubleClick?: () => void;
  onContextAt?: (x: number, y: number) => void;
  onActivate?: () => void;
  onDragStart?: (e: React.DragEvent) => void;
}) {
  const p = usePalette();
  const isMobile = useIsMobile();
  const { t } = useTranslation();
  const { fmtSize, fmtDate } = useFmt();
  const [hover, setHover] = useState(false);
  const [pressing, setPressing] = useState(false);
  // touch long-press → context menu (no right-click on mobile)
  const lpTimer = useRef<number | null>(null);
  useEffect(() => () => { if (lpTimer.current != null) window.clearTimeout(lpTimer.current); }, []);
  const lpFired = useRef(false);
  const lpStart = useRef<{ x: number; y: number } | null>(null);
  const clearLp = () => {
    if (lpTimer.current != null) {
      window.clearTimeout(lpTimer.current);
      lpTimer.current = null;
    }
    setPressing(false);
  };
  const isDir = entry.isDir;
  const isFile = !isDir && !isUp;
  // desktop: hover send arrow on files; mobile: a visible ⋯ actions button.
  const showSend = !isMobile && hover && isFile && !!actionIcon && !!onActivate;
  const showRowMenu = isMobile && !isUp && !!onContextAt;
  const isLink = !isDir && ((entry.mode ?? 0) & 0o170000) === 0o120000;
  const icon: IconName = isUp ? "cl" : isDir ? "folder" : isLink ? "link" : "file";
  const color = isDir ? p.accentText : p.txt3;

  return (
    <div
      id={id}
      role="option"
      aria-selected={!!selected}
      aria-posinset={position}
      aria-setsize={total}
      onClick={onClick}
      onDoubleClick={onDoubleClick}
      onContextMenu={(e) => {
        if (!onContextAt) return;
        e.preventDefault();
        e.stopPropagation();
        onContextAt(e.clientX, e.clientY);
      }}
      draggable={!isUp}
      onDragStart={onDragStart}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      onTouchStart={(e) => {
        if (!onContextAt) return;
        lpFired.current = false;
        const tt = e.touches[0];
        lpStart.current = { x: tt.clientX, y: tt.clientY };
        const { x, y } = lpStart.current;
        clearLp();
        setPressing(true);
        lpTimer.current = window.setTimeout(() => {
          lpFired.current = true;
          setPressing(false);
          navigator.vibrate?.(10);
          onContextAt(x, y);
        }, 450);
      }}
      onTouchMove={(e) => {
        const s = lpStart.current;
        if (!s) return;
        const tt = e.touches[0];
        // tolerate small jitter; only cancel on a real drag/scroll
        if (Math.hypot(tt.clientX - s.x, tt.clientY - s.y) > 10) clearLp();
      }}
      onTouchCancel={clearLp}
      onTouchEnd={(e) => {
        clearLp();
        if (lpFired.current) e.preventDefault();
      }}
      style={{
        display: "flex",
        alignItems: "center",
        gap: rem(9),
        height: isMobile ? rem(44) : rem(30),
        padding: `0 ${rem(10)}`,
        borderRadius: 8,
        cursor: isFile ? "grab" : "pointer",
        userSelect: "none",
        background: pressing
          ? p.bg3
          : selected
            ? p.accentSoft
            : hover
              ? p.bg2
              : "transparent",
        boxShadow: focused
          ? `inset 0 0 0 2px ${p.accent}`
          : selected
            ? `inset 2px 0 0 ${p.accent}`
            : "none",
        fontSize: TEXT.base,
      }}
    >
      <Icon name={icon} size={14} color={color} stroke={1.8} />
      <span
        style={{
          flex: 1,
          minWidth: 0,
          fontFamily: isFile ? MONO : UI,
          color: isUp ? p.txt3 : p.txt,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {isUp ? ".." : entry.name}
      </span>
      {!isUp && showPerms && (
        <span
          title={entry.uid || entry.gid ? `uid ${entry.uid ?? 0} · gid ${entry.gid ?? 0}` : undefined}
          style={{ fontFamily: MONO, fontSize: TEXT.micro, color: p.txt2, width: rem(78), textAlign: "left" }}
        >
          {modeString(entry.mode)}
        </span>
      )}
      {/* ellipsis: RU medium date ("12 сент. 2026 г.") exceeds 96px and would wrap the 30px row */}
      {!isUp && showModified && (
        <span
          style={{
            fontSize: TEXT.micro,
            color: p.txt2,
            width: rem(96),
            textAlign: "right",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {entry.mtime ? fmtDate(entry.mtime) : ""}
        </span>
      )}
      {!isUp && !(isDir && folderSize) && (
        <span style={{ fontFamily: MONO, fontSize: TEXT.micro, color: p.txt2, width: rem(70), textAlign: "right" }}>
          {isDir ? "—" : fmtSize(entry.size)}
        </span>
      )}
      {!isUp && isDir && folderSize && <FolderSizeCell size={folderSize} />}
      {showSend && actionIcon && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onActivate?.();
          }}
          title={t("sftp.send")}
          aria-label={t("sftp.send")}
          style={{
            background: "transparent",
            border: "none",
            padding: 0,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name={actionIcon} size={13} color={p.accentText} />
        </button>
      )}
      {showRowMenu && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onContextAt?.(e.clientX, e.clientY);
          }}
          aria-label={t("sftp.rowActions")}
          style={{
            background: "transparent",
            border: "none",
            padding: 0,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            width: rem(44),
            height: rem(44),
            flexShrink: 0,
            marginRight: rem(-6),
          }}
        >
          <Icon name="more" size={18} color={p.txt3} />
        </button>
      )}
    </div>
  );
}

/** A folder's size cell once a total was asked for: the running figure while
 *  the walk is on, then the total — marked when it is only a lower bound — or
 *  what went wrong. The label is what a screen reader reads with the row; the
 *  figure changing under it is deliberately not a live region. */
function FolderSizeCell({ size }: { size: FolderSizeState }) {
  const p = usePalette();
  const { t } = useTranslation();
  const { fmtSize } = useFmt();
  const label =
    size.state === "pending"
      ? t("sftp.size.pending", { size: fmtSize(size.bytes) })
      : size.state === "failed"
        ? t("sftp.size.failed", { reason: size.error })
        : size.partial
          ? t("sftp.size.partial", { size: fmtSize(size.bytes) })
          : undefined;
  return (
    <span
      title={label}
      aria-label={label}
      aria-busy={size.state === "pending" || undefined}
      style={{
        display: "flex",
        alignItems: "center",
        // The figure may run a few pixels wider than the column ("≥ 1,023.9 MB");
        // it grows towards the name instead of wrapping in a fixed-height row.
        justifyContent: "flex-end",
        gap: rem(5),
        width: rem(70),
        whiteSpace: "nowrap",
        fontFamily: MONO,
        fontSize: TEXT.micro,
        color: p.txt2,
      }}
    >
      {size.state === "pending" && <Spinner size={8} color={p.txt3} />}
      {size.state === "failed" ? (
        <Icon name="alert" size={12} color={p.red} />
      ) : (
        `${size.state === "done" && size.partial ? "≥ " : ""}${fmtSize(size.bytes)}`
      )}
    </span>
  );
}
