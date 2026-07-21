// One file/dir row. Presentational: selection highlight, optional metadata
// columns (size / modified / permissions), a hover/touch "send" action, and the
// drag source + drop-onto-folder hooks. All behaviour is delegated via props so
// FileList owns selection/drag/context logic.

import { useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, UI } from "@/theme/tokens";
import { Icon, type IconName } from "@/components/primitives";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import { useFmt } from "@/i18n/format";
import type { Entry } from "@/store/sftp-types";

/** Unix mode bits → "rwxr-xr-x" (only the low 9 permission bits). */
export function modeString(mode?: number): string {
  if (mode == null) return "";
  const rwx = (m: number) => `${m & 4 ? "r" : "-"}${m & 2 ? "w" : "-"}${m & 1 ? "x" : "-"}`;
  return rwx((mode >> 6) & 7) + rwx((mode >> 3) & 7) + rwx(mode & 7);
}

export function FileRow({
  entry,
  isUp,
  selected,
  dropActive,
  focused,
  showModified,
  showPerms,
  actionIcon,
  onClick,
  onDoubleClick,
  onContextAt,
  onActivate,
  onDragStart,
  onDragEnterDir,
  onDragLeaveDir,
  onDropOnDir,
}: {
  entry: Entry;
  isUp?: boolean;
  selected?: boolean;
  dropActive?: boolean;
  focused?: boolean;
  showModified?: boolean;
  showPerms?: boolean;
  actionIcon?: IconName;
  onClick?: (e: React.MouseEvent) => void;
  onDoubleClick?: () => void;
  onContextAt?: (x: number, y: number) => void;
  onActivate?: () => void;
  onDragStart?: (e: React.DragEvent) => void;
  onDragEnterDir?: (e: React.DragEvent) => void;
  onDragLeaveDir?: (e: React.DragEvent) => void;
  onDropOnDir?: (e: React.DragEvent) => void;
}) {
  const p = usePalette();
  const isMobile = useIsMobile();
  const { t } = useTranslation();
  const { fmtSize, fmtDate } = useFmt();
  const [hover, setHover] = useState(false);
  const [pressing, setPressing] = useState(false);
  // touch long-press → context menu (no right-click on mobile)
  const lpTimer = useRef<number | null>(null);
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
  const isDropDir = isDir && !isUp;
  // desktop: hover send arrow on files; mobile: a visible ⋯ actions button.
  const showSend = !isMobile && hover && isFile && !!actionIcon && !!onActivate;
  const showRowMenu = isMobile && !isUp && !!onContextAt;
  const isLink = !isDir && ((entry.mode ?? 0) & 0o170000) === 0o120000;
  const icon: IconName = isUp ? "cl" : isDir ? "folder" : isLink ? "link" : "file";
  const color = isDir ? p.accentText : p.txt3;

  return (
    <div
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
      onDragEnter={isDropDir ? onDragEnterDir : undefined}
      onDragOver={isDropDir ? (e) => e.preventDefault() : undefined}
      onDragLeave={
        isDropDir
          ? (e) => {
              // Ignore enter/leave churn between the row's own children.
              if (e.currentTarget.contains(e.relatedTarget as Node)) return;
              onDragLeaveDir?.(e);
            }
          : undefined
      }
      onDrop={isDropDir ? onDropOnDir : undefined}
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
      onTouchEnd={(e) => {
        clearLp();
        if (lpFired.current) e.preventDefault();
      }}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 9,
        height: isMobile ? 44 : 30,
        padding: "0 10px",
        borderRadius: 8,
        cursor: isFile ? "grab" : "pointer",
        userSelect: "none",
        background: pressing
          ? p.bg3
          : dropActive
            ? p.accentSoft
            : selected
              ? p.accentSoft
              : hover
                ? p.bg2
                : "transparent",
        boxShadow: focused
          ? `inset 0 0 0 2px ${p.accent}`
          : dropActive
            ? `inset 0 0 0 1.5px ${p.accentLine}`
            : selected
              ? `inset 2px 0 0 ${p.accent}`
              : "none",
        fontSize: 13,
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
          style={{ fontFamily: MONO, fontSize: 11, color: p.txt2, width: 78, textAlign: "left" }}
        >
          {modeString(entry.mode)}
        </span>
      )}
      {/* ellipsis: RU medium date ("12 сент. 2026 г.") exceeds 96px and would wrap the 30px row */}
      {!isUp && showModified && (
        <span
          style={{
            fontSize: 11,
            color: p.txt2,
            width: 96,
            textAlign: "right",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {entry.mtime ? fmtDate(entry.mtime) : ""}
        </span>
      )}
      {!isUp && (
        <span style={{ fontFamily: MONO, fontSize: 11, color: p.txt2, width: 70, textAlign: "right" }}>
          {isDir ? "—" : fmtSize(entry.size)}
        </span>
      )}
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
            width: 44,
            height: 44,
            flexShrink: 0,
            marginRight: -6,
          }}
        >
          <Icon name="more" size={18} color={p.txt3} />
        </button>
      )}
    </div>
  );
}
