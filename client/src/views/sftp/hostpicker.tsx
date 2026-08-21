// Saved-host list. Two presentations of the same rows: HostMenu, the dropdown
// the tab strip's "+" opens, and HostList on its own, which an empty pane slot
// renders inline — a pane with nothing in it should already be showing what can
// go in it, rather than making the hosts a hover away.

import {
  Fragment,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { Icon, NO_AUTOCORRECT } from "@/components/primitives";
import { useCtx } from "@/store/ctx";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import { pickerRows } from "./pickerRows";
import { nextRow } from "@/support/listNav";
import type { ConnectionProfile } from "@/bridge/types";

export function HostList({
  hosts,
  onPick,
  onPickLocal,
  onNavigateAway,
  autoFocusSearch = false,
}: {
  hosts: ConnectionProfile[];
  onPick: (h: ConnectionProfile) => void;
  /** Offer "shell on this machine" above the hosts. Optional because this list
   *  is also the SFTP picker, where a local shell would mean nothing — passing
   *  it is what makes it a terminal picker. */
  onPickLocal?: () => void;
  /** Called before leaving for the new-host form, so a dropdown can close
   *  itself first instead of hanging over the view it just opened. */
  onNavigateAway?: () => void;
  /** Only the dropdown grabs focus: an inline list is part of the page, and a
   *  search box that steals the caret on every SFTP open would be a trap. */
  autoFocusSearch?: boolean;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const isMobile = useIsMobile();

  const [q, setQ] = useState("");
  // Rebuilt only when the inputs change: hover routes through `sel`, so without
  // this every pointer crossing would re-derive and re-lowercase the whole list.
  const localLabel = onPickLocal
    ? `${t("terminal.localShell")} ${t("terminal.localShellHint")}`
    : null;
  const rows = useMemo(() => pickerRows(hosts, q, localLabel), [hosts, q, localLabel]);
  const [sel, setSel] = useState(0);
  // Clamped at RENDER, not only when a key moves it: `hosts` can change under an
  // open picker (a vault sync, a host deleted in another window), and a highlight
  // left past the end paints nothing while Enter quietly does nothing either.
  const active = rows.length === 0 ? -1 : Math.min(sel, rows.length - 1);
  const rowRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const listId = useId();

  const activate = (row: (typeof rows)[number]) => {
    if (row.kind === "local") onPickLocal?.();
    else onPick(row.host);
  };
  const move = (delta: number) => {
    const next = nextRow(active, delta, rows.length);
    setSel(next);
    // Scrolling belongs to the arrow keys alone. As an effect on `sel` it would
    // also fire at mount — yanking the inline pane list, which is deliberately
    // centred, to its first row — and again on every hover.
    rowRefs.current[next]?.scrollIntoView({ block: "nearest" });
  };
  const onSearchKey = (e: React.KeyboardEvent) => {
    // The Enter that commits an IME candidate is not a request to connect.
    if (e.nativeEvent.isComposing) return;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      move(e.key === "ArrowDown" ? 1 : -1);
    } else if (e.key === "Enter" && rows[active]) {
      e.preventDefault();
      activate(rows[active]);
    }
  };

  const rowStyle = (on: boolean): CSSProperties => ({
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
  });

  // One renderer for both kinds: they differ by an icon and two strings, and a
  // second copy is how one of them ends up without the aria state or the ref.
  const renderRow = (row: (typeof rows)[number], i: number) => {
    const local = row.kind === "local";
    return (
      <button
        key={local ? "local" : row.host.profileId}
        id={`${listId}-${i}`}
        role="option"
        aria-selected={i === active}
        ref={(el) => {
          rowRefs.current[i] = el;
        }}
        onClick={() => activate(row)}
        onMouseEnter={() => setSel(i)}
        style={rowStyle(i === active)}
      >
        <Icon name={local ? "laptop" : "server"} size={15} color={p.txt3} />
        <span style={{ flex: 1, minWidth: 0 }}>
          <span style={{ display: "block", fontSize: TEXT.base, fontWeight: 600 }}>
            {local ? t("terminal.localShell") : row.host.label}
          </span>
          <span style={{ display: "block", fontFamily: MONO, fontSize: TEXT.micro, color: p.txt3 }}>
            {local
              ? t("terminal.localShellHint")
              : `${row.host.user}@${row.host.host}:${row.host.port}`}
          </span>
        </span>
      </button>
    );
  };

  return (
    <>
      {/* Shown for any non-empty list, not only past six hosts: a picker whose
          search appears at the seventh reads as one that is broken at the sixth.
          With no hosts at all there is nothing to search, and the only useful
          control is the button below. */}
      {hosts.length > 0 && (
        <input
          // A caret on a phone means the on-screen keyboard over a 340px
          // dropdown before the user has decided to type.
          autoFocus={autoFocusSearch && !isMobile}
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            // Every keystroke rebuilds the list; the highlight goes back to its
            // top match rather than to whatever now sits at the old index.
            setSel(0);
          }}
          onKeyDown={onSearchKey}
          placeholder={t("sftp.searchHosts")}
          aria-label={t("sftp.searchHosts")}
          role="combobox"
          aria-expanded
          aria-controls={listId}
          aria-activedescendant={active >= 0 ? `${listId}-${active}` : undefined}
          {...NO_AUTOCORRECT}
          style={{
            width: "100%",
            boxSizing: "border-box",
            marginBottom: rem(5),
            padding: `${rem(6)} ${rem(9)}`,
            borderRadius: 8,
            border: `1px solid ${p.line2}`,
            background: p.bg2,
            color: p.txt,
            fontSize: TEXT.base,
            outline: "none",
          }}
        />
      )}
      <div id={listId} role="listbox" aria-label={t("sftp.hostsListLabel")}>
        {rows.map((row, i) => (
          <Fragment key={row.kind === "local" ? "local" : row.host.profileId}>
            {renderRow(row, i)}
            {/* Separated, not just listed first: this one does not go over the
                network, and the list below is entirely about things that do. */}
            {row.kind === "local" && rows.length > 1 && (
              <div style={{ height: 1, background: p.line2, margin: `${rem(5)} ${rem(4)}` }} />
            )}
          </Fragment>
        ))}
      </div>
      {rows.length === 0 && hosts.length > 0 && (
        <div style={{ padding: `${rem(8)} ${rem(10)}`, fontSize: TEXT.base, color: p.txt3 }}>
          {t("sftp.noHostMatches", { q: q.trim() })}
        </div>
      )}
      {hosts.length === 0 && (
        <button
          onClick={() => {
            onNavigateAway?.();
            ctx.onNewHost();
          }}
          style={{
            display: "flex",
            alignItems: "center",
            gap: rem(9),
            width: "100%",
            padding: `${rem(8)} ${rem(9)}`,
            borderRadius: 8,
            border: "1px solid transparent",
            background: "transparent",
            color: p.accentText,
            cursor: "pointer",
            textAlign: "left",
            fontSize: TEXT.base,
          }}
          // Clears the row highlight as well as painting itself: two rows lit at
          // once says nothing about which one Enter would take.
          onMouseEnter={(e) => {
            e.currentTarget.style.background = p.bg2;
            setSel(-1);
          }}
          onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
        >
          <Icon name="plus" size={15} color={p.accentText} />
          {t("sftp.addHost")}
        </button>
      )}
    </>
  );
}

export function HostMenu({
  hosts,
  onPick,
  onPickLocal,
  onClose,
  align = "right",
}: {
  hosts: ConnectionProfile[];
  onPick: (h: ConnectionProfile) => void;
  onPickLocal?: () => void;
  onClose: () => void;
  /** Which edge of the "+" to anchor to. Right (default) for a flush-right "+"
   *  (SFTP); left when the "+" sits just after the tabs (terminal), so the menu
   *  opens rightward into free space instead of leftward over the tabs. */
  align?: "left" | "right";
}) {
  const p = usePalette();
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      // preventDefault so a dialog stack beneath this picker survives the Escape.
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  // Nudge the menu back inside the viewport if the anchor edge would push it off
  // (e.g. a left-anchored terminal "+" sitting far right, or vice-versa).
  const [shiftX, setShiftX] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    let dx = 0;
    if (r.right > window.innerWidth - 8) dx = window.innerWidth - 8 - r.right;
    if (r.left + dx < 8) dx = 8 - r.left;
    setShiftX(dx);
  }, []);

  return (
    <div
      ref={ref}
      style={{
        position: "absolute",
        top: "calc(100% + 6px)",
        ...(align === "left" ? { left: 0 } : { right: 0 }),
        transform: shiftX ? `translateX(${shiftX}px)` : undefined,
        zIndex: 40,
        minWidth: rem(240),
        maxHeight: rem(340),
        overflow: "auto",
        background: p.bg1,
        border: `1px solid ${p.line2}`,
        borderRadius: 12,
        boxShadow: p.shadow,
        padding: rem(5),
      }}
    >
      <HostList
        hosts={hosts}
        onPick={onPick}
        onPickLocal={onPickLocal}
        onNavigateAway={onClose}
        autoFocusSearch
      />
    </div>
  );
}
