import { useEffect, useId, useRef, useState, type KeyboardEvent, type RefObject, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { useMeta } from "../store/meta";
import { useUi } from "../store/ui";
import { Icon } from "../ui/icons";
import { Glyph } from "./glyphs";
import { Mark, Wordmark } from "./Mark";
import { NAV } from "./nav";

/** What the rail says about the instance it administers (read once by the shell). */
export interface InstanceLine {
  /** The instance's name, or the panel's word for an unnamed one. */
  name: string;
  /** The machine line under it: the instance id and version; `null` while it is read. */
  id: string | null;
}

/** Handlers that show a folded item's tooltip; `undefined` when the rail is open (the names are on screen). */
type TipFor = ((label: string) => TipHandlers) | undefined;
interface TipHandlers {
  onMouseEnter: (e: SyntheticEvent<HTMLElement>) => void;
  onMouseLeave: () => void;
  onFocus: (e: SyntheticEvent<HTMLElement>) => void;
  onBlur: () => void;
  onKeyDown: (e: KeyboardEvent<HTMLElement>) => void;
}

/**
 * The sections, as one named navigation: each group as a list under its name. Folded, a group's name gives way to a
 * rule for the eye and stays for a reader, and each item is its icon with the name in a tooltip. An item is 30 px,
 * muted at rest, `--elevated` on hover; the active one is `--elevated` at 600 with the 3 px blue rule at the rail's
 * left edge. A count from the overview stands at the item's right in muted mono.
 */
function NavLinks({
  folded = false,
  tipFor,
  onNavigate,
}: {
  folded?: boolean;
  tipFor?: TipFor;
  onNavigate?: () => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const route = useUi((s) => s.route);
  const go = useUi((s) => s.go);
  const counts = useMeta((s) => s.counts);

  return (
    <nav aria-label={t("nav.sections")} className="sh-nav">
      {NAV.map((group, index) => (
        <div key={group.key} className="sh-nav-group">
          {folded && index > 0 ? <div aria-hidden="true" className="sh-nav-rule" /> : null}
          <p id={`${id}-${group.key}`} className={folded ? "sh-sr-only" : "sh-nav-label"}>
            {t(`nav.${group.key}`)}
          </p>
          <ul aria-labelledby={`${id}-${group.key}`} className="sh-nav-list">
            {group.items.map((item) => {
              const name = t(`nav.${item.key}`);
              const count = item.count ? counts[item.count] : undefined;
              return (
                <li key={item.route}>
                  <button
                    type="button"
                    className="sh-nav-item sh-focus"
                    data-folded={folded ? "true" : undefined}
                    aria-current={route === item.route ? "page" : undefined}
                    onClick={() => {
                      go(item.route);
                      onNavigate?.();
                    }}
                    {...tipFor?.(count != null ? `${name} · ${count}` : name)}
                  >
                    <Icon name={item.icon} size={16} />
                    <span className={folded ? "sh-sr-only" : "sh-nav-name"}>{name}</span>
                    {count != null ? <span className={folded ? "sh-sr-only" : "sh-nav-count"}>{count}</span> : null}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

/** The instance under the wordmark: its name at 13 / 600 and a muted mono line with its id. */
function Instance({ instance }: { instance: InstanceLine }) {
  const { t } = useTranslation();
  return (
    <div className="sh-instance">
      <div className="sh-instance-name">{instance.name}</div>
      {instance.id != null ? (
        <div className="sh-instance-id">{instance.id}</div>
      ) : (
        <div>
          <span aria-hidden="true" className="sh-skeleton" />
          <span className="sh-sr-only">{t("common.loading")}</span>
        </div>
      )}
    </div>
  );
}

interface Tip {
  label: string;
  top: number;
  left: number;
}

/**
 * The rail from 768 px up: 232 px, folding to 56 px of icons (the shell remembers the fold), the width eased over
 * 240 ms. The wordmark and the instance on top, the sections, the fold at the foot. A folded item's tooltip is drawn
 * outside the rail, which scrolls and would clip it.
 */
export function Rail({
  folded,
  onToggleFold,
  instance,
}: {
  folded: boolean;
  onToggleFold: () => void;
  instance: InstanceLine;
}) {
  const { t } = useTranslation();
  const [tip, setTip] = useState<Tip | null>(null);

  const show = (label: string) => (e: SyntheticEvent<HTMLElement>) => {
    const box = e.currentTarget.getBoundingClientRect();
    setTip({ label, top: box.top + box.height / 2, left: box.right + 8 });
  };
  const hide = () => setTip(null);
  const tipFor: TipFor = folded
    ? (label) => ({
        onMouseEnter: show(label),
        onMouseLeave: hide,
        onFocus: show(label),
        onBlur: hide,
        onKeyDown: (e) => {
          if (e.key === "Escape") hide();
        },
      })
    : undefined;
  const unfold = t("nav.unfold");

  return (
    <>
      <aside className="sh-rail" data-folded={folded ? "true" : "false"} onScroll={hide}>
        <div className="sh-rail-top" data-folded={folded ? "true" : undefined}>
          {folded ? <Mark /> : <Wordmark />}
        </div>
        {folded ? null : <Instance instance={instance} />}
        <NavLinks folded={folded} tipFor={tipFor} />
        <button
          type="button"
          className="sh-fold sh-focus"
          data-folded={folded ? "true" : undefined}
          aria-label={folded ? unfold : undefined}
          onClick={() => {
            hide();
            onToggleFold();
          }}
          {...tipFor?.(unfold)}
        >
          <Glyph name={folded ? "unfoldRail" : "foldRail"} />
          {folded ? null : t("nav.fold")}
        </button>
      </aside>
      {folded && tip ? (
        <span aria-hidden="true" className="sh-tip" style={{ top: tip.top, left: tip.left }}>
          {tip.label}
        </span>
      ) : null}
    </>
  );
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])';

function focusables(root: HTMLElement | null): HTMLElement[] {
  return root ? Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)) : [];
}

/**
 * The rail of a phone: a 256 px drawer from the left, opened from the header. It holds the focus while open (Tab goes
 * round inside it), closes on Escape, on the scrim and on a chosen section, and gives the focus back to the button
 * that opened it.
 */
export function NavDrawer({
  onClose,
  returnFocusRef,
  instance,
}: {
  onClose: () => void;
  returnFocusRef: RefObject<HTMLButtonElement | null>;
  instance: InstanceLine;
}) {
  const { t } = useTranslation();
  const panel = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const opener = returnFocusRef.current;
    const root = document.documentElement;
    const overflow = root.style.overflow;
    root.style.overflow = "hidden";
    const here = panel.current?.querySelector<HTMLElement>('[aria-current="page"]');
    (here ?? focusables(panel.current)[0] ?? panel.current)?.focus();
    return () => {
      root.style.overflow = overflow;
      opener?.focus();
    };
  }, [returnFocusRef]);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key !== "Tab") return;
    const list = focusables(panel.current);
    if (list.length === 0) {
      e.preventDefault();
      return;
    }
    const first = list[0];
    const last = list[list.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === panel.current)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return (
    <>
      <div aria-hidden="true" className="sh-scrim" onClick={onClose} />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-label={t("nav.sections")}
        tabIndex={-1}
        className="sh-drawer"
        onKeyDown={onKeyDown}
      >
        <div className="sh-drawer-head">
          <Wordmark />
          <button type="button" className="sh-icon-btn sh-focus" aria-label={t("common.close")} onClick={onClose}>
            <Icon name="close" size={16} />
          </button>
        </div>
        <Instance instance={instance} />
        <NavLinks onNavigate={onClose} />
      </div>
    </>
  );
}
