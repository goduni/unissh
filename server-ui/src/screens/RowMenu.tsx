import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent,
} from "react";
import { createPortal } from "react-dom";
import { Icon, type IconName } from "../ui/icons";
import "./identity.css";

export interface RowMenuItem {
  key: string;
  label: string;
  icon?: IconName;
  /** The item that removes or revokes: its word in red. It should still ask before it acts. */
  destructive?: boolean;
  /** Shown, reachable by the arrows, but does nothing (announced as unavailable). */
  disabled?: boolean;
  onSelect: () => void;
}

/** Where the focus goes as the menu opens: the first or last item from the keyboard, the menu itself from a pointer. */
type Landing = "first" | "last" | "menu";

/** Space between the trigger and the menu, and the least the menu keeps from the viewport's edges. */
const GAP = 4;
const EDGE = 8;

/**
 * The last cell of a row (DESIGN.md: Tables): a 28 px ghost icon button (⋯) that opens a small menu of what can be
 * done to the row: --popover on a --border hairline, 7 px corners, 4 px of padding; items 5 px corners, --elevated on
 * focus, the destructive one in red.
 *
 * The menu floats in a portal, so the table's clipped cells and its sideways scroll cannot cut it; it is placed under
 * the trigger's right edge, above it when there is no room below, and follows it as the page or the table scrolls.
 *
 * A menu button by the ARIA pattern: Enter, Space or the arrows open it, the arrows, Home and End walk it, Escape
 * closes it and gives the focus back to the button, Tab closes it and moves on. Choosing an item gives the focus back
 * to the button first, so a dialog the item opens returns the focus there when it closes.
 */
export function RowMenu({ label, items }: { label: string; items: RowMenuItem[] }) {
  const [open, setOpen] = useState(false);
  const landing = useRef<Landing>("menu");
  const trigger = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const triggerId = useId();
  const menuId = useId();

  const list = () => Array.from(menu.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? []);

  // Under the trigger's right edge; above it when the room below is short and the room above is not.
  const place = useCallback(() => {
    const t = trigger.current;
    const m = menu.current;
    if (!t || !m) return;
    const r = t.getBoundingClientRect();
    const h = m.offsetHeight;
    const vh = window.innerHeight;
    const below = r.bottom + GAP;
    const top = below + h > vh - EDGE && r.top - GAP - h >= EDGE ? r.top - GAP - h : below;
    const right = Math.max(EDGE, document.documentElement.clientWidth - r.right);
    m.style.top = `${Math.round(top)}px`;
    m.style.right = `${Math.round(right)}px`;
  }, []);

  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);

  useEffect(() => {
    if (!open) return;
    const all = list();
    const target = landing.current === "first" ? all[0] : landing.current === "last" ? all[all.length - 1] : menu.current;
    target?.focus({ preventScroll: true });
    // A press outside closes the menu and leaves the focus where the press put it.
    const onPointerDown = (e: PointerEvent) => {
      const node = e.target as Node;
      if (menu.current?.contains(node) || trigger.current?.contains(node)) return;
      setOpen(false);
    };
    // Any scroll (the page, or the table sideways) and any resize: the menu stays by its trigger.
    const onMove = () => {
      if (!trigger.current?.isConnected) {
        setOpen(false);
        return;
      }
      place();
    };
    document.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("scroll", onMove, true);
    window.addEventListener("resize", onMove);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("scroll", onMove, true);
      window.removeEventListener("resize", onMove);
    };
  }, [open, place]);

  const openAt = (where: Landing) => {
    landing.current = where;
    setOpen(true);
  };
  const close = () => {
    setOpen(false);
    trigger.current?.focus();
  };

  const onTriggerClick = (e: MouseEvent<HTMLButtonElement>) => {
    // The row may be pressable itself; this press is the menu's.
    e.stopPropagation();
    if (open) {
      setOpen(false);
      return;
    }
    // `detail` is 0 when Enter or Space pressed the button: then the first item takes the focus.
    openAt(e.detail === 0 ? "first" : "menu");
  };
  const onTriggerKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      openAt(e.key === "ArrowDown" ? "first" : "last");
    }
  };

  const onMenuKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const all = list();
    const at = all.indexOf(document.activeElement as HTMLElement);
    const move = (to: number) => {
      e.preventDefault();
      all[(to + all.length) % all.length]?.focus();
    };
    switch (e.key) {
      case "ArrowDown":
        move(at < 0 ? 0 : at + 1);
        break;
      case "ArrowUp":
        move(at < 0 ? all.length - 1 : at - 1);
        break;
      case "Home":
        move(0);
        break;
      case "End":
        move(all.length - 1);
        break;
      case "Escape":
        e.preventDefault();
        e.stopPropagation();
        close();
        break;
      case "Tab":
        // Back on the button before the browser moves on, so Tab leaves from where the menu was opened.
        trigger.current?.focus();
        setOpen(false);
        break;
    }
  };

  // The pointer moves the focus, so one item is lit at a time whether it is walked by keys or by the mouse.
  const follow = (e: MouseEvent<HTMLElement>) => {
    if (document.activeElement !== e.currentTarget) e.currentTarget.focus();
  };

  const choose = (item: RowMenuItem) => {
    if (item.disabled) return;
    close();
    item.onSelect();
  };

  return (
    <>
      <button
        ref={trigger}
        id={triggerId}
        type="button"
        title={label}
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        className="u-btn u-btn--ghost u-iconbtn id-rowmenu-trigger"
        onClick={onTriggerClick}
        onKeyDown={onTriggerKeyDown}
      >
        <Icon name="more" size={16} />
      </button>

      {open
        ? createPortal(
            <div
              ref={menu}
              id={menuId}
              role="menu"
              aria-labelledby={triggerId}
              tabIndex={-1}
              className="id-rowmenu"
              onKeyDown={onMenuKeyDown}
              // Events of a portal still bubble through the React tree: keep them off the row.
              onClick={(e) => e.stopPropagation()}
            >
              {items.map((item) => (
                <button
                  key={item.key}
                  type="button"
                  role="menuitem"
                  tabIndex={-1}
                  aria-disabled={item.disabled || undefined}
                  className={item.destructive ? "id-rowmenu__item id-rowmenu__item--destructive" : "id-rowmenu__item"}
                  onMouseMove={follow}
                  onClick={() => choose(item)}
                >
                  {item.icon ? <Icon name={item.icon} size={16} /> : null}
                  {item.label}
                </button>
              ))}
            </div>,
            document.body,
          )
        : null}
    </>
  );
}
