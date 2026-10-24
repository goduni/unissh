import { useEffect, useId, useRef, useState, type KeyboardEvent, type MouseEvent } from "react";
import { useTranslation } from "react-i18next";
import { lockKeyset } from "../api/auth-service";
import { usePrefs } from "../store/prefs";
import { useSession } from "../store/session";
import { Icon } from "../ui/icons";
import { truncId } from "../util/bytes";
import { Glyph } from "./glyphs";

type Mode = ReturnType<typeof usePrefs.getState>["mode"];

/** The theme is the reader's choice of three, kept per browser: light, dark, or as the system has it. */
const THEMES: { value: Mode; label: string }[] = [
  { value: "light", label: "settings.light" },
  { value: "dark", label: "settings.dark" },
  { value: "auto", label: "settings.system" },
];

/** Two visible letters of the admin's label (a handle, or the short account id). */
function initialsOf(label: string): string {
  const letters = Array.from(label).filter((ch) => /[\p{L}\p{N}]/u.test(ch));
  return letters.slice(0, 2).join("").toUpperCase() || "·";
}

/** Where the focus goes as the menu opens: the first or last item from the keyboard, the menu itself from a pointer. */
type Landing = "first" | "last" | "menu";

/**
 * The signed-in admin, at the header's right: round blue initials, the label in mono, a chevron. The menu says who is
 * signed in and that the keyset is unlocked in this tab, switches the language, chooses the theme (three radio items)
 * and locks: the keyset and the Bearer are wiped from memory and the panel returns to sign-in.
 *
 * A menu button by the ARIA pattern: Enter, Space or the arrows open it, the arrows, Home and End walk it, Escape
 * closes it and gives the focus back to the button, Tab closes it and moves on.
 */
export function AccountMenu() {
  const { t } = useTranslation();
  const label = useSession((s) => s.adminLabel) ?? "—";
  const accountId = useSession((s) => s.adminAccountId);
  const mode = usePrefs((s) => s.mode);
  const setMode = usePrefs((s) => s.setMode);
  const lang = usePrefs((s) => s.lang);
  const setLang = usePrefs((s) => s.setLang);

  const [open, setOpen] = useState(false);
  const landing = useRef<Landing>("menu");
  const trigger = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const triggerId = useId();
  const menuId = useId();
  const themeId = useId();

  const items = () => Array.from(menu.current?.querySelectorAll<HTMLElement>('[role^="menuitem"]') ?? []);

  useEffect(() => {
    if (!open) return;
    const list = Array.from(menu.current?.querySelectorAll<HTMLElement>('[role^="menuitem"]') ?? []);
    const target =
      landing.current === "first" ? list[0] : landing.current === "last" ? list[list.length - 1] : menu.current;
    target?.focus();
    // A press outside closes the menu and leaves the focus where the press put it.
    const onPointerDown = (e: PointerEvent) => {
      const node = e.target as Node;
      if (menu.current?.contains(node) || trigger.current?.contains(node)) return;
      setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  const openAt = (where: Landing) => {
    landing.current = where;
    setOpen(true);
  };
  const close = () => {
    setOpen(false);
    trigger.current?.focus();
  };

  const onTriggerClick = (e: MouseEvent<HTMLButtonElement>) => {
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
    const list = items();
    const at = list.indexOf(document.activeElement as HTMLElement);
    const move = (to: number) => {
      e.preventDefault();
      list[(to + list.length) % list.length]?.focus();
    };
    switch (e.key) {
      case "ArrowDown":
        move(at < 0 ? 0 : at + 1);
        break;
      case "ArrowUp":
        move(at < 0 ? list.length - 1 : at - 1);
        break;
      case "Home":
        move(0);
        break;
      case "End":
        move(list.length - 1);
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

  const shortId = accountId ? truncId(accountId) : null;
  const otherLang = lang === "ru" ? "en" : "ru";

  return (
    <div className="sh-menu-anchor">
      <button
        ref={trigger}
        id={triggerId}
        type="button"
        className="sh-account sh-focus"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={`${t("settings.account")}: ${label}`}
        onClick={onTriggerClick}
        onKeyDown={onTriggerKeyDown}
      >
        <span aria-hidden="true" className="sh-initials">
          {initialsOf(label)}
        </span>
        <span aria-hidden="true" className="sh-account-label">
          {label}
        </span>
        <Icon name="chevronDown" size={14} color="var(--muted-foreground)" />
      </button>

      {open ? (
        <div
          ref={menu}
          id={menuId}
          role="menu"
          aria-labelledby={triggerId}
          tabIndex={-1}
          className="sh-menu"
          onKeyDown={onMenuKeyDown}
        >
          <div className="sh-menu-head">
            <span className="sh-menu-who">{label}</span>
            {shortId && shortId !== label ? <span className="sh-menu-sub">{shortId}</span> : null}
            <span className="sh-badge">
              <span aria-hidden="true" className="sh-badge-dot" />
              {t("access.keysetUnlocked")}
            </span>
          </div>

          <div role="separator" className="sh-menu-sep" />
          <button
            type="button"
            role="menuitem"
            tabIndex={-1}
            className="sh-menu-item"
            lang={otherLang}
            onMouseMove={follow}
            onClick={() => {
              setLang(otherLang);
              close();
            }}
          >
            <Glyph name="languages" />
            {t("settings.switchLang")}
          </button>

          <div role="separator" className="sh-menu-sep" />
          <div role="group" aria-labelledby={themeId}>
            <div id={themeId} className="sh-menu-label">
              {t("settings.theme")}
            </div>
            {THEMES.map((one) => (
              <button
                key={one.value}
                type="button"
                role="menuitemradio"
                aria-checked={mode === one.value}
                tabIndex={-1}
                className="sh-menu-item"
                onMouseMove={follow}
                onClick={() => {
                  setMode(one.value);
                  close();
                }}
              >
                <span aria-hidden="true" className="sh-menu-radio" data-checked={mode === one.value} />
                {t(one.label)}
              </button>
            ))}
          </div>

          <div role="separator" className="sh-menu-sep" />
          <button
            type="button"
            role="menuitem"
            tabIndex={-1}
            className="sh-menu-item"
            onMouseMove={follow}
            onClick={() => {
              setOpen(false);
              lockKeyset();
            }}
          >
            <Icon name="lock" size={16} />
            {t("access.lockSignOut")}
          </button>
        </div>
      ) : null}
    </div>
  );
}
