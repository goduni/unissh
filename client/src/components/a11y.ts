// Shared keyboard/a11y behaviour for overlays and dropdown menus, extracted from
// Modal.tsx so MShell / ConfirmDialog get the exact same treatment instead of
// re-implementing (or skipping) it.

import { useEffect, useRef, type KeyboardEvent as ReactKeyboardEvent } from "react";

/** Enter/Space activation for composite rows/cards that carry role="button"
 *  (they can't be real <button>s because they nest other interactive controls).
 *  Ignores keys bubbling up from those nested controls. */
export function pressActivate(fn: () => void) {
  return (e: ReactKeyboardEvent) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fn();
    }
  };
}

// Open dialogs, innermost last. Escape only closes the topmost one, so a
// confirm raised from inside a modal doesn't take the modal down with it.
const dialogStack: (() => void)[] = [];

/** Capture-phase command handlers must not act on views behind a dialog. */
export function hasOpenDialog(): boolean {
  return dialogStack.length > 0;
}

/** Escape closes the dialog. Register once per mounted dialog — the component
 *  must only be mounted while the dialog is actually open. */
export function useDialogKeys(onClose: () => void) {
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const entry = () => closeRef.current();
    dialogStack.push(entry);
    const onKey = (e: KeyboardEvent) => {
      // Convention: an overlay/control that consumes Escape must preventDefault()
      // so it doesn't also close the dialog stack beneath it (e.g. an inline
      // sub-input, the command palette, a context menu). Single guard, one rule.
      if (e.defaultPrevented) return;
      if (e.key === "Escape" && dialogStack[dialogStack.length - 1] === entry) entry();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      const i = dialogStack.indexOf(entry);
      if (i >= 0) dialogStack.splice(i, 1);
      document.removeEventListener("keydown", onKey);
    };
  }, []);
}

/** Move focus into the dialog on open and restore it on close. Focuses the
 *  first `target` match inside the returned ref (or the ref'd element itself,
 *  which then needs tabIndex={-1}); pass a ref to focus a specific control
 *  (e.g. the Cancel button of a danger confirm). */
export function useDialogFocus<T extends HTMLElement>(
  target: string | React.RefObject<HTMLElement | null> = "input, textarea",
) {
  const ref = useRef<T>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const el =
      typeof target === "string"
        ? (ref.current?.querySelector<HTMLElement>(target) ?? ref.current)
        : target.current;
    el?.focus();
    return () => prev?.focus?.();
    // mount-only: the dialog picks its focus target once, on open
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return ref;
}

/** Dropdown-menu behaviour (vault switcher, sort menu, bulk actions…):
 *  - closes on outside click AND Escape (Escape returns focus to the trigger);
 *  - moves focus to the checked row (or the first row) on open;
 *  - ArrowUp/ArrowDown cycle the [role^="menuitem"] rows.
 *  `ref` must wrap both the trigger (marked with aria-haspopup) and the menu. */
export function useMenu(open: boolean, onClose: () => void, ref: React.RefObject<HTMLElement | null>) {
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    const root = ref.current;
    const rows = () =>
      Array.from(root?.querySelectorAll<HTMLElement>('[role^="menuitem"]') ?? []);
    (root?.querySelector<HTMLElement>('[role^="menuitem"][aria-checked="true"]') ?? rows()[0])?.focus();
    const onDown = (e: MouseEvent) => {
      if (root && !root.contains(e.target as Node)) closeRef.current();
    };
    const onKey = (e: KeyboardEvent) => {
      const ae = document.activeElement as HTMLElement | null;
      if (e.key === "Escape") {
        // capture + stop so an underlying dialog doesn't also close
        e.stopPropagation();
        closeRef.current();
        root?.querySelector<HTMLElement>("[aria-haspopup]")?.focus();
      } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        if (ae && (ae.tagName === "INPUT" || ae.tagName === "TEXTAREA")) return;
        const list = rows();
        if (!list.length) return;
        e.preventDefault();
        const i = list.indexOf(ae as HTMLElement);
        const next =
          e.key === "ArrowDown" ? (i + 1) % list.length : i <= 0 ? list.length - 1 : i - 1;
        list[next]?.focus();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey, true);
    };
  }, [open, ref]);
}
