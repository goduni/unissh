// Capture-phase tab/pane commands. Only handled events are consumed, so shell
// input remains untouched. Defaults and user assignments live in keybindings.

import { hasOpenDialog } from "@/components/a11y";
import { useEffect } from "react";
import { useApp, layoutPaneOrder } from "@/store/app";
import { openLocalTerminal } from "@/store/ctx";
import { matchesShortcut, useShortcuts } from "@/store/shortcuts";

/** True for a real text field the user is typing into.
 *
 *  xterm's hidden helper textarea is excluded on purpose: it is not a text field
 *  in this sense, it *is* the terminal, and the shortcuts have to work there. */
function inTextField(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el) return false;
  if (el.isContentEditable || el.tagName === "INPUT") return true;
  return el.tagName === "TEXTAREA" && !el.classList.contains("xterm-helper-textarea");
}

export function handleTerminalShortcut(e: KeyboardEvent): void {
  const st = useApp.getState();
  if (e.defaultPrevented || e.isComposing || useShortcuts.getState().recording || !st.unlocked
    || hasOpenDialog() || st.importing || st.groupsModal || st.settingsOpen || st.modal || st.confirm || st.palette || st.shortcuts || inTextField(e.target)) return;
  const consume = () => { e.preventDefault(); e.stopPropagation(); };
  if (matchesShortcut(e, "localTerminal")) {
    consume();
    if (!e.repeat) void openLocalTerminal();
    return;
  }
  if (st.route !== "terminal") return;
  const tabs = st.terminals;
  const active = tabs.find((t) => t.id === st.activeTermId) ?? tabs[tabs.length - 1];

  // Cycle tabs: Ctrl+Tab / Ctrl+Shift+Tab (all platforms).
  if (matchesShortcut(e, "tabNext") || matchesShortcut(e, "tabPrev")) {
    if (!tabs.length) return;
    e.preventDefault();
    e.stopPropagation();
    const idx = active ? tabs.findIndex((t) => t.id === active.id) : -1;
    const n = tabs.length;
    const next = matchesShortcut(e, "tabPrev") ? (idx - 1 + n) % n : (idx + 1) % n;
    st.setActiveTerm(tabs[next].id);
    return;
  }

  // Jump to tab N (1..8), 9 = last. e.code so Shift+digit symbols still map.
  const digit = Array.from({ length: 9 }, (_, i) => i + 1).find((n) => matchesShortcut(e, `tab.${n}`));
  if (digit) {
    e.preventDefault();
    e.stopPropagation();
    if (!tabs.length) return;
    const n = digit;
    const target = n === 9 ? tabs[tabs.length - 1] : tabs[n - 1];
    if (target) st.setActiveTerm(target.id);
    return;
  }

  // New tab → open the inline host picker.
  if (matchesShortcut(e, "terminal")) {
    e.preventDefault();
    e.stopPropagation();
    if (!e.repeat) st.requestNewTab();
    return;
  }

  if (!active) return; // the rest need an active tab

  if (matchesShortcut(e, "closePane")) {
    e.preventDefault();
    e.stopPropagation();
    if (!e.repeat) st.closePane(active.id, active.activePaneId);
    return;
  }
  if (matchesShortcut(e, "splitRight")) {
    e.preventDefault();
    e.stopPropagation();
    if (!e.repeat) st.splitPane(active.id, active.activePaneId, "row");
    return;
  }
  if (matchesShortcut(e, "splitDown")) {
    e.preventDefault();
    e.stopPropagation();
    if (!e.repeat) st.splitPane(active.id, active.activePaneId, "col");
    return;
  }
  const step = matchesShortcut(e, "panePrev") ? -1 : matchesShortcut(e, "paneNext") ? 1 : null;
  if (step) {
    const order = layoutPaneOrder(active.layout);
    if (order.length < 2) return;
    e.preventDefault();
    e.stopPropagation();
    const cur = order.indexOf(active.activePaneId);
    const nxt = (cur + step + order.length) % order.length;
    st.setActivePane(active.id, order[nxt]);
  }
}

export function useTerminalShortcuts(enabled: boolean): void {
  useEffect(() => {
    if (!enabled) return;
    window.addEventListener("keydown", handleTerminalShortcut, true);
    return () => window.removeEventListener("keydown", handleTerminalShortcut, true);
  }, [enabled]);
}
