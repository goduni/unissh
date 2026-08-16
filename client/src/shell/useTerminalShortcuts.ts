// Desktop terminal keyboard shortcuts. Installed by ViewTerminal (desktop only);
// the listener is capture-phase so it intercepts a combo before xterm forwards it
// to the shell, and only handled combos preventDefault/stopPropagation — plain
// typing (and shell Ctrl+C / Ctrl+D EOF) fall straight through.
//
// Modifier scheme (avoids clobbering the shell):
//   macOS      → Cmd (metaKey)
//   others     → Ctrl+Shift  (so a bare Ctrl+<key> still reaches the shell)
// Shortcuts: new tab (T), local shell (⇧S), close pane/tab (W), split right (D)
//   / down (E), jump to tab N (1..8, 9=last), focus prev/next pane (← →). Tab
//   cycling is Ctrl+Tab / Ctrl+Shift+Tab on every platform. ↑ ↓ belong to
//   ViewTerminal's prompt jumping — see paneFocusStep.
//
// The local shell is ⌘⇧S / Ctrl+Shift+S, and both halves of that are deliberate.
// Not L (the obvious mnemonic): ⌘L / Ctrl+Shift+L is "lock the instance", and a
// security control does not give up its key to a convenience. S for shell, with
// Shift because a bare ⌘S / Ctrl+S saves in the SFTP file editor.

import { useEffect } from "react";
import { useApp, layoutPaneOrder } from "@/store/app";
import { openLocalTerminal } from "@/store/ctx";
import { hasAppModifier } from "@/support/hotkeys";

/** Which way ← / → move the focus, or null for a key that is not one of them.
 *
 *  ↑ / ↓ are deliberately absent. They were aliases of ← / → here — the pane
 *  order is flat, so left/right already reach every pane — while ViewTerminal
 *  binds them to prompt jumping (OSC 133). This listener is capture-phase on
 *  `window` and stops propagation, so accepting them meant xterm never saw the
 *  key and the jump silently became a pane switch in any tab with two panes.
 *  The rule is now the same on every platform: ← → move panes, ↑ ↓ move by
 *  prompt. */
export function paneFocusStep(key: string): -1 | 1 | null {
  if (key === "ArrowLeft") return -1;
  if (key === "ArrowRight") return 1;
  return null;
}

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

export function useTerminalShortcuts(enabled: boolean): void {
  useEffect(() => {
    if (!enabled) return;
    const onKey = (e: KeyboardEvent) => {
      const st = useApp.getState();
      // The same modifier rule App.tsx and the terminal's own key handler use,
      // from one place — App.tsx has to ask about it to know when to stand down.
      const chord = hasAppModifier(e);

      // A shell on this machine opens from anywhere: it creates its own tab and
      // routes to the terminal, so requiring you to already be there would make
      // the chord useless exactly where it is most useful. Every other shortcut
      // here acts on an existing tab and stays route-scoped.
      //
      // `e.code` as well as `e.key`, because on macOS ⇧ turns the key into "S"
      // and on some layouts into something else entirely.
      if (
        chord &&
        e.shiftKey &&
        (e.key.toLowerCase() === "s" || e.code === "KeyS") &&
        !inTextField(e.target)
      ) {
        e.preventDefault();
        e.stopPropagation();
        void openLocalTerminal();
        return;
      }

      if (st.route !== "terminal") return;
      const tabs = st.terminals;
      const active = tabs.find((t) => t.id === st.activeTermId) ?? tabs[tabs.length - 1];

      // Cycle tabs: Ctrl+Tab / Ctrl+Shift+Tab (all platforms).
      if (e.ctrlKey && e.key === "Tab") {
        if (!tabs.length) return;
        e.preventDefault();
        e.stopPropagation();
        const idx = active ? tabs.findIndex((t) => t.id === active.id) : -1;
        const n = tabs.length;
        const next = e.shiftKey ? (idx - 1 + n) % n : (idx + 1) % n;
        st.setActiveTerm(tabs[next].id);
        return;
      }

      if (!chord) return;

      // Jump to tab N (1..8), 9 = last. e.code so Shift+digit symbols still map.
      const digit = /^Digit([1-9])$/.exec(e.code);
      if (digit) {
        e.preventDefault();
        e.stopPropagation();
        if (!tabs.length) return;
        const n = parseInt(digit[1], 10);
        const target = n === 9 ? tabs[tabs.length - 1] : tabs[n - 1];
        if (target) st.setActiveTerm(target.id);
        return;
      }

      const k = e.key.toLowerCase();

      // New tab → open the inline host picker.
      if (k === "t") {
        e.preventDefault();
        e.stopPropagation();
        st.requestNewTab();
        return;
      }

      if (!active) return; // the rest need an active tab

      if (k === "w") {
        e.preventDefault();
        e.stopPropagation();
        st.closePane(active.id, active.activePaneId);
        return;
      }
      if (k === "d") {
        e.preventDefault();
        e.stopPropagation();
        st.splitPane(active.id, active.activePaneId, "row");
        return;
      }
      if (k === "e") {
        e.preventDefault();
        e.stopPropagation();
        st.splitPane(active.id, active.activePaneId, "col");
        return;
      }
      const step = paneFocusStep(e.key);
      if (step) {
        const order = layoutPaneOrder(active.layout);
        if (order.length < 2) return;
        e.preventDefault();
        e.stopPropagation();
        const cur = order.indexOf(active.activePaneId);
        const nxt = (cur + step + order.length) % order.length;
        st.setActivePane(active.id, order[nxt]);
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [enabled]);
}
