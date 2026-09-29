import { create } from "zustand";
import { isMac } from "@/bridge/platform";
import { ariaBinding, bindingsFor, conflictsFor, formatBinding, matchesBinding, sameBinding, sanitizeOverrides, type KeyBinding, type ShortcutOverrides } from "@/support/keybindings";

const storageKey = () => `unissh.shortcuts.v1.${isMac() ? "mac" : "pc"}`;
function load(): ShortcutOverrides {
  try { return sanitizeOverrides(JSON.parse(localStorage.getItem(storageKey()) ?? "{}")); }
  catch { return {}; }
}
interface ShortcutState {
  overrides: ShortcutOverrides;
  recording: boolean;
  storageError: boolean;
  setRecording: (recording: boolean) => void;
  assign: (id: string, bindings: KeyBinding[] | null, replace?: boolean) => boolean;
  resetAll: () => void;
}
export const useShortcuts = create<ShortcutState>((set, get) => {
  const persist = (overrides: ShortcutOverrides) => {
    let storageError = false;
    try { localStorage.setItem(storageKey(), JSON.stringify(overrides)); }
    catch { storageError = true; }
    set({ overrides, storageError });
  };
  return {
    overrides: load(), recording: false, storageError: false,
    setRecording: (recording) => set({ recording }),
    assign: (id, bindings, replace = false) => {
      const overrides = { ...get().overrides };
      if (bindings === null) delete overrides[id];
      else overrides[id] = bindings;
      const proposed = bindingsFor(id, overrides, isMac());
      const conflicts = conflictsFor(id, proposed, overrides, isMac());
      if (conflicts.length && !replace) return false;
      for (const other of conflicts) {
        overrides[other.id] = bindingsFor(other.id, overrides, isMac()).filter((b) => !proposed.some((p) => sameBinding(b, p)));
      }
      persist(overrides);
      return true;
    },
    resetAll: () => persist({}),
  };
});
export function matchesShortcut(e: KeyboardEvent, id: string): boolean {
  const { overrides, recording } = useShortcuts.getState();
  return !recording && bindingsFor(id, overrides, isMac()).some((b) => matchesBinding(e, b));
}
export function useShortcutLabel(id: string): string {
  const overrides = useShortcuts((s) => s.overrides);
  return bindingsFor(id, overrides, isMac()).slice(0, 1).map((b) => formatBinding(b, isMac())).join(" / ");
}

export function useShortcutAria(id: string): string | undefined {
  const overrides = useShortcuts((s) => s.overrides);
  return bindingsFor(id, overrides, isMac()).map(ariaBinding).join(" ") || undefined;
}
