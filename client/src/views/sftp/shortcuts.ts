// The file list's side of the `sftp` shortcut scope: which registry action a key
// event means while a list has focus, what that action applies to, and how its
// keys are printed in a menu. The bindings themselves live in the registry
// (support/keybindings); the handlers live in ViewSftp.

import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { isMac } from "@/bridge/platform";
import { useShortcuts } from "@/store/shortcuts";
import {
  ariaBinding,
  bindingsFor,
  formatBinding,
  sftpActionFor,
  sftpShortcutId,
  type ShortcutOverrides,
  type SftpAction,
} from "@/support/keybindings";
import type { Entry } from "@/store/sftp-types";

/** What a list hands to a shortcut handler: the row under its cursor (null on
 *  ".."), a point to anchor a menu at, and its own page-wise cursor movement. */
export interface ListCursor {
  entry: Entry | null;
  x: number;
  y: number;
  page: (dir: 1 | -1) => void;
}

/** Returning false leaves the key to the browser (e.g. Tab with no other pane). */
export type ListShortcutHandler = (action: SftpAction, cursor: ListCursor) => void | false;

/** The action a key means in a file list — only for keys pressed on the list
 *  itself, never ones bubbling up from a control inside a row. */
export function fileListShortcut(
  e: Pick<ReactKeyboardEvent, "target" | "currentTarget" | "defaultPrevented" | "nativeEvent">,
): SftpAction | null {
  if (e.target !== e.currentTarget || e.defaultPrevented) return null;
  const { overrides, recording } = useShortcuts.getState();
  return recording ? null : sftpActionFor(e.nativeEvent, overrides, isMac());
}

/** The entries an action on `entry` applies to: the whole selection when the
 *  entry is part of a multi-selection, else the entry alone. With the cursor on
 *  ".." there is no entry, and the selection is all there is to act on. */
export function actionTargets(
  entry: Entry | null,
  slot: { selection: ReadonlySet<string>; selectedEntries: () => Entry[] },
): Entry[] {
  if (!entry) return slot.selectedEntries();
  return slot.selection.has(entry.name) && slot.selection.size > 1 ? slot.selectedEntries() : [entry];
}

/** Menu-item hint for an action: its first bound key, and all of them for AT. */
export function menuKeys(action: SftpAction, overrides: ShortcutOverrides): { keys?: string; ariaKeys?: string } {
  const bindings = bindingsFor(sftpShortcutId(action), overrides, isMac());
  if (!bindings.length) return {};
  return { keys: formatBinding(bindings[0], isMac()), ariaKeys: bindings.map(ariaBinding).join(" ") };
}
