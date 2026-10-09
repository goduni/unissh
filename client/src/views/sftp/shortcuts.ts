// The file list's side of the `sftp` shortcut scope: which registry action a key
// event means while a list has focus, when it runs, and what it applies to. The
// bindings themselves live in the registry (support/keybindings); the handlers
// live in ViewSftp.

import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { matchesShortcut } from "@/store/shortcuts";
import { SFTP_ACTIONS, sftpShortcutId, type SftpAction } from "@/support/keybindings";
import type { Entry } from "@/store/sftp-types";
import { shownNames } from "./sortfilter";

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

type ListKeyEvent = Pick<ReactKeyboardEvent, "target" | "currentTarget" | "defaultPrevented" | "nativeEvent" | "repeat" | "preventDefault">;

/** The action a key means in a file list — only for keys pressed on the list
 *  itself, never ones bubbling up from a control inside a row. */
export function fileListShortcut(e: Pick<ListKeyEvent, "target" | "currentTarget" | "defaultPrevented" | "nativeEvent">): SftpAction | null {
  if (e.target !== e.currentTarget || e.defaultPrevented) return null;
  return SFTP_ACTIONS.find((action) => matchesShortcut(e.nativeEvent, sftpShortcutId(action))) ?? null;
}

/** Runs the action a key is bound to; false when the key is not a shortcut and
 *  stays with the list's fixed navigation. A held key is swallowed without
 *  running again, except paging: nothing else is safe to repeat (F5 would queue
 *  the transfer once per repeat, Backspace would climb several levels). */
export function runFileListShortcut(e: ListKeyEvent, handler: ListShortcutHandler, cursor: () => ListCursor): boolean {
  const action = fileListShortcut(e);
  if (!action) return false;
  const held = e.repeat && action !== "pageUp" && action !== "pageDown";
  if (held || handler(action, cursor()) !== false) e.preventDefault();
  return true;
}

/** The entries an action on `entry` applies to: the whole selection when the
 *  entry is part of a multi-selection, else the entry alone. With the cursor on
 *  ".." there is no entry, and the action takes the selection — but only what
 *  the filter still shows, since the selection outlives a filter change. */
export function actionTargets(
  entry: Entry | null,
  slot: { entries: Entry[]; filter: string; selection: ReadonlySet<string>; selectedEntries: () => Entry[] },
): Entry[] {
  if (!entry) {
    const shown = shownNames(slot.entries, slot.filter);
    return slot.selectedEntries().filter((e) => shown.has(e.name));
  }
  return slot.selection.has(entry.name) && slot.selection.size > 1 ? slot.selectedEntries() : [entry];
}
