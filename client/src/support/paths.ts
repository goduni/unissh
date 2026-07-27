// Where a "save this file" dialog should open.

import { downloadDir, homeDir, join } from "@tauri-apps/api/path";

/** An ABSOLUTE default path for an export dialog, in the user's Downloads folder.
 *
 *  A bare filename leaves the folder to the native panel, which reuses whichever
 *  one it was last in — process-wide and across unrelated dialogs. Importing an
 *  `ssh_config` (that dialog opens at `~/.ssh`, correctly) therefore left every
 *  later export pointing at `~/.ssh`, which is both a surprising place to write
 *  a recording and a directory nothing should be dropped into by accident.
 *
 *  Falls back to the home directory, then to the bare name — a default path is a
 *  convenience, and failing to compute one must not stop the export. */
export async function exportPath(name: string): Promise<string> {
  for (const dir of [downloadDir, homeDir]) {
    try {
      return await join(await dir(), name);
    } catch {
      /* try the next one */
    }
  }
  return name;
}
