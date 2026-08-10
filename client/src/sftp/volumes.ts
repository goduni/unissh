// Pure helpers for the local pane's volume (drive) picker. Kept out of the
// component because the matching is the part that can be wrong: mount points
// nest, Windows mixes separators and ignores case, and picking the wrong volume
// mislabels the button on every path change.

import type { LocalVolume } from "@/bridge/types";

/** "C:", "C:\", "d:/" — a Windows drive root, which is already its own name. */
export function isWinRoot(path: string): boolean {
  return /^[A-Za-z]:[\\/]?$/.test(path);
}

/** Trailing separator removed, except for a bare unix root. */
export function trimTrailing(path: string): string {
  return path.length > 1 ? path.replace(/[\\/]+$/, "") : path;
}

/** Short name for a volume: the drive letter on Windows, else the OS-provided
 *  label, else the last path segment ("USB" for /media/me/USB), else the path. */
export function volumeName(v: LocalVolume): string {
  if (isWinRoot(v.path)) return trimTrailing(v.path);
  if (v.label) return v.label;
  const seg = v.path.split(/[\\/]/).filter(Boolean).pop();
  return seg || v.path;
}

/** The volume `cwd` sits on: the DEEPEST mount point that is a prefix of it.
 *  Deepest, not first, because mounts nest — with "/" and "/home" on separate
 *  disks, /home/me belongs to the second one. Comparison is case-insensitive
 *  and separator-agnostic so a Windows "c:/Users" matches the "C:\" volume. */
export function volumeOf(volumes: LocalVolume[], cwd: string): LocalVolume | null {
  if (!cwd) return null;
  const norm = (s: string) => s.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  const c = norm(cwd);
  let best: LocalVolume | null = null;
  for (const v of volumes) {
    const root = norm(v.path);
    // root === "" is unix "/", whose children all start with a single "/".
    if (c === root || c.startsWith(`${root}/`)) {
      if (!best || norm(best.path).length < root.length) best = v;
    }
  }
  return best;
}
