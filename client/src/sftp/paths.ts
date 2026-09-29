// Pure path helpers for the SFTP views. Remote paths are always POSIX ("/"),
// regardless of the desktop OS — these operate on the remote side. Local-side
// path math goes through @tauri-apps/api/path in the LocalSource adapter.

/** Join a remote base dir with a child name, handling ".." (one level up) and
 *  the root edge cases. Port of the original ViewSftp.remoteJoin. */
export function remoteJoin(base: string, name: string): string {
  if (name === "..") return remoteParent(base);
  if (base === "/") return `/${name}`;
  return `${base.replace(/\/+$/, "")}/${name}`;
}

/** The parent directory of a remote path. "/" stays "/". */
export function remoteParent(path: string): string {
  const cut = path.replace(/\/+$/, "");
  const i = cut.lastIndexOf("/");
  return i <= 0 ? "/" : cut.slice(0, i);
}

/** Reject directory-entry names that could self-recurse or escape the tree:
 *  empty, "." , ".." , or anything containing a path separator. Server-supplied
 *  SFTP listing names MUST pass this before being joined or recursed into — "."
 *  is returned by most servers (infinite walk) and ".."/embedded slashes enable
 *  a path-traversal write outside the chosen destination. */
export function isSafeName(name: string): boolean {
  return name !== "" && name !== "." && name !== ".." && !name.includes("/") && !name.includes("\0");
}

/** Windows components have additional aliases and stream/device syntax. */
export function isPortableWindowsName(name: string): boolean {
  return isSafeName(name) && !/[\\<>:"|?*\x00-\x1f]/.test(name) && !/[. ]$/.test(name)
    && !/^(con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)/i.test(name);
}

export const foldName = (name: string): string => name.normalize("NFC").toLowerCase();

export interface Crumb {
  label: string;
  path: string;
}

/** Split a remote POSIX path into clickable breadcrumb segments, always led by
 *  the root. "/var/www" -> [{/,/}, {var,/var}, {www,/var/www}]. */
export function breadcrumbSegments(path: string): Crumb[] {
  const crumbs: Crumb[] = [{ label: "/", path: "/" }];
  const parts = path.split("/").filter(Boolean);
  let acc = "";
  for (const part of parts) {
    acc += `/${part}`;
    crumbs.push({ label: part, path: acc });
  }
  return crumbs;
}

/** Produce a non-colliding name by inserting " (n)" before the extension:
 *  "app.js" -> "app (2).js", "app (2).js" -> "app (3).js". Dotfiles and
 *  extensionless names get the suffix appended at the end. Used by the
 *  "keep both" conflict choice. */
export function dedupeName(name: string, existing: Iterable<string>): string {
  const taken = new Set(Array.from(existing, foldName));
  if (!taken.has(foldName(name))) return name;

  // Split off a real extension only (leading dot => treat whole name as stem).
  const dot = name.lastIndexOf(".");
  const hasExt = dot > 0;
  const stem = hasExt ? name.slice(0, dot) : name;
  const ext = hasExt ? name.slice(dot) : "";

  // If the stem already ends in " (k)", bump from there.
  const m = stem.match(/^(.*) \((\d+)\)$/);
  const baseStem = m ? m[1] : stem;
  let n = m ? parseInt(m[2], 10) + 1 : 2;

  let candidate = `${baseStem} (${n})${ext}`;
  while (taken.has(foldName(candidate))) {
    n += 1;
    candidate = `${baseStem} (${n})${ext}`;
  }
  return candidate;
}
