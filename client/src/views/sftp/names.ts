// Shared name validation for the SFTP entry dialogs (new folder, new file,
// rename). Kept out of the components so the rules are testable and identical
// everywhere — a name the dialog accepts must be one the server can take.

export type NameError = "empty" | "dup" | "invalid" | "unchanged" | null;

export interface NameCheck {
  /** The trimmed name to submit. Only meaningful when `error` is null. */
  name: string;
  error: NameError;
}

/**
 * @param raw      what the user typed
 * @param existing names already in the directory
 * @param initial  the current name, when renaming — leaving it untouched is a
 *                 no-op rather than a collision with itself
 */
export function validateEntryName(raw: string, existing: string[], initial?: string): NameCheck {
  const name = raw.trim();
  if (name.length === 0) return { name, error: "empty" };
  if (initial !== undefined && name === initial) return { name, error: "unchanged" };
  if (existing.includes(name)) return { name, error: "dup" };
  // Separators would silently retarget the operation at another directory, and
  // "." / ".." always exist, so the server would reject them anyway.
  if (/[/\\]/.test(name) || name === "." || name === "..") return { name, error: "invalid" };
  return { name, error: null };
}
