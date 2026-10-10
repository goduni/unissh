import type { TooLargeItem } from "./types";

/** How many refused items a message names before it counts the rest. */
const NAMED = 3;

/** The items a sync server refused as too large, as one line for a message:
 *  each item with its vault and size, the first few by name and the rest as a
 *  count. Empty when nothing was refused. */
export function tooLargeSummary(items: TooLargeItem[]): string {
  if (items.length === 0) return "";
  const named = items.slice(0, NAMED).map((it) => {
    const mb = (it.bytes / (1024 * 1024)).toFixed(1);
    return `“${it.itemId}” (${it.vaultName || it.vaultId}, ${mb} MB)`;
  });
  const rest = items.length - named.length;
  return rest > 0 ? `${named.join(", ")} +${rest}` : named.join(", ");
}
