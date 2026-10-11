import { tDyn } from "@/i18n";
import { fmtSize } from "@/i18n/format";
import { ItemType, type TooLargeItem } from "./types";

/** How many refused items a message names before it counts the rest. */
const NAMED = 3;

/** `serverCloud.itemKind.*` key of an item type; anything else is "other". */
const KIND_KEY: Partial<Record<number, string>> = {
  [ItemType.SshKey]: "sshKey",
  [ItemType.SshCert]: "certificate",
  [ItemType.Connection]: "host",
  [ItemType.Password]: "password",
  [ItemType.Group]: "group",
  [ItemType.Note]: "note",
  [ItemType.Identity]: "identity",
  [ItemType.Binding]: "binding",
  [ItemType.Snippet]: "snippet",
  [ItemType.Recording]: "recording",
};

/** The items a sync server refused as too large, as one line for a message:
 *  each item by kind and id with its vault and size, the first few named and the
 *  rest counted. Empty when nothing was refused. The id is what the core has
 *  without decrypting the item — a recording's title is inside the very content
 *  that is too large — so the kind is what makes the line readable. */
export function tooLargeSummary(items: TooLargeItem[], lang?: string): string {
  if (items.length === 0) return "";
  const t = (key: string, opts: Record<string, unknown> = {}) => tDyn(`serverCloud.${key}`, { ...opts, lng: lang });
  const named = items
    .slice(0, NAMED)
    .map((it) =>
      t("tooLargeItem", {
        kind: t(`itemKind.${KIND_KEY[it.itemType] ?? "other"}`),
        item: it.itemId,
        vault: it.vaultName || it.vaultId,
        size: fmtSize(it.bytes, lang),
      }),
    )
    .join(", ");
  const rest = items.length - NAMED;
  return rest > 0 ? t("tooLargeMore", { items: named, count: rest }) : named;
}
