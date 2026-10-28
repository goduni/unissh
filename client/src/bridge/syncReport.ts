import { tDyn } from "@/i18n";
import { fmtSize } from "@/i18n/format";
import { ItemType, type SyncReport, type TooLargeItem, type UnpushableItem } from "./types";

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

type Translate = (key: string, opts?: Record<string, unknown>) => string;

/** `serverCloud.*` in the language asked for. */
const tr = (lang?: string): Translate => (key, opts = {}) => tDyn(`serverCloud.${key}`, { ...opts, lng: lang });

/** Items as one line for a message, each written by `line`: the first few named
 *  and the rest counted. Empty when there are none. */
function summarize<T extends { itemType: number }>(
  items: T[],
  lang: string | undefined,
  line: (it: T, kind: string, t: Translate) => string,
): string {
  if (items.length === 0) return "";
  const t = tr(lang);
  const named = items
    .slice(0, NAMED)
    .map((it) => line(it, t(`itemKind.${KIND_KEY[it.itemType] ?? "other"}`), t))
    .join(", ");
  const rest = items.length - NAMED;
  return rest > 0 ? t("tooLargeMore", { items: named, count: rest }) : named;
}

/** The items a sync server refused as too large, as one line for a message:
 *  each item by kind and id with its vault and size, the first few named and the
 *  rest counted. Empty when nothing was refused. The id is what the core has
 *  without decrypting the item — a recording's title is inside the very content
 *  that is too large — so the kind is what makes the line readable. */
export function tooLargeSummary(items: TooLargeItem[], lang?: string): string {
  return summarize(items, lang, (it, kind, t) =>
    t("tooLargeItem", { kind, item: it.itemId, vault: it.vaultName || it.vaultId, size: fmtSize(it.bytes, lang) }),
  );
}

/** The edits no sync can push ({@link SyncReport.unpushable}), as one line for a
 *  message: each by kind and id with its vault, the first few named and the rest
 *  counted. Empty when there are none. */
export function unpushableSummary(items: UnpushableItem[], lang?: string): string {
  return summarize(items, lang, (it, kind, t) =>
    t("unpushableItem", { kind, item: it.itemId, vault: it.vaultName || it.vaultId }),
  );
}

/** What a sync says about the edits it could not push: this device's own, with
 *  the way to restore the server's copy, then other members' ones held here,
 *  which only this device's copy has. Empty when there are none. */
export function unpushableNotice(items: UnpushableItem[], lang?: string): string {
  const t = tr(lang);
  const mine = unpushableSummary(
    items.filter((u) => u.mine),
    lang,
  );
  const theirs = unpushableSummary(
    items.filter((u) => !u.mine),
    lang,
  );
  return [mine && t("syncUnpushable", { items: mine }), theirs && t("syncUnpushableTheirs", { items: theirs })]
    .filter(Boolean)
    .join(" ");
}

/** What the last sync left behind, as one warning: items too large for the
 *  server, then edits it will not take — both when there are both. Null when it
 *  left nothing. */
export function syncLeftBehind(report: SyncReport | null | undefined, lang?: string): string | null {
  const tooLarge = tooLargeSummary(report?.tooLarge ?? [], lang);
  const parts = [
    tooLarge && tr(lang)("syncTooLarge", { items: tooLarge }),
    unpushableNotice(report?.unpushable ?? [], lang),
  ].filter(Boolean);
  return parts.length ? parts.join(" ") : null;
}
