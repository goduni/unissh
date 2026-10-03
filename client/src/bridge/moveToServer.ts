import { ItemType, type ItemInfo, type ServerStatus, type SpaceInfo } from "./types";

/** What a "Move to server…" confirmation counts, in display order. */
export const MOVE_KINDS = [
  "hosts",
  "groups",
  "keys",
  "certificates",
  "passwords",
  "notes",
  "snippets",
  "identities",
  "other",
] as const;
export type MoveKind = (typeof MOVE_KINDS)[number];

const KIND_OF: Partial<Record<number, MoveKind>> = {
  [ItemType.Connection]: "hosts",
  [ItemType.Group]: "groups",
  [ItemType.SshKey]: "keys",
  [ItemType.SshCert]: "certificates",
  [ItemType.Password]: "passwords",
  [ItemType.Note]: "notes",
  [ItemType.Snippet]: "snippets",
  [ItemType.Identity]: "identities",
};

export interface MovePlan {
  /** Servers the vault can move to: linked, with a live session. Empty = refuse. */
  servers: ServerStatus[];
  needsServerPicker: boolean;
  /** The target server: the chosen one, else the active one, else the first. */
  server: ServerStatus | null;
  /** Spaces on that server the caller administers — where the vault may land.
   *  Empty = the link's primary space (the core binds to it by default). */
  spaces: SpaceInfo[];
  needsSpacePicker: boolean;
  /** Item counts by kind, non-zero only, in {@link MOVE_KINDS} order. */
  counts: { kind: MoveKind; count: number }[];
}

/** Everything the "Move to server…" confirmation shows, from the vault's items and
 *  the linked servers. Pure: the modal renders it, the vitest pins it. */
export function planMoveToServer(
  items: Pick<ItemInfo, "itemType">[],
  servers: ServerStatus[],
  pick: { serverId?: string | null; activeServerId?: string | null } = {},
): MovePlan {
  const targets = servers.filter((s) => s.serverId != null && s.connected && s.hasSession);
  const server =
    targets.find((s) => s.serverId === pick.serverId) ??
    targets.find((s) => s.serverId === pick.activeServerId) ??
    targets[0] ??
    null;
  const spaces = (server?.spaces ?? []).filter((sp) => sp.role === "admin");
  const tally = new Map<MoveKind, number>();
  for (const it of items) {
    const kind = KIND_OF[it.itemType] ?? "other";
    tally.set(kind, (tally.get(kind) ?? 0) + 1);
  }
  return {
    servers: targets,
    needsServerPicker: targets.length > 1,
    server,
    spaces,
    needsSpacePicker: spaces.length > 1,
    counts: MOVE_KINDS.filter((k) => tally.has(k)).map((kind) => ({
      kind,
      count: tally.get(kind) ?? 0,
    })),
  };
}
