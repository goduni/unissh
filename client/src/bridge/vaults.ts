import type { ServerStatus, SpaceInfo, VaultInfo } from "./types";

/** Short human label for a server link: its handle, else the host of its base URL. */
export function serverShortLabel(s: ServerStatus): string {
  if (s.handle) return s.handle;
  if (s.baseUrl) {
    try {
      return new URL(s.baseUrl).host;
    } catch {
      return s.baseUrl;
    }
  }
  return "server";
}

/** Resolve which linked server + Space a cloud vault is bound to. A cloud vault's
 *  `syncTenant` is its bound Space id (base64); we find the link whose `spaces`
 *  (the caller's spaces on that server) contains it. null for local/unbound vaults
 *  or a Space that isn't visible on any current link. */
export function vaultSpace(
  v: VaultInfo,
  servers: ServerStatus[],
): { server: ServerStatus; space: SpaceInfo } | null {
  if (v.syncTarget !== "cloud" || !v.syncTenant) return null;
  for (const s of servers) {
    const space = (s.spaces ?? []).find((sp) => sp.spaceId === v.syncTenant);
    if (space) return { server: s, space };
  }
  return null;
}

/** Where a vault physically lives: on-device (local) or a cloud Space on a server.
 *  `server` names the bound Space (falling back to the server host) so the Space
 *  surfaces directly in the vault list/sidebar; `space` is the bare Space name. */
export function vaultLoc(
  v: VaultInfo,
  servers: ServerStatus[],
): { local: boolean; server: string | null; space: string | null } {
  if (v.syncTarget !== "cloud") return { local: true, server: null, space: null };
  const found = vaultSpace(v, servers);
  return {
    local: false,
    server: found ? found.space.name || serverShortLabel(found.server) : null,
    space: found?.space.name ?? null,
  };
}

/** A cloud vault in a Space YOU administer — the kind that can hold identities
 *  inside the company perimeter, invisible to that server's admin. Keyed on the
 *  caller's `admin` role in the vault's bound Space. */
export function isOwnedCloud(v: VaultInfo, servers: ServerStatus[]): boolean {
  const found = vaultSpace(v, servers);
  return found !== null && found.space.role === "admin";
}
