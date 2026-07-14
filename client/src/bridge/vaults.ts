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

/** Resolve just the linked SERVER a cloud vault is bound to. Tries the
 *  session-cached `spaces` first (also gives the Space name via {@link vaultSpace});
 *  falls back to matching the link's own binding label `spaceId`, which needs no
 *  session — so a bound vault still attributes to its server when signed out. null
 *  for local/unbound vaults, or a binding to no currently-linked server. Distinct
 *  from {@link vaultSpace} (kept session-only) so the owned/personal semantics that
 *  depend on it are unaffected. */
export function vaultServer(v: VaultInfo, servers: ServerStatus[]): ServerStatus | null {
  if (v.syncTarget !== "cloud" || !v.syncTenant) return null;
  const viaSpace = vaultSpace(v, servers);
  if (viaSpace) return viaSpace.server;
  return servers.find((s) => s.spaceId != null && s.spaceId === v.syncTenant) ?? null;
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
  // Only a bound cloud vault can be "owned" (a Space you administer). Local /
  // not-yet-bound vaults are handled by the callers' `syncTarget !== "cloud"` guard.
  if (v.syncTarget !== "cloud" || !v.syncTenant) return false;
  const found = vaultSpace(v, servers);
  if (found) return found.space.role === "admin";
  // The vault's bound Space isn't in any link's spaces cache. This is ambiguous:
  // right after unlock the caches are still empty (session not yet restored, or
  // /v1/spaces hasn't returned), so a Space you DO administer would momentarily look
  // foreign and drop out of `privateVaults` — making "Personal" spuriously report
  // "no vault". Stay fail-safe but avoid that transient false: only once at least one
  // linked server has loaded its spaces do we trust an unresolved Space to be
  // genuinely not-ours (→ false). Until then, treat the vault as owned from its local
  // binding (optimistic), so it isn't briefly excluded during the load window.
  const spacesLoaded = servers.some((s) => (s.spaces ?? []).length > 0);
  return !spacesLoaded;
}
