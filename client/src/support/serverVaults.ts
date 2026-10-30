// Loading "On this server": the server's vault catalog and the vaults teammates
// shared that wait for this device to trust their owner. The two load side by
// side and land on their own: the catalog is one request, while every waiting
// vault is inspected (its membership read from the server), so the catalog
// never waits for the inspections, and a failed check never hides it.

import type { PendingSharedVault, PendingSharedVaults, ServerVault } from "@/bridge/types";

export interface ServerVaultsLoad {
  listVaults: () => Promise<ServerVault[]>;
  pendingShared: () => Promise<PendingSharedVaults>;
}

export interface ServerVaultsSink {
  rows: (list: ServerVault[]) => void;
  rowsFailed: (e: unknown) => void;
  shared: (pending: PendingSharedVaults) => void;
  sharedFailed: (e: unknown) => void;
}

/** Starts both loads; each result goes to its own callback as soon as it is in. */
export async function loadServerVaults(load: ServerVaultsLoad, sink: ServerVaultsSink): Promise<void> {
  await Promise.all([
    load.listVaults().then(sink.rows, sink.rowsFailed),
    load.pendingShared().then(sink.shared, sink.sharedFailed),
  ]);
}

/** The catalog rows to list with a plain Pull/Push: the vaults waiting for
 *  trust are listed in their own group, never with "Pull" (a pull before the
 *  owner is confirmed is rejected by verify-before-apply anyway). Not-local
 *  first (things you can pull), then by id. */
export function catalogRows(all: ServerVault[], waiting: PendingSharedVault[]): ServerVault[] {
  const waitingIds = new Set(waiting.map((w) => w.vaultId.toLowerCase()));
  return all
    .filter((v) => !waitingIds.has(v.vaultId.toLowerCase()))
    .sort((a, b) => Number(a.isLocal) - Number(b.isLocal) || a.vaultId.localeCompare(b.vaultId));
}
