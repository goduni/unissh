import * as api from "@/bridge/api";
import { clearSecretKey } from "@/bridge/secretKey";
import { useApp } from "./app";

/** Recover directly into a fresh Core; never create a temporary local identity. */
export async function recoverInstance(baseUrl: string, handle: string, password: string, secretKey: string) {
  try {
    await api.serverEscrowFetchAndUnlock(
      baseUrl.trim(), handle.trim(), password || null, secretKey.replace(/[\s-]/g, ""),
    );
  } finally {
    // The backend may have installed the identity before a later network step
    // failed. Discard a cached keychain miss (or an older key) in either case.
    clearSecretKey();
  }
  // Derive exists/unlocked/password mode from the installed keyset, restore
  // linked server state, and pull vaults through the normal startup path.
  await useApp.getState().boot();
}
