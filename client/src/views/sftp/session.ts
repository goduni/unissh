// Opening a remote SFTP session: turn a saved host profile into a live
// SftpSession in the store. Shared by the tab strip's "+" and the empty state.

import * as api from "@/bridge/api";
import { apiErrorMessage, isApiError } from "@/bridge/types";
import type { ConnectionProfile } from "@/bridge/types";
import { useApp } from "@/store/app";
import { toast } from "@/store/toast";
import { i18n } from "@/i18n";
import type { SftpSession } from "@/store/sftp-types";

/** Open an SFTP channel to `profile`, register it in the store, and return the
 *  new session id (or null on failure — a toast is shown). */
export async function openSession(profile: ConnectionProfile): Promise<string | null> {
  const st = useApp.getState();
  if (!st.vaultId) {
    toast(i18n.t("sftp.toast.noVault"), "err");
    return null;
  }
  try {
    // Personal profiles resolve in-core (binding + anti-redirect) first.
    const { user, auth } = await api.resolveConnectAuth(profile, st.vaultId);
    const id = await api.sftpOpen(
      {
        host: profile.host,
        port: profile.port,
        user,
        auth,
        jumps: profile.jumps,
        proxy: profile.proxy,
      },
      st.sftpParallelism,
    );
    let home = "/";
    try {
      home = await api.sftpRealpath(id, ".");
    } catch {
      /* fall back to root */
    }
    const session: SftpSession = {
      id,
      profileId: profile.profileId,
      host: profile.host,
      user,
      port: profile.port,
      label: profile.label, // the host's friendly name (the tab shows this)
      home,
    };
    st.addSftpSession(session);
    return id;
  } catch (e) {
    // Host-key mismatch is a security stop, not a session failure: surface the
    // Accept/Reject ceremony in Known hosts instead of a generic error toast.
    if (isApiError(e) && e.kind === "hostKeyMismatch") {
      st.reviewMismatch({
        host: e.host ?? profile.host,
        port: e.port ?? profile.port,
        fingerprint: e.fingerprint ?? "",
      });
      toast(apiErrorMessage(e), "err");
      return null;
    }
    toast(`${i18n.t("sftp.toast.sessionFailed")}: ${apiErrorMessage(e)}`, "err");
    return null;
  }
}
