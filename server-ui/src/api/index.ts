import i18n from "i18next";
import { getCrypto } from "../crypto/provider";
import { usePrefs } from "../store/prefs";
import { useSession } from "../store/session";
import { useUi } from "../store/ui";
import { createClient } from "./client";
import { ApiError } from "./errors";
import type { VerifyResp } from "./types";

// Singleton API client. getAuth reads the stores non-reactively at call time, so
// there is no React coupling and no import cycle at module-eval time.
export const api = createClient(
  () => ({
    instanceUrl: usePrefs.getState().instanceUrl,
    bearer: useSession.getState().bearer,
  }),
  // Rotate the admin access token with the in-memory refresh token. Called by the
  // client on a 401 (deduped). The refresh call itself carries no Bearer, so a 401 on
  // it can't recurse. `api` is referenced lazily here, after module init — no cycle.
  async () => {
    const { refreshToken } = useSession.getState();
    if (!refreshToken) return false;
    try {
      const r = await api.call<VerifyResp>("/v1/session/refresh", {
        method: "POST",
        body: { refresh_token: refreshToken },
      });
      useSession.getState().setBearer(r.access_token, r.access_expires);
      useSession.setState({ refreshToken: r.refresh_token });
      return true;
    } catch (e) {
      // Distinguish a dead session from a transient blip. A terminal rejection of
      // the refresh token (revoked/reused/expired, tenant gone) → return false so
      // the caller auto-locks. A network drop or 5xx must NOT force a lock: rethrow
      // so the original request just surfaces an error and the operator can retry.
      if (e instanceof ApiError && [401, 403, 404, 410].includes(e.status)) return false;
      throw e;
    }
  },
  // Auth-tier loss: don't let a dead keyset session hide behind a green badge and a
  // wall of raw 401s. Lock the keyset and say why. Guarded so concurrent 401s don't
  // fire duplicate toasts.
  () => {
    const s = useSession.getState();
    if (!s.keysetUnlocked && !s.bearer) return;
    try {
      getCrypto().lock();
    } catch {
      /* crypto may be unavailable */
    }
    s.lock();
    useUi.getState().toast("error", i18n.t("access.sessionExpired"));
  },
);

export { ApiError } from "./errors";
