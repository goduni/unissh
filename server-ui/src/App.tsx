import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Login } from "./access/Login";
import { pendingOidcRedirect, resumeOidcLogin } from "./api/auth-service";
import { loadWasmProvider } from "./crypto/wasm-provider";
import { Shell } from "./shell/Shell";
import { useSession } from "./store/session";
import { useUi } from "./store/ui";
import { ThemeProvider } from "./theme/ThemeProvider";

// Module-level guard so React StrictMode's double-invoked effect (and any remount)
// runs the single-use OIDC code exchange exactly once.
let oidcResumeStarted = false;

/** Minimal centered "completing sign-in" screen shown while the OIDC redirect is
 *  being resolved (code exchange → callback → session). */
function OidcResuming() {
  const { t } = useTranslation();
  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "var(--desk)",
        color: "var(--txt2)",
        fontSize: 14,
      }}
    >
      {t("access.onb.sso_resuming")}
    </div>
  );
}

function Root() {
  const { t } = useTranslation();
  // Two-level session: a live Bearer (server-trusted) AND an unlocked keyset
  // (crypto). Escrow/claim/SSO sign-in establishes both atomically, so the Shell
  // shows only when both hold; a reload drops the in-memory session → back to Login.
  const bearer = useSession((s) => s.bearer);
  const keysetUnlocked = useSession((s) => s.keysetUnlocked);
  // On an OIDC redirect callback (`?code=…` with a pending flow) finish the dance
  // before deciding what to render.
  const [resuming, setResuming] = useState(() => pendingOidcRedirect());

  useEffect(() => {
    if (!pendingOidcRedirect() || oidcResumeStarted) return;
    oidcResumeStarted = true;
    void (async () => {
      try {
        await loadWasmProvider(); // ensure the wasm keyset ops are ready post-reload
        await resumeOidcLogin(); // exchange + callback + commit the session
      } catch (e) {
        useUi.getState().toast("error", e instanceof Error ? e.message : t("access.onb.sso_err"));
      } finally {
        setResuming(false);
      }
    })();
  }, [t]);

  if (resuming) return <OidcResuming />;
  return bearer && keysetUnlocked ? <Shell /> : <Login />;
}

export function App() {
  return (
    <ThemeProvider>
      <Root />
    </ThemeProvider>
  );
}
