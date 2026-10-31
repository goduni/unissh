import { useEffect, useState } from "react";
import { cliToolsInstall, cliToolsRemove, cliToolsStatus, type CliToolsStatus } from "@/bridge/cliTools";
import { isDesktopOs } from "@/bridge/platform";
import { apiErrorMessage } from "@/bridge/types";
import { useTranslation } from "@/i18n";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { Btn, Spinner } from "./primitives";

/** The optional command is offered before account creation and in Settings. */
export function CliTools({ compact = false }: { compact?: boolean }) {
  return isDesktopOs() ? <DesktopCliTools compact={compact} /> : null;
}

function DesktopCliTools({ compact }: { compact: boolean }) {
  const p = usePalette();
  const { t } = useTranslation();
  const [status, setStatus] = useState<CliToolsStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let cancelled = false;
    void cliToolsStatus().then(value => {
      if (!cancelled) setStatus(value);
    }).catch(e => { if (!cancelled) setError(apiErrorMessage(e)); });
    return () => { cancelled = true; };
  }, []);

  const change = async (remove = false) => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      setStatus(await (remove ? cliToolsRemove() : cliToolsInstall()));
    } catch (e) {
      setError(apiErrorMessage(e));
      // Installing the binary can succeed before PATH registration fails.
      try { setStatus(await cliToolsStatus()); } catch { /* keep the actionable error */ }
    } finally {
      setBusy(false);
    }
  };

  const ready = status?.installed && status.pathConfigured && !status.updateAvailable;
  return (
    <section aria-label={t("cliTools.title")} aria-busy={busy} style={{
      marginTop: compact ? 0 : rem(28), marginBottom: compact ? rem(20) : 0,
      fontSize: TEXT.small, lineHeight: 1.5,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: rem(12), flexWrap: "wrap" }}>
        <div style={{ flex: "1 1 180px" }}>
          <div style={{ color: p.txt, fontWeight: 600, fontSize: TEXT.base }}>{t("cliTools.title")}</div>
          <div style={{ color: p.txt2, marginTop: rem(3) }}>
            {ready ? t("cliTools.installed") : t(compact ? "cliTools.optional" : "cliTools.description")}
          </div>
        </div>
        {status && (!ready || !compact) && (
          <div style={{ display: "flex", alignItems: "center", gap: rem(8), flexWrap: "wrap" }}>
            {!ready && <Btn variant="outline" size="sm" disabled={busy || !status.available} onClick={() => void change()}>
              {busy ? <Spinner size={14} /> : t(status.updateAvailable ? "cliTools.update" : status.installed ? "cliTools.finish" : "cliTools.install")}
            </Btn>}
            {!compact && status.installed && <Btn variant="ghost" size="sm" disabled={busy} onClick={() => void change(true)}>
              {busy && ready ? <Spinner size={14} /> : t("cliTools.remove")}
            </Btn>}
          </div>
        )}
      </div>
      {!status && !error && <div role="status" style={{ color: p.txt2, marginTop: rem(8) }}>{t("cliTools.loading")}</div>}
      {status && !status.available && !ready && <p style={{ color: p.txt2, margin: `${rem(8)} 0 0` }}>{t("cliTools.unavailable")}</p>}
      {status?.installed && !compact && <div role="status" style={{ marginTop: rem(10), color: p.txt2 }}>
        <code style={{ fontFamily: MONO, color: p.txt }}>unissh-cli --help</code>
        <div style={{ marginTop: rem(4) }}>{t("cliTools.newTerminal")}</div>
        <div style={{ overflowWrap: "anywhere", marginTop: rem(4) }}>{status.installPath}</div>
      </div>}
      {error && <p role="alert" style={{ color: p.red, overflowWrap: "anywhere", margin: `${rem(8)} 0 0` }}>{t("cliTools.error", { error })}</p>}
    </section>
  );
}
