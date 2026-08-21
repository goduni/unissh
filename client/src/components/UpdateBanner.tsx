// "A new version is available" — a non-modal card in the bottom corner.
//
// Deliberately not a toast: a toast disappears on a timer, and this has to survive
// until the user acts on it. Deliberately not a modal either — UniSSH is often
// left running with live SSH sessions, and a blocking dialog on launch would be a
// worse citizen than the stale binary it is trying to replace.
//
// Installing restarts the app, so any live session dies with it. That is stated
// up front in a confirm rather than discovered afterwards, but it does not block:
// the user decides whether their sessions matter more than the update.

import { usePalette } from "@/theme/ThemeProvider";
import { useTranslation } from "@/i18n";
import { Btn, Icon, Spinner } from "@/components/primitives";
import { useApp } from "@/store/app";
import { useUpdate } from "@/store/update";
import { rem, TEXT } from "@/theme/tokens";

export function UpdateBanner() {
  const p = usePalette();
  const { t } = useTranslation();
  const info = useUpdate((s) => s.info);
  const dismissed = useUpdate((s) => s.dismissed);
  const installing = useUpdate((s) => s.installing);
  const dismiss = useUpdate((s) => s.dismiss);
  const install = useUpdate((s) => s.install);
  const openReleasePage = useUpdate((s) => s.openReleasePage);
  const setConfirm = useApp((s) => s.setConfirm);
  const allPanes = useApp((s) => s.allPanes);

  if (!info || dismissed) return null;

  const start = () => {
    const live = allPanes().filter((pane) => pane.status === "online").length;
    if (live === 0) {
      void install();
      return;
    }
    setConfirm({
      title: t("update.confirmTitle", { version: info.version }),
      body: t("update.confirmSessions", { count: live }),
      confirmLabel: t("update.install"),
      icon: "download",
      onConfirm: () => void install(),
    });
  };

  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        position: "fixed",
        right: 16,
        bottom: 16,
        zIndex: 8900, // below the auto-lock warning (9000) — that one is time-critical
        width: 320,
        maxWidth: "calc(100% - 32px)",
        padding: 14,
        borderRadius: 12,
        background: p.bg1,
        border: `1px solid ${p.line2}`,
        boxShadow: "0 8px 28px rgba(0,0,0,0.35)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 6 }}>
        <Icon name="download" size={15} color={p.txt2} />
        <span style={{ fontSize: TEXT.base, fontWeight: 700, color: p.txt, flex: 1 }}>
          {t("update.available", { version: info.version })}
        </span>
        <button
          onClick={dismiss}
          aria-label={t("common.close")}
          title={t("common.close")}
          style={{
            background: "none",
            border: "none",
            padding: 2,
            cursor: "pointer",
            display: "flex",
            color: p.txt3,
          }}
        >
          <Icon name="x" size={14} color={p.txt3} />
        </button>
      </div>

      <div style={{ fontSize: rem(12.5), color: p.txt3, lineHeight: 1.45, marginBottom: 12 }}>
        {t("update.currentIs", { version: info.currentVersion })}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Btn size="sm" onClick={start} disabled={installing}>
          {installing ? <Spinner size={13} /> : null}
          {installing ? t("update.installing") : t("update.install")}
        </Btn>
        <Btn size="sm" variant="ghost" onClick={openReleasePage} disabled={installing}>
          {t("update.notes")}
        </Btn>
      </div>
    </div>
  );
}
