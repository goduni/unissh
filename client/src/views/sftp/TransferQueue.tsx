// TransferQueue — the live transfer panel. Reads transfers from the store and
// drives them through the runner's controls. Desktop: a bottom footer panel.
// Mobile: a slim summary bar that opens a bottom sheet with the full list.

import { useEffect, useMemo, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, UI } from "@/theme/tokens";
import { Icon, type IconName } from "@/components/primitives";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import { useFmt } from "@/i18n/format";
import { BottomSheet } from "@/components/Modal";
import { useApp } from "@/store/app";
import type { Transfer, TransferState } from "@/store/sftp-types";
import { cancelTransfer, pauseTransfer, resumeTransfer, retryTransfer } from "@/sftp/transfer-runner";

const ACTIVE_STATES: TransferState[] = ["queued", "scanning", "active", "paused"];

function dirIcon(t: Transfer): IconName {
  const a = t.from.kind;
  const b = t.to.kind;
  if (a === "local" && b === "remote") return "upload";
  if (a === "remote" && b === "local") return "download";
  if (a === "remote" && b === "remote") return "arrows";
  return "copy";
}

function fmtEta(sec: number): string {
  if (!isFinite(sec) || sec <= 0) return "";
  const s = Math.round(sec);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function QueueRow({ t }: { t: Transfer }) {
  const p = usePalette();
  const isMobile = useIsMobile();
  const { t: tr } = useTranslation();
  const { fmtSize } = useFmt();
  const sessions = useApp((s) => s.sftpSessions);
  // Where each leg is rooted, for the muted route line. A remote leg resolves to
  // its live session label; a closed session falls back to the generic word.
  const legLabel = (loc: Transfer["from"]): string =>
    loc.kind === "local"
      ? tr("sftp.paneLocal")
      : loc.kind === "remote"
        ? (sessions.find((s) => s.id === loc.sessionId)?.label ?? tr("sftp.paneRemote"))
        : "";
  const ratio = t.bytesTotal > 0 ? Math.min(1, t.bytesDone / t.bytesTotal) : t.state === "done" ? 1 : 0;
  const pct = Math.round(ratio * 100);
  const terminal = t.state === "done" || t.state === "cancelled" || t.state === "error";
  const barColor = t.state === "error" ? p.red : t.state === "done" ? p.green : p.accent;

  const controls: { icon: IconName; title: string; onClick: () => void; danger?: boolean }[] = [];
  if (t.state === "active" || t.state === "scanning")
    controls.push({ icon: "stop", title: tr("sftp.queue.pause"), onClick: () => pauseTransfer(t.id) });
  if (t.state === "paused")
    controls.push({ icon: "play", title: tr("sftp.queue.resume"), onClick: () => void resumeTransfer(t.id) });
  if (t.state === "error")
    controls.push({ icon: "refresh", title: tr("sftp.queue.retry"), onClick: () => void retryTransfer(t.id) });
  if (!terminal)
    controls.push({ icon: "x", title: tr("sftp.queue.cancel"), onClick: () => cancelTransfer(t.id), danger: true });

  const status =
    t.state === "active"
      ? `${pct}%${t.speedBps > 0 ? ` · ${fmtSize(t.speedBps)}/s` : ""}${fmtEta(t.etaSec) ? ` · ${tr("sftp.queue.eta", { eta: fmtEta(t.etaSec) })}` : ""}`
      : tr(`sftp.queue.state.${t.state}`);

  return (
    <div
      style={{
        padding: "9px 12px",
        borderRadius: 10,
        background: p.bg2,
        border: `1px solid ${p.line}`,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 7 }}>
        <Icon name={dirIcon(t)} size={13} color={t.state === "done" ? p.green : t.state === "error" ? p.red : p.accentText} />
        <span style={{ fontFamily: MONO, fontSize: 11.5, flex: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {t.label}
          {t.kind === "dir" && t.filesTotal > 0 ? ` (${t.filesDone}/${t.filesTotal})` : ""}
        </span>
        <span
          style={{
            fontFamily: MONO,
            fontSize: 10.5,
            color: t.state === "done" ? p.green : p.txt3,
            // ellipsis so a long RU active status ("42% · 1,2 МБ/с · осталось 0:12") can't wrap
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {status}
        </span>
        {controls.map((c) => (
          <button
            key={c.icon}
            onClick={c.onClick}
            title={c.title}
            aria-label={c.title}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "transparent",
              border: "none",
              borderRadius: 8,
              padding: 0,
              width: isMobile ? 38 : 22,
              height: isMobile ? 38 : 22,
              flexShrink: 0,
              marginLeft: c.danger ? 2 : 0,
              cursor: "pointer",
              color: c.danger ? p.red : p.txt2,
            }}
          >
            <Icon name={c.icon} size={isMobile ? 17 : 13} />
          </button>
        ))}
      </div>
      <div
        title={t.toDir}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 5,
          fontFamily: UI,
          fontSize: 10.5,
          color: p.txt3,
          marginBottom: 7,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}>{legLabel(t.from)}</span>
        <span aria-hidden style={{ flexShrink: 0, color: p.txt3 }}>→</span>
        <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}>{legLabel(t.to)}</span>
      </div>
      <div style={{ height: 5, borderRadius: 3, background: p.bg4, overflow: "hidden" }}>
        {/* scaleX, not width: transform animates off the layout path */}
        <div
          style={{
            height: "100%",
            width: "100%",
            borderRadius: 3,
            background: barColor,
            transform: `scaleX(${pct / 100})`,
            transformOrigin: "left",
            transition: "transform .2s",
          }}
        />
      </div>
      {t.state === "error" && t.error && (
        <div
          role="alert"
          title={t.error}
          style={{
            fontFamily: MONO,
            fontSize: 10.5,
            lineHeight: 1.35,
            color: p.red,
            marginTop: 6,
            wordBreak: "break-word",
          }}
        >
          {t.error}
        </div>
      )}
    </div>
  );
}

function QueueBody({ transfers }: { transfers: Transfer[] }) {
  const p = usePalette();
  const { t } = useTranslation();
  const { fmtSize } = useFmt();
  const clear = useApp((s) => s.clearFinishedTransfers);

  const agg = useMemo(() => {
    let done = 0;
    let total = 0;
    let active = 0;
    for (const t of transfers) {
      done += t.bytesDone;
      total += t.bytesTotal;
      if (ACTIVE_STATES.includes(t.state)) active += 1;
    }
    return { done, total, active, ratio: total > 0 ? done / total : 0 };
  }, [transfers]);

  const pauseAll = () => transfers.filter((t) => t.state === "active").forEach((t) => pauseTransfer(t.id));
  const cancelAll = () => transfers.filter((t) => ACTIVE_STATES.includes(t.state)).forEach((t) => cancelTransfer(t.id));

  return (
    <div>
      {/* flexWrap so the pauseAll/cancelAll/clear labels wrap instead of overflowing a narrow panel */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, rowGap: 6, flexWrap: "wrap", marginBottom: 10 }}>
        <Icon name="arrows" size={15} color={p.txt2} />
        <span style={{ fontSize: 12.5, fontWeight: 700 }}>{t("sftp.queue.title")}</span>
        <span style={{ fontFamily: MONO, fontSize: 11, color: p.txt3 }}>
          {t("sftp.queue.overall", {
            count: transfers.length,
            done: fmtSize(agg.done),
            total: fmtSize(agg.total),
          })}
        </span>
        <div style={{ flex: 1 }} />
        {agg.active > 0 && (
          <>
            <button onClick={pauseAll} style={qbtn(p)} title={t("sftp.queue.pauseAll")}>
              {t("sftp.queue.pauseAll")}
            </button>
            <button onClick={cancelAll} style={qbtn(p)} title={t("sftp.queue.cancelAll")}>
              {t("sftp.queue.cancelAll")}
            </button>
          </>
        )}
        <button onClick={clear} style={qbtn(p)}>
          {t("sftp.queue.clear")}
        </button>
      </div>
      {agg.active > 0 && agg.total > 0 && (
        <div style={{ height: 4, borderRadius: 2, background: p.bg4, overflow: "hidden", marginBottom: 10 }}>
          {/* scaleX, not width: transform animates off the layout path */}
          <div
            style={{
              height: "100%",
              width: "100%",
              background: p.accent,
              transform: `scaleX(${agg.ratio})`,
              transformOrigin: "left",
              transition: "transform .2s",
            }}
          />
        </div>
      )}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        {transfers.map((t) => (
          <div key={t.id} style={{ flex: "1 1 240px", maxWidth: 380 }}>
            <QueueRow t={t} />
          </div>
        ))}
      </div>
    </div>
  );
}

function qbtn(p: ReturnType<typeof usePalette>): React.CSSProperties {
  return {
    background: p.bg2,
    border: `1px solid ${p.line}`,
    borderRadius: 7,
    padding: "4px 9px",
    cursor: "pointer",
    fontSize: 11.5,
    color: p.txt2,
    fontFamily: UI,
  };
}

export function TransferQueue() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const transfers = useApp((s) => s.transfers);
  const [open, setOpen] = useState(false);

  // Don't let a stale open sheet survive the queue emptying (e.g. "Clear").
  useEffect(() => {
    if (transfers.length === 0) setOpen(false);
  }, [transfers.length]);

  const agg = useMemo(() => {
    let done = 0;
    let total = 0;
    let active = 0;
    for (const tr of transfers) {
      done += tr.bytesDone;
      total += tr.bytesTotal;
      if (ACTIVE_STATES.includes(tr.state)) active += 1;
    }
    return { active, ratio: total > 0 ? done / total : 0 };
  }, [transfers]);

  if (transfers.length === 0) return null;

  if (isMobile) {
    return (
      <>
        <button
          onClick={() => setOpen(true)}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 9,
            width: "100%",
            borderTop: `1px solid ${p.line}`,
            background: p.bg1,
            padding: "10px 16px calc(10px + env(safe-area-inset-bottom))",
            cursor: "pointer",
          }}
        >
          <Icon name="arrows" size={15} color={p.accentText} />
          <span style={{ fontSize: 12.5, fontWeight: 700, color: p.txt }}>{t("sftp.queue.title")}</span>
          <div style={{ flex: 1, height: 5, borderRadius: 3, background: p.bg4, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${Math.round(agg.ratio * 100)}%`, background: p.accent }} />
          </div>
          <Icon name="cd" size={13} color={p.txt3} />
        </button>
        {open && (
          <BottomSheet onClose={() => setOpen(false)}>
            <QueueBody transfers={transfers} />
          </BottomSheet>
        )}
      </>
    );
  }

  return (
    <div style={{ borderTop: `1px solid ${p.line}`, background: p.bg1, padding: "12px 22px 16px" }}>
      <QueueBody transfers={transfers} />
    </div>
  );
}
