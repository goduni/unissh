// A compact transfer summary with a bounded, expandable activity list.
import { useEffect, useId, useState, type CSSProperties } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { Icon, type IconName } from "@/components/primitives";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import { useFmt } from "@/i18n/format";
import { BottomSheet } from "@/components/Modal";
import { useDialogFocus, useDialogKeys } from "@/components/a11y";
import { useApp } from "@/store/app";
import type { Transfer, TransferState } from "@/store/sftp-types";
import { cancelTransfer, pauseTransfer, resumeTransfer } from "@/sftp/transfer-runner";
import "./TransferQueue.css";

const RUNNING: TransferState[] = ["queued", "scanning", "active", "waiting"];
const FINISHED: TransferState[] = ["done", "error", "cancelled"];
const canCancel = (t: Transfer) => RUNNING.includes(t.state) || t.state === "paused" || t.state === "pausing";

function direction(t: Transfer): IconName {
  if (t.from.kind === "local" && t.to.kind === "remote") return "upload";
  if (t.from.kind === "remote" && t.to.kind === "local") return "download";
  return t.from.kind === "remote" ? "arrows" : "copy";
}

function eta(seconds: number): string {
  const s = Math.ceil(seconds);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function QueueRow({ transfer: item }: { transfer: Transfer }) {
  const { t } = useTranslation();
  const { fmtSize, fmtPercent } = useFmt();
  const sessions = useApp((s) => s.sftpSessions);
  const dismiss = useApp((s) => s.dismissTransfer);
  const leg = (loc: Transfer["from"]) => loc.kind === "local" ? t("sftp.paneLocal")
    : loc.kind === "remote" ? sessions.find((s) => s.id === loc.sessionId)?.label ?? t("sftp.paneRemote") : "";
  const ratio = item.state === "done" ? 1 : item.bytesTotal > 0 ? Math.max(0, Math.min(1, item.bytesDone / item.bytesTotal)) : 0;
  const finished = FINISHED.includes(item.state);
  const actions: { icon: IconName; label: string; run: () => void }[] = [];
  if (RUNNING.includes(item.state)) actions.push({ icon: "pause", label: t("sftp.queue.pause"), run: () => pauseTransfer(item.id) });
  if (item.state === "paused" || item.state === "error") actions.push({
    icon: item.state === "paused" ? "play" : "refresh",
    label: t(item.state === "paused" ? "sftp.queue.resume" : "sftp.queue.retry"),
    run: () => void resumeTransfer(item.id),
  });
  if (canCancel(item)) actions.push({ icon: "stop", label: t("sftp.queue.cancel"), run: () => cancelTransfer(item.id) });
  if (finished || item.state === "cancelling") actions.push({ icon: "x", label: t("sftp.queue.dismiss"), run: () => dismiss(item.id) });

  return (
    <li className="transfer-row" data-state={item.state}>
      <div className="transfer-name">
        <Icon name={item.state === "error" || item.stalled ? "alert" : item.state === "done" ? "check" : direction(item)} size={16} />
        <span className="transfer-filename" title={`${leg(item.from)}: ${item.fromPath}\n${leg(item.to)}: ${item.toDir}`}>{item.label}</span>
        {item.kind === "dir" && item.filesTotal > 0 && <span className="transfer-files" title={t("sftp.queue.files", { done: item.filesDone, total: item.filesTotal })}>{item.filesDone}/{item.filesTotal}</span>}
      </div>
      <div className="transfer-actions">
        {actions.map((action) => <button key={action.label} type="button" title={action.label} aria-label={`${action.label}: ${item.label}`} onClick={action.run}>
          <Icon name={action.icon} size={15} />
        </button>)}
      </div>
      <div className="transfer-metrics">
        {item.move && <span>{t("sftp.queue.move")}</span>}
        {(item.state !== "active" || item.stalled) && <span className="transfer-state">{item.stalled ? t("sftp.queue.stalled") : t(`sftp.queue.state.${item.state}`)}</span>}
        {item.bytesTotal > 0 && <span>{t("sftp.queue.progress", { done: fmtSize(item.bytesDone), total: fmtSize(item.bytesTotal) })}</span>}
        {(item.state === "active" || (item.state === "waiting" && item.speedBps > 0)) && <>
          <span className="transfer-speed">{t("sftp.queue.speed", { speed: fmtSize(item.speedBps) })}</span>
          {!item.stalled && item.speedBps > 0 && Number.isFinite(item.etaSec) && item.etaSec > 0 && <span>{t("sftp.queue.eta", { eta: eta(item.etaSec) })}</span>}
        </>}
        {item.bytesTotal > 0 && <span className="transfer-percent">{fmtPercent(ratio)}</span>}
      </div>
      {!finished && item.bytesTotal > 0 && <div className="transfer-progress" role="progressbar" aria-label={item.label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(ratio * 100)}>
        <div style={{ transform: `scaleX(${ratio})` }} />
      </div>}
      {item.state === "error" && item.error && <div className="transfer-error" role="alert">{item.error}</div>}
    </li>
  );
}

function QueueActions({ transfers }: { transfers: Transfer[] }) {
  const { t } = useTranslation();
  const clear = useApp((s) => s.clearFinishedTransfers);
  return <div className="transfer-toolbar">
    {transfers.some((item) => RUNNING.includes(item.state)) && <button type="button" title={t("sftp.queue.pauseAll")} aria-label={t("sftp.queue.pauseAll")} onClick={() => transfers.filter((item) => RUNNING.includes(item.state)).forEach((item) => pauseTransfer(item.id))}><Icon name="pause" size={15} /></button>}
    {transfers.some((item) => item.state === "paused") && <button type="button" title={t("sftp.queue.resumeAll")} aria-label={t("sftp.queue.resumeAll")} onClick={() => transfers.filter((item) => item.state === "paused").forEach((item) => void resumeTransfer(item.id))}><Icon name="play" size={15} /></button>}
    {transfers.some(canCancel) && <button type="button" title={t("sftp.queue.cancelAll")} aria-label={t("sftp.queue.cancelAll")} onClick={() => transfers.filter(canCancel).forEach((item) => cancelTransfer(item.id))}><Icon name="stop" size={15} /></button>}
    {transfers.some((item) => FINISHED.includes(item.state)) && <button type="button" title={t("sftp.queue.clear")} aria-label={t("sftp.queue.clear")} onClick={clear}><Icon name="trash" size={15} /></button>}
  </div>;
}

function QueueBody({ transfers, id }: { transfers: Transfer[]; id: string }) {
  const { t } = useTranslation();
  // Keep unfinished work above history without shuffling active rows on every tick.
  const rows = [...transfers.filter((item) => !FINISHED.includes(item.state)), ...transfers.filter((item) => FINISHED.includes(item.state))];
  return (
    <div id={id}>
      <ul className="transfer-list" aria-label={t("sftp.queue.title")}>
        {rows.map((item) => <QueueRow key={item.id} transfer={item} />)}
      </ul>
    </div>
  );
}

function QueueSheet({ transfers, id, style, onClose }: {
  transfers: Transfer[]; id: string; style: CSSProperties; onClose: () => void;
}) {
  const { t } = useTranslation();
  useDialogKeys(onClose);
  const ref = useDialogFocus<HTMLDivElement>();
  return <BottomSheet onClose={onClose}>
    <div ref={ref} role="dialog" aria-modal="true" aria-labelledby={`${id}-title`} tabIndex={-1} className="transfer-queue transfer-sheet" style={style}>
      <div className="transfer-sheet-heading">
        <h2 id={`${id}-title`}>{t("sftp.queue.title")}</h2>
        <button type="button" onClick={onClose} aria-label={t("common.close")}><Icon name="x" size={18} /></button>
      </div>
      <QueueActions transfers={transfers} />
      <QueueBody transfers={transfers} id={id} />
    </div>
  </BottomSheet>;
}

export function TransferQueue() {
  const p = usePalette();
  const { t } = useTranslation();
  const { fmtSize } = useFmt();
  const isMobile = useIsMobile();
  const transfers = useApp((s) => s.transfers);
  const [expanded, setExpanded] = useState(true);
  const [sheetOpen, setSheetOpen] = useState(false);
  const bodyId = useId();
  useEffect(() => { if (transfers.length === 0) setSheetOpen(false); }, [transfers.length]);
  if (!transfers.length) return null;
  const running = transfers.filter((item) => RUNNING.includes(item.state) || item.state === "pausing" || item.state === "cancelling").length;
  const failed = transfers.filter((item) => item.state === "error").length;
  const paused = transfers.filter((item) => item.state === "paused").length;
  const finished = transfers.filter((item) => item.state === "done" || item.state === "cancelled").length;
  const active = transfers.filter((item) => item.state === "active" || item.state === "waiting");
  const speed = active.reduce((sum, item) => sum + item.speedBps, 0);
  const open = isMobile ? sheetOpen : expanded;
  const style = {
    "--transfer-bg": p.bg1, "--transfer-hover": p.bg3, "--transfer-line": p.line,
    "--transfer-track": p.bg4, "--transfer-ink": p.txt, "--transfer-muted": p.txt2,
    "--transfer-accent": p.accent, "--transfer-error": p.red, "--transfer-success": p.green,
  } as CSSProperties;
  return (
    <section className="transfer-queue" style={style} aria-label={t("sftp.queue.title")}>
      <div className="transfer-header">
        <button type="button" className="transfer-summary" aria-expanded={open} aria-controls={open ? bodyId : undefined}
          onClick={() => isMobile ? setSheetOpen(!sheetOpen) : setExpanded(!expanded)} title={t(open ? "sftp.queue.collapse" : "sftp.queue.expand")}>
          <Icon name="arrows" size={16} />
          <strong>{t("sftp.queue.title")}</strong>
          <span className="transfer-counts">
            {running > 0 && <span>{t("sftp.queue.running", { count: running })}</span>}
            {paused > 0 && <span>{t("sftp.queue.paused", { count: paused })}</span>}
            {failed > 0 && <span className="transfer-error-count">{t("sftp.queue.failed", { count: failed })}</span>}
            {finished > 0 && <span>{t("sftp.queue.finished", { count: finished })}</span>}
          </span>
          {active.length > 0 && <span className="transfer-summary-speed">{t("sftp.queue.speed", { speed: fmtSize(speed) })}</span>}
          <span style={{ display: "flex", transform: open ? "none" : "rotate(180deg)" }}><Icon name="cd" size={14} /></span>
        </button>
        {!isMobile && expanded && <QueueActions transfers={transfers} />}
      </div>
      {!isMobile && expanded && <QueueBody transfers={transfers} id={bodyId} />}
      {isMobile && sheetOpen && <QueueSheet transfers={transfers} id={bodyId} style={style} onClose={() => setSheetOpen(false)} />}
    </section>
  );
}
