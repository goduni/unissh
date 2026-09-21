import { useEffect, useState } from "react";
import { Btn } from "@/components/primitives";
import { Modal } from "@/components/Modal";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem } from "@/theme/tokens";
import { useTranslation } from "@/i18n";
import { mcpApprove, visibleCommand } from "@/bridge/mcp";
import { clearMcp, refreshMcp, useMcp } from "@/store/mcp";

export function McpApproval() {
  const { t } = useTranslation(); const p = usePalette();
  const status = useMcp(s => s.status); const failed = useMcp(s => s.failed);
  const [selected, setSelected] = useState<string | null>(null); const [busy, setBusy] = useState(false); const [error, setError] = useState(false);
  useEffect(() => { void refreshMcp(); const timer = setInterval(() => { void refreshMcp(); }, 1000); return () => { clearInterval(timer); clearMcp(); }; }, []);
  const pending = status?.activity.runs.filter(r => r.state === "awaiting_approval") ?? [];
  // Newly arriving requests must never replace the command currently being reviewed.
  const selectedRun = pending.find(r => r.run_id === selected);
  useEffect(() => {
    if (!selectedRun) { setSelected(pending[0]?.run_id ?? null); setError(false); }
  }, [selectedRun, pending[0]?.run_id]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!selectedRun || selectedRun.command === undefined || !selectedRun.target) return null;
  const run = selectedRun; const target = run.target!;
  const decide = async (allowed: boolean) => {
    if (busy) return; setBusy(true); setError(false);
    try { await mcpApprove(run.run_id, allowed); await refreshMcp(); } catch { setError(true); } finally { setBusy(false); }
  };
  return <Modal key={run.run_id} icon="shield" title={t("mcp.approvalTitle")}
    subtitle={<span style={{ color: p.txt2, overflowWrap: "anywhere" }}>{status?.integrations.find(i => i.id === run.integration_id)?.label}</span>}
    onClose={() => { void decide(false); }} zIndex={390} w={620}
    footer={<div onKeyDownCapture={e => { if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); } }} style={{ display: "flex", gap: rem(10), flexWrap: "wrap" }}>
      <Btn variant="outline" disabled={busy} onClick={() => void decide(false)}>{t("mcp.deny")}</Btn>
      <Btn disabled={busy || failed} onClick={() => void decide(true)}>{t("mcp.approve")}</Btn>
    </div>}>
    <p style={{ margin: 0, overflowWrap: "anywhere" }}><strong>{target.label}</strong><br />{target.user}@{target.host}:{target.port}</p>
    <pre style={{ margin: 0, padding: rem(14), background: p.bg2, color: p.txt, borderRadius: 8, whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: "35vh", overflow: "auto", fontFamily: MONO }}>{visibleCommand(run.command!)}</pre>
    {run.approval_remaining_seconds !== undefined && <p role="status" style={{ margin: 0 }}>{t("mcp.approvalExpires", { seconds: run.approval_remaining_seconds })}</p>}
    <p style={{ margin: 0 }}>{t("mcp.runtime", { seconds: Math.ceil((run.timeout_ms ?? 120000) / 1000) })}</p>
    <p style={{ margin: 0, color: p.txt2, lineHeight: 1.6 }}>{t("mcp.disclosure")}</p>
    <p style={{ margin: 0, color: p.txt2 }}>{t("mcp.independentShell")}</p>
    {(error || failed) && <p role="alert" style={{ color: p.red }}>{t("mcp.error")}</p>}
  </Modal>;
}
