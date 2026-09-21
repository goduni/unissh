import { useEffect, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Btn, Field, Input } from "@/components/primitives";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { useTranslation, tDyn } from "@/i18n";
import { writeSecretToClipboard } from "@/bridge/clipboard";
import * as api from "@/bridge/mcp";
import { refreshMcp, useMcp } from "@/store/mcp";

export function SettingsMcp() {
  const p = usePalette(); const { t } = useTranslation();
  const status = useMcp(s => s.status); const failed = useMcp(s => s.failed);
  const [port, setPort] = useState(""); const [label, setLabel] = useState("");
  const [token, setToken] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false); const [grantFor, setGrantFor] = useState<string | null>(null);
  const [ticket, setTicket] = useState("");
  const [targets, setTargets] = useState<api.McpTarget[]>([]); const [selected, setSelected] = useState<string[]>([]);
  const [consent, setConsent] = useState(false); const [minutes, setMinutes] = useState("30");
  const key = (v: api.McpTarget) => JSON.stringify([v.vault_id, v.profile_id]);
  useEffect(() => { void refreshMcp(); }, []);
  async function act(f: () => Promise<unknown>) {
    if (busy) return; setBusy(true); setError(false);
    try { await f(); await refreshMcp(); } catch { setError(true); } finally { setBusy(false); }
  }
  const row = { display: "flex", flexWrap: "wrap" as const, alignItems: "center", gap: rem(10) };
  if (!status) return <p role="status">{failed ? t("mcp.error") : t("mcp.loading")}</p>;
  const chosenPort = port === "" ? status.port : Number(port);
  return <div style={{ display: "grid", gap: rem(24), color: p.txt, fontSize: TEXT.base }}>
    <section>
      <p style={{ color: p.txt2, lineHeight: 1.6 }}>{t("mcp.description")}</p>
      <div style={row}>
        <Field label={t("mcp.port")}><Input value={port || String(status.port)} onChange={setPort} type="number" /></Field>
        <Btn disabled={busy || !Number.isInteger(chosenPort) || chosenPort < 0 || chosenPort > 65535}
          onClick={() => void act(() => api.mcpEnable(!status.enabled, chosenPort))}>
          {status.enabled ? t("mcp.disable") : t("mcp.enable")}
        </Btn>
      </div>
      <p role="status">{status.enabled ? t("mcp.listening") : t("mcp.disabled")}</p>
      {status.enabled && <code style={{ wordBreak: "break-all", fontFamily: MONO }}>{status.endpoint}</code>}
      {status.error && <p role="alert" style={{ color: p.red }}>{tDyn(`mcp.${status.error}`)}</p>}
      <p style={{ color: p.txt2, lineHeight: 1.6 }}>{t("mcp.localOnly")}</p>
    </section>
    {(error || failed) && <p role="alert" style={{ color: p.red }}>{t("mcp.error")}</p>}
    <section>
      <h3>{t("mcp.integrations")}</h3>
      <div style={row}>
        <Field label={t("mcp.name")}><Input value={label} onChange={setLabel} /></Field>
        <Btn disabled={busy || !label.trim() || new TextEncoder().encode(label).length > 120}
          onClick={() => void act(async () => { const r = await api.mcpCreate(label); setToken(r.token); setLabel(""); })}>{t("mcp.add")}</Btn>
      </div>
      {token && <div style={{ marginTop: rem(16), padding: rem(16), border: `1px solid ${p.line}`, borderRadius: 8 }}>
        <p>{t("mcp.tokenOnce")}</p>
        <code style={{ display: "block", overflowWrap: "anywhere", fontFamily: MONO, userSelect: "all" }}>{token}</code>
        <div style={{ ...row, marginTop: rem(12) }}>
          <Btn onClick={() => void act(() => writeSecretToClipboard(token))}>{t("mcp.copyToken")}</Btn>
          <Btn variant="ghost" onClick={() => setToken(null)}>{t("mcp.hideToken")}</Btn>
        </div>
      </div>}
      {!status.integrations.length && <p style={{ color: p.txt2 }}>{t("mcp.empty")}</p>}
      {status.integrations.map(i => {
        const grant = status.activity.grants.find(g => g.integration_id === i.id);
        return <div key={i.id} style={{ padding: `${rem(16)} 0`, borderBottom: `1px solid ${p.line}` }}>
          <div style={row}><strong style={{ flex: 1, overflowWrap: "anywhere" }}>{i.label}</strong>
            <span>{grant ? t("mcp.remaining", { minutes: Math.ceil(grant.remaining_seconds / 60) }) : t("mcp.noGrant")}</span>
          </div>
          <div style={{ ...row, marginTop: rem(10) }}>
            <Btn variant="outline" disabled={busy || !status.enabled} onClick={() => void act(async () => { const selection = await api.mcpTargets(); setTargets(selection.targets); setTicket(selection.ticket); setSelected([]); setConsent(false); setGrantFor(i.id); })}>{t("mcp.grant")}</Btn>
            {grant && <Btn variant="ghost" disabled={busy} onClick={() => void act(() => api.mcpRevoke(i.id))}>{t("mcp.revoke")}</Btn>}
            <Btn variant="ghost" disabled={busy} onClick={() => void act(async () => { const r = await api.mcpRotate(i.id); setToken(r.token); setGrantFor(null); })}>{t("mcp.rotate")}</Btn>
            <Btn variant="ghost" disabled={busy} onClick={() => void act(() => api.mcpDelete(i.id))}>{t("common.delete")}</Btn>
          </div>
          {grantFor === i.id && <fieldset style={{ margin: `${rem(16)} 0 0`, padding: rem(16), border: `1px solid ${p.line}`, borderRadius: 8 }}>
            <legend>{t("mcp.selectTargets")}</legend>
            {targets.map(target => <label key={key(target)} style={{ display: "flex", alignItems: "baseline", gap: rem(10), padding: `${rem(6)} 0`, overflowWrap: "anywhere" }}>
              <input type="checkbox" checked={selected.includes(key(target))} onChange={e => setSelected(e.target.checked ? [...selected, key(target)] : selected.filter(s => s !== key(target)))} />
              <span>{target.label} <small style={{ color: p.txt2 }}>{target.user}@{target.host}:{target.port}</small></span>
            </label>)}
            {!targets.length && <p>{t("mcp.noTargets")}</p>}
            <Field label={t("mcp.duration")}><Input type="number" value={minutes} onChange={setMinutes} /></Field>
            <label style={{ display: "flex", gap: rem(10), margin: `${rem(14)} 0`, lineHeight: 1.5 }}>
              <input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} />{t("mcp.disclosure")}
            </label>
            <div style={row}>
              <Btn disabled={busy || !consent || !selected.length || !Number.isInteger(Number(minutes)) || Number(minutes) < 1 || Number(minutes) > 30}
                onClick={() => void act(async () => { await api.mcpGrant(i.id, targets.filter(v => selected.includes(key(v))), Number(minutes) * 60, ticket); setGrantFor(null); })}>{t("mcp.allow")}</Btn>
              <Btn variant="ghost" onClick={() => setGrantFor(null)}>{t("common.cancel")}</Btn>
            </div>
          </fieldset>}
        </div>;
      })}
      <div style={{ ...row, marginTop: rem(16) }}>
        <Btn variant="outline" disabled={!status.enabled || busy} onClick={() => void act(() => writeText(api.mcpConfiguration(status.endpoint)))}>{t("mcp.copyConfig")}</Btn>
        <Btn variant="ghost" disabled={busy || !status.activity.grants.length} onClick={() => void act(() => api.mcpRevoke())}>{t("mcp.revokeAll")}</Btn>
      </div>
      <p style={{ color: p.txt2, lineHeight: 1.6 }}>{t("mcp.configHelp")}</p>
    </section>
    <section><h3>{t("mcp.activity")}</h3>
      {!status.activity.sessions.length && !status.activity.runs.length && <p style={{ color: p.txt2 }}>{t("mcp.noActivity")}</p>}
      {status.activity.sessions.map(s => <p key={s.session_id} style={{ overflowWrap: "anywhere" }}>{t("mcp.session")} · {s.target?.label} · {status.integrations.find(i => i.id === s.integration_id)?.label} · {tDyn(`mcp.state.${s.state}`)}{s.error ? ` · ${tDyn(`mcp.errors.${s.error}`)}` : ""} {s.state === "ready" && <small>{t("mcp.idle", { seconds: s.idle_seconds })}</small>} {s.state !== "closed" && <Btn variant="ghost" disabled={busy} onClick={() => void act(() => api.mcpCloseSession(s.session_id))}>{t("common.close")}</Btn>}</p>)}
      {status.activity.runs.map(r => <p key={r.run_id} style={{ overflowWrap: "anywhere" }}>{t(r.session_id ? "mcp.sessionCommand" : "mcp.oneShot")} · {r.target?.label} · {status.integrations.find(i => i.id === r.integration_id)?.label} · {tDyn(`mcp.state.${r.state}`)}{r.error ? ` · ${tDyn(`mcp.errors.${r.error}`)}` : ""} {["awaiting_approval", "connecting", "running", "cancelling"].includes(r.state) && <Btn variant="ghost" disabled={busy} onClick={() => void act(() => api.mcpCancelCommand(r.run_id))}>{t("common.cancel")}</Btn>}</p>)}
    </section>
  </div>;
}
