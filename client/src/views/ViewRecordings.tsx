// ViewRecordings — recorded sessions: list, replay, export, delete.
//
// The stored document is asciicast v2, so "export" is a real export: the file
// plays in `asciinema` and can be handed to someone who does not run UniSSH. The
// in-app player exists so you don't have to leave to check a recording, not to
// be the only way to read one.

import { useCallback, useEffect, useState, type CSSProperties } from "react";
import * as api from "@/bridge/api";
import { visibleCommand } from "@/bridge/mcp";
import { apiErrorMessage } from "@/bridge/types";
import { useTranslation, tDyn } from "@/i18n";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { Btn, Icon, Input, Spinner } from "@/components/primitives";
import { McpRecordingSettings } from "./mcp/McpRecordingSettings";
import { exportRecording, type RecordingExportFormat } from "@/support/recordings";
import "./mcp/mcp.css";
import "./recordings.css";
import { RecordingPlayer } from "@/components/RecordingPlayer";
import { toast } from "@/store/toast";
import { useApp } from "@/store/app";
import { useNarrow } from "@/store/responsive";
import { exportPath } from "@/support/paths";
import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";

function fmtDuration(secs: number): string {
  const s = Math.max(0, Math.round(secs));
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${s % 60}s` : `${s}s`;
}

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function ViewRecordings() {
  const { t } = useTranslation();
  const p = usePalette();
  const isMobile = useNarrow();
  const vaultId = useApp((s) => s.vaultId) ?? "";
  const [query, setQuery] = useState("");
  const [failuresOnly, setFailuresOnly] = useState(false);
  const [format, setFormat] = useState<RecordingExportFormat>("cast");
  const [items, setItems] = useState<api.RecordingMeta[] | null>(null);
  const [playing, setPlaying] = useState<{ cast: string; title: string } | null>(null);

  const reload = useCallback(async () => {
    if (!vaultId) {
      setItems([]);
      return;
    }
    try {
      setItems(await api.listRecordings(vaultId));
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setItems([]);
    }
  }, [vaultId]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const visible = items?.filter(m => {
    const failed = !!m.mcp && (m.mcp.outcome !== "completed" || m.mcp.exitCode !== 0);
    return (!failuresOnly || failed) && [m.label, m.host, m.user, m.mcp?.application, m.mcp?.command]
      .some(text => text?.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()));
  });

  const play = async (m: api.RecordingMeta) => {
    try {
      const cast = await api.getRecording(vaultId, m.recordingId);
      setPlaying({ cast, title: `${m.label} · ${m.user}@${m.host}` });
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  };

  const exportOne = async (m: api.RecordingMeta) => {
    try {
      const cast = await api.getRecording(vaultId, m.recordingId);
      const path = await save({
        defaultPath: await exportPath(`${m.label.replace(/[^\w.-]+/g, "_")}-${m.startedUnix}.${format}`),
        filters: [{ name: format === "cast" ? "asciicast" : format.toUpperCase(), extensions: [format] }],
      });
      if (!path) return;
      const target = path.toLowerCase().endsWith(`.${format}`) ? path : `${path}.${format}`;
      await writeTextFile(target, exportRecording(cast, format));
      toast(t("recordings.exported"), "ok");
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  };

  const remove = async (m: api.RecordingMeta) => {
    try {
      await api.deleteRecording(vaultId, m.recordingId);
      await reload();
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  };

  return (
    // `flex: 1`, not `height: 100%` — see ViewSnippets. The route slot is a flex
    // ROW, and a child without a basis is sized by its content, so the header
    // re-laid out the moment the list underneath it arrived.
    <div
      className="uh-view"
      style={{
        "--mcp-bg": p.bg0, "--mcp-surface": p.bg1, "--mcp-hover": p.bg2, "--mcp-line": p.line,
        "--mcp-text": p.txt, "--mcp-muted": p.txt2, "--mcp-accent": p.accent, "--mcp-danger": p.red,
        flex: 1,
        display: "flex",
        flexDirection: "column",
        minWidth: 0,
        background: p.bg0,
        overflow: "auto",
      } as CSSProperties}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: rem(10),
          padding: isMobile ? `${rem(16)} ${rem(16)} ${rem(12)}` : `${rem(16)} ${rem(22)} ${rem(12)}`,
          flexWrap: isMobile ? "wrap" : "nowrap",
        }}
      >
        <Icon name="record" size={20} color={p.accentText} />
        <h1 style={{ margin: 0, fontSize: TEXT.h1, fontWeight: 800, letterSpacing: rem(-0.7) }}>
          {t("nav.recordings")}
        </h1>
        <span style={{ fontFamily: MONO, fontSize: TEXT.small, color: p.txt3 }}>
          asciicast · {items?.length ?? 0}
        </span>
      </div>

      <div className="recording-toolbar">
        <div className="recording-search"><Input aria-label={t("recordings.search")} placeholder={t("recordings.search")} value={query} onChange={setQuery} /></div>
        <label className="mcp-check"><input type="checkbox" checked={failuresOnly} onChange={e => setFailuresOnly(e.target.checked)} />{t("recordings.failuresOnly")}</label>
        <fieldset className="recording-formats"><legend className="mcp-field-label">{t("recordings.exportFormat")}</legend>
          <div className="mcp-choice-group">{(["cast", "txt", "json"] as const).map(choice => <label className="mcp-choice" key={choice}>
            <input type="radio" name="recording-export-format" checked={format === choice} onChange={() => setFormat(choice)} /><span>{choice.toUpperCase()}</span>
          </label>)}</div>
        </fieldset>
        <McpRecordingSettings onSaved={() => void reload()} />
      </div>

      <div
        className="uh-stagger"
        style={{
          flex: "1 0 auto",
          overflow: "visible",
          padding: isMobile ? `${rem(4)} ${rem(16)} ${rem(18)}` : `${rem(4)} ${rem(22)} ${rem(18)}`,
        }}
      >
        {items === null ? (
          <div style={{ padding: `${rem(40)} 0`, textAlign: "center" }}>
            <Spinner />
          </div>
        ) : visible?.length === 0 ? (
          <div style={{ padding: `${rem(40)} 0`, textAlign: "center", fontSize: TEXT.base, color: p.txt3 }}>
            {t(items.length === 0 ? "recordings.empty" : "recordings.noMatches")}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: rem(8), minWidth: isMobile ? 0 : rem(680) }}>
            {visible?.map((m) => (
              <div
                key={m.recordingId}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: rem(12),
                  padding: `${rem(12)} ${rem(14)}`,
                  borderRadius: 12,
                  border: `1px solid ${p.line}`,
                  background: p.bg2,
                  flexWrap: isMobile ? "wrap" : "nowrap",
                }}
              >
                <div style={{ minWidth: 0, flex: isMobile ? "1 1 100%" : 1, overflowWrap: "anywhere" }}>
                  <div style={{ fontSize: TEXT.body, fontWeight: 700 }}>{m.label}</div>
                  <div style={{ fontFamily: MONO, fontSize: rem(11.5), color: p.txt3 }}>
                    {m.user}@{m.host} · {new Date(m.startedUnix * 1000).toLocaleString()} ·{" "}
                    {fmtDuration(m.durationSecs)} · {fmtSize(m.sizeBytes)}
                  </div>
                  {m.mcp && <div style={{ display: "flex", gap: rem(6), flexWrap: "wrap", fontSize: TEXT.small, color: p.txt2, marginTop: rem(4), overflowWrap: "anywhere" }}>
                    <strong style={{ color: p.accentText }}>MCP</strong>
                    <span>{m.mcp.application}</span>
                    <span>· {tDyn(`recordings.outcome.${m.mcp.outcome}`)}</span>
                    {m.mcp.exitCode !== null && <span>· {t("recordings.exitCode", { code: m.mcp.exitCode })}</span>}
                  </div>}
                  {m.mcp?.command && <div title={visibleCommand(m.mcp.command)} style={{ fontFamily: MONO, fontSize: TEXT.small, color: p.txt2, marginTop: rem(4), overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{visibleCommand(m.mcp.command)}</div>}
                  {m.truncated && (
                    <div style={{ fontSize: rem(11.5), color: p.amber, marginTop: rem(2) }}>
                      {t(m.mcp ? "recordings.mcpTruncated" : "recordings.truncated")}
                    </div>
                  )}
                </div>
                <Btn variant="ghost" size="sm" icon="play" onClick={() => void play(m)}>
                  {t("recordings.play")}
                </Btn>
                <Btn variant="ghost" size="sm" icon="download" onClick={() => void exportOne(m)}>
                  {t("recordings.export")}
                </Btn>
                <Btn variant="ghost" size="sm" icon="trash" onClick={() => void remove(m)}>
                  {t("common.delete")}
                </Btn>
              </div>
            ))}
          </div>
        )}
      </div>

      {playing && (
        <RecordingPlayer
          cast={playing.cast}
          title={playing.title}
          onClose={() => setPlaying(null)}
        />
      )}
    </div>
  );
}
