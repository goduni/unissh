// ViewRecordings — recorded sessions: list, replay, export, delete.
//
// The stored document is asciicast v2, so "export" is a real export: the file
// plays in `asciinema` and can be handed to someone who does not run UniSSH. The
// in-app player exists so you don't have to leave to check a recording, not to
// be the only way to read one.

import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal as Xterm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import { useTranslation } from "@/i18n";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { MONO, termOptions } from "@/theme/tokens";
import { Btn, Icon, Spinner } from "@/components/primitives";
import { Modal } from "@/components/Modal";
import { toast } from "@/store/toast";
import { useApp } from "@/store/app";
import { useNarrow } from "@/store/responsive";

/** One asciicast event: [seconds since start, stream, payload]. */
type CastEvent = [number, string, string];

/** Splits a document into its header and its events.
 *
 *  Tolerant on purpose: a recording salvaged from a session that ended badly may
 *  have a trailing partial line, and refusing to show any of it would punish the
 *  user for the very failure they are trying to look at. */
function parseCast(text: string): { width: number; height: number; events: CastEvent[] } {
  const lines = text.split("\n").filter((l) => l.trim().length);
  let width = 80;
  let height = 24;
  const events: CastEvent[] = [];
  for (const [i, line] of lines.entries()) {
    try {
      const parsed: unknown = JSON.parse(line);
      if (i === 0 && parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const h = parsed as { width?: number; height?: number };
        if (typeof h.width === "number") width = h.width;
        if (typeof h.height === "number") height = h.height;
        continue;
      }
      if (Array.isArray(parsed) && parsed.length >= 3 && typeof parsed[0] === "number") {
        events.push([parsed[0], String(parsed[1]), String(parsed[2])]);
      }
    } catch {
      // A truncated final line is expected; earlier garbage is not, but skipping
      // it still shows the rest.
    }
  }
  return { width, height, events };
}

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

function Player({ cast, onClose, title }: { cast: string; onClose: () => void; title: string }) {
  const { t } = useTranslation();
  // The same options a live pane uses, so a replay looks like the session did
  // rather than like a generic terminal.
  const { termTheme, termPrefs } = useTheme();
  const hostRef = useRef<HTMLDivElement | null>(null);
  const timersRef = useRef<number[]>([]);
  const [playing, setPlaying] = useState(true);

  useEffect(() => {
    if (!hostRef.current) return;
    const { width, height, events } = parseCast(cast);
    const term = new Xterm({
      ...termOptions(termPrefs, termTheme, 13),
      cols: width,
      rows: height,
      scrollback: 5000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    try {
      fit.fit();
    } catch {
      /* the container may not be laid out yet */
    }

    // One timer per event, scheduled against the event's own timestamp. Simple,
    // and exact: chaining setTimeouts would accumulate drift across a long
    // recording, so a five-minute session would end visibly late.
    const timers = timersRef.current;
    for (const [at, stream, data] of events) {
      if (stream !== "o") continue;
      timers.push(window.setTimeout(() => term.write(data), Math.max(0, at * 1000)));
    }
    const last = events.length ? events[events.length - 1][0] : 0;
    timers.push(window.setTimeout(() => setPlaying(false), Math.max(0, last * 1000) + 50));

    return () => {
      for (const id of timers) clearTimeout(id);
      timers.length = 0;
      term.dispose();
    };
  }, [cast, termPrefs, termTheme]);

  return (
    <Modal
      icon="terminal"
      title={title}
      subtitle={playing ? t("recordings.playing") : t("recordings.finished")}
      onClose={onClose}
      w={900}
      zIndex={300}
    >
      <div
        ref={hostRef}
        style={{ height: 420, borderRadius: 8, overflow: "hidden" }}
        aria-label={t("recordings.playerLabel")}
      />
    </Modal>
  );
}

export function ViewRecordings() {
  const { t } = useTranslation();
  const p = usePalette();
  const isMobile = useNarrow();
  const vaultId = useApp((s) => s.vaultId) ?? "";
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
      const { save } = await import("@tauri-apps/plugin-dialog");
      const { writeTextFile } = await import("@tauri-apps/plugin-fs");
      const path = await save({
        defaultPath: `${m.label.replace(/[^\w.-]+/g, "_")}-${m.startedUnix}.cast`,
        filters: [{ name: "asciicast", extensions: ["cast"] }],
      });
      if (!path) return;
      await writeTextFile(path, cast);
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
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: isMobile ? "16px 16px 12px" : "16px 22px 12px",
          flexWrap: isMobile ? "wrap" : "nowrap",
        }}
      >
        <Icon name="record" size={20} color={p.accentText} />
        <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800, letterSpacing: -0.7 }}>
          {t("nav.recordings")}
        </h1>
        <span style={{ fontFamily: MONO, fontSize: 12, color: p.txt3 }}>
          asciicast · {items?.length ?? 0}
        </span>
      </div>

      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: isMobile ? "4px 16px 18px" : "4px 22px 18px",
        }}
      >
        {items === null ? (
          <div style={{ padding: "40px 0", textAlign: "center" }}>
            <Spinner />
          </div>
        ) : items.length === 0 ? (
          <div style={{ padding: "40px 0", textAlign: "center", fontSize: 13, color: p.txt3 }}>
            {t("recordings.empty")}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: isMobile ? 0 : 680 }}>
            {items.map((m) => (
              <div
                key={m.recordingId}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "12px 14px",
                  borderRadius: 12,
                  border: `1px solid ${p.line}`,
                  background: p.bg2,
                  flexWrap: isMobile ? "wrap" : "nowrap",
                }}
              >
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ fontSize: 14, fontWeight: 700 }}>{m.label}</div>
                  <div style={{ fontFamily: MONO, fontSize: 11.5, color: p.txt3 }}>
                    {m.user}@{m.host} · {new Date(m.startedUnix * 1000).toLocaleString()} ·{" "}
                    {fmtDuration(m.durationSecs)} · {fmtSize(m.sizeBytes)}
                  </div>
                  {m.truncated && (
                    <div style={{ fontSize: 11.5, color: p.amber, marginTop: 2 }}>
                      {t("recordings.truncated")}
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
        <Player
          cast={playing.cast}
          title={playing.title}
          onClose={() => setPlaying(null)}
        />
      )}
    </div>
  );
}
