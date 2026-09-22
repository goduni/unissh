import { useEffect, useMemo, useRef, useState } from "react";
import { Terminal as Xterm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { useTranslation, tDyn } from "@/i18n";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { MONO, rem, termOptions, TEXT } from "@/theme/tokens";
import { Modal } from "./Modal";
import { mcpRecordingDetails } from "@/support/recordings";
import { visibleCommand } from "@/bridge/mcp";

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

export function RecordingPlayer({ cast, onClose, title }: { cast: string; onClose: () => void; title: string }) {
  const { t } = useTranslation();
  const p = usePalette();
  const mcp = useMemo(() => mcpRecordingDetails(cast), [cast]);
  // The same options a live pane uses, so a replay looks like the session did
  // rather than like a generic terminal.
  const { termTheme, termPrefs } = useTheme();
  const hostRef = useRef<HTMLDivElement | null>(null);
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

    // A single cursor advanced against the wall clock, rather than one timer per
    // event: an 8 MB recording holds tens of thousands of events, and scheduling
    // a timer for each would hand the browser a queue that size at once. Reading
    // the elapsed time on each tick also means no drift accumulates, which is
    // what chaining timeouts would have cost.
    const out = events.filter(([, stream]) => stream === "o");
    const startedAt = performance.now();
    let next = 0;
    let raf = 0;
    const step = () => {
      const elapsed = (performance.now() - startedAt) / 1000;
      // Everything now due is written in one pass, so a tab that was throttled
      // catches up instead of replaying the rest in slow motion.
      let batch = "";
      while (next < out.length && out[next][0] <= elapsed) {
        batch += out[next][2];
        next++;
      }
      if (batch) term.write(batch);
      if (next < out.length) {
        raf = requestAnimationFrame(step);
      } else {
        setPlaying(false);
      }
    };
    raf = requestAnimationFrame(step);

    return () => {
      cancelAnimationFrame(raf);
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
      {mcp && (
        <div style={{ marginBottom: rem(16), minWidth: 0 }}>
          <div style={{ display: "flex", gap: rem(8), flexWrap: "wrap", color: p.txt2, fontSize: TEXT.small }}>
            <strong style={{ color: p.accentText }}>MCP</strong>
            <span style={{ overflowWrap: "anywhere" }}>{mcp.application}</span>
            <span>· {tDyn(`recordings.outcome.${mcp.outcome}`)}</span>
            {mcp.exitCode !== null && <span>· {t("recordings.exitCode", { code: mcp.exitCode })}</span>}
          </div>
          {mcp.destination && <div style={{ marginTop: rem(6), fontFamily: MONO, fontSize: TEXT.small, color: p.txt2, overflowWrap: "anywhere" }}>{mcp.destination}</div>}
          <pre style={{ fontFamily: MONO, fontSize: TEXT.small, whiteSpace: "pre-wrap", overflowWrap: "anywhere", background: p.bg2, borderRadius: 8, padding: rem(12), margin: `${rem(10)} 0` }}>
            {visibleCommand(mcp.command)}
          </pre>
          {mcp.stdin !== undefined && <details><summary>{t("mcp.standardInput")}</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: "20vh", overflow: "auto", fontFamily: MONO }}>{visibleCommand(mcp.stdin)}</pre></details>}
          {mcp.env && Object.keys(mcp.env).length > 0 && <details><summary>{t("mcp.environment")}</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: "20vh", overflow: "auto", fontFamily: MONO }}>{Object.entries(mcp.env).map(([key, value]) => `${key}=${visibleCommand(value)}`).join("\n")}</pre></details>}
          {mcp.cwd && <div style={{ fontSize: TEXT.small, color: p.txt2, overflowWrap: "anywhere" }}>{t("recordings.cwd")}: <code>{visibleCommand(mcp.cwd)}</code></div>}
          {mcp.truncated && <p style={{ fontSize: TEXT.small, color: p.amber }}>{t("recordings.mcpTruncated")}</p>}
        </div>
      )}
      <div
        ref={hostRef}
        style={{ height: rem(420), borderRadius: 8, overflow: "hidden" }}
        aria-label={t("recordings.playerLabel")}
      />
    </Modal>
  );
}
