// A real xterm rendering fixed sample output, built by the SAME termOptions() the live
// panes use. That shared constructor is the point: a preview assembled separately drifts
// from reality, and a preview that lies about what a setting does is worse than none.
//
// DOM renderer, not WebGL — a second GPU context for a 14-row preview is not worth the
// resources, and nothing here needs the throughput.

import { FitAddon } from "@xterm/addon-fit";
import { Terminal as Xterm } from "@xterm/xterm";
import { useEffect, useRef } from "react";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { termOptions } from "@/theme/tokens";
import "@xterm/xterm/css/xterm.css";

const CSI = "\x1b["; // ANSI Control Sequence Introducer
const c = (code: string, s: string): string => `${CSI}${code}m${s}${CSI}0m`;

/** Deliberately covers what the settings actually change: a prompt, coloured `ls`
 *  output, a diff (where bright-vs-normal matters), the full 16-colour ramp so derived
 *  bright variants are visible, and one box-drawing + one emoji line so line height and
 *  Unicode width are inspectable rather than guessed at. */
const SAMPLE: string[] = [
  `${c("32;1", "user@web-01")}:${c("34;1", "~/srv")}$ ls --color`,
  `${c("34;1", "config/")}  ${c("32", "deploy.sh")}  ${c("36", "current -> releases/42")}  ${c("31", "backup.tar.gz")}`,
  "",
  c("1", "diff --git a/server/src/main.rs b/server/src/main.rs"),
  c("36", "@@ -12,7 +12,7 @@"),
  c("31", '-    let addr = "127.0.0.1:8080";'),
  c("32", '+    let addr = std::env::var("BIND")?;'),
  "",
  [30, 31, 32, 33, 34, 35, 36, 37].map((n) => c(String(n), " ██ ")).join(""),
  [90, 91, 92, 93, 94, 95, 96, 97].map((n) => c(String(n), " ██ ")).join(""),
  "",
  "┌───────────┬─────────┐  0123456789",
  "│ hostname  │ status  │  != -> === =>",
  "└───────────┴─────────┘  ✓ ✗ ⚠ 🚀 日本語",
];

export function TerminalPreview() {
  const p = usePalette();
  const { termTheme, termPrefs } = useTheme();
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Xterm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);

  // Mount once. Re-creating the terminal on every settings change would flash the sample
  // on each keystroke of the custom-font box.
  useEffect(() => {
    if (!hostRef.current) return;
    const term = new Xterm({
      ...termOptions(termPrefs, termTheme, 12),
      disableStdin: true,
      scrollback: 0,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    for (const line of SAMPLE) term.writeln(line);
    try {
      fit.fit();
    } catch {
      /* zero-size container during layout — the resize observer below refits */
    }
    termRef.current = term;
    fitRef.current = fit;

    const ro = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        /* ignore transient 0x0 */
      }
    });
    ro.observe(hostRef.current);

    return () => {
      ro.disconnect();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Push option changes into the mounted instance, same as a real pane does.
  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    const next = termOptions(termPrefs, termTheme, 12);
    term.options.fontFamily = next.fontFamily;
    term.options.fontSize = next.fontSize;
    term.options.lineHeight = next.lineHeight;
    term.options.letterSpacing = next.letterSpacing;
    term.options.cursorStyle = next.cursorStyle;
    term.options.cursorBlink = next.cursorBlink;
    term.options.minimumContrastRatio = next.minimumContrastRatio;
    term.options.theme = next.theme;
    fitRef.current?.fit();
  }, [termPrefs, termTheme]);

  return (
    <div
      style={{
        borderRadius: 12,
        overflow: "hidden",
        border: `1px solid ${p.line}`,
        background: termTheme.bg,
        padding: 10,
        height: 240,
        boxSizing: "border-box",
      }}
    >
      <div ref={hostRef} style={{ width: "100%", height: "100%" }} />
    </div>
  );
}
