// The parts of a pane's session that are the same whichever end of it is a PTY:
// accumulating the rail preview from raw output, and dispatching the TermEvent
// stream into the terminal.
//
// Lifted out of ViewTerminal's open effect when the local terminal landed —
// there are now two ways to open a session and exactly one way to consume one,
// and having that written once is what keeps them from drifting.

import type { Terminal as Xterm } from "@xterm/xterm";
import type { TermEvent } from "@/bridge/types";
import type { TerminalPaneState } from "@/store/app";

/** Whether returning from the background should re-open this pane.
 *
 * A resume is a deliberate act, equivalent to pressing reconnect — but only for
 * panes a resume could actually have healed:
 *
 * - `closed` is an exited shell, the user's own `exit`. Reopening it would
 *   resurrect a session they deliberately ended.
 * - a host-key mismatch is also status `error`, and must never be retried: the
 *   attempt cannot succeed, and each one re-offers a possibly hostile key. That
 *   decision belongs to the Accept/Reject ceremony.
 * - a **local** pane has no link a resume could have healed. Its error means the
 *   shell would not start — wrong path, no permission, missing directory — and
 *   retrying that on every window focus is a loop, not a recovery. Restart is
 *   there for once the user has fixed the setting.
 */
export function shouldRetryOnResume(pane: TerminalPaneState): boolean {
  return pane.status === "error" && !pane.mismatch && pane.target.kind !== "local";
}

/** How many recent output lines the rail preview keeps, and how many it shows. */
const PREVIEW_KEEP = 6;
const PREVIEW_SHOW = 3;
/** Debounce for pushing the preview into the store — a busy session would
 *  otherwise re-render the hosts rail on every read. */
const PREVIEW_DEBOUNCE_MS = 500;

const stripAnsi = (str: string): string =>
  str
    .replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, "") // OSC
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "") // CSI
    .replace(/\x1b[@-Z\\-_]/g, "") // other escapes
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, ""); // stray controls

/** A carriage return rewrites the line, so only what follows the last one is
 *  what the user can actually see (progress bars, spinners). */
const lastLine = (s: string): string => (s.includes("\r") ? s.slice(s.lastIndexOf("\r") + 1) : s);

export interface PreviewCapture {
  /** Feed raw session output. */
  push: (bytes: Uint8Array) => void;
  /** Drop any pending debounce — for pane teardown. */
  dispose: () => void;
}

/** Keeps a rolling window of recent output lines so the hosts-rail shows a
 *  stable multi-line preview: real output, debounced, rather than the latest
 *  tail (which at an idle prompt would collapse to one line). */
export function createPreviewCapture(emit: (lines: string[]) => void): PreviewCapture {
  const decoder = new TextDecoder();
  let partial = ""; // an incomplete trailing line, carried to the next read
  let lines: string[] = [];
  // Plain setTimeout, not window.setTimeout: this module is exercised directly
  // by its tests, which run without a DOM.
  let timer: ReturnType<typeof setTimeout> | null = null;

  return {
    push(bytes: Uint8Array) {
      const parts = (partial + decoder.decode(bytes, { stream: true }))
        .replace(/\r\n/g, "\n") // PTY uses CRLF; normalize so lines aren't lost
        .split("\n");
      partial = (parts.pop() ?? "").slice(-2000);
      for (const raw of parts) {
        const clean = stripAnsi(lastLine(raw)).replace(/\s+$/, "");
        if (clean.trim().length) {
          lines.push(clean);
          if (lines.length > PREVIEW_KEEP) lines = lines.slice(-PREVIEW_KEEP);
        }
      }
      if (timer != null) return;
      timer = setTimeout(() => {
        timer = null;
        const tail = stripAnsi(lastLine(partial)).replace(/\s+$/, "");
        const all = tail.trim().length ? [...lines, tail] : lines;
        emit(all.slice(-PREVIEW_SHOW));
      }, PREVIEW_DEBOUNCE_MS);
    },
    dispose() {
      if (timer != null) {
        clearTimeout(timer);
        timer = null;
      }
    },
  };
}

export interface PaneEventOptions {
  term: Xterm;
  /** True once this run has been superseded or the pane torn down — late events
   *  from a channel we no longer own must not touch the terminal. */
  cancelled: () => boolean;
  /** Debounced preview lines for the hosts rail. */
  onPreview: (lines: string[]) => void;
  /** The localized "session closed (code N)" line. */
  closedText: (code: number) => string;
  /** The session ended. `dropped` means the peer died rather than the shell
   *  exiting — the only case where reconnecting can help, and one a local shell
   *  never produces (its exit code is always ≥ 0). */
  onClosed: (exit: number, dropped: boolean) => void;
}

export interface PaneEvents {
  onEvent: (e: TermEvent) => void;
  dispose: () => void;
}

/** Wire a session's event channel to the terminal: output in, close reported
 *  once, preview kept up to date. Identical for local and remote sessions. */
export function createPaneEvents(opts: PaneEventOptions): PaneEvents {
  const preview = createPreviewCapture(opts.onPreview);
  return {
    onEvent(e: TermEvent) {
      if (opts.cancelled()) return;
      if (e.type === "data") {
        const bytes = new Uint8Array(e.bytes);
        opts.term.write(bytes);
        preview.push(bytes);
        return;
      }
      // exit < 0 ⇒ no clean exit status (peer died / keepalive gave up) ⇒ a drop
      // we can auto-recover. A clean shell `exit` (code ≥ 0) stays closed.
      opts.term.writeln("");
      opts.term.writeln(`\x1b[2m${opts.closedText(e.exit)}\x1b[0m`);
      opts.onClosed(e.exit, e.exit < 0);
    },
    dispose: preview.dispose,
  };
}
