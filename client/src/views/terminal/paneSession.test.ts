// The pane's session plumbing. Both kinds of session — a shell on this machine
// and a shell across SSH — go through exactly this code, so what it does with
// bytes and with a close is worth pinning rather than re-verifying by eye in two
// places.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPaneEvents, createPreviewCapture, shouldRetryOnResume } from "./paneSession";
import type { TermEvent } from "@/bridge/types";
import type { TerminalPaneState } from "@/store/app";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const bytes = (s: string): number[] => Array.from(enc(s));

/** The pieces of xterm this module actually touches. */
function fakeTerm() {
  return { write: vi.fn(), writeln: vi.fn() } as unknown as Parameters<
    typeof createPaneEvents
  >[0]["term"] & { write: ReturnType<typeof vi.fn>; writeln: ReturnType<typeof vi.fn> };
}

beforeEach(() => {
  vi.useFakeTimers();
});

describe("createPreviewCapture", () => {
  it("emits recent lines once, after the debounce", () => {
    const emit = vi.fn();
    const cap = createPreviewCapture(emit);
    cap.push(enc("one\r\ntwo\r\n"));
    cap.push(enc("three\r\n"));
    expect(emit).not.toHaveBeenCalled();
    vi.runAllTimers();
    expect(emit).toHaveBeenCalledTimes(1);
    expect(emit).toHaveBeenCalledWith(["one", "two", "three"]);
  });

  it("keeps only the last few lines", () => {
    const emit = vi.fn();
    const cap = createPreviewCapture(emit);
    cap.push(enc("a\r\nb\r\nc\r\nd\r\ne\r\nf\r\ng\r\n"));
    vi.runAllTimers();
    expect(emit).toHaveBeenCalledWith(["e", "f", "g"]);
  });

  it("strips escape sequences, so the rail shows text and not control codes", () => {
    const emit = vi.fn();
    const cap = createPreviewCapture(emit);
    cap.push(enc("\x1b[32mgreen\x1b[0m\r\n\x1b]0;a title\x07plain\r\n"));
    vi.runAllTimers();
    expect(emit).toHaveBeenCalledWith(["green", "plain"]);
  });

  it("shows only what a carriage return left visible", () => {
    // Progress bars rewrite one line; the preview should show the final state,
    // not every frame concatenated.
    const emit = vi.fn();
    const cap = createPreviewCapture(emit);
    cap.push(enc("10%\r50%\r100%\r\n"));
    vi.runAllTimers();
    expect(emit).toHaveBeenCalledWith(["100%"]);
  });

  it("carries an unfinished line across reads instead of splitting a word", () => {
    const emit = vi.fn();
    const cap = createPreviewCapture(emit);
    cap.push(enc("unfini"));
    cap.push(enc("shed\r\n"));
    vi.runAllTimers();
    expect(emit).toHaveBeenCalledWith(["unfinished"]);
  });

  it("includes the line still being typed at an idle prompt", () => {
    // Without this the preview of a session sitting at a prompt would be empty.
    const emit = vi.fn();
    const cap = createPreviewCapture(emit);
    cap.push(enc("done\r\n$ "));
    vi.runAllTimers();
    expect(emit).toHaveBeenCalledWith(["done", "$"]);
  });

  it("stays quiet after dispose", () => {
    const emit = vi.fn();
    const cap = createPreviewCapture(emit);
    cap.push(enc("late\r\n"));
    cap.dispose();
    vi.runAllTimers();
    expect(emit).not.toHaveBeenCalled();
  });

  it("emits as many lines as the caller asked for", () => {
    // The broadcast grid mirrors a deeper tail than the hosts rail does.
    const emit = vi.fn();
    const cap = createPreviewCapture(emit, { show: 6 });
    cap.push(enc("a\r\nb\r\nc\r\nd\r\ne\r\nf\r\ng\r\nh\r\n"));
    vi.runAllTimers();
    expect(emit).toHaveBeenCalledWith(["c", "d", "e", "f", "g", "h"]);
  });

  it("emits on the caller's debounce, not the rail's", () => {
    // The broadcast grid is a live mirror; the rail is glanced at. Same pipeline,
    // different cadence.
    const emit = vi.fn();
    const cap = createPreviewCapture(emit, { debounceMs: 100 });
    cap.push(enc("quick\r\n"));
    vi.advanceTimersByTime(100);
    expect(emit).toHaveBeenCalledWith(["quick"]);
  });

  it("defaults to the rail's slower cadence", () => {
    const emit = vi.fn();
    const cap = createPreviewCapture(emit);
    cap.push(enc("slow\r\n"));
    vi.advanceTimersByTime(100);
    expect(emit).not.toHaveBeenCalled();
    vi.advanceTimersByTime(400);
    expect(emit).toHaveBeenCalledWith(["slow"]);
  });

  it("mirrors a real send: echo, output and prompt redraw, no control codes", () => {
    // What a bash host actually writes back after a broadcast send — bracketed
    // paste off/on, an OSC title, a colour-coded prompt, and a \r-rewritten
    // progress line. None of it may reach a plain-text tile as literal text.
    const emit = vi.fn();
    const cap = createPreviewCapture(emit, { show: 6 });
    cap.push(enc("uptime\r\n\x1b[?2004l\r"));
    cap.push(enc(" 14:22:01 up 12 days,  3:11,  2 users\r\n"));
    cap.push(enc("sync: 10%\rsync: 60%\rsync: 100%\r\n"));
    cap.push(enc("\x1b]0;root@web-01: ~\x07\x1b[?2004h\x1b[01;32mroot@web-01\x1b[00m:~$ "));
    vi.runAllTimers();
    expect(emit).toHaveBeenCalledWith([
      "uptime",
      " 14:22:01 up 12 days,  3:11,  2 users",
      "sync: 100%",
      "root@web-01:~$",
    ]);
  });

  it("decodes multi-byte characters split across reads", () => {
    // A PTY read can end mid-character; decoding each chunk on its own turns
    // the halves into U+FFFD.
    const emit = vi.fn();
    const cap = createPreviewCapture(emit);
    const utf8 = enc("Загрузка\r\n");
    cap.push(utf8.slice(0, 5));
    cap.push(utf8.slice(5));
    vi.runAllTimers();
    expect(emit).toHaveBeenCalledWith(["Загрузка"]);
  });
});

describe("createPaneEvents", () => {
  const base = {
    cancelled: () => false,
    onPreview: () => {},
    closedText: (code: number) => `[closed ${code}]`,
    onClosed: () => {},
  };

  it("writes output straight to the terminal", () => {
    const term = fakeTerm();
    const { onEvent } = createPaneEvents({ ...base, term });
    onEvent({ type: "data", bytes: bytes("hello") } as TermEvent);
    expect(term.write).toHaveBeenCalledTimes(1);
    expect(new TextDecoder().decode(term.write.mock.calls[0][0])).toBe("hello");
  });

  it("reports a clean exit as not-a-drop, so nothing reconnects", () => {
    // A local shell always exits with a code ≥ 0; this is the branch that keeps
    // `exit` from being mistaken for a lost connection.
    const onClosed = vi.fn();
    const term = fakeTerm();
    createPaneEvents({ ...base, term, onClosed }).onEvent({ type: "close", exit: 0 });
    expect(onClosed).toHaveBeenCalledWith(0, false);

    onClosed.mockClear();
    createPaneEvents({ ...base, term, onClosed }).onEvent({ type: "close", exit: 130 });
    expect(onClosed).toHaveBeenCalledWith(130, false);
  });

  it("reports a missing exit status as a drop", () => {
    // -1 is the core's "no exit status" — the peer died or keepalive gave up,
    // which is the one case a reconnect can fix.
    const onClosed = vi.fn();
    createPaneEvents({ ...base, term: fakeTerm(), onClosed }).onEvent({
      type: "close",
      exit: -1,
    });
    expect(onClosed).toHaveBeenCalledWith(-1, true);
  });

  it("prints the close line into the terminal", () => {
    const term = fakeTerm();
    createPaneEvents({ ...base, term }).onEvent({ type: "close", exit: 7 });
    const written = term.writeln.mock.calls.map((c) => String(c[0])).join("");
    expect(written).toContain("[closed 7]");
  });

  it("ignores everything once the run is cancelled", () => {
    // A superseded run's channel can still deliver: writing into a terminal that
    // has moved on, or closing a pane that already reopened, is worse than
    // dropping the event.
    const term = fakeTerm();
    const onClosed = vi.fn();
    const { onEvent } = createPaneEvents({ ...base, term, cancelled: () => true, onClosed });
    onEvent({ type: "data", bytes: bytes("ghost") } as TermEvent);
    onEvent({ type: "close", exit: 0 });
    expect(term.write).not.toHaveBeenCalled();
    expect(onClosed).not.toHaveBeenCalled();
  });
});

describe("shouldRetryOnResume", () => {
  const pane = (over: Partial<TerminalPaneState>): TerminalPaneState =>
    ({
      id: "p",
      sessionId: null,
      title: "t",
      target: { kind: "ssh", profile: {} },
      status: "error",
      gen: 0,
      reconnects: 0,
      lastOnlineAt: 0,
      ...over,
    }) as TerminalPaneState;

  it("retries a host pane that failed to connect", () => {
    expect(shouldRetryOnResume(pane({}))).toBe(true);
  });

  it("never retries a local pane", () => {
    // Its error is a settings problem, not a link a resume could have healed —
    // retrying on every window focus would be a loop, not a recovery.
    expect(
      shouldRetryOnResume(
        pane({ target: { kind: "local", spec: { shell: "/bin/zsh", args: [], label: "zsh" } } }),
      ),
    ).toBe(false);
  });

  it("leaves an exited session alone", () => {
    expect(shouldRetryOnResume(pane({ status: "closed" }))).toBe(false);
  });

  it("never retries past a host-key mismatch", () => {
    expect(
      shouldRetryOnResume(pane({ mismatch: { host: "h", port: 22, fingerprint: "f" } })),
    ).toBe(false);
  });

  it("leaves a live session running", () => {
    expect(shouldRetryOnResume(pane({ status: "online" }))).toBe(false);
    expect(shouldRetryOnResume(pane({ status: "connecting" }))).toBe(false);
  });
});
