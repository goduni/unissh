// OSC 52 is how a remote multiplexer/editor (zellij, tmux, nvim) asks the
// terminal to write its selection into the system clipboard. The payload
// reaches us as `Pc;Pd` — selection targets, then base64 text. Getting this
// wrong either drops the user's copy on the floor (the bug this fixes) or
// hands the remote host a clipboard-read primitive (the "?" query), so the
// accept/reject line is worth pinning.

import { describe, expect, it } from "vitest";
import { parseOsc52, OSC52_MAX_B64 } from "./osc52";

const b64 = (s: string): string => btoa(String.fromCharCode(...new TextEncoder().encode(s)));

describe("parseOsc52", () => {
  it("decodes a plain copy to the clipboard selection", () => {
    expect(parseOsc52("c;aGVsbG8sIHdvcmxk")).toBe("hello, world");
  });

  it("decodes multi-byte UTF-8", () => {
    expect(parseOsc52(`c;${b64("привет ⌘")}`)).toBe("привет ⌘");
  });

  it("accepts an empty selection field (defaults to clipboard)", () => {
    expect(parseOsc52(";aGk=")).toBe("hi");
  });

  it("accepts multiple selection targets", () => {
    expect(parseOsc52(`cs;${b64("hi")}`)).toBe("hi");
  });

  it("tolerates whitespace inside the base64 (chunked senders)", () => {
    expect(parseOsc52("c;aGVs\nbG8=")).toBe("hello");
  });

  it("refuses the clipboard-read query", () => {
    expect(parseOsc52("c;?")).toBeNull();
  });

  it("ignores an empty payload rather than clearing the clipboard", () => {
    expect(parseOsc52("c;")).toBeNull();
  });

  it("ignores invalid base64", () => {
    expect(parseOsc52("c;!!!not-base64!!!")).toBeNull();
  });

  it("ignores a payload with no selection separator", () => {
    expect(parseOsc52("aGk=")).toBeNull();
  });

  it("ignores an oversized payload", () => {
    const big = "A".repeat(OSC52_MAX_B64 + 4);
    expect(parseOsc52(`c;${big}`)).toBeNull();
  });
});
