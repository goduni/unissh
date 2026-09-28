import { describe, expect, it } from "vitest";
import type { McpOutputChunk, McpRun } from "@/bridge/mcp";
import { commandText, elapsed, isFailedRun, mergeOutput, outputGroups, readableOutput, sortRuns } from "./activity";

const run = (run_id: string, state: string, created_unix_ms: number, exit_code: number | null = null): McpRun => ({ run_id, state, created_unix_ms, exit_code, integration_id: "app", session_id: null, error: null });
const chunk = (cursor: string, data: string, stream: "stdout" | "stderr" = "stdout", encoding: "utf8" | "base64" = "utf8"): McpOutputChunk => ({ cursor, data, stream, encoding });

describe("MCP activity", () => {
  it("keeps active work first, then recent finished work, without mutating the review", () => {
    const input = [run("old", "completed", 1, 0), run("new", "completed", 3, 1), run("active", "running", 2)];
    expect(sortRuns(input).map(r => r.run_id)).toEqual(["active", "new", "old"]);
    expect(input[0].run_id).toBe("old");
    expect(isFailedRun(input[1])).toBe(true);
    expect(isFailedRun(run("unknown", "completed", 4))).toBe(false);
    expect(isFailedRun(run("failure", "failed", 5))).toBe(true);
  });
  it("deduplicates cursor retries without dropping interleaved streams", () => {
    expect(mergeOutput([chunk("0", "a")], [chunk("0", "a"), chunk("1", "b", "stderr"), chunk("1", "b", "stderr")])).toEqual([chunk("0", "a"), chunk("1", "b", "stderr")]);
  });
  it("joins text packets but keeps independently padded binary chunks intact", () => {
    const input = [chunk("0", "he"), chunk("1", "llo"), chunk("2", "warning", "stderr"), chunk("3", "AA==", "stdout", "base64"), chunk("4", "AQ==", "stdout", "base64")];
    expect(outputGroups(input, "all").map(c => c.data)).toEqual(["hello", "warning", "AA==", "AQ=="]);
    expect(outputGroups(input, "stderr")).toEqual([input[2]]);
    expect(input[0].data).toBe("he");
  });
  it("renders text safely, strips completed terminal sequences and retains surrounding output", () => {
    const text = 'before\x1b[31mred\x1b[0m\x1b]0;title\x07after\x1b]0;second\x1b\\end\n\t\u202e\r';
    expect(readableOutput(text)).toBe('beforeredafterend\n\t\\u202e\\u000d');
    const packets = [chunk("0", "\x1b]0;ti"), chunk("1", "tle\x07visible")];
    expect(readableOutput(outputGroups(packets, "all")[0].data)).toBe("visible");
    expect(readableOutput("\x1b]incomplete")).toBe("\\u001b]incomplete");
    expect(commandText("echo ok\nrm file\u202e")).toBe("echo ok\\nrm file\\u202e");
  });
  it("formats elapsed time in the interface locale and leaves unstarted commands unknown", () => {
    expect(elapsed(null)).toBe("—");
    expect(elapsed(0)).toBe("<1s");
    expect(elapsed(61000)).toBe("1m 1s");
    expect(elapsed(3600000)).toBe("1h 0m");
    expect(elapsed(61000, "ru")).toContain("мин");
  });
});
