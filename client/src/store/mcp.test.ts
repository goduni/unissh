import { beforeEach, expect, it, vi } from "vitest";
const { status } = vi.hoisted(() => ({ status: vi.fn() }));
vi.mock("@/bridge/mcp", () => ({ mcpStatus: status }));
import { clearMcp, refreshMcp, useMcp } from "./mcp";
import type { McpStatus } from "@/bridge/mcp";
const review = { enabled: true, activity: { runs: [{ command: "sensitive review text" }] } } as McpStatus;
beforeEach(() => { clearMcp(); status.mockReset(); });
it("deduplicates polls and clears review text when the UI locks", async () => {
  let resolve!: (value: McpStatus) => void;
  status.mockReturnValue(new Promise<McpStatus>(done => { resolve = done; }));
  const a = refreshMcp(); const b = refreshMcp();
  expect(status).toHaveBeenCalledTimes(1);
  resolve(review); await Promise.all([a,b]);
  expect(useMcp.getState().status).toBe(review);
  clearMcp(); expect(useMcp.getState().status).toBeNull();
});
it("rejects a late response after lock even if a new poll already completed", async () => {
  let resolve!: (value: McpStatus) => void;
  status.mockReturnValueOnce(new Promise<McpStatus>(done => { resolve = done; }));
  const old = refreshMcp(); clearMcp();
  const fresh = { ...review, enabled: false };
  status.mockResolvedValueOnce(fresh); await refreshMcp();
  resolve(review); await old;
  expect(useMcp.getState().status).toBe(fresh);
});
