import { create } from "zustand";
import { mcpStatus, type McpStatus } from "@/bridge/mcp";

export const useMcp = create<{ status: McpStatus | null; failed: boolean }>(() => ({ status: null, failed: false }));
let pending: Promise<void> | null = null;
let generation = 0;

/** Drop native review text on lock/unmount; a late poll cannot restore it. */
export function clearMcp(): void {
  generation += 1;
  pending = null;
  useMcp.setState({ status: null, failed: false });
}
export function refreshMcp(): Promise<void> {
  if (pending) return pending;
  const issued = generation;
  const request = mcpStatus().then(status => {
    if (issued === generation) useMcp.setState({ status, failed: false });
  }, () => {
    if (issued === generation) useMcp.setState({ failed: true });
  }).finally(() => { if (pending === request) pending = null; });
  pending = request;
  return request;
}
