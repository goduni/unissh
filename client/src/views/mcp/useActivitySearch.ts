import { useEffect, useState } from "react";
import { mcpSearchCommands, type McpRun } from "@/bridge/mcp";

/** Search immutable command bodies in the native broker. Only matching IDs cross IPC. */
export function useActivitySearch(integrationId: string, runs: McpRun[], query: string) {
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<{ key: string; ids: Set<string>; failed: boolean } | null>(null);
  // Polls change timing/state, not searchable text. Search again only for new/removed runs.
  const inventory = runs.map(run => run.run_id).sort().join(",");
  const key = JSON.stringify([integrationId, inventory, query, attempt]);
  useEffect(() => {
    if (!query || !inventory) return;
    let alive = true;
    const timer = setTimeout(() => {
      void mcpSearchCommands(integrationId, query).then(ids => {
        if (alive) setResult({ key, ids: new Set(ids), failed: false });
      }, () => {
        if (alive) setResult({ key, ids: new Set(), failed: true });
      });
    }, 180);
    return () => { alive = false; clearTimeout(timer); };
  }, [integrationId, inventory, query, key]);
  const current = result?.key === key ? result : null;
  return {
    matches: query ? runs.filter(run => current?.ids.has(run.run_id)) : runs,
    searching: Boolean(query && inventory && !current),
    failed: Boolean(query && inventory && current?.failed),
    retry: () => setAttempt(n => n + 1),
  };
}
