// "On this server" — the per-vault catalog + Pull/Push actions for the vault picker
// (Phase 4). Self-contained so it can be mounted inside Settings (and later the vault
// switcher) without entangling the rest of the screen.
//
// NOTE: strings are literal English for a first cut — wrap them in i18n keys
// (serverCloud.*) once the flow is confirmed in the running app.
import { useCallback, useEffect, useState } from "react";

import * as api from "@/bridge/api";
import type { ServerVault } from "@/bridge/types";
import { Btn, Icon, Spinner, Tag } from "@/components/primitives";
import { toast } from "@/store/toast";
import { usePalette } from "@/theme/ThemeProvider";

/** A vault's status decides the single action offered on its row. */
type Kind = "inSync" | "pull" | "push";

function classify(v: ServerVault): Kind {
  if (!v.isLocal) return "pull"; // on the server, not here → Pull it down
  if (!v.bound) return "push"; // here, but not synced to a server → Push it up
  return "inSync";
}

/** Short, stable label for a vault we can't (yet) show a name for. */
function shortId(vaultIdHex: string): string {
  return vaultIdHex.length > 10 ? `${vaultIdHex.slice(0, 10)}…` : vaultIdHex;
}

export function ServerVaultsSection({
  serverId,
  hasSession,
}: {
  serverId: string | null | undefined;
  hasSession: boolean;
}) {
  const p = usePalette();
  const [rows, setRows] = useState<ServerVault[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!hasSession) return;
    setLoading(true);
    try {
      const list = await api.serverListVaults(serverId ?? undefined);
      // Stable order: not-local first (things you can pull), then by id.
      list.sort((a, b) => Number(a.isLocal) - Number(b.isLocal) || a.vaultId.localeCompare(b.vaultId));
      setRows(list);
    } catch (e) {
      setRows([]);
      toast(`Couldn't list server vaults: ${String(e)}`, "err");
    } finally {
      setLoading(false);
    }
  }, [serverId, hasSession]);

  useEffect(() => {
    void load();
  }, [load]);

  const pull = async (v: ServerVault) => {
    setBusy(v.vaultId);
    try {
      const r = await api.serverPullVault(v.vaultId, serverId ?? undefined);
      toast(`Pulled — ${r.applied} applied`, r.rejected > 0 ? "warn" : "ok");
      await load();
    } catch (e) {
      toast(`Pull failed: ${String(e)}`, "err");
    } finally {
      setBusy(null);
    }
  };

  const push = async (v: ServerVault) => {
    setBusy(v.vaultId);
    try {
      const r = await api.serverAdoptVault(v.vaultId, serverId ?? undefined);
      toast(`Pushed — ${r.pushed} object(s)`, "ok");
      await load();
    } catch (e) {
      toast(`Push failed: ${String(e)}`, "err");
    } finally {
      setBusy(null);
    }
  };

  if (!hasSession) return null;

  return (
    <div style={{ marginTop: 18 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 8,
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 600, color: p.txt }}>On this server</div>
        <Btn variant="ghost" icon="refresh" onClick={load} disabled={loading}>
          Refresh
        </Btn>
      </div>

      {loading && rows === null ? (
        <div style={{ display: "flex", alignItems: "center", gap: 8, color: p.txt3, fontSize: 13 }}>
          <Spinner /> Loading…
        </div>
      ) : rows && rows.length === 0 ? (
        <div style={{ fontSize: 13, color: p.txt3, padding: "6px 0" }}>
          No vaults you can access on this server.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {(rows ?? []).map((v) => {
            const kind = classify(v);
            const rowBusy = busy === v.vaultId;
            return (
              <div
                key={v.vaultId}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "8px 10px",
                  border: `1px solid ${p.line}`,
                  borderRadius: 8,
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 13,
                      color: p.txt,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {v.isLocal && v.localName ? v.localName : shortId(v.vaultId)}
                  </div>
                  <div style={{ display: "flex", gap: 6, marginTop: 3 }}>
                    {v.tombstone && <Tag>deleted</Tag>}
                    {!v.isLocal && <Tag>on server</Tag>}
                    {v.isLocal && !v.bound && <Tag>local only</Tag>}
                  </div>
                </div>

                {rowBusy ? (
                  <Spinner />
                ) : kind === "inSync" ? (
                  <span style={{ fontSize: 12, color: p.txt3, display: "inline-flex", gap: 4, alignItems: "center" }}>
                    <Icon name="check" /> in sync
                  </span>
                ) : kind === "pull" ? (
                  <Btn variant="ghost" icon="download" onClick={() => pull(v)}>
                    Pull
                  </Btn>
                ) : (
                  <Btn variant="ghost" icon="upload" onClick={() => push(v)}>
                    Push
                  </Btn>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
