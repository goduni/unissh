// "On this server" — the per-vault catalog + Pull/Push actions for the vault picker
// (Phase 4). Self-contained so it can be mounted inside Settings (and later the vault
// switcher) without entangling the rest of the screen.
import { useCallback, useEffect, useRef, useState } from "react";

import * as api from "@/bridge/api";
import { tooLargeSummary } from "@/bridge/syncReport";
import { apiErrorMessage, type ServerVault } from "@/bridge/types";
import { useTranslation } from "@/i18n";
import { Btn, Icon, Spinner, Tag } from "@/components/primitives";
import { toast } from "@/store/toast";
import { usePalette } from "@/theme/ThemeProvider";
import { rem, TEXT } from "@/theme/tokens";
import { catalogRows, loadServerVaults } from "@/support/serverVaults";
import { SharedWithYou, type SharedLoad } from "./SharedVaultTrust";

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
  const { t } = useTranslation();
  const [all, setAll] = useState<ServerVault[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  // Vaults a teammate shared that wait for this device to trust their owner:
  // their own group, with its own loading state and error.
  const [shared, setShared] = useState<SharedLoad>({ status: "idle" });
  const titleRef = useRef<HTMLHeadingElement>(null);
  const generation = useRef(0);

  const load = useCallback(async () => {
    if (!hasSession) return;
    const gen = ++generation.current;
    const current = () => gen === generation.current;
    setLoading(true);
    setShared((s) => (s.status === "ready" ? s : { status: "loading" }));
    await loadServerVaults(
      {
        listVaults: () => api.serverListVaults(serverId ?? undefined),
        pendingShared: () => api.serverPendingSharedVaults(serverId ?? undefined),
      },
      {
        rows: (list) => {
          if (!current()) return;
          setAll(list);
          setLoading(false);
        },
        rowsFailed: (e) => {
          if (!current()) return;
          setAll([]);
          setLoading(false);
          toast(t("serverVaults.listFailed", { error: apiErrorMessage(e) }), "err");
        },
        shared: (r) => {
          if (current()) setShared({ status: "ready", vaults: r.vaults, malformed: r.malformed });
        },
        // Shown in its group, not as a second toast: offline, the catalog's
        // toast already says why.
        sharedFailed: (e) => {
          if (current()) setShared({ status: "failed", error: apiErrorMessage(e) });
        },
      },
    );
  }, [serverId, hasSession, t]);

  useEffect(() => {
    void load();
  }, [load]);

  const waiting = shared.status === "ready" ? shared.vaults : [];
  const rows = all === null ? null : catalogRows(all, waiting);
  // Until the shared check is in, a not-local vault may be one that waits for
  // trust: its Pull is held back rather than offered and then taken away.
  const checkingShared = shared.status === "loading";

  const pull = async (v: ServerVault) => {
    setBusy(v.vaultId);
    try {
      const r = await api.serverPullVault(v.vaultId, serverId ?? undefined);
      toast(t("serverVaults.pulled", { count: r.applied }), r.rejected > 0 ? "warn" : "ok");
      await load();
    } catch (e) {
      toast(t("serverVaults.pullFailed", { error: apiErrorMessage(e) }), "err");
    } finally {
      setBusy(null);
    }
  };

  const push = async (v: ServerVault) => {
    setBusy(v.vaultId);
    try {
      const r = await api.serverBindAndPushVault(v.vaultId, serverId ?? undefined);
      // Items the server refused as too large are named, as after any other
      // sync, instead of being counted out of "pushed".
      const notUploaded = tooLargeSummary(r.tooLarge);
      if (notUploaded) toast(t("serverCloud.syncTooLarge", { items: notUploaded }), "warn");
      else toast(t("serverVaults.pushed", { count: r.pushed }), "ok");
      await load();
    } catch (e) {
      toast(t("serverVaults.pushFailed", { error: apiErrorMessage(e) }), "err");
    } finally {
      setBusy(null);
    }
  };

  if (!hasSession) return null;

  return (
    <div style={{ marginTop: rem(18) }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: rem(8),
        }}
      >
        <h3
          ref={titleRef}
          tabIndex={-1}
          style={{ margin: 0, fontSize: TEXT.base, fontWeight: 600, color: p.txt }}
        >
          {t("serverVaults.title")}
        </h3>
        <Btn variant="ghost" icon="refresh" onClick={load} disabled={loading}>
          {t("common.refresh")}
        </Btn>
      </div>

      <SharedWithYou
        load={shared}
        serverId={serverId}
        onChanged={(focus) => {
          void load();
          // The dialog's trigger row is about to go: focus the list the vault
          // now shows in.
          if (focus) requestAnimationFrame(() => titleRef.current?.focus());
        }}
      />

      {loading && rows === null ? (
        <div style={{ display: "flex", alignItems: "center", gap: rem(8), color: p.txt3, fontSize: TEXT.base }}>
          <Spinner /> {t("serverVaults.loading")}
        </div>
      ) : rows && rows.length === 0 ? (
        <div style={{ fontSize: TEXT.base, color: p.txt3, padding: `${rem(6)} 0` }}>
          {t("serverVaults.empty")}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: rem(6) }}>
          {(rows ?? []).map((v) => {
            const kind = classify(v);
            const rowBusy = busy === v.vaultId;
            return (
              <div
                key={v.vaultId}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: rem(10),
                  padding: `${rem(8)} ${rem(10)}`,
                  border: `1px solid ${p.line}`,
                  borderRadius: 8,
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: TEXT.base,
                      color: p.txt,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {v.isLocal && v.localName ? v.localName : shortId(v.vaultId)}
                  </div>
                  <div style={{ display: "flex", gap: rem(6), marginTop: rem(3) }}>
                    {v.tombstone && <Tag>{t("serverVaults.tagDeleted")}</Tag>}
                    {!v.isLocal && <Tag>{t("serverVaults.tagOnServer")}</Tag>}
                    {v.isLocal && !v.bound && <Tag>{t("serverVaults.tagLocalOnly")}</Tag>}
                  </div>
                </div>

                {rowBusy ? (
                  <Spinner />
                ) : kind === "inSync" ? (
                  <span style={{ fontSize: TEXT.small, color: p.txt3, display: "inline-flex", gap: rem(4), alignItems: "center" }}>
                    <Icon name="check" /> {t("serverVaults.inSync")}
                  </span>
                ) : kind === "pull" ? (
                  <Btn variant="ghost" icon="download" onClick={() => pull(v)} disabled={checkingShared}>
                    {t("serverVaults.pull")}
                  </Btn>
                ) : (
                  <Btn variant="ghost" icon="upload" onClick={() => push(v)}>
                    {t("serverVaults.push")}
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
