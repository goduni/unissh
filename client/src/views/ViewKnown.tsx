// Known hosts (TOFU) — list of pinned host keys + host-key mismatch banner.
// Pixel-faithful port of view-known.jsx; mock rows replaced with the real
// store.knownHosts list and api.* calls. The mismatch banner is surfaced from a
// live connect attempt via store.pendingMismatch (no fake mismatch state).

import { useEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, rgba, TEXT } from "@/theme/tokens";
import { Btn, Icon } from "@/components/primitives";
import { useApp, type PendingMismatch } from "@/store/app";
import { toast } from "@/store/toast";
import { guard } from "@/store/action";
import * as api from "@/bridge/api";
import type { KnownHostInfo } from "@/bridge/types";
import { useTranslation, Trans } from "@/i18n";
import { useFmt } from "@/i18n/format";
import { useNarrow } from "@/store/responsive";
import { open } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";

// ── helpers ────────────────────────────────────────────────────
/** Split a stored host key string ("ssh-ed25519 AAAA…") into algo + fingerprint. */
function parseHostKey(key: string): { algo: string; fp: string } {
  const parts = key.trim().split(/\s+/);
  if (parts.length >= 2) return { algo: parts[0], fp: parts.slice(1).join(" ") };
  return { algo: "", fp: key };
}

// minmax(0,1fr) lets the host/fingerprint tracks shrink below content so cells can
// ellipsize. The fixed tracks hold type (an algo name, a date), so they are design
// pixels — at 150 % a 130 CSS-px track no longer fits "ssh-ed25519".
const GRID = `minmax(0,1fr) ${rem(130)} minmax(0,1fr) ${rem(110)} ${rem(90)}`;

export function ViewKnown() {
  const p = usePalette();
  const { t } = useTranslation();
  const { fmtDate } = useFmt();
  // The wide (grid) layout needs ~680px; switch to the stacked card layout on the
  // CONTENT width, not the window — a wide sidebar can starve the content below that
  // while the window is still > the useNarrow breakpoint (else the 5-col grid collides
  // and clips its right edge).
  const rootRef = useRef<HTMLDivElement>(null);
  const [rootW, setRootW] = useState(0);
  useEffect(() => {
    const el = rootRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((ents) => {
      for (const e of ents) setRootW(e.contentRect.width);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const isMobile = useNarrow() || (rootW > 0 && rootW < 720);
  const knownHosts = useApp((s) => s.knownHosts);
  const pendingMismatch = useApp((s) => s.pendingMismatch);

  const importKnown = async () => {
    await guard(async () => {
      const selected = await open({
        multiple: false,
        directory: false,
        title: t("known.importTitle"),
      });
      if (!selected || Array.isArray(selected)) return;
      const text = await readTextFile(selected);
      const report = await api.importKnownHosts(text);
      await useApp.getState().reloadVault();
      toast(t("known.imported", { hosts: t("count.hosts", { count: report.imported }) }), "ok");
    });
  };

  // Unpinning a key silently would defeat the pin: gate it behind an explicit
  // danger confirm that spells out the consequence (next connect re-pins via TOFU).
  const forget = (k: KnownHostInfo) => {
    const label = k.port && k.port !== 22 ? `${k.host}:${k.port}` : k.host;
    useApp.getState().setConfirm({
      title: t("known.forgetTitle"),
      body: t("known.forgetBody", { host: label }),
      danger: true,
      confirmLabel: t("known.forget"),
      icon: "fingerprint",
      onConfirm: async () => {
        await guard(async () => {
          await api.forgetHost(k.host, k.port);
          await useApp.getState().reloadVault();
          toast(t("known.hostRemoved"), "ok");
        });
      },
    });
  };

  // Clear the in-pane security card on every terminal pane stopped by THIS
  // mismatch. Both accept and reject resolve the pending mismatch, so both must
  // sweep the panes — otherwise a rejected pane keeps a stuck card with no
  // Reconnect (a mismatch pane deliberately offers no Reconnect until resolved).
  const clearMismatchPanes = (m: PendingMismatch) => {
    const st = useApp.getState();
    for (const tab of st.terminals)
      for (const pn of tab.panes)
        if (pn.mismatch && pn.mismatch.host === m.host && pn.mismatch.port === m.port)
          st.updatePane(tab.id, pn.id, { mismatch: undefined });
  };

  const accept = async () => {
    const m = useApp.getState().pendingMismatch;
    if (!m) return;
    await guard(async () => {
      await api.trustHost(m.host, m.port, m.fingerprint);
      useApp.getState().setPendingMismatch(null);
      clearMismatchPanes(m);
      await useApp.getState().reloadVault();
      toast(t("known.newKeyAccepted"), "ok");
    });
  };

  const reject = () => {
    const m = useApp.getState().pendingMismatch;
    useApp.getState().setPendingMismatch(null);
    if (m) clearMismatchPanes(m);
  };

  return (
    <div
      ref={rootRef}
      className="uh-view"
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        minWidth: 0,
        background: p.bg0,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: rem(10),
          padding: isMobile ? `${rem(16)} ${rem(16)} ${rem(12)}` : `${rem(16)} ${rem(22)} ${rem(12)}`,
          flexWrap: isMobile ? "wrap" : "nowrap",
        }}
      >
        <Icon name="shieldcheck" size={20} color={p.accentText} />
        <h1 style={{ margin: 0, fontSize: TEXT.h1, fontWeight: 800, letterSpacing: rem(-0.7) }}>
          {t("nav.known")}
        </h1>
        <span
          style={{
            fontFamily: MONO,
            fontSize: TEXT.small,
            color: p.txt3,
          }}
        >
          TOFU · {knownHosts.length}
        </span>
        <div style={{ flex: 1 }} />
        <Btn variant="ghost" icon="download" size="sm" onClick={importKnown}>
          {t("known.import")}
        </Btn>
      </div>

      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: isMobile ? `${rem(4)} ${rem(16)} ${rem(18)}` : `${rem(4)} ${rem(22)} ${rem(18)}`,
        }}
      >
        <div style={{ minWidth: isMobile ? 0 : rem(680) }}>
          {/* mismatch banner — only when a live connect surfaced a key change */}
          {pendingMismatch && (
            <div
              style={{
                marginBottom: rem(16),
                borderRadius: 16,
                overflow: "hidden",
                border: `1px solid ${rgba(p.red, 0.5)}`,
                background: rgba(p.red, 0.07),
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: rem(11),
                  padding: `${rem(13)} ${rem(16)}`,
                  borderBottom: `1px solid ${rgba(p.red, 0.3)}`,
                }}
              >
                <span
                  style={{
                    width: rem(34),
                    height: rem(34),
                    borderRadius: 10,
                    background: rgba(p.red, 0.18),
                    border: `1px solid ${rgba(p.red, 0.5)}`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <Icon name="alert" size={18} color={p.red} />
                </span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: TEXT.body, fontWeight: 800, color: p.red }}>
                    ⚠ {t("known.mismatchTitle")}
                  </div>
                  <div style={{ fontSize: TEXT.base, color: p.txt2 }}>
                    <Trans
                      i18nKey="known.mismatchBody"
                      values={{ host: pendingMismatch.host }}
                      components={{ b: <b style={{ color: p.txt }} /> }}
                    />
                  </div>
                </div>
              </div>
              <div
                style={{
                  padding: `${rem(13)} ${rem(16)}`,
                  display: "flex",
                  flexDirection: isMobile ? "column" : "row",
                  alignItems: isMobile ? "stretch" : "center",
                  gap: isMobile ? rem(12) : rem(20),
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: TEXT.micro, color: p.txt3, marginBottom: rem(3) }}>
                    {t("known.stored")}
                  </div>
                  <div
                    style={{
                      fontFamily: MONO,
                      fontSize: TEXT.small,
                      color: p.txt2,
                      // Break fingerprint on desktop too: full SHA256 overflows its ~200px column.
                      wordBreak: "break-all",
                    }}
                  >
                    {knownHosts.find(
                      (k) => k.host === pendingMismatch.host && k.port === pendingMismatch.port,
                    )?.fingerprint || "—"}
                  </div>
                </div>
                <Icon
                  name="ar"
                  size={16}
                  color={p.red}
                  style={isMobile ? { transform: "rotate(90deg)" } : undefined}
                />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: TEXT.micro, color: p.txt3, marginBottom: rem(3) }}>
                    {t("known.presentedNow")}
                  </div>
                  <div
                    style={{
                      fontFamily: MONO,
                      fontSize: TEXT.small,
                      color: p.red,
                      // Break fingerprint on desktop too: full SHA256 overflows its ~200px column.
                      wordBreak: "break-all",
                    }}
                  >
                    {pendingMismatch.fingerprint}
                  </div>
                </div>
                <div
                  style={{
                    display: "flex",
                    gap: rem(8),
                    ...(isMobile ? { width: "100%" } : null),
                  }}
                >
                  <Btn
                    variant="ghost"
                    size="sm"
                    onClick={reject}
                    style={isMobile ? { flex: 1, minHeight: rem(40) } : undefined}
                  >
                    {t("known.reject")}
                  </Btn>
                  <Btn
                    variant="danger"
                    size="sm"
                    icon="refresh"
                    style={isMobile ? { flex: 1, minHeight: rem(40) } : undefined}
                    onClick={accept}
                  >
                    {t("known.acceptNew")}
                  </Btn>
                </div>
              </div>
            </div>
          )}

          {/* table */}
          {knownHosts.length === 0 ? (
            <div
              style={{
                borderRadius: 12,
                border: `1px solid ${p.line}`,
                background: p.bg1,
                padding: `${rem(48)} ${rem(22)}`,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: rem(10),
                textAlign: "center",
              }}
            >
              <span
                style={{
                  width: rem(52),
                  height: rem(52),
                  borderRadius: 16,
                  background: p.bg2,
                  border: `1px solid ${p.line}`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Icon name="fingerprint" size={24} color={p.txt3} />
              </span>
              <div style={{ fontSize: TEXT.lead, fontWeight: 700 }}>{t("known.emptyTitle")}</div>
              <div style={{ fontSize: TEXT.base, color: p.txt2, maxWidth: rem(360) }}>
                {t("known.emptyBody")}
              </div>
            </div>
          ) : (
            <div
              style={{
                borderRadius: 12,
                border: `1px solid ${p.line}`,
                overflow: "hidden",
                background: p.bg1,
              }}
            >
              {!isMobile && (
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: GRID,
                    padding: `${rem(9)} ${rem(16)}`,
                    fontFamily: MONO,
                    fontSize: TEXT.micro,
                    letterSpacing: rem(0.8),
                    color: p.txt3,
                    textTransform: "uppercase",
                    borderBottom: `1px solid ${p.line}`,
                    background: "transparent",
                  }}
                >
                  <span>{t("known.col.host")}</span>
                  <span>{t("known.col.algo")}</span>
                  <span>{t("known.col.fingerprint")}</span>
                  <span>{t("known.col.added")}</span>
                  <span style={{ textAlign: "right" }} />
                </div>
              )}
              {knownHosts.map((k, i) => {
                const { algo } = parseHostKey(k.key);
                const label = k.port && k.port !== 22 ? `${k.host}:${k.port}` : k.host;
                const lastRow = i === knownHosts.length - 1;
                if (isMobile) {
                  return (
                    <div
                      key={`${k.host}:${k.port}`}
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: rem(6),
                        padding: `${rem(12)} ${rem(14)}`,
                        borderBottom: lastRow ? "none" : `1px solid ${p.line}`,
                        background: "transparent",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: rem(8),
                          fontSize: TEXT.body,
                          fontWeight: 600,
                          minWidth: 0,
                        }}
                      >
                        <Icon name="fingerprint" size={15} color={p.green} />
                        <span
                          style={{
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {label}
                        </span>
                      </div>
                      <div
                        style={{
                          fontFamily: MONO,
                          fontSize: TEXT.small,
                          color: p.txt2,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                        title={k.fingerprint}
                      >
                        {k.fingerprint}
                      </div>
                      <div style={{ fontFamily: MONO, fontSize: TEXT.micro, color: p.txt3 }}>
                        {algo} · {fmtDate(k.addedAt)}
                      </div>
                      <button
                        title={t("known.forget")}
                        onClick={() => forget(k)}
                        style={{
                          marginTop: rem(2),
                          minHeight: rem(40),
                          width: "100%",
                          borderRadius: 8,
                          border: `1px solid ${p.line}`,
                          background: p.bg2,
                          color: p.txt2,
                          cursor: "pointer",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          gap: rem(8),
                          fontSize: TEXT.base,
                          fontWeight: 600,
                        }}
                      >
                        <Icon name="trash" size={14} />
                        {t("known.forget")}
                      </button>
                    </div>
                  );
                }
                return (
                  <div
                    key={`${k.host}:${k.port}`}
                    style={{
                      display: "grid",
                      gridTemplateColumns: GRID,
                      alignItems: "center",
                      padding: `${rem(11)} ${rem(16)}`,
                      borderBottom: lastRow ? "none" : `1px solid ${p.line}`,
                      background: "transparent",
                    }}
                  >
                    <span
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: rem(8),
                        fontSize: TEXT.base,
                        fontWeight: 600,
                        // Ellipsize long host:port instead of forcing horizontal scroll.
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        minWidth: 0,
                      }}
                    >
                      <Icon name="fingerprint" size={15} color={p.green} />
                      {label}
                    </span>
                    <span
                      style={{
                        fontFamily: MONO,
                        fontSize: TEXT.small,
                        color: p.txt3,
                        // Ellipsize long algo names in the fixed 130px track.
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        minWidth: 0,
                      }}
                    >
                      {algo}
                    </span>
                    <span
                      style={{
                        fontFamily: MONO,
                        fontSize: TEXT.small,
                        color: p.txt2,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                      title={k.fingerprint}
                    >
                      {k.fingerprint}
                    </span>
                    <span style={{ fontSize: TEXT.small, color: p.txt3 }}>{fmtDate(k.addedAt)}</span>
                    <span style={{ display: "flex", justifyContent: "flex-end", gap: rem(6) }}>
                      <button
                        title={t("known.forget")}
                        aria-label={t("known.forget")}
                        onClick={() => forget(k)}
                        style={{
                          width: rem(26),
                          height: rem(26),
                          borderRadius: 8,
                          border: `1px solid ${p.line}`,
                          background: p.bg2,
                          color: p.txt3,
                          cursor: "pointer",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                        }}
                      >
                        <Icon name="trash" size={13} />
                      </button>
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
