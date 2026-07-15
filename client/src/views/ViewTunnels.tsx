// Tunnels — port forwarding manager (-L / -R / -D). Pixel-faithful port of
// view-tunnels.jsx; mock data replaced with the real store registry. The core
// has no tunnel registry, so active tunnels live in the app store and only
// until the instance is locked. Turning a tunnel OFF closes it on the core and
// drops it from the list (re-enabling means re-opening via the modal).

import { usePalette } from "@/theme/ThemeProvider";
import { MONO } from "@/theme/tokens";
import { Btn, Icon, Toggle, StatusDot } from "@/components/primitives";
import { HairlineRow } from "@/components/mono";
import { useApp } from "@/store/app";
import { useCtx } from "@/store/ctx";
import { useIsMobile, useNarrow } from "@/store/responsive";
import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import type { ActiveTunnel, TunnelType } from "@/store/app";
import { useTranslation, tDyn } from "@/i18n";

interface TypeMeta {
  letter: "L" | "R" | "D";
  nameKey: string;
  /** Palette token, not a raw hex — Candy/light themes get their own hues. */
  colorKey: "accent" | "purple" | "green";
}

const TYPE_META: Record<TunnelType, TypeMeta> = {
  local: { letter: "L", nameKey: "tunnels.type.local", colorKey: "accent" },
  remote: { letter: "R", nameKey: "tunnels.type.remote", colorKey: "purple" },
  dynamic: { letter: "D", nameKey: "tunnels.type.dynamic", colorKey: "green" },
};

function TunnelRow({ t: tun, first }: { t: ActiveTunnel; first?: boolean }) {
  const { t } = useTranslation();
  const p = usePalette();
  const ctx = useCtx();
  const isMobile = useIsMobile();
  const narrow = useNarrow();
  const m = TYPE_META[tun.type];

  const turnOff = async () => {
    try {
      await api.tunnelClose(tun.id);
      useApp.getState().removeTunnel(tun.id);
      ctx.toast(t("tunnels.toastClosed"), "ok");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  return (
    // Rows share the single bg0 surface: no per-row box/fill/radius — a 1px hairline
    // (HairlineRow's first-aware border-top) is the only separator.
    <HairlineRow
      first={first}
      style={{
        flexWrap: narrow ? "wrap" : "nowrap",
        gap: narrow ? "10px 12px" : 16,
        padding: "14px 16px",
        opacity: tun.on ? 1 : 0.7,
      }}
    >
      <span
        style={{
          width: 36,
          height: 36,
          borderRadius: 10,
          background: p.bg2,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontFamily: MONO,
          fontWeight: 700,
          fontSize: 15,
          color: p.txt2,
          flexShrink: 0,
          ...(narrow ? { order: 0 } : null),
        }}
      >
        {m.letter}
      </span>
      <div style={{ ...(narrow ? { flex: 1, minWidth: 0, order: 1 } : { width: 150, flexShrink: 0 }) }}>
        {/* Ellipsize a long label so it can't spill into the route column. */}
        <div
          style={{
            fontSize: 14.5,
            fontWeight: 700,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            minWidth: 0,
          }}
        >
          {tun.label}
        </div>
        <div style={{ fontSize: 11.5, color: p.txt3 }}>{tDyn(m.nameKey)}</div>
      </div>
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          flexWrap: narrow ? "wrap" : "nowrap",
          gap: 10,
          fontFamily: MONO,
          fontSize: 12.5,
          minWidth: 0,
          ...(narrow ? { order: 4, flexBasis: "100%" } : null),
        }}
      >
        <span
          style={{
            color: p.txt,
            minWidth: 0,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {tun.route}
        </span>
        {tun.via && (
          <span
            style={{
              color: p.txt3,
              fontSize: 11.5,
              display: "flex",
              alignItems: "center",
              gap: 4,
              whiteSpace: "nowrap",
            }}
          >
            <Icon name="branch" size={12} color={p.txt3} />
            {t("tunnels.via", { via: tun.via })}
          </span>
        )}
      </div>
      <span
        style={{
          display: "inline-flex",
          justifyContent: "flex-end",
          fontSize: 11.5,
          whiteSpace: "nowrap",
          // minWidth (not a hard width) so a longer-language status word grows the
          // column instead of spilling out of it.
          ...(narrow ? { width: "auto", order: 2, flexShrink: 0 } : { minWidth: 80, flexShrink: 0 }),
        }}
      >
        <StatusDot
          status={tun.on ? "online" : "offline"}
          size={7}
          label={tun.on ? t("tunnels.active") : t("tunnels.off")}
        />
      </span>
      {/* OFF means destroyed: the core closed the tunnel and re-enabling means
          re-opening via the modal, so the off switch is inert (aria-disabled). */}
      <span style={{ display: "inline-flex", flexShrink: 0, ...(narrow ? { order: 3 } : null) }}>
        <Toggle
          checked={tun.on}
          disabled={!tun.on}
          touch={isMobile}
          onChange={(v) => {
            if (!v) void turnOff();
          }}
          title={tun.on ? t("tunnels.closeTooltip") : undefined}
          aria-label={tun.on ? t("tunnels.closeTooltip") : t("tunnels.off")}
        />
      </span>
    </HairlineRow>
  );
}

export function ViewTunnels() {
  const { t } = useTranslation();
  const p = usePalette();
  const ctx = useCtx();
  const isMobile = useIsMobile();
  const tunnels = useApp((s) => s.tunnels);
  const activeCount = tunnels.filter((tun) => tun.on).length;

  return (
    // Entry motion comes from the uh-stagger row rise below — no root fade on top.
    <div
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
          // Always wrap so the "Новый туннель" action isn't clipped in a narrow window.
          flexWrap: "wrap",
          rowGap: 8,
          gap: 10,
          padding: isMobile ? "16px 16px 12px" : "16px 22px 12px",
        }}
      >
        <Icon name="branch" size={20} color={p.accent} />
        <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800, letterSpacing: -0.7 }}>{t("nav.tunnels")}</h1>
        <span
          style={{
            fontFamily: MONO,
            fontSize: 12,
            color: p.txt2,
          }}
        >
          {t("count.tunnelsActive", { count: activeCount })}
        </span>
        <div style={{ flex: 1 }} />
        <Btn icon="plus" size="sm" onClick={() => ctx.openModal({ kind: "tunnel" })}>
          {t("tunnels.newTunnel")}
        </Btn>
      </div>

      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: isMobile ? "4px 16px 18px" : "4px 22px 18px",
          display: "flex",
          flexDirection: "column",
          gap: 11,
        }}
      >
        {tunnels.length === 0 ? (
          <div
            style={{
              flex: 1,
              minHeight: 240,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 12,
            }}
          >
            <span
              style={{
                width: 56,
                height: 56,
                borderRadius: 16,
                background: p.bg2,
                border: `1px solid ${p.line}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Icon name="branch" size={26} color={p.txt3} />
            </span>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: 16, fontWeight: 700, color: p.txt }}>{t("tunnels.emptyTitle")}</div>
              <div style={{ fontSize: 13, color: p.txt3, marginTop: 3 }}>
                {t("tunnels.emptyHint")}
              </div>
            </div>
            <Btn size="sm" icon="plus" onClick={() => ctx.openModal({ kind: "tunnel" })}>
              {t("tunnels.newTunnel")}
            </Btn>
          </div>
        ) : (
          <div className="uh-stagger" style={{ display: "flex", flexDirection: "column" }}>
            {tunnels.map((tun, i) => (
              <TunnelRow key={tun.id} t={tun} first={i === 0} />
            ))}
          </div>
        )}

        <div
          style={{
            display: "flex",
            gap: 8,
            marginTop: 4,
            padding: 14,
            borderRadius: 13,
            border: `1px solid ${p.line}`,
            color: p.txt3,
            fontSize: 12.5,
          }}
        >
          <Icon name="alert" size={15} color={p.txt3} style={{ flexShrink: 0 }} />
          {t("tunnels.footerNote")}
        </div>
      </div>
    </div>
  );
}
