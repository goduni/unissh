// Settings → Security → System agent (desktop only).
//
// The switch, what state the listener is actually in, and the two lines a shell
// or ssh_config needs to reach it. Which keys it offers is chosen per key in
// Secrets; nothing here lists or changes keys.

import { useEffect, useRef, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Btn, Toggle } from "@/components/primitives";
import { MetaChip } from "@/components/mono";
import { useTranslation } from "@/i18n";
import { guard } from "@/store/action";
import { toast } from "@/store/toast";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import {
  systemAgentSetEnabled,
  systemAgentSetup,
  systemAgentStatus,
  type SystemAgentStatus,
} from "@/bridge/systemAgent";
import { SectionLabel, SettingRow } from "./ViewSettings";

const ERROR_KEY = {
  unsupported: "systemAgent.errorUnsupported",
  in_use: "systemAgent.errorInUse",
  bind_failed: "systemAgent.errorBindFailed",
  listener_failed: "systemAgent.errorListenerFailed",
} as const;

function CopyLine({ label, value }: { label: string; value: string }) {
  const p = usePalette();
  const { t } = useTranslation();
  return (
    <div style={{ display: "flex", alignItems: "center", gap: rem(10), marginTop: rem(8) }}>
      <code
        aria-label={label}
        style={{
          flex: 1,
          minWidth: 0,
          fontFamily: MONO,
          fontSize: TEXT.small,
          color: p.txt2,
          background: p.bg2,
          border: `1px solid ${p.line}`,
          borderRadius: 8,
          padding: `${rem(7)} ${rem(10)}`,
          overflowX: "auto",
          whiteSpace: "nowrap",
        }}
      >
        {value}
      </code>
      <Btn
        variant="ghost"
        size="sm"
        icon="copy"
        title={t("systemAgent.copy")}
        aria-label={`${t("systemAgent.copy")}: ${label}`}
        onClick={() =>
          void guard(async () => {
            await writeText(value);
            toast(t("systemAgent.copied"), "ok");
          })
        }
      />
    </div>
  );
}

export function SettingsSystemAgent() {
  const p = usePalette();
  const { t } = useTranslation();
  const [status, setStatus] = useState<SystemAgentStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);

  const refresh = async () => {
    const next = await systemAgentStatus();
    if (alive.current) setStatus(next);
  };

  useEffect(() => {
    alive.current = true;
    void guard(refresh);
    return () => {
      alive.current = false;
    };
  }, []);

  const onToggle = (enabled: boolean) => {
    if (busy) return;
    setBusy(true);
    void guard(() => systemAgentSetEnabled(enabled)).finally(() => {
      void guard(refresh).finally(() => {
        if (alive.current) setBusy(false);
      });
    });
  };

  if (!status) return null;
  const setup = status.endpoint ? systemAgentSetup(status.endpoint) : null;
  const state = status.running
    ? { tone: "good" as const, label: t("systemAgent.statusRunning") }
    : status.error
      ? { tone: "danger" as const, label: t(ERROR_KEY[status.error]) }
      : { tone: "neutral" as const, label: t("systemAgent.statusOff") };

  return (
    <>
      <SectionLabel>{t("systemAgent.section")}</SectionLabel>
      <SettingRow title={t("systemAgent.enableTitle")} desc={t("systemAgent.enableDesc")}>
        <MetaChip tone={state.tone}>{state.label}</MetaChip>
        <Toggle
          checked={status.enabled}
          onChange={onToggle}
          disabled={busy || !status.supported}
          aria-label={t("systemAgent.enableTitle")}
        />
      </SettingRow>
      {status.supported && setup && (
        <div style={{ padding: `${rem(14)} 0`, borderBottom: `1px solid ${p.line}` }}>
          <div style={{ fontSize: TEXT.body, fontWeight: 700 }}>{t("systemAgent.setupTitle")}</div>
          <div style={{ fontSize: TEXT.base, color: p.txt3, marginTop: rem(2) }}>
            {t("systemAgent.setupDesc")}
          </div>
          <CopyLine label={t("systemAgent.shellLabel")} value={setup.shell} />
          <CopyLine label={t("systemAgent.sshConfigLabel")} value={setup.sshConfig} />
        </div>
      )}
      <div style={{ fontSize: TEXT.small, color: p.txt3, marginTop: rem(12) }}>
        {t("systemAgent.signingNote")}
      </div>
    </>
  );
}
