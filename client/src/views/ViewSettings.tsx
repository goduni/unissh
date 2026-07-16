// Settings — sub-nav: Appearance / General / Security / About.
// Pixel-faithful port of view-settings.jsx, wired to the real theme store,
// localStorage-persisted preferences, and core api.* calls. No mock build/
// platform strings: the About panel reads real platform info from plugin-os,
// and the danger zone clears real known_hosts via api.forgetHost.

import { useEffect, useRef, useState } from "react";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { ACCENT_KEYS, ACCENTS, MONO, UI, rgba } from "@/theme/tokens";
import type { AppThemeFamily, Density, HostsLayout, Mode, Palette, TermTheme } from "@/theme/tokens";
import { Btn, Icon, NO_AUTOCORRECT, Segmented, Spinner, Tag, Toggle, VaultBadge } from "@/components/primitives";
import { ServerVaultsSection } from "./ServerVaultsSection";
import { Modal } from "@/components/Modal";
import type { IconName } from "@/components/primitives";
import { useApp } from "@/store/app";
import { useCtx } from "@/store/ctx";
import { toast } from "@/store/toast";
import { guard } from "@/store/action";
import * as api from "@/bridge/api";
import { isOwnedCloud, serverShortLabel, vaultServer } from "@/bridge/vaults";
import {
  apiErrorMessage,
  isServerErrorCode,
  ItemType,
  type AccountInfo,
  type AuditEntry,
  type DeviceInfo,
  type InstanceInfo,
  type JoinPreview,
  type MemberInfo,
  type MemberRole,
  type PairingPayload,
  type ServerStatus,
  type VaultInfo,
} from "@/bridge/types";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { writeSecretToClipboard } from "@/bridge/clipboard";
import { readSecretKeyOnce } from "@/bridge/secretKey";
import { getVersion } from "@tauri-apps/api/app";
import { platform, version as osVersion } from "@tauri-apps/plugin-os";
import { useTranslation, setLang, currentLang, tDyn, LANGS, LANG_LABELS } from "@/i18n";
import type { Lang } from "@/i18n";
import { useFmt } from "@/i18n/format";
import { useNarrow } from "@/store/responsive";

// ── localStorage helpers ───────────────────────────────────────
function lsGet(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}
function lsSet(key: string, val: string) {
  try {
    localStorage.setItem(key, val);
  } catch {
    /* ignore */
  }
}

// ── shared layout atoms (mirroring the prototype) ──────────────
function SettingRow({
  title,
  desc,
  children,
}: {
  title: string;
  desc?: string;
  children: React.ReactNode;
}) {
  const p = usePalette();
  // Keep the control inline with the label and let it WRAP to the next line only
  // when it genuinely doesn't fit (flexWrap) — a small button stays in the remaining
  // space, a wide control (Segmented) drops below on its own. minWidth:0 lets a long
  // RU title wrap instead of forcing the control off the row.
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        gap: 16,
        rowGap: 12,
        padding: "16px 0",
        borderBottom: `1px solid ${p.line}`,
      }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 700 }}>{title}</div>
        {desc && <div style={{ fontSize: 12.5, color: p.txt3, marginTop: 2 }}>{desc}</div>}
      </div>
      {children}
    </div>
  );
}

function SectionLabel({ children, first }: { children: React.ReactNode; first?: boolean }) {
  const p = usePalette();
  return (
    <div
      style={{
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: 0.6,
        color: p.txt3,
        textTransform: "uppercase",
        marginTop: first ? 4 : 26,
      }}
    >
      {children}
    </div>
  );
}

function inputStyle(p: Palette, mono?: boolean): React.CSSProperties {
  return {
    width: "100%",
    boxSizing: "border-box",
    padding: "9px 12px",
    fontFamily: mono ? MONO : UI,
    fontSize: 13.5,
    color: p.txt,
    background: p.bg0,
    border: `1px solid ${p.line2}`,
    borderRadius: 9,
    outline: "none",
  };
}

// ── Appearance ─────────────────────────────────────────────────

/** Small overlaid edit/delete control on a custom theme card. Kept as a sibling
 *  of the (selection) card button rather than nested, to avoid a button-in-button. */
function ThemeCardAction({
  icon,
  label,
  onClick,
}: {
  icon: IconName;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      title={label}
      aria-label={label}
      onClick={onClick}
      style={{
        width: 22,
        height: 22,
        borderRadius: 6,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        cursor: "pointer",
        background: "rgba(0,0,0,0.45)",
        border: "1px solid rgba(255,255,255,0.18)",
        color: "#fff",
      }}
    >
      <Icon name={icon} size={12} color="#fff" />
    </button>
  );
}

function SettingsAppearance() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useNarrow(); // width-aware: also true on a narrow desktop window
  const {
    mode,
    setMode,
    family,
    setFamily,
    accent,
    setAccent,
    density,
    setDensity,
    hostsLayout,
    setHostsLayout,
    termThemeId,
    setTermThemeId,
    termThemes,
    customThemes,
    deleteTermTheme,
    resetTermTheme,
  } = useTheme();
  const openModal = useApp((s) => s.openModal);
  const setConfirm = useApp((s) => s.setConfirm);
  const termZoom = useApp((s) => s.termZoom);
  const bumpTermZoom = useApp((s) => s.bumpTermZoom);
  const resetTermZoom = useApp((s) => s.resetTermZoom);
  const keepaliveSecs = useApp((s) => s.keepaliveSecs);
  const setKeepaliveSecs = useApp((s) => s.setKeepaliveSecs);
  const sftpParallelism = useApp((s) => s.sftpParallelism);
  const setSftpParallelism = useApp((s) => s.setSftpParallelism);
  const [customizeOpen, setCustomizeOpen] = useState(false);
  const customIds = new Set(customThemes.map((c) => c.id));
  const confirmDeleteTheme = (th: TermTheme) =>
    setConfirm({
      title: t("termtheme.deleteTitle"),
      body: t("termtheme.deleteBody", { name: th.name }),
      danger: true,
      icon: "trash",
      confirmLabel: t("termtheme.deleteConfirm"),
      onConfirm: () => deleteTermTheme(th.id),
    });

  return (
    <>
      <SectionLabel first>{t("settings.sectionApp")}</SectionLabel>
      {/* Two orthogonal axes, one block: palette family, then light/dark/auto —
          replacing the old family+mode combo <select> that duplicated the mode
          Segmented and could drift out of sync with it. */}
      <SettingRow title={t("settings.themePickerTitle")} desc={t("settings.themeFamilyDesc")}>
        <Segmented<AppThemeFamily>
          value={family}
          onChange={setFamily}
          options={[
            { value: "mono", label: t("settings.themeFamilyMono") },
            { value: "nebula", label: t("settings.themeFamilyNebula") },
            { value: "candy", label: t("settings.themeFamilyCandy") },
          ]}
        />
      </SettingRow>
      <SettingRow title={t("settings.appThemeTitle")} desc={t("settings.appThemeDesc")}>
        <Segmented<Mode>
          value={mode}
          onChange={setMode}
          options={[
            { value: "light", label: t("settings.themeLight"), icon: "sun" },
            { value: "dark", label: t("settings.themeDark"), icon: "moon" },
            { value: "auto", label: t("settings.themeAuto"), icon: "refresh" },
          ]}
        />
      </SettingRow>
      <SettingRow title={t("settings.languageLabel")} desc={t("settings.languageDesc")}>
        <select
          value={currentLang()}
          onChange={(e) => setLang(e.target.value as Lang)}
          style={{ ...inputStyle(p), width: "auto", appearance: "none", cursor: "pointer" }}
        >
          {LANGS.map((l) => (
            <option key={l} value={l}>
              {LANG_LABELS[l]}
            </option>
          ))}
        </select>
      </SettingRow>
      {family === "nebula" && (
        <SettingRow title={t("settings.accentTitle")} desc={t("settings.accentDesc")}>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 8 }}>
            <Btn
              variant="ghost"
              size="sm"
              icon={customizeOpen ? "cd" : "cr"}
              onClick={() => setCustomizeOpen((o) => !o)}
            >
              {t("settings.customize")}
            </Btn>
            {customizeOpen && (
              <div style={{ display: "flex", gap: 9 }}>
                {ACCENT_KEYS.map((key) => {
                  const c = ACCENTS[key].accent;
                  const on = accent === key;
                  return (
                    <button
                      key={key}
                      onClick={() => setAccent(key)}
                      style={{
                        width: 30,
                        height: 30,
                        borderRadius: "50%",
                        background: c,
                        cursor: "pointer",
                        border: on ? `2px solid ${p.txt}` : "2px solid transparent",
                        boxShadow: on ? `0 0 0 2px ${p.bg0}, 0 0 0 4px ${c}` : "none",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      {on && <Icon name="check" size={15} color="#fff" stroke={3} />}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </SettingRow>
      )}
      <SettingRow title={t("settings.densityTitle")} desc={t("settings.densityDesc")}>
        <Segmented<Density>
          value={density}
          onChange={setDensity}
          options={[
            { value: "comfortable", label: t("settings.densityComfortable") },
            { value: "compact", label: t("settings.densityCompact") },
          ]}
        />
      </SettingRow>
      <SettingRow title={t("settings.hostsLayoutTitle")} desc={t("settings.hostsLayoutDesc")}>
        <Segmented<HostsLayout>
          value={hostsLayout}
          onChange={setHostsLayout}
          options={[
            { value: "cards", label: t("settings.hostsLayoutCards"), icon: "grid" },
            { value: "list", label: t("settings.hostsLayoutList"), icon: "list" },
          ]}
        />
      </SettingRow>

      <SectionLabel>{t("settings.sectionTerminal")}</SectionLabel>
      <SettingRow title={t("settings.termFontTitle")} desc={t("settings.termFontDesc")}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Btn
            variant="ghost"
            size="sm"
            icon="minus"
            onClick={() => bumpTermZoom(-1)}
            title={t("settings.termFontSmaller")}
          />
          <span
            style={{
              minWidth: 52,
              textAlign: "center",
              fontFamily: MONO,
              fontSize: 13,
              fontWeight: 700,
            }}
          >
            {(13.5 + termZoom).toFixed(1)}
          </span>
          <Btn
            variant="ghost"
            size="sm"
            icon="plus"
            onClick={() => bumpTermZoom(1)}
            title={t("settings.termFontLarger")}
          />
          {termZoom !== 0 && (
            <Btn variant="ghost" size="sm" onClick={resetTermZoom}>
              {t("settings.termFontReset")}
            </Btn>
          )}
        </div>
      </SettingRow>
      <SettingRow title={t("settings.keepaliveTitle")} desc={t("settings.keepaliveDesc")}>
        <Segmented<string>
          value={String(keepaliveSecs)}
          onChange={(v) => setKeepaliveSecs(parseInt(v, 10) || 0)}
          options={[
            { value: "0", label: t("settings.keepaliveOff") },
            { value: "15", label: t("settings.keepaliveSec", { n: 15 }) },
            { value: "30", label: t("settings.keepaliveSec", { n: 30 }) },
            { value: "60", label: t("settings.keepaliveSec", { n: 60 }) },
          ]}
        />
      </SettingRow>
      <SettingRow
        title={t("settings.sftpParallelismTitle")}
        desc={t("settings.sftpParallelismDesc")}
      >
        <Segmented<string>
          value={String(sftpParallelism)}
          onChange={(v) => setSftpParallelism(parseInt(v, 10) || 1)}
          options={[
            { value: "1", label: t("settings.sftpParallelismOff") },
            { value: "2", label: "2" },
            { value: "4", label: "4" },
            { value: "8", label: "8" },
          ]}
        />
      </SettingRow>
      <div style={{ padding: "16px 0" }}>
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 12,
            marginBottom: 14,
            flexWrap: "wrap", // let the reset Btn drop below the title on a narrow window
          }}
        >
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 3 }}>
              {t("settings.termThemeTitle")}
            </div>
            <div style={{ fontSize: 12.5, color: p.txt3 }}>{t("settings.termThemeDesc")}</div>
          </div>
          <Btn variant="ghost" size="sm" icon="refresh" onClick={resetTermTheme}>
            {t("settings.termResetDefault")}
          </Btn>
        </div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: isMobile
              ? "repeat(auto-fill, minmax(150px, 1fr))"
              : "repeat(4, 1fr)",
            gap: 10,
          }}
        >
          {termThemes.map((th) => {
            const active = th.id === termThemeId;
            const isCustom = customIds.has(th.id);
            return (
              <div key={th.id} style={{ position: "relative" }}>
                <button
                  onClick={() => setTermThemeId(th.id)}
                  style={{
                    width: "100%",
                    textAlign: "left",
                    padding: 0,
                    borderRadius: 11,
                    overflow: "hidden",
                    cursor: "pointer",
                    border: `1px solid ${active ? p.accentLine : p.line}`,
                    background: th.bg,
                    boxShadow: active ? `0 0 0 3px ${p.accentSoft}` : "none",
                  }}
                >
                  <div style={{ padding: "10px 12px", fontFamily: MONO, fontSize: 11, lineHeight: 1.5 }}>
                    <div>
                      <span style={{ color: th.green }}>$</span>{" "}
                      <span style={{ color: th.fg }}>ssh</span>{" "}
                      <span style={{ color: th.blue }}>web-01</span>
                    </div>
                    <div>
                      <span style={{ color: th.purple }}>git</span>{" "}
                      <span style={{ color: th.fg }}>push</span>{" "}
                      <span style={{ color: th.red }}>--force</span>
                    </div>
                  </div>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      padding: "7px 12px",
                      background: "rgba(0,0,0,0.25)",
                    }}
                  >
                    <span style={{ fontSize: 11.5, fontWeight: 700, color: "#fff", flex: 1 }}>
                      {th.name}
                    </span>
                    {active && <Icon name="check" size={13} color="#fff" />}
                  </div>
                </button>
                {isCustom && (
                  <div style={{ position: "absolute", top: 6, right: 6, display: "flex", gap: 4 }}>
                    <ThemeCardAction
                      icon="pencil"
                      label={t("termtheme.editTitle")}
                      onClick={() => openModal({ kind: "termtheme", edit: th })}
                    />
                    <ThemeCardAction
                      icon="trash"
                      label={t("termtheme.delete")}
                      onClick={() => confirmDeleteTheme(th)}
                    />
                  </div>
                )}
              </div>
            );
          })}
          <button
            onClick={() => openModal({ kind: "termtheme" })}
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 6,
              borderRadius: 11,
              cursor: "pointer",
              border: `1px solid ${p.line}`,
              background: "transparent",
              color: p.txt3,
              minHeight: 86,
            }}
          >
            <Icon name="plus" size={18} />
            <span style={{ fontSize: 12, fontWeight: 600 }}>{t("settings.customTheme")}</span>
          </button>
        </div>
      </div>
    </>
  );
}

// ── General ────────────────────────────────────────────────────
type AutoLock = "5" | "15" | "60" | "never";
type Startup = "locked" | "unlocked";

function SettingsGeneral() {
  const [lock, setLock] = useState<AutoLock>(() => lsGet("unissh.autolock", "15") as AutoLock);
  const [startup, setStartup] = useState<Startup>(
    () => lsGet("unissh.startup", "unlocked") as Startup,
  );
  const [confirmQuit, setConfirmQuit] = useState<boolean>(
    () => lsGet("unissh.confirmquit", "1") === "1",
  );
  const autoReconnect = useApp((s) => s.autoReconnect);
  const setAutoReconnect = useApp((s) => s.setAutoReconnect);

  // Master-password instances can't auto-unlock at startup (the password is
  // stored nowhere), so gate the "start unlocked" option honestly. Treat the
  // unknown state (null — no readable keyset) as "disabled" too: boot()'s
  // auto-unlock gate is a strict `requiresPassword === false`, so anything that
  // isn't a definite "passwordless" must not advertise the feature as working.
  const requiresPassword = useApp((s) => s.requiresPassword);
  const startupDisabled = requiresPassword !== false;

  const onLock = (v: AutoLock) => {
    setLock(v);
    lsSet("unissh.autolock", v);
    // Push to the store too so the idle timer re-arms live (no restart needed).
    useApp.getState().setAutolockMin(v === "never" ? null : parseInt(v, 10));
  };
  const onStartup = (v: Startup) => {
    setStartup(v);
    lsSet("unissh.startup", v);
  };
  const onConfirmQuit = (v: boolean) => {
    setConfirmQuit(v);
    lsSet("unissh.confirmquit", v ? "1" : "0");
  };

  const { t } = useTranslation();

  const openLogs = async () => {
    await guard(async () => {
      await api.revealLogDir();
    });
  };
  const copyDiagnostics = async () => {
    await guard(async () => {
      const [dir, appVer] = await Promise.all([
        api.logDir().catch(() => "?"),
        getVersion().catch(() => "?"),
      ]);
      let plat = "?";
      let osv = "?";
      try {
        plat = platform();
        osv = osVersion();
      } catch {
        /* not in a Tauri context */
      }
      await writeText(`UniSSH ${appVer}\nOS: ${plat} ${osv}\nLogs: ${dir}`);
      toast(t("settings.diagnosticsCopied"), "ok");
    });
  };

  return (
    <>
      <SectionLabel first>{t("settings.sectionLock")}</SectionLabel>
      <SettingRow title={t("settings.autoLockTitle")} desc={t("settings.autoLockDesc")}>
        <Segmented<AutoLock>
          value={lock}
          onChange={onLock}
          options={[
            { value: "5", label: t("settings.lock5min") },
            { value: "15", label: t("settings.lock15min") },
            { value: "60", label: t("settings.lock1hour") },
            { value: "never", label: t("settings.lockNever") },
          ]}
        />
      </SettingRow>
      <SettingRow
        title={t("settings.startupTitle")}
        desc={startupDisabled ? t("settings.startupPwNote") : t("settings.startupDesc")}
      >
        <Segmented<Startup>
          value={startupDisabled ? "locked" : startup}
          onChange={onStartup}
          disabled={startupDisabled}
          options={[
            { value: "locked", label: t("settings.startupLocked") },
            { value: "unlocked", label: t("settings.startupUnlocked") },
          ]}
        />
      </SettingRow>

      <SectionLabel>{t("settings.sectionBehavior")}</SectionLabel>
      <SettingRow title={t("settings.confirmQuitTitle")} desc={t("settings.confirmQuitDesc")}>
        <Toggle checked={confirmQuit} onChange={onConfirmQuit} />
      </SettingRow>
      <SettingRow title={t("settings.autoReconnectTitle")} desc={t("settings.autoReconnectDesc")}>
        <Toggle checked={autoReconnect} onChange={setAutoReconnect} />
      </SettingRow>

      <SectionLabel>{t("settings.sectionDiagnostics")}</SectionLabel>
      <SettingRow title={t("settings.logsTitle")} desc={t("settings.logsDesc")}>
        {/* wrap so the two long RU labels can stack instead of overflowing */}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Btn variant="ghost" icon="folder" onClick={openLogs}>
            {t("settings.openLogFolder")}
          </Btn>
          <Btn variant="ghost" icon="copy" onClick={copyDiagnostics}>
            {t("settings.copyDiagnostics")}
          </Btn>
        </div>
      </SettingRow>
    </>
  );
}

// ── Security ───────────────────────────────────────────────────
function ChangePasswordForm({ onClose }: { onClose: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await api.changePassword(
        oldPw ? oldPw : null,
        newPw ? newPw : null,
        secretKey.replace(/[\s-]/g, ""),
      );
      // Keep the startup gating honest: adding/removing the master password flips
      // whether "start unlocked" can ever apply.
      useApp.setState({ requiresPassword: !!newPw });
      toast(t("settings.masterPwChanged"), "ok");
      onClose();
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
      style={{
        marginTop: 12,
        padding: 16,
        borderRadius: 13,
        border: `1px solid ${p.line2}`,
        background: p.bg1,
        display: "flex",
        flexDirection: "column",
        gap: 11,
      }}
    >
      <div style={{ fontSize: 13.5, fontWeight: 700 }}>{t("settings.changeMasterPw")}</div>
      <input
        {...NO_AUTOCORRECT}
        type="password"
        value={oldPw}
        onChange={(e) => setOldPw(e.target.value)}
        placeholder={t("settings.currentPwPlaceholder")}
        style={inputStyle(p)}
      />
      <input
        {...NO_AUTOCORRECT}
        type="password"
        value={newPw}
        onChange={(e) => setNewPw(e.target.value)}
        placeholder={t("settings.newPwPlaceholder")}
        style={inputStyle(p)}
      />
      <input
        {...NO_AUTOCORRECT}
        type="password"
        value={secretKey}
        onChange={(e) => setSecretKey(e.target.value)}
        placeholder={t("settings.secretKeyPlaceholder")}
        style={inputStyle(p, true)}
      />
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
        <Btn variant="ghost" size="sm" onClick={onClose} disabled={busy}>
          {t("common.cancel")}
        </Btn>
        <Btn size="sm" icon="check" onClick={submit} disabled={busy}>
          {t("common.save")}
        </Btn>
      </div>
    </form>
  );
}

function SettingsSecurity() {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const knownHosts = useApp((s) => s.knownHosts);
  const [changing, setChanging] = useState(false);
  const [clip, setClip] = useState<boolean>(() => lsGet("unissh.clipclear", "1") === "1");

  const onClip = (v: boolean) => {
    setClip(v);
    lsSet("unissh.clipclear", v ? "1" : "0");
  };

  const checkDbConsistency = async () => {
    await guard(async () => {
      const r = await api.checkConsistency();
      if (r.ok) toast(t("settings.dbConsistencyOk"), "ok");
      else toast(t("settings.dbConsistencyFailed", { count: r.issues.length }), "err");
    });
  };

  const clearKnownHosts = () => {
    ctx.confirm({
      title: t("settings.clearKnownHostsTitle"),
      body: t("settings.clearKnownHostsBody"),
      danger: true,
      confirmLabel: t("settings.clear"),
      icon: "trash",
      onConfirm: async () => {
        await guard(async () => {
          const hosts = useApp.getState().knownHosts;
          for (const h of hosts) {
            await api.forgetHost(h.host, h.port);
          }
          await useApp.getState().reloadVault();
          toast(t("settings.knownHostsCleared"), "ok");
        });
      },
    });
  };

  return (
    <>
      <SectionLabel first>{t("settings.sectionAccess")}</SectionLabel>
      <SettingRow title={t("settings.masterPwTitle")} desc={t("settings.masterPwDesc")}>
        <Btn variant="ghost" size="sm" icon="lock" onClick={() => setChanging((v) => !v)}>
          {t("settings.change")}
        </Btn>
      </SettingRow>
      {changing && <ChangePasswordForm onClose={() => setChanging(false)} />}
      <SettingRow title={t("settings.clipClearTitle")} desc={t("settings.clipClearDesc")}>
        <Toggle checked={clip} onChange={onClip} />
      </SettingRow>

      <SectionLabel>{t("settings.sectionRecovery")}</SectionLabel>
      <SettingRow title="Emergency Kit" desc={t("settings.emergencyKitDesc")}>
        <Btn variant="ghost" size="sm" icon="key" onClick={() => ctx.onShowKit()}>
          {t("common.show")}
        </Btn>
      </SettingRow>

      <SectionLabel>{t("settings.sectionMaintenance")}</SectionLabel>
      <SettingRow
        title={t("settings.dbConsistencyTitle")}
        desc={t("settings.dbConsistencyDesc")}
      >
        <Btn variant="ghost" size="sm" icon="shieldcheck" onClick={checkDbConsistency}>
          {t("settings.check")}
        </Btn>
      </SettingRow>

      <div
        style={{
          marginTop: 26,
          paddingTop: 20,
          borderTop: `1px solid ${p.line}`,
        }}
      >
        <div style={{ fontSize: 13.5, fontWeight: 700, color: p.red, marginBottom: 4 }}>
          {t("settings.dangerZone")}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ flex: 1, fontSize: 12.5, color: p.txt2 }}>
            {t("settings.dangerZoneDesc")}
          </div>
          <Btn
            variant="ghost"
            size="sm"
            icon="trash"
            onClick={clearKnownHosts}
            disabled={knownHosts.length === 0}
            style={{ color: p.red, borderColor: rgba(p.red, 0.4) }}
          >
            {t("settings.clear")}
          </Btn>
        </div>
      </div>
    </>
  );
}

// ── About ──────────────────────────────────────────────────────
function AboutRow({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  const p = usePalette();
  const isMobile = useNarrow(); // width-aware: also true on a narrow desktop window
  return (
    <div
      style={{
        display: "flex",
        flexDirection: isMobile ? "column" : "row",
        alignItems: isMobile ? "stretch" : "baseline",
        gap: isMobile ? 2 : 10,
        padding: "11px 0",
        borderBottom: `1px solid ${p.line}`,
      }}
    >
      <span style={{ width: isMobile ? "auto" : 150, fontSize: 13, color: p.txt3 }}>{k}</span>
      <span
        style={{
          flex: 1,
          minWidth: 0,
          fontSize: 13.5,
          color: p.txt,
          fontFamily: mono ? MONO : UI,
          wordBreak: isMobile ? "break-all" : undefined,
        }}
      >
        {v}
      </span>
    </div>
  );
}

/** External link row: the URL is visible and copyable. The webview deliberately
 *  has no opener/shell capability, so "copy link" IS the action — an honest
 *  affordance instead of a dead Website/GitHub button. */
function LinkRow({ label, url }: { label: string; url: string }) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useNarrow(); // width-aware: also true on a narrow desktop window
  const copy = async () => {
    await guard(async () => {
      await writeText(url);
      toast(t("settings.linkCopied"), "ok");
    });
  };
  return (
    <div
      style={{
        display: "flex",
        flexDirection: isMobile ? "column" : "row",
        alignItems: isMobile ? "stretch" : "center",
        gap: isMobile ? 2 : 10,
        padding: "7px 0",
        borderBottom: `1px solid ${p.line}`,
      }}
    >
      <span style={{ width: isMobile ? "auto" : 150, fontSize: 13, color: p.txt3, flexShrink: 0 }}>
        {label}
      </span>
      <span
        className="uh-selectable"
        style={{
          flex: 1,
          minWidth: 0,
          fontSize: 13,
          fontFamily: MONO,
          color: p.txt,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {url}
      </span>
      <Btn
        variant="ghost"
        size="sm"
        icon="copy"
        onClick={copy}
        title={t("settings.copyLink")}
        aria-label={t("settings.copyLink")}
      />
    </div>
  );
}

function SettingsAbout() {
  const p = usePalette();
  const { t } = useTranslation();
  const [platformStr, setPlatformStr] = useState("…");
  const [engineStr, setEngineStr] = useState("Tauri 2.0");
  const [acctId, setAcctId] = useState("…");
  // Live app version (same source the diagnostics copy uses) — never hardcoded.
  const [appVersion, setAppVersion] = useState("…");

  useEffect(() => {
    let alive = true;
    getVersion()
      .then((v) => {
        if (alive) setAppVersion(v);
      })
      .catch(() => {
        if (alive) setAppVersion("—"); /* not in a Tauri context */
      });
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const { platform, arch, version } = await import("@tauri-apps/plugin-os");
        const plat = platform();
        const a = arch();
        const v = version();
        if (!alive) return;
        setPlatformStr(`${plat} · ${a}`);
        setEngineStr(`Tauri 2.0 · ${plat} ${v}`);
      } catch {
        /* keep defaults — info only available inside Tauri */
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const id = await api.accountId();
        if (alive) setAcctId(id);
      } catch {
        if (alive) setAcctId("—");
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  return (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 18 }}>
        <span
          style={{
            width: 56,
            height: 56,
            borderRadius: 16,
            background: p.accent,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name="terminal" size={26} color={p.accentInk} stroke={2} />
        </span>
        <div>
          <div style={{ fontSize: 20, fontWeight: 800, letterSpacing: -0.4 }}>UniSSH</div>
          <div style={{ fontSize: 13, color: p.txt3 }}>{t("settings.tagline")}</div>
        </div>
      </div>
      <AboutRow k={t("settings.aboutVersion")} v={appVersion} mono />
      <AboutRow k={t("settings.aboutPlatform")} v={platformStr} />
      <AboutRow k={t("settings.aboutEngine")} v={engineStr} />
      <AboutRow k={t("settings.accountId")} v={acctId} mono />
      <AboutRow k={t("settings.aboutLicense")} v="MIT OR Apache-2.0" />
      <LinkRow label={t("settings.website")} url="https://goduni.github.io/unissh/" />
      <LinkRow label="GitHub" url="https://github.com/goduni/unissh" />
    </>
  );
}

// ── Vaults ─────────────────────────────────────────────────────
function SettingsVaults() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useNarrow(); // width-aware: also true on a narrow desktop window
  const vaults = useApp((s) => s.vaults);
  const vaultId = useApp((s) => s.vaultId);
  const openModal = useApp((s) => s.openModal);
  const setConfirm = useApp((s) => s.setConfirm);
  const servers = useApp((s) => s.servers);
  const activeServerId = useApp((s) => s.activeServerId);

  // Inline "pick a server" popover for Bind / Move (the accessible path alongside
  // drag-and-drop): holds the vault id whose picker is open.
  const [pickerVault, setPickerVault] = useState<string | null>(null);
  // Selected server id in the bind/move modal (which vault is being (re)homed is
  // held by `pickerVault`).
  const [bindSel, setBindSel] = useState<string | null>(null);
  // Drag-and-drop: `dragId` is the live source (a ref, read in dragover/drop without
  // forcing a re-render); `dragging`/`dragOver` drive the visual state only.
  const dragId = useRef<string | null>(null);
  const [dragging, setDragging] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState<string | null>(null);

  const reload = () => useApp.getState().reloadVaults();
  const errToast = (e: unknown) => toast(apiErrorMessage(e), "err");

  // Binding management (bind / move / unbind) is OWNER-ONLY: only a vault you
  // administer (admin in its space) may be re-homed. A member sees where a shared
  // vault lives but can't move it — that would desync the team and scatter the
  // owner's ciphertext onto personal servers (it grants a member no new plaintext,
  // since they can already decrypt, but WHERE the vault syncs is the owner's call).
  const owned = (v: VaultInfo) => isOwnedCloud(v, servers);
  // Bindable = a cloud vault you may (re)home to a server. A vault with NO binding
  // at all (empty syncTenant) is yours to bind — isOwnedCloud can't read a role from
  // a Space that doesn't exist yet, so binding must not require `owned` there (that
  // was the catch-22 that left unbound vaults unbindable). A bound vault stays
  // owner-only. Used by both the Bind affordance and the actual (re)bind action.
  const canRehome = (v: VaultInfo) =>
    v.syncTarget === "cloud" && (!v.syncTenant || owned(v));

  const cloudVaults = vaults.filter((v) => v.syncTarget === "cloud");
  const localVaults = vaults.filter((v) => v.syncTarget !== "cloud");
  const vaultsOn = (s: ServerStatus) =>
    cloudVaults.filter((v) => vaultServer(v, servers)?.serverId === s.serverId);
  // Cloud vaults resolving to NO linked server: unbound (empty tenant) or bound to a
  // server that isn't linked here. They don't sync until (re)bound.
  const unboundVaults = cloudVaults.filter((v) => vaultServer(v, servers) == null);

  // Bind an unbound vault immediately (no prior server → no old copy to warn about).
  const bindTo = (v: VaultInfo, serverId: string) =>
    api
      .serverBindCloudVault(v.vaultId, serverId)
      .then(() => {
        void reload();
        setPickerVault(null);
        toast(t("vault.boundDone"), "ok");
      })
      .catch(errToast);

  // (Re)bind a vault to `s`. A MOVE (it was already bound to a linked server) is
  // confirmed first and we're explicit that the OLD server keeps its (encrypted)
  // copy — Move re-points syncing, it does NOT delete remotely.
  const rebindTo = (v: VaultInfo, s: ServerStatus) => {
    if (!s.serverId || !canRehome(v)) return;
    if (vaultServer(v, servers)?.serverId === s.serverId) return; // already there
    if (vaultServer(v, servers) == null) {
      void bindTo(v, s.serverId);
      return;
    }
    setConfirm({
      title: t("vault.moveTitle"),
      body: t("vault.moveBody", { name: v.name, server: serverShortLabel(s) }),
      confirmLabel: t("vault.moveConfirm"),
      onConfirm: async () => {
        await guard(async () => {
          await api.serverBindCloudVault(v.vaultId, s.serverId!);
          await reload();
          setPickerVault(null);
          toast(t("vault.moveDone"), "ok");
        });
      },
    });
  };

  const syncNow = (s: ServerStatus) => {
    if (!s.serverId) return;
    void guard(async () => {
      await api.serverSyncNow(s.serverId!);
      await reload();
      toast(t("vault.syncDone"), "ok");
    });
  };

  // Unbind a bound cloud vault (confirm first): it stops syncing and stays only on
  // this device. Data already on the server is untouched; it can be bound again.
  const onUnbindVault = (v: VaultInfo) => {
    setConfirm({
      title: t("vault.unbindTitle"),
      body: t("vault.unbindBody", { name: v.name }),
      confirmLabel: t("vault.unbind"),
      onConfirm: async () => {
        await guard(async () => {
          const changed = await api.serverUnbindCloudVault(v.vaultId);
          await useApp.getState().reloadVaults();
          if (changed) toast(t("vault.unbindDone"), "ok");
        });
      },
    });
  };

  const remove = (v: VaultInfo) => {
    if (vaults.length <= 1) {
      toast(t("vault.cannotDeleteLast"), "warn");
      return;
    }
    setConfirm({
      title: t("vault.deleteTitle"),
      body: t("vault.deleteBody", { name: v.name }),
      danger: true,
      confirmLabel: t("vault.deleteConfirm"),
      onConfirm: async () => {
        await guard(async () => {
          await api.deleteVault(v.vaultId);
          await useApp.getState().reloadVaults();
          toast(t("vault.removed"), "ok");
        });
      },
    });
  };

  const verify = async (v: VaultInfo) => {
    await guard(async () => {
      const r = await api.verifyVaultIntegrity(v.vaultId);
      if (r.ok) toast(t("vault.integrityOk", { count: r.checked }), "ok");
      else toast(t("vault.integrityFailed", { count: r.issues.length }), "err");
    });
  };

  const purge = (v: VaultInfo) => {
    if (vaults.length <= 1) {
      toast(t("vault.cannotDeleteLast"), "warn");
      return;
    }
    setConfirm({
      title: t("vault.purgeTitle"),
      body: t("vault.purgeBody", { name: v.name }),
      danger: true,
      confirmLabel: t("vault.purgeConfirm"),
      icon: "trash",
      onConfirm: async () => {
        await guard(async () => {
          await api.purgeVault(v.vaultId);
          await useApp.getState().reloadVaults();
          toast(t("vault.purged"), "ok");
        });
      },
    });
  };

  // ── one vault row ─────────────────────────────────────────────
  const vaultRow = (v: VaultInfo, kind: "server" | "local" | "unbound") => {
    const isCurrent = v.vaultId === vaultId;
    const canBind = kind !== "local" && canRehome(v); // owner-only for bound; open for unbound
    const isMember = kind === "server" && !owned(v);
    // Rename + delete are owner-only in core (require_owner → AuthorityInvalid for a
    // member), so don't offer them on a shared vault you don't own. Verify + purge are
    // local (a member can integrity-check and remove their own copy).
    const canEdit = kind === "local" || owned(v);
    const targets =
      kind === "server"
        ? servers.filter(
            (s) => s.serverId != null && s.serverId !== vaultServer(v, servers)?.serverId,
          )
        : servers.filter((s) => s.serverId != null);
    return (
      <div
        key={v.vaultId}
        draggable={canBind}
        onDragStart={
          canBind
            ? (e) => {
                dragId.current = v.vaultId;
                e.dataTransfer.effectAllowed = "move";
                e.dataTransfer.setData("text/plain", v.vaultId);
                setDragging(v.vaultId);
              }
            : undefined
        }
        onDragEnd={
          canBind
            ? () => {
                dragId.current = null;
                setDragging(null);
                setDragOver(null);
              }
            : undefined
        }
        style={{
          display: "flex",
          alignItems: "center",
          // Always wrap: on desktop the trailing destructive move/unbind/delete
          // Btns were clipped by groupBox overflow:hidden. rowGap spaces wrapped rows.
          flexWrap: "wrap",
          gap: 10,
          rowGap: 10,
          padding: "12px 14px",
          borderTop: `1px solid ${p.line}`,
          background: isCurrent ? p.bg2 : "transparent",
          opacity: dragging === v.vaultId ? 0.45 : 1,
          cursor: canBind ? "grab" : "default",
        }}
      >
        <Icon name="layers" size={16} color={p.txt3} />
        <div
          style={{
            flex: 1,
            minWidth: isMobile ? "100%" : 0,
            display: "flex",
            alignItems: "center",
            gap: 8,
            flexWrap: "wrap",
          }}
        >
          <span style={{ fontSize: 13.5, fontWeight: 650 }}>{v.name}</span>
          {isCurrent && <Tag>{t("vault.current")}</Tag>}
          {kind === "local" && <VaultBadge target="local" label={t("vault.local")} />}
          {isMember && (
            <span
              title={t("vault.memberManaged")}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                fontSize: 11,
                color: p.txt3,
              }}
            >
              <Icon name="lock" size={12} color={p.txt3} />
              {t("vault.roleMember")}
            </span>
          )}
          {kind === "unbound" && (
            <span style={{ fontSize: 11, color: p.amber, fontWeight: 600, whiteSpace: "nowrap" }}>
              {t("vault.wontSync")}
            </span>
          )}
        </div>

        {canBind && targets.length > 0 && (
          <Btn
            variant="ghost"
            size="sm"
            icon="cloud"
            onClick={() => {
              setBindSel(targets.length === 1 ? (targets[0].serverId ?? null) : null);
              setPickerVault(v.vaultId);
            }}
          >
            {t(kind === "server" ? "vault.move" : "vault.bind")}
          </Btn>
        )}
        {canBind && kind === "server" && (
          <Btn variant="ghost" size="sm" onClick={() => onUnbindVault(v)}>
            {t("vault.unbind")}
          </Btn>
        )}

        {canEdit && (
          <Btn
            variant="ghost"
            size="sm"
            icon="pencil"
            title={t("vault.rename")}
            onClick={() => openModal({ kind: "vault", edit: v })}
          />
        )}
        <Btn
          variant="ghost"
          size="sm"
          icon="shieldcheck"
          title={t("vault.verify")}
          onClick={() => verify(v)}
        />
        <Btn
          variant="ghost"
          size="sm"
          icon="zap"
          title={isMember ? t("vault.removeLocal") : t("vault.purge")}
          disabled={vaults.length <= 1}
          onClick={() => purge(v)}
          style={{ color: p.red, borderColor: rgba(p.red, 0.4) }}
        />
        {canEdit && (
          <Btn
            variant="ghost"
            size="sm"
            icon="trash"
            title={t("common.delete")}
            disabled={vaults.length <= 1}
            onClick={() => remove(v)}
            style={{ color: p.red, borderColor: rgba(p.red, 0.4) }}
          />
        )}
      </div>
    );
  };

  // Bordered "group box" holding the rows; a server box is a drop target for owner
  // vaults (drop = bind/move to that server).
  const groupBox = (children: React.ReactNode, dropServerId?: string) => {
    const over = dropServerId != null && dragOver === dropServerId;
    return (
      <div
        onDragOver={
          dropServerId != null
            ? (e) => {
                if (dragId.current) {
                  e.preventDefault();
                  setDragOver(dropServerId);
                }
              }
            : undefined
        }
        onDragLeave={
          dropServerId != null
            ? () => setDragOver((o) => (o === dropServerId ? null : o))
            : undefined
        }
        onDrop={
          dropServerId != null
            ? (e) => {
                e.preventDefault();
                const vid = dragId.current;
                dragId.current = null;
                setDragging(null);
                setDragOver(null);
                const s = servers.find((x) => x.serverId === dropServerId);
                const v = vaults.find((x) => x.vaultId === vid);
                if (v && s) rebindTo(v, s);
              }
            : undefined
        }
        style={{
          border: `1px solid ${over ? p.accent : p.line}`,
          borderRadius: 12,
          overflow: "hidden",
          background: over ? p.bg2 : "transparent",
          transition: "border-color .12s, background .12s",
        }}
      >
        {children}
      </div>
    );
  };

  const groupIcon = (name: IconName, color: string, borderColor: string) => (
    <span
      style={{
        width: 28,
        height: 28,
        borderRadius: 8,
        flex: "none",
        display: "grid",
        placeItems: "center",
        border: `1px solid ${borderColor}`,
        color,
      }}
    >
      <Icon name={name} size={15} />
    </span>
  );

  const serverGroup = (s: ServerStatus) => {
    const vs = vaultsOn(s);
    const isActive = s.serverId === activeServerId;
    return (
      <div key={s.serverId ?? s.baseUrl ?? ""} style={{ marginBottom: 22 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "0 2px 9px",
            flexWrap: "wrap", // let the "Sync now" Btn drop below the server name when narrow
          }}
        >
          {groupIcon("cloud", p.txt, p.line)}
          <div
            style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0, flexWrap: "wrap" }}
          >
            <span style={{ fontSize: 14, fontWeight: 700 }}>{serverShortLabel(s)}</span>
            {s.handle && (
              <span
                style={{
                  fontSize: 11.5,
                  color: p.txt3,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 4,
                }}
                title={t("vault.srvAccount")}
              >
                <Icon name="fingerprint" size={11} color={p.txt3} />
                {s.handle}
              </span>
            )}
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: "50%",
                background: s.hasSession ? p.green : p.txt3,
                opacity: s.hasSession ? 1 : 0.5,
              }}
            />
            <span style={{ fontSize: 11.5, color: p.txt3 }}>
              {s.hasSession ? t("vault.srvConnected") : t("vault.srvSignedOut")}
            </span>
            {isActive && <Tag>{t("vault.srvActive")}</Tag>}
          </div>
          <div style={{ flex: 1 }} />
          {s.hasSession && (
            <Btn variant="ghost" size="sm" icon="refresh" onClick={() => syncNow(s)}>
              {t("vault.syncNow")}
            </Btn>
          )}
        </div>
        {groupBox(
          vs.length === 0 ? (
            <div style={{ padding: "14px 15px", fontSize: 12.5, color: p.txt3 }}>
              {dragging ? t("vault.dropHere") : t("vault.emptyServer")}
            </div>
          ) : (
            vs.map((v) => vaultRow(v, "server"))
          ),
          s.serverId ?? undefined,
        )}
      </div>
    );
  };

  const localGroup = () => (
    <div style={{ marginBottom: 22 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 2px 9px" }}>
        {groupIcon("home", p.txt3, p.line)}
        <span style={{ fontSize: 14, fontWeight: 700 }}>{t("vault.grpLocal")}</span>
        <span style={{ fontSize: 11.5, color: p.txt3 }}>· {t("vault.grpLocalHint")}</span>
      </div>
      {groupBox(localVaults.map((v) => vaultRow(v, "local")))}
    </div>
  );

  const unboundGroup = () => (
    <div style={{ marginBottom: 22 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 2px 9px" }}>
        {groupIcon("alert", p.amber, rgba(p.amber, 0.4))}
        <span style={{ fontSize: 14, fontWeight: 700, color: p.amber }}>
          {t("vault.grpUnbound")}
        </span>
        <span style={{ fontSize: 11.5, color: p.amber, opacity: 0.85 }}>
          · {t("vault.grpUnboundHint")}
        </span>
      </div>
      {groupBox(unboundVaults.map((v) => vaultRow(v, "unbound")))}
    </div>
  );

  return (
    <>
      <SectionLabel first>{t("vault.manage")}</SectionLabel>
      <div style={{ fontSize: 12.5, color: p.txt3, margin: "6px 0 18px", maxWidth: 560 }}>
        {t("vault.topoDesc")}
      </div>

      {servers.map((s) => serverGroup(s))}
      {localVaults.length > 0 && localGroup()}
      {unboundVaults.length > 0 && unboundGroup()}

      <div style={{ marginTop: 20 }}>
        <Btn icon="plus" onClick={() => openModal({ kind: "vault" })}>
          {t("vault.create")}
        </Btn>
      </div>

      {pickerVault &&
        (() => {
          const v = vaults.find((x) => x.vaultId === pickerVault);
          if (!v) return null;
          const current = vaultServer(v, servers)?.serverId;
          const isMove = current != null;
          const opts = servers.filter((s) => s.serverId != null && s.serverId !== current);
          const close = () => {
            setPickerVault(null);
            setBindSel(null);
          };
          return (
            <Modal
              icon="cloud"
              title={t(isMove ? "vault.move" : "vault.bind")}
              subtitle={v.name}
              onClose={close}
              w={420}
              footer={
                <>
                  <Btn variant="ghost" onClick={close}>
                    {t("common.cancel")}
                  </Btn>
                  <Btn
                    variant="primary"
                    disabled={!bindSel}
                    onClick={() => {
                      const s = opts.find((x) => x.serverId === bindSel);
                      close();
                      if (s) rebindTo(v, s);
                    }}
                  >
                    {t(isMove ? "vault.move" : "vault.bind")}
                  </Btn>
                </>
              }
            >
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {opts.map((s) => {
                  const active = bindSel === s.serverId;
                  return (
                    <button
                      key={s.serverId!}
                      onClick={() => setBindSel(s.serverId ?? null)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "12px 14px",
                        borderRadius: 10,
                        cursor: "pointer",
                        textAlign: "left",
                        border: `1px solid ${active ? p.accent : p.line}`,
                        background: active ? rgba(p.accent, 0.1) : p.bg2,
                        color: p.txt,
                      }}
                    >
                      <Icon name="cloud" size={16} color={active ? p.accent : p.txt3} />
                      <span style={{ flex: 1, fontSize: 13.5 }}>{serverShortLabel(s)}</span>
                      {active && <Icon name="check" size={15} color={p.accent} />}
                    </button>
                  );
                })}
              </div>
            </Modal>
          );
        })()}
    </>
  );
}

// ── Cloud / Server ─────────────────────────────────────────────
/** Read-only key/value row — mirrors AboutRow, with monospace value option. */
function CloudInfoRow({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  const p = usePalette();
  const isMobile = useNarrow(); // width-aware: also true on a narrow desktop window
  return (
    <div
      style={{
        display: "flex",
        flexDirection: isMobile ? "column" : "row",
        alignItems: isMobile ? "stretch" : "baseline",
        gap: isMobile ? 2 : 10,
        padding: "11px 0",
        borderBottom: `1px solid ${p.line}`,
      }}
    >
      <span style={{ width: isMobile ? "auto" : 150, flexShrink: 0, fontSize: 13, color: p.txt3 }}>
        {k}
      </span>
      <span
        style={{
          flex: 1,
          minWidth: 0,
          fontSize: 13.5,
          color: p.txt,
          fontFamily: mono ? MONO : UI,
          wordBreak: "break-all",
        }}
      >
        {v}
      </span>
    </div>
  );
}

// Small labelled text field used throughout the connect form.
function ConnectField({
  label,
  value,
  onChange,
  placeholder,
  mono,
  type,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
  type?: "text" | "password";
}) {
  const p = usePalette();
  return (
    <label style={{ display: "block" }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: p.txt2, marginBottom: 6 }}>{label}</div>
      <input
        {...NO_AUTOCORRECT}
        type={type ?? "text"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={inputStyle(p, mono)}
      />
    </label>
  );
}

// After a server is linked/joined via Settings, run the SAME post-session sequence
// as every other session-establishing path (boot / Unlock / JoinDevice): refresh the
// server list, bind any legacy unbound cloud vaults, then pull the account's cloud
// vaults — so a newly added server's cloud vaults appear without a manual "Sync now"
// or a restart. reloadServerStatus must complete first (it populates `servers`, which
// the bind + auto-sync steps read); cloudAutoSync is fire-and-forget (it reloads the
// vault list itself once its pass finishes).
async function pullCloudVaultsAfterConnect(): Promise<void> {
  const app = useApp.getState();
  await app.reloadServerStatus();
  await app.maybeBindLegacyCloudVaults();
  app.cloudAutoSync();
  await app.reloadVaults();
}

// Add-server flow (shown when no server is linked, and to link another). Requires
// an unlocked instance. One flow: enter the server address → probe it with
// instanceInfo → an UNCLAIMED instance is set up with a setup code (you become its
// owner); a CLAIMED instance is joined with an invite link, or signed in to with
// your existing account keyset.
function CloudConnectForm({
  onConnected,
  onArm,
}: {
  onConnected: (s: ServerStatus) => void;
  // Fired ONLY on a fresh claim/join (not on sign-in / reconnect / SSO, which
  // recover an already-escrowed identity): the parent arms this identity's keyset
  // escrow so it can sign in from other devices. Kept separate from onConnected so
  // the recovery/reconnect paths never re-run it.
  onArm?: (s: ServerStatus) => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  // Persisted links — the "Reconnect" segment only makes sense when THIS instance is
  // already linked on this device (server_login targets the active link; with no link
  // it is a dead entry). Match on the probed instance id below.
  const servers = useApp((s) => s.servers);
  const [baseUrl, setBaseUrl] = useState("");
  const [info, setInfo] = useState<InstanceInfo | null>(null);
  const [probing, setProbing] = useState(false);
  const [busy, setBusy] = useState(false);

  // account profile — applies to claim (owner) and join (new member).
  const [displayName, setDisplayName] = useState("");
  const [handle, setHandle] = useState("");

  // claim (unclaimed instance): the one-time setup code + a name for the first Space.
  const [setupCode, setSetupCode] = useState("");
  const [spaceName, setSpaceName] = useState("");

  // join a claimed instance: redeem an invite link, sign in with an existing identity
  // (escrow), restore that identity offline from an Emergency-Kit file, or reconnect the
  // local keyset.
  const [branch, setBranch] = useState<"invite" | "identity" | "kit" | "signin">("invite");
  const [inviteToken, setInviteToken] = useState("");
  const [preview, setPreview] = useState<JoinPreview | null>(null);

  // "Sign in with existing identity" (escrow): the account handle + password + Secret
  // Key (Emergency Kit) recover the keyset on this fresh device with no prior link.
  const [escrowPw, setEscrowPw] = useState("");
  const [secretKey, setSecretKey] = useState("");

  // "Restore from Emergency Kit" (offline): the encrypted keyset FILE (identity.kit) bytes
  // + password + Secret Key install the keyset from disk — no server escrow round-trip.
  const [keysetBytes, setKeysetBytes] = useState<number[] | null>(null);
  const [kitFileName, setKitFileName] = useState("");

  const optProfile = () => ({
    displayName: displayName.trim() || undefined,
    handle: handle.trim() || undefined,
  });

  // Step 1 → 2: probe the instance so we can branch on claimed/auth.
  const probe = async () => {
    const url = baseUrl.trim();
    if (!url) {
      toast(t("serverCloud.fillBaseUrl"), "warn");
      return;
    }
    setProbing(true);
    try {
      const nfo = await api.instanceInfo(url);
      setInfo(nfo);
      setBranch("invite");
      setPreview(null);
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    } finally {
      setProbing(false);
    }
  };

  const back = () => {
    setInfo(null);
    setPreview(null);
  };

  // Read-only invite preview: the spaces (with roles) the token grants. Stateless.
  const doPreview = async () => {
    if (!inviteToken.trim()) {
      toast(t("serverCloud.fillInvite"), "warn");
      return;
    }
    await guard(async () => {
      setPreview(await api.serverJoinPreview(baseUrl.trim(), inviteToken.trim()));
    });
  };

  const doClaim = async () => {
    if (busy) return;
    if (!setupCode.trim()) {
      toast(t("serverCloud.fillSetupCode"), "warn");
      return;
    }
    setBusy(true);
    try {
      const status = await api.serverClaim(baseUrl.trim(), {
        setupCode: setupCode.trim(),
        spaceName: spaceName.trim() || undefined,
        ...optProfile(),
      });
      toast(t("serverCloud.claimed"), "ok");
      onConnected(status);
      onArm?.(status);
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  const doJoin = async () => {
    if (busy) return;
    if (!inviteToken.trim()) {
      toast(t("serverCloud.fillInvite"), "warn");
      return;
    }
    setBusy(true);
    try {
      const status = await api.serverJoin(baseUrl.trim(), inviteToken.trim(), optProfile());
      toast(t("serverCloud.registered"), "ok");
      onConnected(status);
      onArm?.(status);
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  // Sign in with an existing identity via ESCROW (the fresh-device path). By handle +
  // password + Secret Key, the server-side keyset escrow is recovered, THIS device is
  // self-enrolled, and a session + link are established — no invite, no prior link on
  // this device. This is the session-less keyset link the old TODO tracked.
  // Zero-knowledge: the password + Secret Key go straight to the Rust command (which
  // feeds them only into the core to derive K_auth / unwrap the blob); never logged.
  const doIdentitySignIn = async () => {
    if (busy) return;
    if (!handle.trim()) {
      toast(t("serverCloud.fillHandle"), "warn");
      return;
    }
    if (!secretKey.trim()) {
      toast(t("serverCloud.fillSecretKey"), "warn");
      return;
    }
    setBusy(true);
    try {
      const status = await api.serverEscrowFetchAndUnlock(
        baseUrl.trim(),
        handle.trim(),
        escrowPw ? escrowPw : null,
        secretKey.replace(/[\s-]/g, ""),
      );
      toast(t("serverCloud.signedIn"), "ok");
      onConnected(status);
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  // Pick the Emergency-Kit keyset file (identity.kit) and read its RAW bytes — the encrypted
  // EncryptedKeyset blob the offline restore installs. Uses the same dialog+fs idiom as the
  // other import flows (known-hosts, ssh config), but readFile (binary) not readTextFile.
  const pickKitFile = async () => {
    await guard(async () => {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const { readFile } = await import("@tauri-apps/plugin-fs");
      const selected = await open({
        multiple: false,
        directory: false,
        title: t("serverCloud.kitPickTitle"),
      });
      if (!selected || Array.isArray(selected)) return;
      const bytes = await readFile(selected);
      setKeysetBytes(Array.from(bytes));
      setKitFileName(selected.split(/[/\\]/).pop() || selected);
    });
  };

  // Restore an existing identity OFFLINE from the Emergency-Kit keyset FILE (the escrow tail
  // sourced from disk): the kit bytes + password + Secret Key install + unlock the keyset,
  // THIS device is self-enrolled, and a session + link are established — no server escrow, no
  // prior link on this device. For recovering when the server's escrow is unavailable, or an
  // identity that was never escrowed. Zero-knowledge: the bytes + password + Secret Key go
  // straight to the Rust command (fed only into the core to unwrap the blob); never logged.
  const doKitRestore = async () => {
    if (busy) return;
    if (!keysetBytes) {
      toast(t("serverCloud.fillKitFile"), "warn");
      return;
    }
    if (!secretKey.trim()) {
      toast(t("serverCloud.fillSecretKey"), "warn");
      return;
    }
    setBusy(true);
    try {
      const status = await api.serverImportKeysetAndUnlock(
        baseUrl.trim(),
        keysetBytes,
        escrowPw ? escrowPw : null,
        secretKey.replace(/[\s-]/g, ""),
      );
      toast(t("serverCloud.signedIn"), "ok");
      onConnected(status);
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  // Reconnect the local account keyset (no invite, no escrow). server_login proves the
  // keyset and re-establishes the session for an account this device ALREADY belongs to
  // (a persisted link whose session dropped) — the recovery counterpart to the escrow
  // "existing identity" path above, which handles a brand-new device with no local link.
  const doSignIn = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const status = await api.serverLogin();
      toast(t("serverCloud.signedIn"), "ok");
      onConnected(status);
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  // Sign in with SSO (OIDC browser flow). Opens the system browser to the instance's
  // IdP; on the loopback redirect the Rust command exchanges the code and runs the
  // nonce-bound callback. Gated on the probed `auth.includes("oidc")`.
  const doOidc = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const status = await api.serverOidcLogin(baseUrl.trim());
      toast(t("serverCloud.signedIn"), "ok");
      onConnected(status);
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  // The probed instance is already linked on this device (a persisted ServerConfig for it
  // exists) — gates the "Reconnect" action, whose server_login re-auths an existing link.
  const alreadyLinked = !!info && servers.some((s) => s.connected && s.instanceId === info.instanceId);
  // The instance advertises OIDC SSO — gates the "Sign in with SSO" action.
  const hasOidc = !!info && info.auth.includes("oidc");

  // ── Step 1: enter the server address ──────────────────────────
  if (!info) {
    return (
      <>
        <SectionLabel first>{t("serverCloud.sectionConnect")}</SectionLabel>
        <div style={{ display: "flex", flexDirection: "column", gap: 12, padding: "16px 0" }}>
          <ConnectField
            label={t("serverCloud.baseUrl")}
            value={baseUrl}
            onChange={setBaseUrl}
            placeholder={t("serverCloud.baseUrlPlaceholder")}
            mono
          />
          <div style={{ fontSize: 12.5, color: p.txt3, lineHeight: 1.5 }}>
            {t("serverCloud.baseUrlHint")}
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <Btn icon={probing ? undefined : "enter"} onClick={probe} disabled={probing}>
              {probing ? t("serverCloud.probing") : t("serverCloud.continue")}
            </Btn>
          </div>
        </div>
      </>
    );
  }

  // ── Step 2: instance found — claim / join / sign in ───────────
  return (
    <>
      <SectionLabel first>{t("serverCloud.sectionConnect")}</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: 12, padding: "16px 0" }}>
        {/* Probed instance summary: name, claimed state, advertised sign-in methods. */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            padding: "12px 14px",
            borderRadius: 12,
            border: `1px solid ${p.line2}`,
            background: p.bg1,
          }}
        >
          <Icon name="server" size={18} style={{ color: p.accent, flexShrink: 0 }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 13.5, fontWeight: 700, color: p.txt }}>
              {info.name || baseUrl.trim()}
            </div>
            <div
              style={{
                fontSize: 12,
                color: p.txt3,
                fontFamily: MONO,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {baseUrl.trim()}
              {info.auth.length ? ` · ${info.auth.join(", ")}` : ""}
            </div>
          </div>
          <span
            style={{
              fontSize: 10.5,
              fontWeight: 700,
              letterSpacing: 0.4,
              textTransform: "uppercase",
              color: info.claimed ? p.txt3 : p.green,
              border: `1px solid ${info.claimed ? p.line2 : rgba(p.green, 0.5)}`,
              borderRadius: 6,
              padding: "1px 6px",
              flexShrink: 0,
            }}
          >
            {info.claimed ? t("serverCloud.instanceClaimed") : t("serverCloud.instanceUnclaimed")}
          </span>
          <Btn variant="ghost" size="sm" onClick={back} disabled={busy}>
            {t("serverCloud.changeServer")}
          </Btn>
        </div>

        {!info.claimed ? (
          // Unclaimed → set up as owner with the printed setup code.
          <>
            <div style={{ fontSize: 12.5, color: p.txt3, lineHeight: 1.5 }}>
              {t("serverCloud.setupCodeHint")}
            </div>
            <ConnectField
              label={t("serverCloud.setupCode")}
              value={setupCode}
              onChange={setSetupCode}
              placeholder={t("serverCloud.setupCodePlaceholder")}
              mono
            />
            <ConnectField
              label={t("serverCloud.spaceName")}
              value={spaceName}
              onChange={setSpaceName}
              placeholder={t("serverCloud.spaceNamePlaceholder")}
            />
            <ConnectField
              label={t("serverCloud.displayName")}
              value={displayName}
              onChange={setDisplayName}
              placeholder={t("serverCloud.displayNamePlaceholder")}
            />
            <ConnectField
              label={t("serverCloud.handle")}
              value={handle}
              onChange={setHandle}
              placeholder={t("serverCloud.handlePlaceholder")}
              mono
            />
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <Btn icon={busy ? undefined : "enter"} onClick={doClaim} disabled={busy}>
                {busy ? t("serverCloud.connecting") : t("serverCloud.claimCta")}
              </Btn>
            </div>
          </>
        ) : (
          // Claimed → join with an invite link, or sign in with the local keyset.
          <>
            <Segmented<"invite" | "identity" | "kit" | "signin">
              value={branch}
              onChange={(v) => {
                setBranch(v);
                setPreview(null);
              }}
              options={[
                { value: "invite", label: t("serverCloud.branchInvite") },
                { value: "identity", label: t("serverCloud.branchIdentity") },
                { value: "kit", label: t("serverCloud.branchKit") },
                // "Reconnect" re-auths an existing link (server_login) — only when this
                // instance is already linked here; when it isn't but the server advertises
                // SSO, the same segment carries the (fresh-device) SSO sign-in instead.
                // Hidden entirely when neither applies, so no dead entry shows.
                ...(alreadyLinked || hasOidc
                  ? [
                      {
                        value: "signin" as const,
                        label: alreadyLinked
                          ? t("serverCloud.branchSignIn")
                          : t("serverCloud.branchSso"),
                      },
                    ]
                  : []),
              ]}
            />

            {branch === "invite" ? (
              <>
                <div style={{ fontSize: 12.5, color: p.txt3, lineHeight: 1.5 }}>
                  {t("serverCloud.inviteLinkHint")}
                </div>
                <ConnectField
                  label={t("serverCloud.inviteLink")}
                  value={inviteToken}
                  onChange={(v) => {
                    setInviteToken(v);
                    setPreview(null);
                  }}
                  placeholder={t("serverCloud.inviteLinkPlaceholder")}
                  mono
                />
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Btn variant="ghost" size="sm" icon="eye" onClick={doPreview} disabled={busy}>
                    {t("serverCloud.preview")}
                  </Btn>
                </div>
                {preview && (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 6,
                      padding: "10px 12px",
                      borderRadius: 10,
                      border: `1px solid ${p.line2}`,
                      background: p.bg2,
                    }}
                  >
                    {preview.instanceName && (
                      <div style={{ fontSize: 12.5, fontWeight: 700, color: p.txt }}>
                        {preview.instanceName}
                      </div>
                    )}
                    {preview.spaces.length === 0 ? (
                      <div style={{ fontSize: 12, color: p.txt3 }}>
                        {t("serverCloud.previewNoSpaces")}
                      </div>
                    ) : (
                      preview.spaces.map((sp) => (
                        <div
                          key={sp.spaceId}
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 8,
                            fontSize: 12.5,
                            color: p.txt2,
                          }}
                        >
                          <Icon name="cloud" size={13} style={{ color: p.txt3 }} />
                          <span style={{ flex: 1, minWidth: 0 }}>{sp.name || sp.spaceId}</span>
                          <span style={{ fontSize: 11, color: p.txt3 }}>{sp.role}</span>
                        </div>
                      ))
                    )}
                  </div>
                )}
                <ConnectField
                  label={t("serverCloud.displayName")}
                  value={displayName}
                  onChange={setDisplayName}
                  placeholder={t("serverCloud.displayNamePlaceholder")}
                />
                <ConnectField
                  label={t("serverCloud.handle")}
                  value={handle}
                  onChange={setHandle}
                  placeholder={t("serverCloud.handlePlaceholder")}
                  mono
                />
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <Btn icon={busy ? undefined : "enter"} onClick={doJoin} disabled={busy}>
                    {busy ? t("serverCloud.connecting") : t("serverCloud.joinCta")}
                  </Btn>
                </div>
              </>
            ) : branch === "identity" ? (
              <>
                <div style={{ fontSize: 12.5, color: p.txt3, lineHeight: 1.5 }}>
                  {t("serverCloud.identityHint")}
                </div>
                <ConnectField
                  label={t("serverCloud.handle")}
                  value={handle}
                  onChange={setHandle}
                  placeholder={t("serverCloud.handlePlaceholder")}
                  mono
                />
                <ConnectField
                  label={t("serverCloud.identityPassword")}
                  value={escrowPw}
                  onChange={setEscrowPw}
                  placeholder={t("serverCloud.identityPasswordPlaceholder")}
                  type="password"
                />
                <ConnectField
                  label={t("serverCloud.identitySecretKey")}
                  value={secretKey}
                  onChange={setSecretKey}
                  placeholder={t("serverCloud.identitySecretKeyPlaceholder")}
                  type="password"
                  mono
                />
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <Btn
                    icon={busy ? undefined : "unlock"}
                    onClick={doIdentitySignIn}
                    disabled={busy}
                  >
                    {busy ? t("serverCloud.connecting") : t("serverCloud.identityCta")}
                  </Btn>
                </div>
              </>
            ) : branch === "kit" ? (
              <>
                <div style={{ fontSize: 12.5, color: p.txt3, lineHeight: 1.5 }}>
                  {t("serverCloud.kitHint")}
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: p.txt2, marginBottom: 6 }}>
                    {t("serverCloud.kitFile")}
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <Btn
                      variant="ghost"
                      size="sm"
                      icon="folder"
                      onClick={pickKitFile}
                      disabled={busy}
                    >
                      {t("serverCloud.kitChooseFile")}
                    </Btn>
                    <span
                      style={{
                        flex: 1,
                        minWidth: 0,
                        fontSize: 12.5,
                        fontFamily: MONO,
                        color: kitFileName ? p.txt2 : p.txt3,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {kitFileName || t("serverCloud.kitNoFile")}
                    </span>
                  </div>
                </div>
                <ConnectField
                  label={t("serverCloud.identityPassword")}
                  value={escrowPw}
                  onChange={setEscrowPw}
                  placeholder={t("serverCloud.identityPasswordPlaceholder")}
                  type="password"
                />
                <ConnectField
                  label={t("serverCloud.identitySecretKey")}
                  value={secretKey}
                  onChange={setSecretKey}
                  placeholder={t("serverCloud.identitySecretKeyPlaceholder")}
                  type="password"
                  mono
                />
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <Btn icon={busy ? undefined : "unlock"} onClick={doKitRestore} disabled={busy}>
                    {busy ? t("serverCloud.connecting") : t("serverCloud.kitCta")}
                  </Btn>
                </div>
              </>
            ) : (
              <>
                {/* Reconnect the local keyset — only for an already-linked instance. */}
                {alreadyLinked && (
                  <>
                    <div style={{ fontSize: 12.5, color: p.txt3, lineHeight: 1.5 }}>
                      {t("serverCloud.signInHint")}
                    </div>
                    <div style={{ display: "flex", justifyContent: "flex-end" }}>
                      <Btn icon={busy ? undefined : "unlock"} onClick={doSignIn} disabled={busy}>
                        {busy ? t("serverCloud.connecting") : t("serverCloud.signInCta")}
                      </Btn>
                    </div>
                  </>
                )}
                {hasOidc && (
                  <>
                    {/* The "or" separator only makes sense above another option. */}
                    {alreadyLinked && (
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                          color: p.txt3,
                          fontSize: 11.5,
                          textTransform: "uppercase",
                          letterSpacing: 0.4,
                          margin: "2px 0",
                        }}
                      >
                        <span style={{ flex: 1, height: 1, background: p.line2 }} />
                        {t("serverCloud.ssoOr")}
                        <span style={{ flex: 1, height: 1, background: p.line2 }} />
                      </div>
                    )}
                    <div style={{ fontSize: 12.5, color: p.txt3, lineHeight: 1.5 }}>
                      {t("serverCloud.ssoHint")}
                    </div>
                    <div style={{ display: "flex", justifyContent: "flex-end" }}>
                      <Btn
                        variant="ghost"
                        icon={busy ? undefined : "enter"}
                        onClick={doOidc}
                        disabled={busy}
                      >
                        {busy ? t("serverCloud.connecting") : t("serverCloud.ssoCta")}
                      </Btn>
                    </div>
                  </>
                )}
              </>
            )}
          </>
        )}
      </div>
    </>
  );
}

// Lists the account's own devices (GET /v1/devices), with revoke. The current
// device is badged and can't revoke itself (that would kill this session).
function CloudDevicesList({ currentDeviceId }: { currentDeviceId: string | null }) {
  const p = usePalette();
  const { t } = useTranslation();
  const { fmtDate } = useFmt();
  const setConfirm = useApp((s) => s.setConfirm);
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [loaded, setLoaded] = useState(false);

  const load = async () => {
    try {
      setDevices(await api.serverListDevices());
    } catch {
      // Additive + tolerant: a server that predates GET /v1/devices (not yet
      // redeployed), or an offline/locked instance, just yields no list — never a
      // noisy error toast on every Cloud-settings open.
      setDevices([]);
    } finally {
      setLoaded(true);
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const revoke = (d: DeviceInfo) => {
    setConfirm({
      title: t("serverCloud.revokeDeviceTitle"),
      body: t("serverCloud.revokeDeviceBody"),
      danger: true,
      confirmLabel: t("serverCloud.revokeDevice"),
      onConfirm: async () => {
        await guard(async () => {
          await api.serverDeviceRevoke(d.deviceId);
          toast(t("serverCloud.revokeDeviceDone"), "ok");
          await load();
        });
      },
    });
  };

  if (!loaded || devices.length === 0) return null;
  return (
    <div style={{ marginTop: 4 }}>
      {devices.map((d) => {
        const isCurrent = !!currentDeviceId && d.deviceId === currentDeviceId;
        const revoked = d.status !== "active";
        return (
          <div
            key={d.deviceId}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "11px 0",
              borderBottom: `1px solid ${p.line}`,
              opacity: revoked ? 0.55 : 1,
            }}
          >
            <Icon name="server" size={16} color={isCurrent ? p.accent : p.txt3} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <span
                  style={{
                    fontSize: 12.5,
                    fontFamily: MONO,
                    color: p.txt,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={d.deviceId}
                >
                  {d.deviceId.slice(0, 16)}…
                </span>
                {isCurrent && <Tag>{t("serverCloud.thisDevice")}</Tag>}
              </div>
              <div style={{ fontSize: 11, color: p.txt3 }}>
                {t("serverCloud.deviceRegistered", { date: fmtDate(d.registeredAt) })}
                {" · "}
                {t("serverCloud.deviceSessions", { n: d.activeSessions })}
                {revoked ? ` · ${t("serverCloud.deviceRevoked")}` : ""}
              </div>
            </div>
            {!isCurrent && !revoked && (
              <Btn
                variant="ghost"
                size="sm"
                icon="trash"
                title={t("serverCloud.revokeDevice")}
                onClick={() => revoke(d)}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// Add-device pairing card. serverOnboardComplete BLOCKS until the new device
// joins, so we run it without blocking the UI and show a "waiting…" spinner.
function PairingCard({ onClose }: { onClose: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const [payload, setPayload] = useState<PairingPayload | null>(null);
  const [waiting, setWaiting] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const pl = await api.serverOnboardInitiate();
        if (!alive) return;
        setPayload(pl);
        setWaiting(true);
        // Fire-and-forget: this resolves only once the new device joins.
        api
          .serverOnboardComplete(pl.channelId, pl.oobCode)
          .then(() => {
            if (!alive) return;
            setWaiting(false);
            setDone(true);
            toast(t("serverCloud.pairingDone"), "ok");
            void useApp.getState().reloadServerStatus();
          })
          .catch((e) => {
            if (!alive) return;
            setWaiting(false);
            toast(apiErrorMessage(e), "err");
          });
      } catch (e) {
        if (alive) toast(apiErrorMessage(e), "err");
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const payloadText = payload
    ? [
        `baseUrl: ${payload.baseUrl}`,
        `instanceId: ${payload.instanceId}`,
        `spaceId: ${payload.spaceId}`,
        `accountId: ${payload.accountId}`,
        `deviceId: ${payload.deviceId}`,
        `channelId: ${payload.channelId}`,
        `oobCode: ${payload.oobCode}`,
      ].join("\n")
    : "";

  const copy = async () => {
    await guard(async () => {
      // Pairing payload carries the OOB code (device-onboarding secret) →
      // auto-clear from the clipboard like other secrets.
      await writeSecretToClipboard(payloadText);
      toast(t("serverCloud.pairingCopied"), "ok");
    });
  };

  return (
    <div
      style={{
        marginTop: 12,
        padding: 16,
        borderRadius: 13,
        border: `1px solid ${p.line2}`,
        background: p.bg1,
        display: "flex",
        flexDirection: "column",
        gap: 11,
      }}
    >
      <div style={{ fontSize: 13.5, fontWeight: 700 }}>{t("serverCloud.pairingTitle")}</div>
      <div style={{ fontSize: 12.5, color: p.txt3 }}>{t("serverCloud.pairingHint")}</div>
      <textarea
        readOnly
        value={payloadText}
        spellCheck={false}
        style={{
          width: "100%",
          minHeight: 132,
          resize: "vertical",
          padding: 12,
          borderRadius: 9,
          background: p.bg0,
          border: `1px solid ${p.line2}`,
          outline: "none",
          fontFamily: MONO,
          fontSize: 12,
          lineHeight: 1.5,
          color: p.txt,
          boxSizing: "border-box",
        }}
      />
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        {waiting && (
          <span style={{ display: "flex", alignItems: "center", gap: 8, color: p.txt2, fontSize: 12.5 }}>
            <Spinner size={14} />
            {t("serverCloud.pairingWaiting")}
          </span>
        )}
        {done && (
          <span style={{ display: "flex", alignItems: "center", gap: 6, color: p.green, fontSize: 12.5 }}>
            <Icon name="check" size={14} color={p.green} />
            {t("serverCloud.pairingDone")}
          </span>
        )}
        <div style={{ flex: 1 }} />
        <Btn variant="ghost" size="sm" icon="copy" onClick={copy} disabled={!payload}>
          {t("serverCloud.pairingCopy")}
        </Btn>
        <Btn variant="ghost" size="sm" onClick={onClose}>
          {done ? t("common.done") : t("serverCloud.pairingCancel")}
        </Btn>
      </div>
    </div>
  );
}

// Edit display name / handle.
function CloudProfileForm({ status, onClose }: { status: ServerStatus; onClose: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const [displayName, setDisplayName] = useState("");
  const [handle, setHandle] = useState(status.handle ?? "");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await api.serverAccountProfile(displayName.trim() || null, handle.trim() || null);
      await useApp.getState().reloadServerStatus();
      toast(t("serverCloud.profileSaved"), "ok");
      onClose();
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        marginTop: 12,
        padding: 16,
        borderRadius: 13,
        border: `1px solid ${p.line2}`,
        background: p.bg1,
        display: "flex",
        flexDirection: "column",
        gap: 11,
      }}
    >
      <div style={{ fontSize: 13.5, fontWeight: 700 }}>{t("serverCloud.editProfile")}</div>
      <input
        {...NO_AUTOCORRECT}
        value={displayName}
        onChange={(e) => setDisplayName(e.target.value)}
        placeholder={t("serverCloud.displayNamePlaceholder")}
        style={inputStyle(p)}
      />
      <input
        {...NO_AUTOCORRECT}
        value={handle}
        onChange={(e) => setHandle(e.target.value)}
        placeholder={t("serverCloud.handlePlaceholder")}
        style={inputStyle(p, true)}
      />
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
        <Btn variant="ghost" size="sm" onClick={onClose} disabled={busy}>
          {t("common.cancel")}
        </Btn>
        <Btn size="sm" icon="check" onClick={submit} disabled={busy}>
          {t("serverCloud.saveProfile")}
        </Btn>
      </div>
    </div>
  );
}

// Inline "enable sign-in on your other devices" step shown right after a claim/join
// when we can't arm the escrow silently (a master-password account, or a passwordless
// account whose Secret Key isn't in the keychain). Arming uploads the encrypted keyset
// + the escrow K_auth derived from (master password?, Secret Key), so the SAME identity
// can later sign in from the admin panel or another client by handle + Secret Key.
// The password field appears ONLY for master-password accounts (`requiresPassword !==
// false`); a passwordless account is armed with password=null. Idempotent — re-arming
// just re-uploads. Zero-knowledge: the password + Secret Key go straight to the Rust
// command; never logged, never persisted, cleared once the step closes.
function ArmEscrowForm({
  serverId,
  prefillKey,
  onClose,
}: {
  serverId: string | null;
  prefillKey?: string;
  onClose: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  // `requiresPassword === false` is the strict "passwordless" signal used across
  // Settings (see startupDisabled); anything else keeps the password field so a
  // master-password account is never armed without its password.
  const usesPassword = useApp((s) => s.requiresPassword) !== false;
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState(prefillKey ?? "");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (busy) return;
    if (!secretKey.trim()) {
      toast(t("serverCloud.fillSecretKey"), "warn");
      return;
    }
    setBusy(true);
    try {
      await api.serverKeysetPush(
        usesPassword && password ? password : null,
        secretKey.replace(/[\s-]/g, ""),
        serverId ?? undefined,
      );
      toast(t("serverCloud.armEscrowDone"), "ok");
      setPassword("");
      setSecretKey("");
      onClose();
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
      style={{
        marginTop: 12,
        padding: 16,
        borderRadius: 13,
        border: `1px solid ${p.line2}`,
        background: p.bg1,
        display: "flex",
        flexDirection: "column",
        gap: 11,
      }}
    >
      <div style={{ fontSize: 13.5, fontWeight: 700 }}>{t("serverCloud.armEscrowFormTitle")}</div>
      <div style={{ fontSize: 12.5, color: p.txt3, lineHeight: 1.5 }}>
        {t("serverCloud.armEscrowHint")}
      </div>
      {usesPassword && (
        <ConnectField
          label={t("serverCloud.armEscrowPasswordLabel")}
          value={password}
          onChange={setPassword}
          placeholder={t("serverCloud.armEscrowPasswordPlaceholder")}
          type="password"
        />
      )}
      <ConnectField
        label={t("serverCloud.armEscrowSecretKeyLabel")}
        value={secretKey}
        onChange={setSecretKey}
        placeholder={t("serverCloud.armEscrowSecretKeyPlaceholder")}
        type="password"
        mono
      />
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
        <Btn variant="ghost" size="sm" onClick={onClose} disabled={busy}>
          {t("common.cancel")}
        </Btn>
        <Btn size="sm" icon="shieldcheck" onClick={submit} disabled={busy}>
          {t("serverCloud.armEscrowSubmit")}
        </Btn>
      </div>
    </form>
  );
}

// Audit log subsection — admin-only; tolerate a forbidden error gracefully.
function CloudAuditLog() {
  const p = usePalette();
  const { t } = useTranslation();
  const { fmtDate } = useFmt();
  const isMobile = useNarrow(); // width-aware: also true on a narrow desktop window
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [forbidden, setForbidden] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = async () => {
    try {
      const rows = await api.serverAuditQuery();
      setEntries(rows);
      setForbidden(false);
    } catch (e) {
      if (isServerErrorCode(e, "forbidden")) {
        setForbidden(true);
      } else {
        toast(apiErrorMessage(e), "err");
      }
    } finally {
      setLoaded(true);
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <>
      <SectionLabel>{t("serverCloud.sectionAudit")}</SectionLabel>
      <SettingRow title={t("serverCloud.sectionAudit")} desc={t("serverCloud.auditDesc")}>
        <Btn variant="ghost" size="sm" icon="refresh" onClick={load}>
          {t("serverCloud.auditRefresh")}
        </Btn>
      </SettingRow>
      {forbidden ? (
        <div style={{ fontSize: 12.5, color: p.txt3, padding: "10px 0" }}>
          {t("serverCloud.auditForbidden")}
        </div>
      ) : loaded && entries.length === 0 ? (
        <div style={{ fontSize: 12.5, color: p.txt3, padding: "10px 0" }}>
          {t("serverCloud.auditEmpty")}
        </div>
      ) : (
        <div style={{ marginTop: 8 }}>
          {!isMobile && (
            <div
              style={{
                display: "flex",
                gap: 10,
                padding: "7px 0",
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: 0.4,
                color: p.txt3,
                textTransform: "uppercase",
                borderBottom: `1px solid ${p.line}`,
              }}
            >
              <span style={{ width: 56 }}>{t("serverCloud.auditSeq")}</span>
              <span style={{ width: 110 }}>{t("serverCloud.auditSource")}</span>
              <span style={{ flex: 1 }}>{t("serverCloud.auditRecordedAt")}</span>
              <span style={{ width: 130 }}>{t("serverCloud.auditAuthor")}</span>
            </div>
          )}
          {entries.map((a) =>
            isMobile ? (
              <div
                key={a.seq}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 3,
                  padding: "10px 0",
                  fontSize: 12.5,
                  borderBottom: `1px solid ${p.line}`,
                }}
              >
                <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                  <span style={{ fontFamily: MONO, color: p.txt3 }}>{a.seq}</span>
                  <span style={{ fontWeight: 700, color: p.txt2 }}>{a.source}</span>
                </div>
                <div style={{ color: p.txt2 }}>{fmtDate(a.recordedAt)}</div>
                <div
                  style={{
                    fontFamily: MONO,
                    color: p.txt3,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={a.authorPubkey ?? ""}
                >
                  {a.authorPubkey ? a.authorPubkey.slice(0, 12) + "…" : "—"}
                </div>
              </div>
            ) : (
              <div
                key={a.seq}
                style={{
                  display: "flex",
                  gap: 10,
                  padding: "8px 0",
                  fontSize: 12.5,
                  borderBottom: `1px solid ${p.line}`,
                }}
              >
                <span style={{ width: 56, fontFamily: MONO, color: p.txt3 }}>{a.seq}</span>
                <span style={{ width: 110, color: p.txt2 }}>{a.source}</span>
                <span style={{ flex: 1, color: p.txt2 }}>{fmtDate(a.recordedAt)}</span>
                <span
                  style={{
                    width: 130,
                    fontFamily: MONO,
                    color: p.txt3,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={a.authorPubkey ?? ""}
                >
                  {a.authorPubkey ? a.authorPubkey.slice(0, 12) + "…" : "—"}
                </span>
              </div>
            ),
          )}
        </div>
      )}
    </>
  );
}

// Members panel for the currently-selected cloud vault.
function CloudMembersPanel({ vault }: { vault: VaultInfo }) {
  const p = usePalette();
  const { t } = useTranslation();
  const setConfirm = useApp((s) => s.setConfirm);
  const [members, setMembers] = useState<MemberInfo[]>([]);
  const [accounts, setAccounts] = useState<AccountInfo[]>([]);
  const [adding, setAdding] = useState(false);
  const [ed, setEd] = useState("");
  const [x, setX] = useState("");
  const [role, setRole] = useState<MemberRole>("viewer");
  const [busy, setBusy] = useState(false);
  // #14: a vault that holds identities/bindings must stay single-member (they must
  // never sync to another member). Block adding a member to any such vault. (The core
  // also refuses to WRITE an identity into a multi-member vault — save_identity.)
  const [hasIdentities, setHasIdentities] = useState(false);

  const roleLabel = (r: MemberRole) =>
    r === "admin"
      ? t("serverCloud.roleAdmin")
      : r === "editor"
        ? t("serverCloud.roleEditor")
        : t("serverCloud.roleViewer");

  const load = async () => {
    await guard(async () => {
      const ms = await api.serverListMembers(vault.vaultId);
      setMembers(ms);
    });
    // Account list is admin-only — tolerate a forbidden error silently.
    try {
      setAccounts(await api.serverListAccounts());
    } catch {
      setAccounts([]);
    }
    try {
      const its = await api.listItems(vault.vaultId);
      setHasIdentities(its.some((i) => i.itemType === ItemType.Identity));
    } catch {
      setHasIdentities(false);
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vault.vaultId]);

  const doAddMember = async () => {
    setBusy(true);
    try {
      await guard(async () => {
        await api.serverAddMember(vault.vaultId, ed.trim(), x.trim(), role);
        toast(t("serverCloud.memberAdded"), "ok");
        setEd("");
        setX("");
        setAdding(false);
        await load();
      });
    } finally {
      setBusy(false);
    }
  };

  const addMember = () => {
    if (busy) return;
    if (!ed.trim() || !x.trim()) {
      toast(t("serverCloud.fillMemberKeys"), "warn");
      return;
    }
    // #14: never add a member to a vault holding identities — their private keys +
    // bindings would then sync to the new member.
    if (hasIdentities) {
      toast(t("serverCloud.cantAddToPersonal"), "err");
      return;
    }
    // B5.3(c): adding a member VK-shares EVERY existing secret in this vault with
    // them retroactively — confirm before that irreversible share.
    setConfirm({
      title: t("serverCloud.addMemberConfirmTitle"),
      body: t("serverCloud.addMemberConfirmBody"),
      confirmLabel: t("serverCloud.addMemberConfirmCta"),
      icon: "users",
      onConfirm: () => {
        void doAddMember();
      },
    });
  };

  const pickAccount = (id: string) => {
    const a = accounts.find((acc) => acc.accountId === id);
    if (a) {
      setEd(a.ed25519PubHex ?? "");
      setX(a.x25519PubHex ?? "");
    }
  };

  const confirmPin = async (ed25519PubHex: string) => {
    // The pin is keyed on the member's account id (per-account anti-substitution).
    // Without it (non-admins can't list accounts) we must NOT pin under an empty
    // id — that corrupts the pin table. Require the account context.
    const acc = accounts.find((a) => a.ed25519PubHex === ed25519PubHex);
    if (!acc?.accountId) {
      toast(t("serverCloud.pinNeedsAccount"), "warn");
      return;
    }
    await guard(async () => {
      await api.serverConfirmMemberPin(acc.accountId, ed25519PubHex);
      toast(t("serverCloud.pinConfirmed"), "ok");
    });
  };

  const rotateVk = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await guard(async () => {
        // Rebuild the remaining-member set from the current members + their keys.
        const remaining = members
          .map((m) => {
            const acc = accounts.find((a) => a.ed25519PubHex === m.ed25519PubHex);
            return acc?.x25519PubHex
              ? { ed25519PubHex: m.ed25519PubHex, x25519PubHex: acc.x25519PubHex, role: m.role }
              : null;
          })
          .filter((r): r is NonNullable<typeof r> => r !== null);
        const epoch = await api.serverRotateVk(vault.vaultId, remaining);
        toast(t("serverCloud.rotateVkConfirmed", { epoch }), "ok");
        await load();
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <SectionLabel>{t("serverCloud.members")}</SectionLabel>
      <div style={{ fontSize: 12.5, color: p.txt3, margin: "6px 0 8px" }}>
        {t("serverCloud.membersDesc")}
      </div>
      {members.length === 0 ? (
        <div style={{ fontSize: 12.5, color: p.txt3, padding: "8px 0" }}>
          {t("serverCloud.membersEmpty")}
        </div>
      ) : (
        members.map((m) => (
          <div
            key={m.ed25519PubHex}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "12px 0",
              borderBottom: `1px solid ${p.line}`,
            }}
          >
            <Icon name="fingerprint" size={16} color={p.txt3} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div
                style={{
                  fontSize: 12.5,
                  fontFamily: MONO,
                  color: p.txt,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
                title={m.ed25519PubHex}
              >
                {m.ed25519PubHex.slice(0, 20)}…
              </div>
              <div style={{ fontSize: 11, color: p.txt3, fontFamily: MONO }}>{m.fingerprint}</div>
            </div>
            <Tag>{roleLabel(m.role)}</Tag>
            <Btn
              variant="ghost"
              size="sm"
              icon="check"
              title={t("serverCloud.confirmPin")}
              disabled={!accounts.find((a) => a.ed25519PubHex === m.ed25519PubHex)?.accountId}
              onClick={() => confirmPin(m.ed25519PubHex)}
            />
          </div>
        ))
      )}

      {adding ? (
        <div
          style={{
            marginTop: 12,
            padding: 16,
            borderRadius: 13,
            border: `1px solid ${p.line2}`,
            background: p.bg1,
            display: "flex",
            flexDirection: "column",
            gap: 11,
          }}
        >
          <div style={{ fontSize: 13.5, fontWeight: 700 }}>{t("serverCloud.addMember")}</div>
          {accounts.length > 0 && (
            <select
              onChange={(e) => pickAccount(e.target.value)}
              defaultValue=""
              style={{ ...inputStyle(p), appearance: "none", cursor: "pointer" }}
            >
              <option value="">{t("serverCloud.pickAccount")}</option>
              {accounts.map((a) => (
                <option key={a.accountId} value={a.accountId}>
                  {a.handle ?? a.displayName ?? a.accountId}
                </option>
              ))}
            </select>
          )}
          <input
            {...NO_AUTOCORRECT}
            value={ed}
            onChange={(e) => setEd(e.target.value)}
            placeholder={t("serverCloud.memberEd25519Placeholder")}
            style={inputStyle(p, true)}
          />
          <input
            {...NO_AUTOCORRECT}
            value={x}
            onChange={(e) => setX(e.target.value)}
            placeholder={t("serverCloud.memberX25519Placeholder")}
            style={inputStyle(p, true)}
          />
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: p.txt2, marginBottom: 6 }}>
              {t("serverCloud.memberRole")}
            </div>
            <Segmented<MemberRole>
              value={role}
              onChange={setRole}
              options={[
                { value: "viewer", label: t("serverCloud.roleViewer") },
                { value: "editor", label: t("serverCloud.roleEditor") },
                { value: "admin", label: t("serverCloud.roleAdmin") },
              ]}
            />
          </div>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <Btn variant="ghost" size="sm" onClick={() => setAdding(false)} disabled={busy}>
              {t("common.cancel")}
            </Btn>
            <Btn size="sm" icon="check" onClick={addMember} disabled={busy}>
              {t("common.add")}
            </Btn>
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", gap: 10, marginTop: 14 }}>
          <Btn icon="plus" size="sm" onClick={() => setAdding(true)}>
            {t("serverCloud.addMember")}
          </Btn>
          <Btn variant="ghost" size="sm" icon="refresh" onClick={rotateVk} disabled={busy}>
            {t("serverCloud.rotateVk")}
          </Btn>
        </div>
      )}
    </>
  );
}

// A short, human-friendly label for a linked server (host of the base URL).
function serverLabel(s: ServerStatus): string {
  const base = s.baseUrl ?? "";
  try {
    return new URL(base).host || base;
  } catch {
    return base || s.serverId || "—";
  }
}

// List of linked cloud servers: switch the active one, remove one, or add another.
// The detailed session/profile/devices/audit panels below key off the active server.
function CloudServersList({
  servers,
  activeServerId,
  onAdd,
}: {
  servers: ServerStatus[];
  activeServerId: string | null;
  onAdd: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const setActiveServer = useApp((s) => s.setActiveServer);
  const reloadServerStatus = useApp((s) => s.reloadServerStatus);
  const setConfirm = useApp((s) => s.setConfirm);

  const doRemove = (s: ServerStatus) => {
    if (!s.serverId) return;
    setConfirm({
      title: t("serverCloud.removeServerTitle"),
      body: t("serverCloud.removeServerBody", { server: serverLabel(s) }),
      danger: true,
      confirmLabel: t("serverCloud.removeServer"),
      onConfirm: async () => {
        await guard(async () => {
          await api.serverRemove(s.serverId!);
          await reloadServerStatus();
          toast(t("serverCloud.removeServerDone"), "ok");
        });
      },
    });
  };

  return (
    <>
      <SectionLabel first>{t("serverCloud.sectionServers")}</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", padding: "12px 0" }}>
        {servers.map((s) => {
          const isActive = s.serverId === activeServerId;
          return (
            <div
              key={s.serverId ?? s.baseUrl ?? ""}
              onClick={() => {
                if (!isActive && s.serverId)
                  setActiveServer(s.serverId).catch((e) => toast(apiErrorMessage(e), "err"));
              }}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "12px 0",
                cursor: isActive ? "default" : "pointer",
                borderBottom: `1px solid ${p.line}`,
                background: isActive ? p.bg2 : "transparent",
              }}
              title={isActive ? undefined : t("serverCloud.switchTo")}
            >
              <Icon
                name="cloud"
                size={18}
                style={{ color: isActive ? p.accent : p.txt3, flexShrink: 0 }}
              />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    fontSize: 13.5,
                    fontWeight: 600,
                    color: p.txt,
                    minWidth: 0, // let the ellipsis label span actually truncate
                  }}
                >
                  <span
                    style={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      minWidth: 0,
                    }}
                  >
                    {serverLabel(s)}
                  </span>
                  {isActive && (
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                      <span
                        aria-hidden
                        style={{
                          width: 6,
                          height: 6,
                          borderRadius: "50%",
                          background: p.accent,
                          flexShrink: 0,
                        }}
                      />
                      <span
                        style={{ fontSize: 11, fontWeight: 600, fontFamily: MONO, color: p.txt2 }}
                      >
                        {t("serverCloud.activeBadge")}
                      </span>
                    </span>
                  )}
                  {/* Owner vs member — distinguishes your own space from a joined one
                      (e.g. two spaces on the same host, which would otherwise look
                      like two identical "servers"). Role is not a status → neutral
                      greyscale word, never a coloured pill. */}
                  <Tag>{t(s.owned ? "serverCloud.roleOwner" : "serverCloud.roleMember")}</Tag>
                  <Icon
                    name={s.hasSession ? "shieldcheck" : "alert"}
                    size={13}
                    style={{ color: s.hasSession ? p.green : p.amber, flexShrink: 0 }}
                  />
                </div>
                <div
                  style={{
                    fontSize: 12,
                    color: p.txt3,
                    fontFamily: MONO,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {s.baseUrl ?? "—"}
                  {s.handle ? ` · ${s.handle}` : ""}
                </div>
              </div>
              <Btn
                variant="ghost"
                size="sm"
                icon="x"
                onClick={(e) => {
                  e.stopPropagation();
                  doRemove(s);
                }}
                style={{ color: p.red, borderColor: rgba(p.red, 0.4), flexShrink: 0 }}
              >
                {t("serverCloud.removeServer")}
              </Btn>
            </div>
          );
        })}
        <div style={{ display: "flex", justifyContent: "flex-start", marginTop: 4 }}>
          <Btn variant="ghost" size="sm" icon="plus" onClick={onAdd}>
            {t("serverCloud.addAnotherServer")}
          </Btn>
        </div>
      </div>
    </>
  );
}

function SettingsCloud() {
  const p = usePalette();
  const { t } = useTranslation();
  const { fmtDate } = useFmt();
  const unlocked = useApp((s) => s.unlocked);
  const servers = useApp((s) => s.servers);
  const activeServerId = useApp((s) => s.activeServerId);
  const serverStatus = useApp((s) => s.serverStatus);
  const syncStatus = useApp((s) => s.syncStatus);
  const vaults = useApp((s) => s.vaults);
  const vaultId = useApp((s) => s.vaultId);
  const reloadServerStatus = useApp((s) => s.reloadServerStatus);
  const syncNow = useApp((s) => s.syncNow);
  const repull = useApp((s) => s.repull);

  const [editingProfile, setEditingProfile] = useState(false);
  const [pairing, setPairing] = useState(false);
  // The "Add server" form is a persistent entry below the linked-server list.
  const [addingServer, setAddingServer] = useState(false);
  // Post-claim/join "enable sign-in on other devices" step: set when we couldn't arm
  // the escrow silently (master-password account, or a passwordless account with no
  // keychain Secret Key) → we render the inline ArmEscrowForm, Secret Key pre-filled
  // when we could read it. Null once armed or dismissed.
  const [armPrompt, setArmPrompt] = useState<{ serverId: string | null; prefillKey: string } | null>(
    null,
  );

  // Refresh server status whenever the Cloud section mounts.
  useEffect(() => {
    void reloadServerStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const currentVault = vaults.find((v) => v.vaultId === vaultId);

  // Make a freshly claimed/joined identity recoverable on OTHER devices out of the
  // box, without extra work for the user. A passwordless account arms fully
  // automatically from the keychain Secret Key (the same value Settings → Security
  // reveals) with password=null — zero prompts. A master-password account can't
  // retain the plaintext password, so we surface a one-time inline step (Secret Key
  // pre-filled from the keychain; the user types the password once). Non-blocking:
  // the claim/join already succeeded. Zero-knowledge: the Secret Key only rides the
  // process cache the keychain already primed; it never lands in a store or a log.
  const armEscrowAfterConnect = async (status: ServerStatus) => {
    const serverId = status.serverId;
    const passwordless = useApp.getState().requiresPassword === false;
    let key = "";
    try {
      const raw = await readSecretKeyOnce();
      key = raw ? raw.replace(/[\s-]/g, "") : "";
    } catch {
      key = "";
    }
    if (passwordless && key) {
      try {
        await api.serverKeysetPush(null, key, serverId ?? undefined);
        toast(t("serverCloud.armEscrowDone"), "ok");
        return;
      } catch {
        // Silent arm failed → fall through to the manual step so the user can retry.
      }
    }
    // Master-password account, no keychain Secret Key, or a failed silent arm → the
    // one-time inline step (Secret Key pre-filled when we could read it).
    setArmPrompt({ serverId, prefillKey: key });
  };

  if (!unlocked) {
    return (
      <div style={{ fontSize: 13, color: p.txt3, padding: "12px 0" }}>
        {t("serverCloud.needUnlock")}
      </div>
    );
  }

  // No servers linked yet → straight to the connect form (first link).
  if (servers.length === 0) {
    return (
      <CloudConnectForm
        onConnected={() => void pullCloudVaultsAfterConnect()}
        onArm={(st) => void armEscrowAfterConnect(st)}
      />
    );
  }

  // Resolve the active server explicitly so the panels — and the commands below,
  // which pass s.serverId — never act on a different server than the one shown
  // (the `serverStatus ?? servers[0]` fallback could otherwise diverge from active).
  const s = servers.find((x) => x.serverId === activeServerId) ?? serverStatus ?? servers[0];

  const onAddedServer = () => {
    setAddingServer(false);
    void pullCloudVaultsAfterConnect();
  };

  const doSync = async () => {
    await guard(async () => {
      await syncNow();
      const r = useApp.getState().syncStatus.lastReport;
      if (r) {
        toast(
          t("serverCloud.syncDone", {
            applied: r.applied,
            pushed: r.pushed,
            conflicts: r.conflicts,
            rejected: r.rejected,
          }),
          r.conflicts > 0 || r.rejected > 0 ? "warn" : "ok",
        );
      }
    });
  };

  // Full re-pull of THIS server: reset the pull cursor + sync, so a vault that was
  // rejected under a prior identity (its seqs already past the cursor) is recovered.
  const doRepull = async () => {
    await guard(async () => {
      await repull(s.serverId ?? undefined);
      const r = useApp.getState().syncStatus.lastReport;
      if (r) {
        toast(
          t("serverCloud.repullDone", {
            applied: r.applied,
            rejected: r.rejected,
            conflicts: r.conflicts,
          }),
          r.conflicts > 0 || r.rejected > 0 ? "warn" : "ok",
        );
      }
    });
  };

  // Recovery: bring back cloud vaults deleted locally but still live on the server.
  // A local delete tombstones the vault above the server's version, so LWW won't let
  // a pull resurrect it and the list hides it. Purge the local tombstone + re-pull.
  const doRestoreDeleted = async () => {
    await guard(async () => {
      const n = await api.serverRestoreDeletedVaults(s.serverId ?? undefined);
      await useApp.getState().reloadVaults();
      await reloadServerStatus();
      toast(
        n > 0 ? t("serverCloud.restoreDone", { count: n }) : t("serverCloud.restoreNone"),
        n > 0 ? "ok" : "warn",
      );
    });
  };

  const doRefresh = async () => {
    await guard(async () => {
      await api.serverRefreshSession(s.serverId ?? undefined);
      await reloadServerStatus();
      toast(t("serverCloud.sessionRefreshed"), "ok");
    });
  };
  // Full re-auth via the local keyset (server_login) — for a fully dropped
  // connection where the refresh token is dead, so "Refresh session" can't help.
  // Works because the account identity is the keyset, not the session tokens.
  const doSignIn = async () => {
    await guard(async () => {
      await api.serverLogin(s.serverId ?? undefined);
      await reloadServerStatus();
      toast(t("serverCloud.signedIn"), "ok");
    });
  };

  const doSignOut = async () => {
    await guard(async () => {
      await api.serverLogout(s.serverId ?? undefined);
      await reloadServerStatus();
      toast(t("serverCloud.signedOut"), "ok");
    });
  };

  const lastSyncStr = syncStatus.lastSyncAt
    ? fmtDate(Math.floor(syncStatus.lastSyncAt / 1000))
    : t("serverCloud.lastSyncNever");

  return (
    <>
      <CloudServersList
        servers={servers}
        activeServerId={activeServerId}
        onAdd={() => setAddingServer((v) => !v)}
      />
      {addingServer && (
        <div
          style={{
            marginTop: 4,
            marginBottom: 8,
            padding: "0 14px 8px",
            borderRadius: 12,
            border: `1px solid ${p.line2}`,
            background: p.bg1,
          }}
        >
          <CloudConnectForm onConnected={onAddedServer} onArm={(st) => void armEscrowAfterConnect(st)} />
        </div>
      )}

      {armPrompt && (
        <div
          style={{
            marginTop: 8,
            marginBottom: 4,
            padding: "13px 15px 15px",
            borderRadius: 12,
            border: `1px solid ${rgba(p.accent, 0.5)}`,
            background: p.accentSoft,
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              fontSize: 13.5,
              fontWeight: 700,
            }}
          >
            <Icon name="shieldcheck" size={16} color={p.accent} />
            {t("serverCloud.armEscrowPromptTitle")}
          </div>
          <div style={{ fontSize: 12.5, color: p.txt2, lineHeight: 1.5, marginTop: 4 }}>
            {t("serverCloud.armEscrowPromptBody")}
          </div>
          <ArmEscrowForm
            serverId={armPrompt.serverId}
            prefillKey={armPrompt.prefillKey}
            onClose={() => setArmPrompt(null)}
          />
        </div>
      )}

      <SectionLabel>{t("serverCloud.sectionSession")}</SectionLabel>
      <SettingRow title={serverLabel(s)}>
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            fontSize: 12.5,
            fontWeight: 600,
            color: s.hasSession ? p.green : p.amber,
          }}
        >
          <Icon name={s.hasSession ? "shieldcheck" : "alert"} size={15} />
          {s.hasSession ? t("serverCloud.hasSession") : t("serverCloud.noSession")}
        </span>
      </SettingRow>
      <CloudInfoRow k={t("serverCloud.baseUrlRow")} v={s.baseUrl ?? "—"} />
      <CloudInfoRow k={t("serverCloud.instanceRow")} v={s.instanceId ?? "—"} mono />
      <CloudInfoRow
        k={t("serverCloud.spacesRow")}
        v={
          s.spaces && s.spaces.length
            ? s.spaces.map((sp) => `${sp.name || sp.spaceId} (${sp.role})`).join(", ")
            : "—"
        }
      />
      <CloudInfoRow k={t("serverCloud.accountIdRow")} v={s.accountId ?? "—"} mono />
      <CloudInfoRow k={t("serverCloud.deviceIdRow")} v={s.deviceId ?? "—"} mono />
      <CloudInfoRow k={t("serverCloud.handleRow")} v={s.handle ?? "—"} />
      <CloudInfoRow k={t("serverCloud.lastSync")} v={lastSyncStr} />

      <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 16 }}>
        <Btn
          icon={syncStatus.syncing ? undefined : "refresh"}
          onClick={doSync}
          disabled={syncStatus.syncing || !s.hasSession}
        >
          {syncStatus.syncing ? t("serverCloud.syncing") : t("serverCloud.syncNow")}
        </Btn>
        <Btn
          variant="ghost"
          icon="download"
          onClick={doRepull}
          disabled={syncStatus.syncing || !s.hasSession}
          title={t("serverCloud.pullFromServerHint")}
        >
          {t("serverCloud.pullFromServer")}
        </Btn>
        <Btn
          variant="ghost"
          icon="clock"
          onClick={doRestoreDeleted}
          disabled={syncStatus.syncing || !s.hasSession}
          title={t("serverCloud.restoreDeletedHint")}
        >
          {t("serverCloud.restoreDeleted")}
        </Btn>
        <Btn variant="ghost" icon="refresh" onClick={doRefresh}>
          {t("serverCloud.refreshSession")}
        </Btn>
        <Btn
          variant={s.hasSession ? "ghost" : "primary"}
          icon="unlock"
          onClick={doSignIn}
          title={t("serverCloud.signInAgainHint")}
        >
          {t("serverCloud.signInAgain")}
        </Btn>
      </div>

      <ServerVaultsSection serverId={s.serverId} hasSession={s.hasSession} />

      {syncStatus.lastReport && (
        <div style={{ fontSize: 12, color: p.txt3, marginTop: 10, display: "flex", gap: 12, flexWrap: "wrap" }}>
          <span>{t("serverCloud.syncReportApplied", { count: syncStatus.lastReport.applied })}</span>
          <span>{t("serverCloud.syncReportPushed", { count: syncStatus.lastReport.pushed })}</span>
          <span>{t("serverCloud.syncReportConflicts", { count: syncStatus.lastReport.conflicts })}</span>
          <span>{t("serverCloud.syncReportRejected", { count: syncStatus.lastReport.rejected })}</span>
          <span>{t("serverCloud.syncReportSkipped", { count: syncStatus.lastReport.skippedStale })}</span>
        </div>
      )}

      <SectionLabel>{t("serverCloud.sectionProfile")}</SectionLabel>
      <SettingRow title={t("serverCloud.editProfile")} desc={s.handle ?? "—"}>
        <Btn variant="ghost" size="sm" icon="pencil" onClick={() => setEditingProfile((v) => !v)}>
          {t("common.edit")}
        </Btn>
      </SettingRow>
      {editingProfile && (
        <CloudProfileForm
          key={`profile-${activeServerId ?? ""}`}
          status={s}
          onClose={() => setEditingProfile(false)}
        />
      )}

      <SectionLabel>{t("serverCloud.sectionDevices")}</SectionLabel>
      <SettingRow title={t("serverCloud.addDevice")} desc={t("serverCloud.addDeviceDesc")}>
        <Btn variant="ghost" size="sm" icon="link" onClick={() => setPairing((v) => !v)}>
          {t("serverCloud.addDevice")}
        </Btn>
      </SettingRow>
      {/* No key={activeServerId} here: a successful join calls reloadServerStatus,
          which can change activeServerId and would remount this card → its effect
          re-runs serverOnboardInitiate → a phantom SECOND pairing card. The card
          is transient and bound to the channel it opened, so a stable identity is
          correct. */}
      {pairing && <PairingCard onClose={() => setPairing(false)} />}
      {/* Key includes `pairing` so the list re-fetches when the add-device card
          closes (a freshly-joined device then shows up), and activeServerId so it
          re-fetches on a server switch. Unique prefix avoids sibling-key clashes. */}
      <CloudDevicesList
        key={`devices-${activeServerId ?? ""}-${pairing ? 1 : 0}`}
        currentDeviceId={s.deviceId}
      />

      {currentVault?.syncTarget === "cloud" ? (
        <CloudMembersPanel key={`members-${activeServerId ?? ""}`} vault={currentVault} />
      ) : (
        <>
          <SectionLabel>{t("serverCloud.sectionVault")}</SectionLabel>
          <div style={{ fontSize: 12.5, color: p.txt3, padding: "8px 0" }}>
            {t("serverCloud.noCloudVault")}
          </div>
        </>
      )}

      {/* re-key on the active server so the audit log re-fetches on a switch.
          Keys must be UNIQUE among siblings — sharing the bare activeServerId with
          the profile/members panels collided and rendered a phantom empty panel. */}
      <CloudAuditLog key={`audit-${activeServerId ?? ""}`} />

      <div style={{ display: "flex", gap: 10, marginTop: 26 }}>
        <Btn variant="ghost" size="sm" icon="unlock" onClick={doSignOut} disabled={!s.hasSession}>
          {t("serverCloud.signOut")}
        </Btn>
      </div>
    </>
  );
}

// ── shell ──────────────────────────────────────────────────────
type TabId = "appearance" | "general" | "vaults" | "cloud" | "security" | "about";
const SETTINGS_TABS: { id: TabId; icon: IconName; labelKey: string }[] = [
  { id: "appearance", icon: "sliders", labelKey: "settings.tabAppearance" },
  { id: "general", icon: "refresh", labelKey: "settings.tabGeneral" },
  { id: "vaults", icon: "layers", labelKey: "vault.manage" },
  { id: "cloud", icon: "cloud", labelKey: "serverCloud.tab" },
  { id: "security", icon: "shieldcheck", labelKey: "settings.tabSecurity" },
  { id: "about", icon: "note", labelKey: "settings.tabAbout" },
];

export function ViewSettings() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useNarrow(); // width-aware: also true on a narrow desktop window
  const [tab, setTab] = useState<TabId>("appearance");
  // Reset the content scroll when switching tabs — otherwise a tab scrolled halfway
  // down leaves the next tab opening mid-content instead of at its top.
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: 0 });
  }, [tab]);
  const title = tDyn(SETTINGS_TABS.find((tb) => tb.id === tab)?.labelKey ?? "");

  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        flexDirection: isMobile ? "column" : "row",
        minWidth: 0,
        background: p.bg0,
      }}
    >
      <div
        style={{
          width: isMobile ? "100%" : 200,
          flexShrink: 0,
          borderRight: isMobile ? "none" : `1px solid ${p.line}`,
          borderBottom: isMobile ? `1px solid ${p.line}` : "none",
          padding: isMobile ? "12px" : "20px 12px",
          display: "flex",
          flexDirection: isMobile ? "row" : "column",
          gap: isMobile ? 6 : 3,
          overflowX: isMobile ? "auto" : undefined,
          boxSizing: "border-box",
        }}
      >
        {!isMobile && (
          <h1
            style={{ margin: "0 0 14px 10px", fontSize: 20, fontWeight: 800, letterSpacing: -0.5 }}
          >
            {t("settings.heading")}
          </h1>
        )}
        {SETTINGS_TABS.map((tb) => {
          const on = tab === tb.id;
          return (
            <button
              key={tb.id}
              onClick={() => setTab(tb.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: isMobile ? "10px 14px" : "9px 11px",
                borderRadius: 9,
                cursor: "pointer",
                textAlign: "left",
                border: "1px solid transparent",
                background: "transparent",
                color: on ? p.txt : p.txt2,
                boxShadow: on
                  ? isMobile
                    ? `inset 0 -2px 0 ${p.accent}`
                    : `inset 2px 0 0 ${p.accent}`
                  : "none",
                fontFamily: UI,
                fontSize: 13.5,
                fontWeight: on ? 700 : 500,
                whiteSpace: isMobile ? "nowrap" : undefined,
                flexShrink: isMobile ? 0 : undefined,
              }}
            >
              <Icon name={tb.icon} size={16} color={on ? p.txt : p.txt3} />
              {tDyn(tb.labelKey)}
            </button>
          );
        })}
      </div>
      <div ref={scrollRef} style={{ flex: 1, minWidth: 0, overflow: "auto" }}>
        <div
          style={{
            maxWidth: 720,
            padding: isMobile ? "18px 16px 30px" : "22px 26px 30px",
            width: "100%",
            boxSizing: "border-box",
          }}
        >
          <h2 style={{ margin: "0 0 6px", fontSize: 22, fontWeight: 800, letterSpacing: -0.5 }}>
            {title}
          </h2>
          <div style={{ height: 8 }} />
          {tab === "appearance" && <SettingsAppearance />}
          {tab === "general" && <SettingsGeneral />}
          {tab === "vaults" && <SettingsVaults />}
          {tab === "cloud" && <SettingsCloud />}
          {tab === "security" && <SettingsSecurity />}
          {tab === "about" && <SettingsAbout />}
        </div>
      </div>
    </div>
  );
}
