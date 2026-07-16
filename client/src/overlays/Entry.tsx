// Entry flow overlays — onboarding (create_account), Emergency Kit (one-time
// Secret Key reveal), and unlock. All wired to the real core.

import React, { useEffect, useRef, useState } from "react";
import { writeSecretToClipboard } from "@/bridge/clipboard";
import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, UI, rgba } from "@/theme/tokens";
import { Btn, Checkbox, Field, Icon, Input, Logo, NO_AUTOCORRECT, Spinner, Toggle } from "@/components/primitives";
import { useApp } from "@/store/app";
import { useIsMobile, useNarrow } from "@/store/responsive";
import { toast } from "@/store/toast";
import { guard } from "@/store/action";
import * as api from "@/bridge/api";
import { readSecretKeyOnce, rememberSecretKey } from "@/bridge/secretKey";
import { logWarn } from "@/bridge/log";
import { apiErrorMessage, type PairingPayload } from "@/bridge/types";
import { useTranslation, Trans } from "@/i18n";

function Modal({ children, w = 460 }: { children: React.ReactNode; w?: number }) {
  const p = usePalette();
  const isMobile = useIsMobile();
  const narrow = useNarrow();
  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        zIndex: 100,
        display: "flex",
        flexDirection: narrow ? "column" : "row",
        // Center the card. On phones the card's `margin: auto` does the vertical
        // centering (not `justifyContent`), so when content + the software
        // keyboard exceed the viewport a focused input can still scroll above the
        // keyboard: auto margins center within spare space and collapse to 0 on
        // overflow, leaving the top reachable (a center-anchored flex item taller
        // than the viewport would push its top out of the scrollable area).
        alignItems: "center",
        justifyContent: isMobile ? "flex-start" : "center",
        overflow: isMobile ? "auto" : "hidden",
        background: p.bg0,
        ...(isMobile
          ? {
              padding: "calc(env(safe-area-inset-top) + 20px) 16px calc(env(safe-area-inset-bottom) + 16px)",
            }
          : null),
      }}
    >
      <div
        style={{
          position: isMobile ? "fixed" : "absolute",
          inset: 0,
          background: p.name === "dark" ? "rgba(6,7,11,0.6)" : "rgba(255,255,255,0.5)",
        }}
      />
      <div
        className="uh-view"
        style={{
          position: "relative",
          // `margin: auto` + `flexShrink: 0` (mobile) centers the card vertically
          // when it fits, yet keeps its natural height so the outer container
          // scrolls (top reachable above the keyboard) when it doesn't.
          margin: isMobile ? "auto" : undefined,
          flexShrink: isMobile ? 0 : undefined,
          width: isMobile ? "100%" : w,
          maxWidth: isMobile ? "100%" : "92vw",
          maxHeight: isMobile ? "none" : "92%",
          overflow: "auto",
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 16,
          padding: isMobile ? 20 : 30,
          boxShadow: p.shadow,
        }}
      >
        {children}
      </div>
    </div>
  );
}

function Stepper({ step, isMobile }: { step: number; isMobile?: boolean }) {
  const p = usePalette();
  const { t } = useTranslation();
  const steps = [
    t("onboarding.step.instance"),
    t("onboarding.step.masterPassword"),
    t("onboarding.step.emergencyKit"),
  ];
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        // wrap on desktop too: 3 long RU step labels exhaust the ~400px card and hyphen-break
        flexWrap: "wrap",
        gap: isMobile ? "8px 6px" : 10,
        marginBottom: 26,
      }}
    >
      {steps.map((s, i) => (
        <React.Fragment key={s}>
          <div style={{ display: "flex", alignItems: "center", gap: isMobile ? 6 : 8 }}>
            <span
              style={{
                width: 24,
                height: 24,
                flexShrink: 0,
                borderRadius: "50%",
                fontSize: 12,
                fontWeight: 700,
                fontFamily: MONO,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: i === step ? p.bg4 : p.bg3,
                color: i < step ? p.txt2 : i === step ? p.txt : p.txt3,
                border: `1px solid ${i === step ? p.line2 : p.line}`,
              }}
            >
              {i < step ? "✓" : i + 1}
            </span>
            <span
              style={{
                fontSize: isMobile ? 12 : 13,
                fontWeight: i === step ? 700 : 500,
                color: i === step ? p.txt : p.txt2,
              }}
            >
              {s}
            </span>
          </div>
          {i < steps.length - 1 && (
            <span style={{ width: isMobile ? 12 : 22, height: 1, flexShrink: 0, background: p.line2 }} />
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

// Shared box metrics for the entry-overlay fields (taller + rounder than the modal
// default). Only the height varies with the viewport, passed per call site.
const ENTRY_BOX = { radius: 11, pad: "0 14px", gap: 10, fontSize: 14 } as const;

/** Coarse 0–4 master-password strength: length plus character-class variety.
 *  Drives the meter only — the hard gate is non-empty + matching confirmation. */
function pwStrength(pw: string): number {
  if (!pw) return 0;
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(4, s);
}

function Onboarding({ onCreated }: { onCreated: (secretKey: string) => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [usePwd, setUsePwd] = useState(true);
  const [password, setPassword] = useState("");
  const [confirmPwd, setConfirmPwd] = useState("");
  const [busy, setBusy] = useState(false);

  const strength = usePwd ? pwStrength(password) : 0;
  const mismatch = usePwd && confirmPwd.length > 0 && confirmPwd !== password;
  // Gate: with a master password on, require a non-empty value confirmed identically.
  const canCreate = !busy && (!usePwd || (password.length > 0 && confirmPwd === password));

  const create = async () => {
    if (!canCreate) return;
    setBusy(true);
    try {
      const sk = await api.createAccount(usePwd ? password : null);
      useApp.setState({ requiresPassword: usePwd });
      onCreated(sk);
    } catch (e) {
      logWarn(`account creation failed: ${apiErrorMessage(e)}`);
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  const onPwKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      void create();
    }
  };

  return (
    <Modal>
      <div style={{ marginBottom: 20 }}>
        <Logo size={24} />
      </div>
      <Stepper step={0} isMobile={isMobile} />
      <h1 style={{ margin: "0 0 6px", fontSize: 24, fontWeight: 800, letterSpacing: -0.5 }}>
        {t("onboarding.newInstanceTitle")}
      </h1>
      <p style={{ margin: "0 0 20px", fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
        {t("onboarding.newInstanceDesc")}
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: 15 }}>
        <div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: 7,
            }}
          >
            <span style={{ fontSize: 12, fontWeight: 600, color: p.txt2 }}>
              {t("onboarding.masterPassword")}{" "}
              <span style={{ color: p.txt3, fontWeight: 500 }}>· {t("onboarding.optional")}</span>
            </span>
            <Toggle
              checked={usePwd}
              onChange={setUsePwd}
              aria-label={t("onboarding.masterPassword")}
            />
          </div>
          {usePwd ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <Field>
                <Input
                  icon="lock"
                  accent
                  {...ENTRY_BOX}
                  height={isMobile ? 50 : 46}
                  type="password"
                  autoFocus
                  value={password}
                  onChange={setPassword}
                  onKeyDown={onPwKeyDown}
                  placeholder={t("onboarding.masterPasswordPlaceholder")}
                />
              </Field>
              {password.length > 0 && (
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ flex: 1, display: "flex", gap: 4 }}>
                    {[0, 1, 2, 3].map((i) => (
                      <div
                        key={i}
                        style={{
                          flex: 1,
                          height: 4,
                          borderRadius: 2,
                          background:
                            i < strength
                              ? strength <= 1
                                ? p.red
                                : strength === 2
                                  ? p.amber
                                  : p.green
                              : p.bg4,
                          transition: "background .15s",
                        }}
                      />
                    ))}
                  </div>
                  <span style={{ fontSize: 11, color: p.txt3, minWidth: 44, textAlign: "right" }}>
                    {t(
                      `onboarding.pwStrength.${strength <= 1 ? "weak" : strength === 2 ? "fair" : strength === 3 ? "good" : "strong"}`,
                    )}
                  </span>
                </div>
              )}
              <Field>
                <Input
                  icon="lock"
                  accent={!mismatch}
                  {...ENTRY_BOX}
                  height={isMobile ? 50 : 46}
                  type="password"
                  value={confirmPwd}
                  onChange={setConfirmPwd}
                  onKeyDown={onPwKeyDown}
                  placeholder={t("onboarding.confirmPasswordPlaceholder")}
                />
              </Field>
              {mismatch && (
                <div style={{ fontSize: 12, color: p.red, padding: "0 2px" }}>
                  {t("onboarding.passwordMismatch")}
                </div>
              )}
            </div>
          ) : (
            <div style={{ fontSize: 13, color: p.txt2, padding: "6px 2px" }}>
              {t("onboarding.noPasswordHint")}
            </div>
          )}
        </div>
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: 9,
          margin: "20px 0",
          padding: "14px 0",
          borderTop: `1px solid ${p.line}`,
          borderBottom: `1px solid ${p.line}`,
        }}
      >
        <Icon name="shieldcheck" size={17} color={p.txt3} style={{ marginTop: 1 }} />
        <span style={{ fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
          <Trans
            i18nKey="onboarding.secretKeyNotice"
            components={{
              b: <b style={{ color: p.txt }} />,
              once: <b style={{ color: p.txt }} />,
            }}
          />
        </span>
      </div>
      <Btn
        size="lg"
        icon={busy ? undefined : "key"}
        full
        onClick={create}
        disabled={!canCreate}
        style={isMobile ? { minHeight: 48 } : undefined}
      >
        {busy ? <Spinner size={16} color={p.accentInk} /> : t("onboarding.generateSecretKey")}
      </Btn>
      <button
        onClick={() => useApp.getState().setOverlay("join")}
        disabled={busy}
        style={{
          display: "block",
          width: "100%",
          marginTop: 14,
          padding: 0,
          background: "none",
          border: "none",
          cursor: busy ? "default" : "pointer",
          fontFamily: UI,
          fontSize: 13,
          color: p.txt3,
          textAlign: "center",
        }}
      >
        {t("onboarding.haveAccount")}{" "}
        <span style={{ color: p.accentText, fontWeight: 600 }}>{t("onboarding.connectDevice")}</span>
      </button>
    </Modal>
  );
}

function formatSecretKey(hex: string): string[] {
  // group into readable chunks of 5
  const up = hex.toUpperCase();
  const out: string[] = [];
  for (let i = 0; i < up.length; i += 5) out.push(up.slice(i, i + 5));
  return out;
}

function EmergencyKit({ secretKey, onDone }: { secretKey: string | null; onDone: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [saved, setSaved] = useState(false);
  // Reveal mode: opened from Settings → Recovery without a freshly-created key.
  // Re-read the Secret Key from this device's OS keychain so the user can retrieve
  // and re-save it (the "pull the keychain key again" path). Works only where a key
  // is stored (a trusted, already-unlocked device); null elsewhere (e.g. Android).
  const isReveal = !secretKey;
  const [revealed, setRevealed] = useState<string | null>(null);
  const [loading, setLoading] = useState(isReveal);
  useEffect(() => {
    if (!isReveal) return;
    let alive = true;
    api
      .keychainGetSecretKey()
      .then((k) => alive && setRevealed(k))
      .catch(() => {})
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [isReveal]);
  const key = secretKey ?? revealed;
  const segs = key ? formatSecretKey(key) : [];

  const copy = async () => {
    if (!key) return;
    try {
      await writeSecretToClipboard(key);
      toast(t("onboarding.toast.secretKeyCopied"), "ok");
    } catch {
      toast(t("onboarding.toast.copyFailed"), "err");
    }
  };
  const download = async () => {
    if (!key) return;
    const body = t("onboarding.kitFileBody", { secretKey: key });
    await guard(async () => {
      const path = await save({
        defaultPath: "unissh-emergency-kit.txt",
        filters: [{ name: "Text", extensions: ["txt"] }],
      });
      if (path) {
        await writeTextFile(path, body);
        toast(t("onboarding.toast.kitSaved"), "ok");
      }
    });
  };

  return (
    <Modal w={540}>
      {!isReveal && <Stepper step={2} isMobile={isMobile} />}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span
          style={{
            width: 38,
            height: 38,
            flexShrink: 0,
            borderRadius: 12,
            background: rgba(p.amber, 0.12),
            border: `1px solid ${rgba(p.amber, 0.5)}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name="key" size={20} color={p.amber} />
        </span>
        <h1
          style={{ margin: 0, fontSize: 24, fontWeight: 800, letterSpacing: -0.5, whiteSpace: "nowrap" }}
        >
          {t("onboarding.yourSecretKey")}
        </h1>
      </div>
      {loading ? (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "40px 0" }}>
          <Spinner size={22} />
        </div>
      ) : key ? (
        <>
          <p style={{ margin: "0 0 18px", fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
            {isReveal ? t("onboarding.revealNotice") : t("onboarding.singleShowNotice")}
          </p>
          <div
            style={{
              position: "relative",
              padding: "16px 18px 18px",
              borderRadius: 16,
              background: p.bg0,
              border: `1px solid ${p.line2}`,
              marginBottom: 14,
            }}
          >
            <div
              style={{
                fontFamily: MONO,
                fontSize: 11,
                color: p.txt2,
                letterSpacing: 1,
                marginBottom: 12,
              }}
            >
              {t("onboarding.secretKeyLabel")}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "11px 9px", alignItems: "center" }}>
              {segs.map((s, i) => (
                <React.Fragment key={i}>
                  <span
                    style={{ fontFamily: MONO, fontSize: 18, fontWeight: 700, color: p.txt, letterSpacing: 2 }}
                  >
                    {s}
                  </span>
                  {i < segs.length - 1 && <span style={{ color: p.txt3, fontWeight: 700 }}>-</span>}
                </React.Fragment>
              ))}
            </div>
          </div>
          <div
            style={{
              display: "flex",
              // wrap on desktop too: long RU labels (Скачать .txt / Скопировать) overlap below ~587px
              flexWrap: "wrap",
              gap: 10,
              marginBottom: 16,
            }}
          >
            <Btn
              variant="ghost"
              icon="copy"
              style={{ flex: isMobile ? "1 1 100%" : 1, minHeight: isMobile ? 44 : undefined }}
              onClick={copy}
            >
              {t("common.copy")}
            </Btn>
            <Btn
              variant="ghost"
              icon="download"
              style={{ flex: isMobile ? "1 1 100%" : 1, minHeight: isMobile ? 44 : undefined }}
              onClick={download}
            >
              {t("onboarding.downloadTxt")}
            </Btn>
            <Btn
              variant="ghost"
              icon="hash"
              style={{ flex: isMobile ? "1 1 100%" : 1, minHeight: isMobile ? 44 : undefined }}
              onClick={() => window.print()}
            >
              {t("onboarding.print")}
            </Btn>
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: 9,
              marginBottom: 16,
              padding: 12,
              borderRadius: 12,
              background: rgba(p.amber, 0.1),
              border: `1px solid ${rgba(p.amber, 0.4)}`,
            }}
          >
            <Icon name="shield" size={17} color={p.amber} style={{ marginTop: 1 }} />
            <span style={{ fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
              <Trans
                i18nKey="onboarding.lossWarning"
                components={{ b: <b style={{ color: p.txt }} /> }}
              />
            </span>
          </div>
          {isReveal ? (
            <Btn
              size="lg"
              full
              onClick={onDone}
              style={isMobile ? { minHeight: 48 } : undefined}
            >
              {t("common.done")}
            </Btn>
          ) : (
            <>
              <Checkbox
                checked={saved}
                onChange={setSaved}
                size={22}
                label={t("onboarding.kitSaved")}
                style={{ display: "flex", gap: 11, marginBottom: 16 }}
                labelStyle={{ fontSize: 13, color: p.txt, fontWeight: 600 }}
              />
          {/* really disabled (not opacity-faked): unfocusable and announced as
              disabled until the "I saved it" checkbox is ticked */}
          <Btn
            size="lg"
            icon="ar"
            full
            variant={saved ? "primary" : "ghost"}
            disabled={!saved}
            style={{
              ...(saved ? {} : { opacity: 0.5, cursor: "not-allowed" }),
              ...(isMobile ? { minHeight: 48 } : null),
            }}
            onClick={() => saved && onDone()}
          >
            {t("onboarding.goToInstance")}
          </Btn>
            </>
          )}
        </>
      ) : (
        <>
          <p style={{ margin: "0 0 18px", fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
            <Trans
              i18nKey="onboarding.alreadyShownNotice"
              components={{ b: <b style={{ color: p.txt }} /> }}
            />
          </p>
          <Btn size="lg" full onClick={onDone} style={isMobile ? { minHeight: 48 } : undefined}>
            {t("onboarding.gotIt")}
          </Btn>
        </>
      )}
    </Modal>
  );
}

function Unlock() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [fromKeychain, setFromKeychain] = useState(false);
  const [busy, setBusy] = useState(false);
  // Hide the master-password field for a passwordless (Secret-Key-only) instance —
  // there's nothing to type. `requiresPassword` is derived from the on-disk keyset
  // header at boot, so it's known before unlocking. null/true → keep the field.
  const requiresPassword = useApp((s) => s.requiresPassword);

  // prefill the Secret Key from the OS keychain if it was saved on this device
  // (cached read — at most one keychain access per process)
  useEffect(() => {
    readSecretKeyOnce()
      .then((k) => {
        if (k) {
          setSecretKey(k);
          setFromKeychain(true);
        }
      })
      .catch(() => {});
  }, []);

  const unlock = async () => {
    if (busy) return;
    setBusy(true);
    const cleanKey = secretKey.replace(/[\s-]/g, "");
    try {
      await api.unlock(password ? password : null, cleanKey);
      // store the key only if it wasn't already in the keychain — avoids a
      // write (and its prompt) on every unlock.
      if (!fromKeychain) rememberSecretKey(cleanKey);
      useApp.setState({ unlocked: true, overlay: null });
      await useApp.getState().reloadVaults();
      await useApp.getState().reloadServerStatus();
      // Bind legacy unbound cloud vaults now — the normal locked cold-start path
      // doesn't run boot()'s unlocked branch, so this is where it actually fires.
      await useApp.getState().maybeBindLegacyCloudVaults();
      // Pull cloud vaults from any live server session (no-op without one).
      useApp.getState().cloudAutoSync();
      toast(t("onboarding.toast.unlocked"), "ok");
    } catch (e) {
      logWarn(`unlock failed: ${apiErrorMessage(e)}`);
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  // Escape hatch for a returning user who genuinely can't unlock (lost the master
  // password / Secret Key): wipe this device's instance and start over. Confirm-
  // gated and destructive — the backend refuses while unlocked.
  const resetDevice = () => {
    useApp.getState().setConfirm({
      title: t("entry.unlock.resetTitle"),
      body: t("entry.unlock.resetBody"),
      danger: true,
      icon: "trash",
      confirmLabel: t("entry.unlock.resetConfirm"),
      onConfirm: async () => {
        await guard(async () => {
          await api.resetInstance();
          await useApp.getState().boot(); // both files gone → lands on onboarding
          toast(t("entry.unlock.resetDone"), "ok");
        });
      },
    });
  };

  return (
    <Modal w={400}>
      <div style={{ textAlign: "center" }}>
        <div
          style={{
            width: 60,
            height: 60,
            margin: "0 auto 18px",
            borderRadius: 16,
            background: p.bg3,
            border: `1px solid ${p.line2}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name="lock" size={26} color={p.txt2} stroke={2} />
        </div>
        <h1 style={{ margin: "0 0 4px", fontSize: 19, fontWeight: 800, letterSpacing: -0.4 }}>
          {t("onboarding.locked")}
        </h1>
        <p style={{ margin: "0 0 22px", fontSize: 13, color: p.txt2 }}>
          {t("onboarding.secretsZeroed")}
        </p>
      </div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void unlock();
        }}
        style={{ display: "flex", flexDirection: "column", gap: 13 }}
      >
        {requiresPassword !== false && (
          <Field label={t("onboarding.masterPassword")} labelGap={7}>
            <Input
              icon="lock"
              accent
              {...ENTRY_BOX}
              height={isMobile ? 50 : 46}
              type="password"
              value={password}
              onChange={setPassword}
              placeholder={t("onboarding.ifSetPlaceholder")}
            />
          </Field>
        )}
        <Field label={t("onboarding.secretKeyFromKit")} labelGap={7}>
          <Input
            icon="key"
            mono
            {...ENTRY_BOX}
            height={isMobile ? 50 : 46}
            type="password"
            value={secretKey}
            autoFocus={!fromKeychain}
            onChange={(v) => {
              setSecretKey(v);
              setFromKeychain(false);
            }}
            placeholder="A3-7KQX2-…"
          />
        </Field>
        {fromKeychain && (
          <div
            style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: p.green }}
          >
            <Icon name="shieldcheck" size={12} color={p.green} />
            {t("onboarding.loadedFromKeychain")}
          </div>
        )}
        <div style={{ margin: "5px 0" }}>
          <Btn
            size="lg"
            icon={busy ? undefined : "unlock"}
            full
            onClick={unlock}
            disabled={busy}
            style={isMobile ? { minHeight: 48 } : undefined}
          >
            {busy ? <Spinner size={16} color={p.accentInk} /> : t("onboarding.unlock")}
          </Btn>
        </div>
      </form>
      <button
        onClick={() => useApp.getState().setOverlay("join")}
        style={{
          display: "block",
          width: "100%",
          margin: "2px 0 10px",
          padding: 0,
          background: "none",
          border: "none",
          cursor: "pointer",
          fontFamily: UI,
          fontSize: 13,
          fontWeight: 600,
          color: p.accentText,
          textAlign: "center",
        }}
      >
        {t("entry.unlock.connectDevice")}
      </button>
      <button
        onClick={resetDevice}
        style={{
          display: "block",
          width: "100%",
          margin: "2px 0 14px",
          padding: 0,
          background: "none",
          border: "none",
          cursor: "pointer",
          fontFamily: UI,
          fontSize: 12,
          color: p.txt3,
          textAlign: "center",
        }}
      >
        {t("entry.unlock.cantUnlock")}{" "}
        <span style={{ color: p.red, fontWeight: 600 }}>{t("entry.unlock.reset")}</span>
      </button>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 6,
          fontSize: 12,
          color: p.txt3,
        }}
      >
        <Icon name="refresh" size={12} color={p.txt3} />
        {t("onboarding.autoLock")}
      </div>
    </Modal>
  );
}

/** Shown when the instance is half-written on disk (exactly one of the DB /
 *  keyset files present). Such an instance can neither be unlocked nor recreated,
 *  so we explain the inconsistency and offer a safe, confirm-gated reset that
 *  clears the stray file(s) and drops back to onboarding. */
function Repair() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [busy, setBusy] = useState(false);
  // Disable the button while the confirm is up so a backdrop-dismiss + re-click
  // can't restack the dialog; clears itself when the confirm is cancelled.
  const confirmShown = useApp((s) => s.confirm !== null);
  // The confirm's onConfirm closure captures `busy` at definition time, so the
  // state read there is stale across re-clicks — guard with a ref read/written
  // synchronously instead. (The backend reset is idempotent + hard-guarded too.)
  const busyRef = useRef(false);

  const reset = () => {
    useApp.getState().setConfirm({
      title: t("entry.repair.resetTitle"),
      body: t("entry.repair.resetBody"),
      danger: true,
      icon: "trash",
      confirmLabel: t("entry.repair.resetConfirm"),
      onConfirm: async () => {
        if (busyRef.current) return;
        busyRef.current = true;
        setBusy(true);
        try {
          await api.resetPartialInstance();
          // re-boot: with both files gone, boot() lands on onboarding.
          await useApp.getState().boot();
          toast(t("entry.repair.done"), "ok");
        } catch (e) {
          toast(apiErrorMessage(e), "err");
          busyRef.current = false;
          setBusy(false);
        }
      },
    });
  };

  return (
    <Modal w={460}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span
          style={{
            width: 38,
            height: 38,
            flexShrink: 0,
            borderRadius: 12,
            background: rgba(p.amber, 0.12),
            border: `1px solid ${rgba(p.amber, 0.5)}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name="shield" size={20} color={p.amber} />
        </span>
        <h1 style={{ margin: 0, fontSize: 19, fontWeight: 800, letterSpacing: -0.4 }}>
          {t("entry.repair.title")}
        </h1>
      </div>
      <p style={{ margin: "0 0 20px", fontSize: 13, color: p.txt2, lineHeight: 1.55 }}>
        {t("entry.repair.body")}
      </p>
      <Btn
        size="lg"
        icon={busy ? undefined : "trash"}
        variant="outline"
        full
        onClick={reset}
        disabled={busy || confirmShown}
        style={{ color: p.red, borderColor: rgba(p.red, 0.5), ...(isMobile ? { minHeight: 48 } : null) }}
      >
        {busy ? <Spinner size={16} color={p.red} /> : t("entry.repair.reset")}
      </Btn>
    </Modal>
  );
}

/** Shown when `instance_status` itself failed (a transient backend error, not
 *  "no instance"). Offers a retry so a returning user isn't pushed to onboarding. */
function Retry() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [busy, setBusy] = useState(false);

  const retry = async () => {
    if (busy) return;
    setBusy(true);
    await useApp.getState().boot();
    // boot() always resolves and re-routes the overlay; if it still fails we land
    // back here, so clear busy for another attempt.
    setBusy(false);
  };

  return (
    <Modal w={400}>
      <div style={{ textAlign: "center" }}>
        <div
          style={{
            width: 60,
            height: 60,
            margin: "0 auto 18px",
            borderRadius: 16,
            background: p.bg3,
            border: `1px solid ${p.line2}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name="refresh" size={26} color={p.txt2} stroke={2} />
        </div>
        <h1 style={{ margin: "0 0 4px", fontSize: 19, fontWeight: 800, letterSpacing: -0.4 }}>
          {t("entry.retry.title")}
        </h1>
        <p style={{ margin: "0 0 22px", fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
          {t("entry.retry.body")}
        </p>
      </div>
      <Btn
        size="lg"
        icon={busy ? undefined : "refresh"}
        full
        onClick={retry}
        disabled={busy}
        style={isMobile ? { minHeight: 48 } : undefined}
      >
        {busy ? <Spinner size={16} color={p.accentInk} /> : t("entry.retry.retry")}
      </Btn>
    </Modal>
  );
}

/** Parse the 6-line `key: value` pairing payload copied from an existing device's
 *  "Add device" card back into a PairingPayload. Lenient: ignores order, blank
 *  lines and stray whitespace, and splits each line on its FIRST colon so a
 *  value's own `:` (e.g. an `https://` URL) is preserved. */
function parsePairingPayload(text: string): PairingPayload | null {
  const map: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const i = line.indexOf(":");
    if (i < 0) continue;
    const k = line.slice(0, i).trim();
    const v = line.slice(i + 1).trim();
    if (k && v) map[k] = v;
  }
  const { baseUrl, instanceId, spaceId, accountId, deviceId, channelId, oobCode } = map;
  if (baseUrl && instanceId && spaceId && accountId && deviceId && channelId && oobCode) {
    return { baseUrl, instanceId, spaceId, accountId, deviceId, channelId, oobCode };
  }
  return null;
}

/** New-device join (Path B): paste the pairing payload from an existing, unlocked
 *  device, run the PAKE, and receive the account keyset + its shared Secret Key.
 *  The backend installs the keyset and persists the shared key to the OS keychain
 *  itself — the key never enters the webview, and there is no new Emergency Kit
 *  (the user already holds the account's one). */
function JoinDevice({ onBack }: { onBack: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [code, setCode] = useState("");
  const [usePwd, setUsePwd] = useState(true);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const join = async () => {
    if (busy) return;
    const payload = parsePairingPayload(code);
    if (!payload) {
      toast(t("entry.join.invalidCode"), "warn");
      return;
    }
    setBusy(true);
    try {
      // Blocks until the other device's PAKE completes (it must be on its
      // "Add device" screen). The shared Secret Key is persisted backend-side.
      await api.serverOnboardJoin(payload, usePwd ? password : null);
      useApp.setState({
        instanceExists: true,
        unlocked: true,
        overlay: null,
        requiresPassword: usePwd,
      });
      await useApp.getState().reloadVaults();
      await useApp.getState().reloadServerStatus();
      // The join established a cloud session — pull the account's cloud vaults so
      // they appear on this new device without a manual "Sync now".
      useApp.getState().cloudAutoSync();
      toast(t("entry.join.done"), "ok");
    } catch (e) {
      logWarn(`device join failed: ${apiErrorMessage(e)}`);
      toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  return (
    <Modal w={460}>
      <div style={{ marginBottom: 18 }}>
        <Logo size={24} />
      </div>
      <h1 style={{ margin: "0 0 6px", fontSize: 24, fontWeight: 800, letterSpacing: -0.5 }}>
        {t("entry.join.title")}
      </h1>
      <p style={{ margin: "0 0 18px", fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
        {t("entry.join.desc")}
      </p>
      <textarea
        {...NO_AUTOCORRECT}
        value={code}
        onChange={(e) => setCode(e.target.value)}
        placeholder={t("entry.join.codePlaceholder")}
        spellCheck={false}
        disabled={busy}
        style={{
          width: "100%",
          minHeight: 128,
          resize: "vertical",
          padding: 12,
          borderRadius: 12,
          background: p.bg2,
          border: `1px solid ${p.line2}`,
          outline: "none",
          fontFamily: MONO,
          fontSize: 12,
          lineHeight: 1.5,
          color: p.txt,
          boxSizing: "border-box",
        }}
      />
      <div style={{ marginTop: 15 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 7,
          }}
        >
          <span style={{ fontSize: 12, fontWeight: 600, color: p.txt2 }}>
            {t("onboarding.masterPassword")}{" "}
            <span style={{ color: p.txt3, fontWeight: 500 }}>· {t("onboarding.optional")}</span>
          </span>
          <Toggle
            checked={usePwd}
            onChange={setUsePwd}
            aria-label={t("onboarding.masterPassword")}
          />
        </div>
        {usePwd ? (
          <Field>
            <Input
              icon="lock"
              accent
              {...ENTRY_BOX}
              height={isMobile ? 50 : 46}
              type="password"
              value={password}
              onChange={setPassword}
              placeholder={t("onboarding.masterPasswordPlaceholder")}
            />
          </Field>
        ) : (
          <div style={{ fontSize: 13, color: p.txt2, padding: "6px 2px" }}>
            {t("onboarding.noPasswordHint")}
          </div>
        )}
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: 9,
          margin: "18px 0",
          padding: "14px 0",
          borderTop: `1px solid ${p.line}`,
          borderBottom: `1px solid ${p.line}`,
        }}
      >
        <Icon name="link" size={17} color={p.txt3} style={{ marginTop: 1 }} />
        <span style={{ fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
          {busy ? t("entry.join.waiting") : t("entry.join.hint")}
        </span>
      </div>
      <Btn
        size="lg"
        icon={busy ? undefined : "link"}
        full
        onClick={join}
        disabled={busy}
        style={isMobile ? { minHeight: 48 } : undefined}
      >
        {busy ? <Spinner size={16} color={p.accentInk} /> : t("entry.join.connect")}
      </Btn>
      <button
        onClick={onBack}
        disabled={busy}
        style={{
          display: "block",
          width: "100%",
          marginTop: 14,
          padding: 0,
          background: "none",
          border: "none",
          cursor: busy ? "default" : "pointer",
          fontFamily: UI,
          fontSize: 13,
          color: p.txt3,
          textAlign: "center",
        }}
      >
        {t("common.back")}
      </button>
    </Modal>
  );
}

/** Renders whichever entry overlay is active, owning the one-time Secret Key. */
export function EntryOverlays() {
  const overlay = useApp((s) => s.overlay);
  const setOverlay = useApp((s) => s.setOverlay);
  const instanceExists = useApp((s) => s.instanceExists);
  const [secretKey, setSecretKey] = useState<string | null>(null);

  if (overlay === "onboarding") {
    return (
      <Onboarding
        onCreated={(sk) => {
          setSecretKey(sk);
          // remember on this trusted device for quick unlock (single write)
          rememberSecretKey(sk);
          useApp.setState({ instanceExists: true, unlocked: true });
          setOverlay("kit");
        }}
      />
    );
  }
  if (overlay === "kit") {
    return (
      <EmergencyKit
        secretKey={secretKey}
        onDone={async () => {
          setSecretKey(null);
          setOverlay(null);
          await useApp.getState().reloadVaults();
        }}
      />
    );
  }
  if (overlay === "unlock") {
    return <Unlock />;
  }
  if (overlay === "join") {
    return <JoinDevice onBack={() => setOverlay(instanceExists ? "unlock" : "onboarding")} />;
  }
  if (overlay === "repair") {
    return <Repair />;
  }
  if (overlay === "retry") {
    return <Retry />;
  }
  return null;
}
