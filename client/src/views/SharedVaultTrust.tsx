// Vaults a teammate shared with this account, before this device trusts their
// owner — and this account's own fingerprint, which a teammate checks the other
// way round.
//
// Sync verifies a shared vault against its creator's key, and this device learns
// that key only from the user: the server is never trusted to say who owns a
// vault. So the owner's fingerprint is confirmed out of band, the core compares
// and pins it (`server_trust_shared_vault`), then the vault is pulled. The
// server's name for the owner is shown only as its claim.
import { useEffect, useRef, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

import * as api from "@/bridge/api";
import { apiErrorMessage, type MemberRole, type PendingSharedVault } from "@/bridge/types";
import { i18n, useTranslation } from "@/i18n";
import { Btn, Checkbox, Field, Icon, Input, Spinner, Tag } from "@/components/primitives";
import { Modal } from "@/components/Modal";
import { useApp } from "@/store/app";
import { toast } from "@/store/toast";
import {
  expectedFingerprint,
  FINGERPRINT_DIGITS,
  fetchShared,
  typedDigits,
  verifyAndFetch,
  type TrustDeps,
  type TrustResult,
} from "@/support/sharedVaultTrust";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, rgba, TEXT } from "@/theme/tokens";

/** Short, stable label for a vault we can't show a name for yet (its name is
 *  encrypted under a key this device gets only after the pull). */
function shortId(vaultIdHex: string): string {
  return vaultIdHex.length > 10 ? `${vaultIdHex.slice(0, 10)}…` : vaultIdHex;
}

const ROLE_KEY: Record<MemberRole, "serverCloud.roleViewer" | "serverCloud.roleEditor" | "serverCloud.roleAdmin"> = {
  viewer: "serverCloud.roleViewer",
  editor: "serverCloud.roleEditor",
  admin: "serverCloud.roleAdmin",
};

/** The owner as the server's directory names them, or null when it names no one. */
function claimedOwner(v: PendingSharedVault): string | null {
  if (v.claimedName && v.claimedHandle) return `${v.claimedName} (${v.claimedHandle})`;
  return v.claimedName ?? v.claimedHandle ?? null;
}

/** The pull + "is it here now" half, shared by the dialog and "Fetch now". */
function trustDeps(serverId: string | null | undefined): TrustDeps {
  return {
    trust: (vaultId, expected) => api.serverTrustSharedVault(vaultId, expected, serverId ?? undefined),
    pull: (vaultId) => api.serverPullVault(vaultId, serverId ?? undefined),
    isHere: async (vaultId) => {
      await useApp.getState().reloadVaults();
      return useApp.getState().vaults.some((v) => v.vaultId.toLowerCase() === vaultId.toLowerCase());
    },
  };
}

/** Says what a successful trust or fetch did; a mismatch/owner change is shown
 *  in place (the dialog or the row), not as a toast. */
function toastResult(r: TrustResult) {
  if (r.kind === "fetched") {
    toast(i18n.t("sharedVaults.fetched", { count: r.applied }), r.rejected > 0 ? "warn" : "ok");
  } else if (r.kind === "notFetched") {
    toast(i18n.t("sharedVaults.notFetched"), "warn");
  }
}

/** "Shared with you — not verified yet": one row per waiting vault. */
export function SharedWithYou({
  vaults,
  serverId,
  onChanged,
}: {
  vaults: PendingSharedVault[];
  serverId: string | null | undefined;
  onChanged: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const [verifying, setVerifying] = useState<PendingSharedVault | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  if (vaults.length === 0) return null;

  const fetchNow = async (v: PendingSharedVault) => {
    setBusy(v.vaultId);
    try {
      toastResult(await fetchShared(v.vaultId, trustDeps(serverId)));
      onChanged();
    } catch (e) {
      toast(t("serverVaults.pullFailed", { error: apiErrorMessage(e) }), "err");
    } finally {
      setBusy(null);
    }
  };

  return (
    <section aria-labelledby="shared-with-you-title" style={{ marginBottom: rem(14) }}>
      <div
        id="shared-with-you-title"
        style={{
          display: "flex",
          alignItems: "center",
          gap: rem(6),
          fontSize: TEXT.base,
          fontWeight: 600,
          color: p.txt,
        }}
      >
        <Icon name="alert" size={15} color={p.amber} />
        {t("sharedVaults.title")}
      </div>
      <div style={{ fontSize: TEXT.small, color: p.txt3, lineHeight: 1.5, margin: `${rem(4)} 0 ${rem(8)}` }}>
        {t("sharedVaults.intro")}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: rem(6) }}>
        {vaults.map((v) => {
          const owner = claimedOwner(v);
          const changed = v.state === "ownerChanged";
          return (
            <div
              key={v.vaultId}
              style={{
                display: "flex",
                flexDirection: changed ? "column" : "row",
                alignItems: changed ? "stretch" : "center",
                gap: rem(10),
                padding: `${rem(8)} ${rem(10)}`,
                border: `1px solid ${changed ? p.red : rgba(p.amber, 0.55)}`,
                background: changed ? rgba(p.red, 0.08) : undefined,
                borderRadius: 8,
              }}
            >
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: TEXT.base, color: p.txt, fontFamily: MONO }} title={v.vaultId}>
                  {shortId(v.vaultId)}
                </div>
                {v.state !== "unverifiable" && (
                  <div
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      alignItems: "center",
                      gap: rem(6),
                      marginTop: rem(3),
                      fontSize: TEXT.small,
                      color: p.txt2,
                    }}
                  >
                    <span style={{ overflowWrap: "anywhere" }}>
                      {owner ? t("sharedVaults.claimedOwner", { who: owner }) : t("sharedVaults.noClaimedOwner")}
                    </span>
                    {owner && <Tag>{t("sharedVaults.claimTag")}</Tag>}
                    {v.role && <Tag>{t(ROLE_KEY[v.role])}</Tag>}
                  </div>
                )}
                {v.state === "trustedNotFetched" && (
                  <div style={{ marginTop: rem(3), fontSize: TEXT.small, color: p.txt3 }}>
                    {t("sharedVaults.trustedNotFetched")}
                  </div>
                )}
                {v.state === "unverifiable" && (
                  <div style={{ marginTop: rem(3), fontSize: TEXT.small, color: p.amber, overflowWrap: "anywhere" }}>
                    {t("sharedVaults.unverifiable", { error: v.error ?? "" })}
                  </div>
                )}
              </div>

              {changed ? (
                <div role="alert" style={{ fontSize: TEXT.small, color: p.txt, lineHeight: 1.5 }}>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: rem(6),
                      fontWeight: 700,
                      color: p.red,
                    }}
                  >
                    <Icon name="alert" size={15} color={p.red} />
                    {t("sharedVaults.ownerChangedTitle")}
                  </div>
                  <div style={{ marginTop: rem(4) }}>{t("sharedVaults.ownerChangedBody")}</div>
                  {v.fingerprint && (
                    <div style={{ marginTop: rem(6), color: p.txt3 }}>
                      {t("sharedVaults.presentedNow")}{" "}
                      <span className="uh-selectable" style={{ fontFamily: MONO, color: p.txt2, overflowWrap: "anywhere" }}>
                        {v.fingerprint}
                      </span>
                    </div>
                  )}
                </div>
              ) : busy === v.vaultId ? (
                <Spinner />
              ) : v.state === "waiting" ? (
                <Btn variant="soft" icon="fingerprint" onClick={() => setVerifying(v)}>
                  {t("sharedVaults.verify")}
                </Btn>
              ) : v.state === "trustedNotFetched" ? (
                <Btn variant="ghost" icon="download" onClick={() => void fetchNow(v)}>
                  {t("sharedVaults.fetchNow")}
                </Btn>
              ) : null}
            </div>
          );
        })}
      </div>
      {verifying && (
        <VerifyOwnerDialog
          vault={verifying}
          deps={trustDeps(serverId)}
          onClose={() => setVerifying(null)}
          onDone={(r) => {
            setVerifying(null);
            toastResult(r);
            onChanged();
          }}
        />
      )}
    </section>
  );
}

/** Confirms a shared vault's owner. The strong path is the fingerprint the owner
 *  gave out of band, typed or pasted; the weaker one shows the fingerprint the
 *  server's chain yields and needs an explicit "it matches". Either way the core
 *  gets an expected fingerprint and compares it itself. */
export function VerifyOwnerDialog({
  vault,
  deps,
  onClose,
  onDone,
}: {
  vault: PendingSharedVault;
  deps: TrustDeps;
  onClose: () => void;
  onDone: (r: TrustResult) => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const [compare, setCompare] = useState(false);
  const [typed, setTyped] = useState("");
  const [matches, setMatches] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<"mismatch" | "ownerChanged" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const firstRender = useRef(true);

  // Switching paths moves focus to the control the new path starts with.
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    bodyRef.current?.querySelector<HTMLElement>(compare ? '[role="checkbox"]' : "input")?.focus();
  }, [compare]);

  const displayed = vault.fingerprint ?? "";
  const expected = expectedFingerprint(
    compare ? { kind: "confirmed", displayed, matches } : { kind: "typed", typed },
  );
  const owner = claimedOwner(vault);

  const close = () => {
    if (!busy) onClose();
  };

  const submit = async () => {
    if (expected === null || busy) return;
    setBusy(true);
    setFailure(null);
    setError(null);
    try {
      const r = await verifyAndFetch(vault.vaultId, expected, deps);
      if (r.kind === "mismatch" || r.kind === "ownerChanged") {
        setFailure(r.kind);
        setBusy(false);
        return;
      }
      onDone(r);
    } catch (e) {
      setError(apiErrorMessage(e));
      setBusy(false);
    }
  };

  const digits = typedDigits(typed);

  return (
    <Modal
      icon="fingerprint"
      title={t("sharedVaults.dialogTitle")}
      subtitle={<span style={{ fontFamily: MONO, overflowWrap: "anywhere" }}>{vault.vaultId}</span>}
      onClose={close}
      w={500}
      footer={
        <>
          <Btn variant="ghost" onClick={close} disabled={busy} style={{ marginLeft: "auto" }}>
            {t("common.cancel")}
          </Btn>
          <Btn
            variant="primary"
            icon={busy ? undefined : "shieldcheck"}
            disabled={expected === null || busy}
            onClick={() => void submit()}
          >
            {busy ? t("sharedVaults.working") : compare ? t("sharedVaults.confirmSubmit") : t("sharedVaults.submit")}
          </Btn>
        </>
      }
    >
      <div ref={bodyRef} style={{ display: "flex", flexDirection: "column", gap: rem(14) }}>
        <div style={{ fontSize: TEXT.base, color: p.txt2, lineHeight: 1.5 }}>
          <p style={{ margin: `0 0 ${rem(6)}` }}>
            {owner ? t("sharedVaults.claimedOwner", { who: owner }) : t("sharedVaults.noClaimedOwner")}{" "}
            {owner && <Tag>{t("sharedVaults.claimTag")}</Tag>}
          </p>
          <p style={{ margin: 0 }}>{t("sharedVaults.how")}</p>
        </div>

        {failure && (
          <div
            role="alert"
            style={{
              display: "flex",
              gap: rem(8),
              padding: `${rem(10)} ${rem(12)}`,
              borderRadius: 10,
              border: `1px solid ${p.red}`,
              background: rgba(p.red, 0.1),
              fontSize: TEXT.base,
              color: p.txt,
              lineHeight: 1.5,
            }}
          >
            <Icon name="alert" size={16} color={p.red} />
            <span>{failure === "mismatch" ? t("sharedVaults.mismatch") : t("sharedVaults.ownerChangedBody")}</span>
          </div>
        )}
        {error && (
          <div role="alert" style={{ fontSize: TEXT.small, color: p.red, lineHeight: 1.5, overflowWrap: "anywhere" }}>
            {t("sharedVaults.trustFailed", { error })}
          </div>
        )}

        {!compare ? (
          <>
            <Field
              label={t("sharedVaults.fieldLabel")}
              hint={t("sharedVaults.digits", { n: digits, total: FINGERPRINT_DIGITS })}
            >
              <Input
                value={typed}
                onChange={(v) => {
                  setTyped(v);
                  setFailure(null);
                }}
                placeholder={t("sharedVaults.placeholder")}
                mono
                autoFocus
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    void submit();
                  }
                }}
              />
            </Field>
            {displayed && (
              <div>
                <Btn variant="ghost" size="sm" onClick={() => setCompare(true)} disabled={busy}>
                  {t("sharedVaults.noFingerprint")}
                </Btn>
              </div>
            )}
          </>
        ) : (
          <>
            <Field label={t("sharedVaults.displayedLabel")} group>
              <div
                className="uh-selectable"
                style={{
                  fontFamily: MONO,
                  fontSize: TEXT.lead,
                  letterSpacing: rem(0.5),
                  lineHeight: 1.6,
                  padding: `${rem(10)} ${rem(12)}`,
                  borderRadius: 9,
                  border: `1px solid ${p.line2}`,
                  background: p.bg2,
                  color: p.txt,
                  overflowWrap: "anywhere",
                }}
              >
                {displayed}
              </div>
            </Field>
            <div style={{ fontSize: TEXT.small, color: p.amber, lineHeight: 1.5 }}>{t("sharedVaults.weaker")}</div>
            <Checkbox
              checked={matches}
              onChange={(v) => {
                setMatches(v);
                setFailure(null);
              }}
              label={t("sharedVaults.matches")}
            />
            <div>
              <Btn
                variant="ghost"
                size="sm"
                onClick={() => {
                  setCompare(false);
                  setMatches(false);
                }}
                disabled={busy}
              >
                {t("sharedVaults.backToTyped")}
              </Btn>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}

/** This account's own fingerprint, for a teammate who confirms a vault this
 *  account shared with them. */
export function OwnFingerprintRow() {
  const p = usePalette();
  const { t } = useTranslation();
  const [fp, setFp] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    api
      .ownFingerprint()
      .then((v) => {
        if (alive) setFp(v);
      })
      .catch(() => {
        if (alive) setFailed(true);
      });
    return () => {
      alive = false;
    };
  }, []);

  const copy = async () => {
    if (!fp) return;
    try {
      await writeText(fp);
      toast(t("ownFingerprint.copied"), "ok");
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  };

  return (
    <div style={{ padding: `${rem(11)} 0`, borderBottom: `1px solid ${p.line}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: rem(10) }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: TEXT.base, fontWeight: 600, color: p.txt }}>{t("ownFingerprint.title")}</div>
          <div style={{ fontSize: TEXT.small, color: p.txt3, lineHeight: 1.5, marginTop: rem(2) }}>
            {t("ownFingerprint.desc")}
          </div>
        </div>
        <Btn
          variant="ghost"
          size="sm"
          icon="copy"
          onClick={() => void copy()}
          disabled={!fp}
          aria-label={t("ownFingerprint.copy")}
        >
          {t("ownFingerprint.copy")}
        </Btn>
      </div>
      <div
        className="uh-selectable"
        style={{
          marginTop: rem(8),
          fontFamily: MONO,
          fontSize: TEXT.base,
          letterSpacing: rem(0.5),
          lineHeight: 1.6,
          color: failed ? p.amber : p.txt,
          overflowWrap: "anywhere",
        }}
      >
        {failed ? t("ownFingerprint.failed") : (fp ?? <Spinner size={14} />)}
      </div>
    </div>
  );
}
