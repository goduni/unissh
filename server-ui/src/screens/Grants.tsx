import { useId, useMemo, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { api } from "../api";
import { ROLE_BY_CODE, type VaultRole } from "../api/types";
import { CryptoUnavailableError, getCrypto } from "../crypto/provider";
import { usePrefs } from "../store/prefs";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { b64ToBytes, truncId } from "../util/bytes";
import { decodeManifestMembers, type ManifestMember } from "../util/grant-codec";
import { DataTable, type Column } from "../ui/DataTable";
import { Icon } from "../ui/icons";
import { Modal } from "../ui/overlays";
import {
  Btn,
  Card,
  CardHeader,
  EmptyState,
  ErrorCard,
  InlineError,
  Missing,
  PubkeyChip,
  RoleBadge,
  SectionLabel,
  Skeleton,
  ToneBadge,
  ZkBanner,
  tint,
} from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";
import "./data.css";

export function Grants() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.grants.title")} sub={t("screen.grants.sub")} zk>
      <GrantsBody />
    </Screen>
  );
}

const MUTED = { color: "var(--muted-foreground)" } as const;
/** A muted note line under a figure: 12/16. */
const NOTE = { fontSize: 12, lineHeight: "16px", ...MUTED } as const;

function GrantsBody() {
  const { t } = useTranslation();
  const reloadTick = useUi((s) => s.reloadTick);
  const pickLabel = useId();

  const vaults = useAsync(() => api.admin.vaults(), [reloadTick]);
  const [sel, setSel] = useState<string | null>(null);
  const selected = sel ?? vaults.data?.vaults[0]?.vault_id ?? null;

  const grants = useAsync(
    () => (selected ? api.identity.grants(selected) : Promise.resolve(null)),
    [selected, reloadTick],
  );

  // /v1/grants returns base64 SyncObject envelopes — decode the manifest for members.
  const decoded = useMemo(
    () => (grants.data ? decodeManifestMembers(grants.data.manifest) : null),
    [grants.data],
  );
  const members = decoded?.members ?? [];

  const [rotating, setRotating] = useState(false);

  const list = vaults.data?.vaults ?? [];
  const firstVaults = vaults.loading && !vaults.data;

  const memberColumns: Column<ManifestMember>[] = [
    {
      key: "member_pubkey",
      label: t("screen.grants.colMember"),
      width: "minmax(0, 1.6fr)",
      render: (m) => <PubkeyChip value={m.ed25519_pub} />,
    },
    {
      key: "role",
      label: t("screen.grants.roleColumn"),
      // The badge says the role in the reader's words («Администратор», "Admin").
      width: "128px",
      render: (m) => <RoleBadge role={String(ROLE_BY_CODE[m.role] ?? m.role)} />,
    },
    {
      key: "access",
      label: t("screen.grants.accessColumn"),
      width: "112px",
      render: () => <ToneBadge tone="success">{t("screen.grants.allowed")}</ToneBadge>,
    },
  ];

  return (
    <>
      <ZkBanner tone="amber">{t("zk.grants")}</ZkBanner>

      {vaults.error ? (
        <ErrorCard message={vaults.error} onRetry={vaults.reload} retrying={vaults.loading} />
      ) : null}

      {!vaults.error && !vaults.loading && list.length === 0 ? (
        <EmptyState icon="lock" title={t("screen.grants.noVaults")} />
      ) : null}

      {/* Which vault: one of the instance's, chosen in place. Pressed is --elevated at 600, never blue. */}
      {firstVaults || list.length > 0 ? (
        <div role="group" aria-labelledby={pickLabel} aria-busy={firstVaults || undefined}>
          <SectionLabel id={pickLabel}>{t("screen.grants.vaultLabel")}</SectionLabel>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 8 }}>
            {firstVaults
              ? [0, 1, 2].map((i) => <Skeleton key={i} width={132} height={28} />)
              : list.map((v) => (
                  <button
                    key={v.vault_id}
                    type="button"
                    className="u-btn u-btn--outline data-pick"
                    aria-pressed={v.vault_id === selected}
                    title={v.vault_id}
                    onClick={() => setSel(v.vault_id)}
                  >
                    {truncId(v.vault_id, 8, 4)}
                  </button>
                ))}
          </div>
        </div>
      ) : null}

      {selected ? (
        <div className="data-grants-split">
          {/* The epoch in force, and the one action of the screen: rotating it, with its consequence said first. */}
          <Card pad={false}>
            <CardHeader
              title={t("screen.grants.keyEpoch")}
              actions={
                <Btn size="sm" variant="primary" icon="refresh" onClick={() => setRotating(true)}>
                  {t("screen.grants.rotate")}
                </Btn>
              }
            />
            <div style={{ padding: 16 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 28 }}>
                {grants.loading && !grants.data ? (
                  <Skeleton width={48} height={28} />
                ) : (
                  <span
                    style={{
                      fontFamily: MONO,
                      fontSize: 20,
                      fontWeight: 600,
                      lineHeight: "28px",
                      letterSpacing: "-0.025em",
                    }}
                  >
                    {grants.data ? grants.data.key_epoch : <Missing />}
                  </span>
                )}
                {grants.data ? <ToneBadge tone="success">{t("screen.grants.currentBadge")}</ToneBadge> : null}
              </div>
              <p style={{ ...NOTE, margin: "4px 0 0" }}>{t("screen.grants.membersSummary", { count: members.length })}</p>
              <p style={{ ...NOTE, margin: "12px 0 0", paddingTop: 12, borderTop: "1px solid var(--rule)" }}>
                {t("screen.grants.rotateModalSub")}
              </p>
            </div>
          </Card>

          <Card pad={false}>
            <CardHeader title={t("screen.grants.currentEpochMembers")}>
              <span style={NOTE}>{t("screen.grants.fromSignedManifest")}</span>
            </CardHeader>
            <DataTable
              bare
              columns={memberColumns}
              rows={members}
              rowKey={(m) => m.ed25519_pub}
              loading={grants.loading}
              empty={{ title: t("screen.grants.noMembers"), icon: "user" }}
              summary
              minWidth={420}
              ariaLabel={t("screen.grants.currentEpochMembers")}
            />
          </Card>
        </div>
      ) : null}

      {rotating && selected ? (
        <RotateModal
          vaultId={selected}
          currentMembers={members}
          currentManifestB64={grants.data?.manifest ?? ""}
          currentEpoch={grants.data?.key_epoch ?? 0}
          onClose={() => setRotating(false)}
          onDone={() => {
            setRotating(false);
            grants.reload();
          }}
        />
      ) : null}
    </>
  );
}

function RotateModal({
  vaultId,
  currentMembers,
  currentManifestB64,
  currentEpoch,
  onClose,
  onDone,
}: {
  vaultId: string;
  currentMembers: ManifestMember[];
  currentManifestB64: string;
  currentEpoch: number;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const toast = useUi((s) => s.toast);
  const titleId = useId();
  const subId = useId();
  const accounts = useAsync(() => api.identity.accounts(), []);
  const [keep, setKeep] = useState<Record<string, VaultRole | "remove">>({});
  // Per-member access expiry as a "YYYY-MM-DD" string (empty = no expiry).
  const [expiry, setExpiry] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const members = useMemo(() => {
    const byPub = new Map((accounts.data?.accounts ?? []).map((a) => [a.member_pubkey ?? "", a]));
    return currentMembers.map((m) => {
      const acc = byPub.get(m.ed25519_pub);
      return {
        pub: m.ed25519_pub,
        role: ROLE_BY_CODE[m.role] ?? "viewer",
        who: acc?.handle ?? null,
        x25519: acc?.x25519_pub ?? null,
      };
    });
  }, [currentMembers, accounts.data]);

  const publish = async () => {
    setBusy(true);
    setError(null);
    try {
      const cr = getCrypto();

      // C1: verify the CURRENT manifest against the TOFU-pinned instance owner
      // before trusting its member set for rotation. The server cannot forge the
      // owner's Ed25519 signature, so it can no longer slip an injected, unverified
      // member set past the panel. The instance owner (the claimer) is the root of
      // trust; we require exactly one so the anchor is unambiguous — a multi-owner
      // instance fails closed here (see the Task-5 note: multi-owner rotation needs
      // a proper trust-anchor design).
      const owners = (accounts.data?.accounts ?? []).filter((a) => a.is_owner);
      const genesis = owners.length === 1 ? owners[0].member_pubkey : null;
      if (!genesis) {
        throw new Error(
          "cannot verify members: the instance does not have exactly one owner to anchor trust",
        );
      }
      // Pin per-instance (discriminated by the instance URL): a global key would
      // raise a false MITM alarm across different instances the panel connects to.
      const PIN_KEY = `unissh.ownerPin:${usePrefs.getState().instanceUrl}`;
      const pinned = localStorage.getItem(PIN_KEY);
      if (pinned && pinned !== genesis) {
        throw new Error(
          "owner pin mismatch — the server reported a different instance owner than " +
            "first seen. Possible MITM; rotation blocked. Clear the pin only if you " +
            "intentionally re-claimed this instance.",
        );
      }
      if (!pinned) localStorage.setItem(PIN_KEY, genesis); // trust-on-first-use
      // Fetch the FULL manifest chain (epoch 1..current) and verify it from the
      // pinned genesis owner — each later manifest must be signed by an admin of
      // the previous verified epoch (multi-admin safe). A hole or foreign signer
      // anywhere in the chain fails. `currentManifestB64` is the last link.
      let verifiedEds: Set<string>;
      try {
        const envelopes: string[] = [];
        for (let e = 1; e <= currentEpoch; e++) {
          const g = e === currentEpoch ? { manifest: currentManifestB64 } : await api.identity.grants(vaultId, e);
          if (!g.manifest) throw new Error(`missing manifest for epoch ${e}`);
          envelopes.push(g.manifest);
        }
        if (envelopes.length === 0) throw new Error("vault has no membership manifest to verify");
        const vm = await cr.verifyManifestChain(genesis, envelopes.join("\n"), vaultId);
        verifiedEds = new Set(vm.members.map((mm) => mm.ed25519_pub));
      } catch (e) {
        throw new Error(
          "manifest authority chain failed verification from the pinned genesis owner — " +
            "refusing to rotate to an unverified member set" +
            (e instanceof Error && e.message ? ` (${e.message})` : ""),
          { cause: e },
        );
      }

      const chosen = members.filter((m) => keep[m.pub] !== "remove");
      // Belt-and-suspenders: every retained member must be in the verified set.
      if (chosen.some((m) => !verifiedEds.has(m.pub))) {
        throw new Error("a retained member is not in the cryptographically-verified manifest");
      }
      if (chosen.length === 0) throw new Error(t("screen.grants.needAtLeastOneMember"));
      const missing = chosen.filter((m) => !m.x25519);
      if (missing.length) {
        throw new Error(
          t("screen.grants.missingX25519", { count: missing.length }),
        );
      }

      // M14 (mandatory): each retained member's x25519 MUST be attested by its own
      // registration signature, verified against the EXACT stored reg_payload under
      // the manifest-verified ed25519. We then wrap the fresh VK to the ATTESTED
      // x25519 the check returns — never to the server-supplied account row — so a
      // substituted x25519 can never reach the wrap step. A missing binding is NOT
      // silently skipped (that would be a server-controlled downgrade): we block.
      const byEd = new Map(
        (accounts.data?.accounts ?? []).map((a) => [a.member_pubkey ?? "", a]),
      );
      const attestedX = new Map<string, string>();
      for (const m of chosen) {
        const acc = byEd.get(m.pub);
        const who = acc?.handle ?? m.pub.slice(0, 12);
        if (!acc?.reg_payload || !acc?.reg_signature) {
          throw new Error(
            `member ${who}: no registration binding on file — cannot prove its x25519 is ` +
              `genuine; refusing to wrap the vault key (rotate after the member re-enrolls)`,
          );
        }
        try {
          const x = await cr.verifyMemberBinding(acc.reg_payload, acc.reg_signature, m.pub);
          attestedX.set(m.pub, x);
        } catch {
          throw new Error(
            `member ${who}: x25519 key is not attested by the registration signature — ` +
              `refusing to wrap the vault key to a possibly substituted key`,
          );
        }
      }

      // F24: validate per-member expiry up front. A malformed or PAST date must be
      // rejected loudly — never silently coerced to 0 ("no expiry"), which would
      // hand the member unbounded access the operator believed they had time-limited.
      const nowSec = Math.floor(Date.now() / 1000);
      const notAfter = new Map<string, number>();
      for (const m of chosen) {
        const s = expiry[m.pub];
        if (!s) {
          notAfter.set(m.pub, 0); // empty = no expiry
          continue;
        }
        const secs = Math.floor(new Date(`${s}T23:59:59Z`).getTime() / 1000);
        if (!Number.isFinite(secs) || secs <= nowSec) {
          const who = byEd.get(m.pub)?.handle ?? m.pub.slice(0, 12);
          throw new Error(
            `member ${who}: expiry "${s}" is invalid or in the past — pick a future date or clear it`,
          );
        }
        notAfter.set(m.pub, secs);
      }

      const out = await cr.rotateGrants({
        vaultId: b64ToBytes(vaultId),
        currentEpoch,
        currentManifestB64: "",
        currentGrants: [],
        members: chosen.map((m) => ({
          ed25519_pub: b64ToBytes(m.pub),
          x25519_pub: b64ToBytes(attestedX.get(m.pub) as string),
          role: roleCode((keep[m.pub] as VaultRole) || m.role),
          // Validated above: end-of-day UTC unix seconds, or 0 for no expiry.
          // Authenticated into the grant signature; enforced on read by both the
          // server and the native client (open_grant).
          not_after: notAfter.get(m.pub) ?? 0,
        })),
      });
      await api.identity.grantsPublish({
        manifest: out.manifest,
        grants: out.grants,
        new_epoch: out.new_epoch,
        revoke_epoch: currentEpoch,
      });
      toast("success", t("screen.grants.epochPublished", { epoch: out.new_epoch }));
      onDone();
    } catch (e) {
      setError(
        e instanceof CryptoUnavailableError
          ? t("screen.grants.cryptoUnavailable")
          : e instanceof Error
            ? e.message
            : t("screen.grants.rotationError"),
      );
    } finally {
      setBusy(false);
    }
  };

  // Controls inside the rows of the dialog are 28 px.
  const rowControl = { height: 28, padding: "0 8px", fontSize: 12 } as const;

  return (
    <Modal onClose={onClose} width={600} labelledBy={titleId} describedBy={subId}>
      <div style={{ padding: "24px 24px 16px" }}>
        <h2
          id={titleId}
          style={{ margin: 0, fontSize: 18, fontWeight: 600, lineHeight: "24px", letterSpacing: "-0.025em" }}
        >
          {t("screen.grants.rotateModalTitle")}
        </h2>
        <p id={subId} style={{ margin: "8px 0 0", fontSize: 14, lineHeight: "20px", maxWidth: "72ch", ...MUTED }}>
          {t("screen.grants.rotateModalSub")}
        </p>
      </div>

      <div style={{ padding: "0 24px 16px" }}>
        {/* What the rotation does, said before the click: the caution box (warning edge at 40 % on a 10 % fill). */}
        <div
          role="note"
          style={{
            display: "flex",
            gap: 8,
            alignItems: "flex-start",
            padding: "8px 12px",
            marginBottom: 12,
            borderRadius: "var(--radius-lg)",
            background: tint("var(--warning)", 10),
            border: `1px solid ${tint("var(--warning)", 40)}`,
          }}
        >
          <Icon name="alert" size={16} color="var(--warning)" style={{ marginTop: 2, flexShrink: 0 }} />
          <p style={{ margin: 0, fontSize: 13, lineHeight: "20px", maxWidth: "72ch", color: "var(--foreground)" }}>
            <Trans
              i18nKey="screen.grants.rotateHint"
              values={{ next: currentEpoch + 1, cur: currentEpoch }}
              components={{
                b: <b style={{ fontWeight: 600 }} />,
                code: <code style={{ fontFamily: MONO, fontSize: 12 }} />,
              }}
            />
          </p>
        </div>

        <div
          style={{
            maxHeight: 280,
            overflowY: "auto",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-md)",
          }}
        >
          {members.map((m) => {
            const role = (keep[m.pub] as VaultRole) || m.role;
            const removed = keep[m.pub] === "remove";
            return (
              <div key={m.pub} className="data-member">
                {/* A member taken out stays in the list: dimmed, the handle struck, "restore" beside it. */}
                <div style={{ minWidth: 0, opacity: removed ? 0.5 : undefined }}>
                  <PubkeyChip value={m.pub} />
                  <div
                    style={{
                      fontSize: 12,
                      lineHeight: "16px",
                      fontFamily: m.who ? MONO : undefined,
                      color: m.x25519 ? "var(--muted-foreground)" : "var(--destructive)",
                      textDecoration: removed ? "line-through" : undefined,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {m.who ?? (m.x25519 ? "—" : t("screen.grants.noAccount"))}
                  </div>
                </div>
                <select
                  className="u-input"
                  value={role}
                  disabled={removed}
                  aria-label={t("screen.grants.roleColumn")}
                  onChange={(e) => setKeep((k) => ({ ...k, [m.pub]: e.target.value as VaultRole }))}
                  style={rowControl}
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {t(`role.${r}`)}
                    </option>
                  ))}
                </select>
                <input
                  type="date"
                  className="u-input"
                  value={expiry[m.pub] ?? ""}
                  disabled={removed}
                  min={new Date().toISOString().slice(0, 10)}
                  aria-label={t("screen.grants.expiryLabel")}
                  title={t("screen.grants.expiryTitle")}
                  onChange={(e) => setExpiry((x) => ({ ...x, [m.pub]: e.target.value }))}
                  style={rowControl}
                />
                <Btn
                  size="sm"
                  variant={removed ? "outline" : "danger"}
                  onClick={() => setKeep((k) => ({ ...k, [m.pub]: removed ? m.role : "remove" }))}
                >
                  {removed ? t("screen.grants.restore") : t("screen.grants.remove")}
                </Btn>
              </div>
            );
          })}
          {members.length === 0 ? (
            <EmptyState compact flat icon="user" title={t("screen.grants.noMembersShort")} />
          ) : null}
        </div>

        {error ? (
          <div style={{ marginTop: 12 }}>
            <InlineError>{error}</InlineError>
          </div>
        ) : null}
      </div>

      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          justifyContent: "flex-end",
          gap: 8,
          padding: "16px 24px",
          borderTop: "1px solid var(--rule)",
        }}
      >
        <Btn variant="outline" onClick={onClose}>
          {t("common.cancel")}
        </Btn>
        <Btn variant="primary" icon="shieldcheck" loading={busy} onClick={publish}>
          {t("screen.grants.signAndPublish")}
        </Btn>
      </div>
    </Modal>
  );
}

/** The roles a member can hold, the least first: the options of the role picker. */
const ROLES: VaultRole[] = ["viewer", "editor", "admin"];

function roleCode(r: VaultRole): number {
  return r === "admin" ? 2 : r === "editor" ? 1 : 0;
}
