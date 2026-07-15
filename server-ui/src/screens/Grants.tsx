import { useMemo, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { api } from "../api";
import { ROLE_BY_CODE, type VaultRole } from "../api/types";
import { CryptoUnavailableError, getCrypto } from "../crypto/provider";
import { usePrefs } from "../store/prefs";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { b64ToBytes, truncId } from "../util/bytes";
import { decodeManifestMembers, type ManifestMember } from "../util/grant-codec";
import { Icon } from "../ui/icons";
import { Modal } from "../ui/overlays";
import { Btn, PubkeyChip, Spinner, Tag, ZkBanner } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Grants() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.grants.title")} sub={t("screen.grants.sub")} zk>
      <GrantsBody />
    </Screen>
  );
}

function roleTone(role: number): "amber" | "accent" | "neutral" {
  return role === 2 ? "amber" : role === 1 ? "accent" : "neutral";
}

function GrantsBody() {
  const { t } = useTranslation();
  const reloadTick = useUi((s) => s.reloadTick);

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

  return (
    <>
      <ZkBanner tone="amber">{t("zk.grants")}</ZkBanner>

      <div style={{ fontSize: 12, color: "var(--txt3)", marginBottom: 8 }}>Vault</div>
      <div style={{ display: "flex", gap: 8, marginBottom: 18, flexWrap: "wrap" }}>
        {vaults.loading && !vaults.data ? <Spinner size={16} /> : null}
        {(vaults.data?.vaults ?? []).map((v) => {
          const on = v.vault_id === selected;
          return (
            <button
              key={v.vault_id}
              onClick={() => setSel(v.vault_id)}
              style={{
                fontFamily: MONO,
                fontSize: 12,
                padding: "6px 11px",
                borderRadius: 8,
                cursor: "pointer",
                border: on ? "1px solid var(--accentLine)" : "1px solid var(--line)",
                background: on ? "var(--accentSoft)" : "var(--bg1)",
                color: on ? "var(--accent)" : "var(--txt2)",
              }}
            >
              {truncId(v.vault_id, 8, 4)}
            </button>
          );
        })}
        {!vaults.loading && (vaults.data?.vaults.length ?? 0) === 0 ? (
          <span style={{ fontSize: 12.5, color: "var(--txt3)" }}>{t("screen.grants.noVaults")}</span>
        ) : null}
      </div>

      {selected ? (
        <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: 14 }}>
          <div style={{ background: "var(--bg1)", border: "1px solid var(--line)", borderRadius: 13, padding: "16px 18px" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
              <span style={{ fontSize: 13.5, fontWeight: 700 }}>{t("screen.grants.keyEpoch")}</span>
              <Btn size="sm" variant="soft" icon="refresh" onClick={() => setRotating(true)}>
                {t("screen.grants.rotate")}
              </Btn>
            </div>
            <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
              <span style={{ fontFamily: MONO, fontSize: 30, fontWeight: 700, letterSpacing: -1 }}>
                {grants.data?.key_epoch ?? "—"}
              </span>
              <span style={{ fontSize: 11.5, color: "var(--green)", fontWeight: 700 }}>{t("screen.grants.current")}</span>
            </div>
            <div style={{ fontSize: 11.5, color: "var(--txt3)", marginTop: 6 }}>
              {t("screen.grants.membersSummary", { count: members.length })}
            </div>
          </div>

          <div style={{ background: "var(--bg1)", border: "1px solid var(--line)", borderRadius: 13, overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 18px", borderBottom: "1px solid var(--line)" }}>
              <span style={{ fontSize: 13.5, fontWeight: 700 }}>{t("screen.grants.currentEpochMembers")}</span>
              <span style={{ fontSize: 11.5, color: "var(--txt3)" }}>{t("screen.grants.fromSignedManifest")}</span>
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1.6fr 110px 110px",
                gap: 10,
                padding: "10px 18px",
                borderBottom: "1px solid var(--line)",
                background: "var(--bg2)",
                fontSize: 10,
                fontWeight: 700,
                letterSpacing: 0.3,
                textTransform: "uppercase",
                color: "var(--txt3)",
              }}
            >
              <span>member_pubkey</span>
              <span>{t("screen.grants.roleColumn")}</span>
              <span>{t("screen.grants.accessColumn")}</span>
            </div>
            {grants.loading && !grants.data ? (
              <div style={{ display: "flex", justifyContent: "center", padding: 40 }}>
                <Spinner />
              </div>
            ) : members.length === 0 ? (
              <div style={{ padding: "28px 18px", textAlign: "center", color: "var(--txt3)", fontSize: 13 }}>
                {t("screen.grants.noMembers")}
              </div>
            ) : (
              members.map((m) => (
                <div
                  key={m.ed25519_pub}
                  style={{ display: "grid", gridTemplateColumns: "1.6fr 110px 110px", gap: 10, padding: "11px 18px", borderBottom: "1px solid var(--line)", alignItems: "center" }}
                >
                  <PubkeyChip value={m.ed25519_pub} />
                  <Tag tone={roleTone(m.role)}>{ROLE_BY_CODE[m.role] ?? m.role}</Tag>
                  <span style={{ fontSize: 12, fontWeight: 600, color: "var(--green)" }}>{t("screen.grants.allowed")}</span>
                </div>
              ))
            )}
          </div>
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

  return (
    <Modal onClose={onClose} width={520}>
      <div style={{ padding: "20px 22px 0" }}>
        <div style={{ fontSize: 16, fontWeight: 800 }}>{t("screen.grants.rotateModalTitle")}</div>
        <div style={{ fontSize: 12, color: "var(--txt3)", marginTop: 2 }}>
          {t("screen.grants.rotateModalSub")}
        </div>
      </div>
      <div style={{ padding: "18px 22px" }}>
        <div
          style={{
            display: "flex",
            gap: 10,
            alignItems: "flex-start",
            background: "color-mix(in srgb, var(--amber) 9%, transparent)",
            border: "1px solid color-mix(in srgb, var(--amber) 30%, transparent)",
            borderRadius: 10,
            padding: "11px 13px",
            marginBottom: 14,
          }}
        >
          <Icon name="alert" size={15} color="var(--amber)" style={{ marginTop: 1 }} />
          <div style={{ fontSize: 12, color: "var(--txt2)", lineHeight: 1.5 }}>
            <Trans
              i18nKey="screen.grants.rotateHint"
              values={{ next: currentEpoch + 1, cur: currentEpoch }}
              components={{
                b: <b style={{ color: "var(--txt)" }} />,
                code: <code style={{ color: "var(--amber)", fontFamily: MONO }} />,
              }}
            />
          </div>
        </div>

        <div style={{ maxHeight: 280, overflowY: "auto", border: "1px solid var(--line)", borderRadius: 10 }}>
          {members.map((m) => {
            const role = (keep[m.pub] as VaultRole) || m.role;
            const removed = keep[m.pub] === "remove";
            return (
              <div key={m.pub} style={{ display: "grid", gridTemplateColumns: "1fr 120px 140px 90px", gap: 10, padding: "10px 14px", borderBottom: "1px solid var(--line)", alignItems: "center", opacity: removed ? 0.5 : 1 }}>
                <div style={{ minWidth: 0 }}>
                  <PubkeyChip value={m.pub} />
                  <div style={{ fontSize: 11, color: m.x25519 ? "var(--txt3)" : "var(--red)", fontFamily: MONO }}>
                    {m.who ?? (m.x25519 ? "—" : t("screen.grants.noAccount"))}
                  </div>
                </div>
                <select
                  value={role}
                  disabled={removed}
                  onChange={(e) => setKeep((k) => ({ ...k, [m.pub]: e.target.value as VaultRole }))}
                  style={{ height: 30, borderRadius: 8, background: "var(--bg2)", border: "1px solid var(--line)", color: "var(--txt)", fontFamily: "inherit", fontSize: 12.5, padding: "0 8px" }}
                >
                  <option value="viewer">viewer</option>
                  <option value="editor">editor</option>
                  <option value="admin">admin</option>
                </select>
                <input
                  type="date"
                  value={expiry[m.pub] ?? ""}
                  disabled={removed}
                  min={new Date().toISOString().slice(0, 10)}
                  title="Access expiry (optional) — after this date the member's grant is no longer active (enforced by both the server and the client). Must be a future date."
                  onChange={(e) => setExpiry((x) => ({ ...x, [m.pub]: e.target.value }))}
                  style={{ height: 30, borderRadius: 8, background: "var(--bg2)", border: "1px solid var(--line)", color: "var(--txt)", fontFamily: "inherit", fontSize: 12, padding: "0 8px" }}
                />
                <Btn size="sm" variant={removed ? "soft" : "danger"} onClick={() => setKeep((k) => ({ ...k, [m.pub]: removed ? m.role : "remove" }))}>
                  {removed ? t("screen.grants.restore") : t("screen.grants.remove")}
                </Btn>
              </div>
            );
          })}
          {members.length === 0 ? <div style={{ padding: 20, textAlign: "center", color: "var(--txt3)", fontSize: 13 }}>{t("screen.grants.noMembersShort")}</div> : null}
        </div>

        {error ? (
          <div style={{ fontSize: 12.5, color: "var(--red)", margin: "14px 0 0", display: "flex", gap: 6, alignItems: "center" }}>
            <Icon name="alert" size={14} color="var(--red)" />
            {error}
          </div>
        ) : null}

        <div style={{ display: "flex", gap: 9, marginTop: 16 }}>
          <Btn full onClick={onClose}>
            {t("common.cancel")}
          </Btn>
          <Btn full variant="primary" icon="shieldcheck" loading={busy} onClick={publish}>
            {t("screen.grants.signAndPublish")}
          </Btn>
        </div>
      </div>
    </Modal>
  );
}

function roleCode(r: VaultRole): number {
  return r === "admin" ? 2 : r === "editor" ? 1 : 0;
}
