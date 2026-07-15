import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { AccountRow } from "../api/types";
import { usePrefs } from "../store/prefs";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { DataTable, type Column } from "../ui/DataTable";
import { Icon } from "../ui/icons";
import { Drawer } from "../ui/overlays";
import {
  Avatar,
  Btn,
  PubkeyChip,
  Segmented,
  Spinner,
  StatusDot,
  Tag,
  ZkBanner,
  initialsOf,
} from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

// Seed the avatar color from a char-hash of account_id (same hash as the Directory
// list / Spaces tile) — seeding on .length collapses nearly every account onto one color.
const seedOf = (id: string) => {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) | 0;
  return Math.abs(h);
};

export function Accounts() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.accounts.title")} sub={t("screen.accounts.sub")} zk>
      <AccountsBody />
    </Screen>
  );
}

function AccountsBody() {
  const { t } = useTranslation();
  const density = usePrefs((s) => s.density);
  const setDensity = usePrefs((s) => s.setDensity);
  const reloadTick = useUi((s) => s.reloadTick);

  const data = useAsync(() => api.identity.accounts(), [reloadTick]);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);

  const accounts = data.data?.accounts ?? [];
  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return accounts;
    return accounts.filter(
      (a) =>
        (a.display_name ?? "").toLowerCase().includes(s) ||
        (a.handle ?? "").toLowerCase().includes(s) ||
        (a.member_pubkey ?? "").toLowerCase().includes(s),
    );
  }, [accounts, q]);

  const selected = accounts.find((a) => a.account_id === sel) ?? null;

  const nameOf = (a: AccountRow) => a.display_name || a.handle || "—";

  const columns: Column<AccountRow>[] = [
    {
      key: "acc",
      label: t("screen.accounts.colAccount"),
      width: "2fr",
      render: (a) => (
        <span style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
          <Avatar label={initialsOf(nameOf(a))} seed={seedOf(a.account_id)} size={30} />
          <span style={{ minWidth: 0 }}>
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 13, fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {nameOf(a)}
              </span>
              {a.is_owner ? <Tag tone="green">{t("screen.accounts.ownerBadge")}</Tag> : null}
            </span>
            <span style={{ fontSize: 11, color: "var(--txt3)", fontFamily: MONO }}>
              {a.handle ?? "—"}
            </span>
          </span>
        </span>
      ),
    },
    { key: "pub", label: "member_pubkey", width: "1.6fr", render: (a) => <PubkeyChip value={a.member_pubkey} /> },
    { key: "dev", label: t("screen.accounts.colDevices"), width: "90px", render: (a) => <span style={mono}>{a.device_count}</span> },
    {
      key: "status",
      label: t("screen.accounts.colStatus"),
      width: "100px",
      render: (a) => (
        <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 600, color: a.status === "active" ? "var(--green)" : "var(--red)" }}>
          <StatusDot status={a.status === "active" ? "online" : "offline"} size={7} />
          {a.status === "active" ? t("common.active") : t("common.disabled")}
        </span>
      ),
    },
    { key: "chev", label: "", width: "40px", align: "right", render: () => <Icon name="chevronRight" size={16} color="var(--txt3)" /> },
  ];

  return (
    <>
      <ZkBanner>{t("zk.accounts")}</ZkBanner>

      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            flex: 1,
            minWidth: 0,
            height: 34,
            padding: "0 12px",
            borderRadius: 9,
            background: "var(--bg1)",
            border: "1px solid var(--line)",
          }}
        >
          <Icon name="searchIcon" size={14} color="var(--txt3)" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={t("screen.accounts.filterPlaceholder")}
            style={{ flex: 1, border: "none", background: "transparent", color: "var(--txt)", fontSize: 13, outline: "none", fontFamily: "inherit" }}
          />
        </div>
        <Segmented
          value={density}
          onChange={setDensity}
          options={[
            { value: "cards", label: t("common.cards"), icon: "grid" },
            { value: "list", label: t("common.list") },
          ]}
        />
      </div>

      {data.loading && accounts.length === 0 ? (
        <div style={{ display: "flex", justifyContent: "center", padding: 48 }}>
          <Spinner />
        </div>
      ) : density === "cards" ? (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(290px, 1fr))", gap: 12 }}>
          {filtered.map((a) => (
            <div
              key={a.account_id}
              className="hoverable"
              onClick={() => setSel(a.account_id)}
              style={{ background: "var(--bg1)", border: "1px solid var(--line)", borderRadius: 13, padding: "15px 16px", cursor: "pointer" }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 11 }}>
                <Avatar label={initialsOf(nameOf(a))} seed={seedOf(a.account_id)} size={38} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                    <span style={{ fontSize: 14, fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {nameOf(a)}
                    </span>
                    {a.is_owner ? <Tag tone="green">{t("screen.accounts.ownerBadge")}</Tag> : null}
                  </div>
                  <div style={{ fontSize: 12, color: "var(--txt3)", fontFamily: MONO }}>{a.handle ?? "—"}</div>
                </div>
                <StatusDot status={a.status === "active" ? "online" : "offline"} size={8} />
              </div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 7,
                  marginTop: 13,
                  padding: "7px 9px",
                  borderRadius: 8,
                  background: "var(--bg2)",
                  border: "1px solid var(--line)",
                }}
              >
                <Icon name="key" size={13} color="var(--txt3)" />
                <PubkeyChip value={a.member_pubkey} />
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 14, marginTop: 11, fontSize: 11.5, color: "var(--txt3)" }}>
                <span style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <Icon name="fingerprint" size={13} />
                  {t("screen.accounts.deviceCount", { count: a.device_count })}
                </span>
                <span style={{ color: a.status === "active" ? "var(--green)" : "var(--red)", fontWeight: 600 }}>
                  {a.status === "active" ? t("common.active") : t("common.disabled")}
                </span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <DataTable
          columns={columns}
          rows={filtered}
          rowKey={(a) => a.account_id}
          onRowClick={(a) => setSel(a.account_id)}
          error={data.error}
          onRetry={data.reload}
          empty={{ title: t("screen.accounts.empty"), icon: "server" }}
        />
      )}

      {selected ? (
        <AccountDrawer account={selected} onClose={() => setSel(null)} onChanged={() => data.reload()} />
      ) : null}
    </>
  );
}

function AccountDrawer({
  account,
  onClose,
  onChanged,
}: {
  account: AccountRow;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { t } = useTranslation();
  const askConfirm = useUi((s) => s.askConfirm);
  const toast = useUi((s) => s.toast);
  const go = useUi((s) => s.go);

  const name = account.display_name || account.handle || "—";
  const disabled = account.status === "disabled";

  const toggleOwner = () => {
    askConfirm({
      title: account.is_owner ? t("screen.accounts.ownerRevokeTitle") : t("screen.accounts.ownerGrantTitle"),
      desc: account.is_owner
        ? t("screen.accounts.ownerRevokeDesc")
        : t("screen.accounts.ownerGrantDesc"),
      danger: account.is_owner,
      confirmLabel: account.is_owner ? t("screen.accounts.ownerRevokeConfirm") : t("screen.accounts.ownerGrantConfirm"),
      onConfirm: async () => {
        await api.owner.set(account.account_id, !account.is_owner);
        toast("success", t("common.done"));
        onChanged();
        onClose();
      },
    });
  };

  const toggleDisabled = () => {
    askConfirm({
      title: disabled ? t("screen.accounts.enableTitle") : t("screen.accounts.disableTitle"),
      desc: disabled
        ? t("screen.accounts.enableDesc")
        : t("screen.accounts.disableDesc"),
      danger: !disabled,
      confirmLabel: disabled ? t("screen.accounts.enableConfirm") : t("screen.accounts.disableConfirm"),
      onConfirm: async () => {
        await api.admin.accountStatus(account.account_id, !disabled);
        toast("success", t("common.done"));
        onChanged();
        onClose();
      },
    });
  };

  return (
    <Drawer onClose={onClose}>
      <div style={{ padding: "20px 22px", borderBottom: "1px solid var(--line)", display: "flex", alignItems: "center", gap: 13 }}>
        <Avatar label={initialsOf(name)} seed={seedOf(account.account_id)} size={44} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <span style={{ fontSize: 16, fontWeight: 800, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{name}</span>
            {account.is_owner ? <Tag tone="green">{t("screen.accounts.ownerBadge")}</Tag> : null}
          </div>
          <div style={{ fontSize: 12, color: "var(--txt3)", fontFamily: MONO }}>{account.handle ?? "—"}</div>
        </div>
        <button onClick={onClose} style={{ border: "none", background: "transparent", color: "var(--txt3)", cursor: "pointer", display: "flex" }}>
          <Icon name="plus" size={18} style={{ transform: "rotate(45deg)" }} />
        </button>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "18px 22px" }}>
        <DrawerRow label="account_id">
          <PubkeyChip value={account.account_id} />
        </DrawerRow>
        <DrawerRow label={t("screen.accounts.memberPubkeyLabel")}>
          <PubkeyChip value={account.member_pubkey} />
        </DrawerRow>
        <DrawerRow label={t("common.status")}>
          <span style={{ color: disabled ? "var(--red)" : "var(--green)", fontWeight: 600, fontSize: 13 }}>
            {disabled ? t("common.disabled") : t("common.active")}
          </span>
        </DrawerRow>
        <DrawerRow label={t("screen.accounts.drawerDevices")}>
          <span style={mono}>{account.device_count}</span>
        </DrawerRow>

        <div
          style={{
            marginTop: 6,
            marginBottom: 16,
            fontSize: 12,
            color: "var(--txt3)",
            lineHeight: 1.5,
            background: "var(--accentSoft)",
            border: "1px solid var(--accentLine)",
            borderRadius: 10,
            padding: "10px 12px",
          }}
        >
          {t("screen.accounts.serverVisibilityNote")}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
          <Btn full variant={account.is_owner ? "outline" : "soft"} icon="shield" onClick={toggleOwner}>
            {account.is_owner ? t("screen.accounts.ownerRevokeTitle") : t("screen.accounts.ownerGrantTitle")}
          </Btn>
          <Btn full icon="shieldcheck" onClick={() => go("grants")}>
            {t("screen.accounts.issueGrant")}
          </Btn>
          <Btn full variant="danger" icon={disabled ? "unlock" : "lock"} onClick={toggleDisabled}>
            {disabled ? t("screen.accounts.enableTitle") : t("screen.accounts.disableTitle")}
          </Btn>
        </div>
      </div>
    </Drawer>
  );
}

function DrawerRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 0.4, textTransform: "uppercase", color: "var(--txt3)", marginBottom: 6 }}>
        {label}
      </div>
      {children}
    </div>
  );
}

const mono: React.CSSProperties = { fontFamily: MONO, fontSize: 12.5, color: "var(--txt2)" };
