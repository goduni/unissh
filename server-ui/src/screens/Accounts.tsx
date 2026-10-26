import { useId, useMemo, useState, type CSSProperties, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { AccountRow } from "../api/types";
import { usePrefs } from "../store/prefs";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { DataTable, type Column } from "../ui/DataTable";
import { Icon, type IconName } from "../ui/icons";
import { Drawer } from "../ui/overlays";
import {
  Avatar,
  Btn,
  Card,
  EmptyState,
  ErrorCard,
  IconBtn,
  Missing,
  PubkeyChip,
  SectionLabel,
  Segmented,
  Skeleton,
  StateBadge,
  SummaryCount,
  SummaryLine,
  SummaryPart,
  Tag,
  TextInput,
  Well,
  ZkBanner,
  initialsOf,
} from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";
import "./identity.css";

export function Accounts() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.accounts.title")} sub={t("screen.accounts.sub")} zk>
      <AccountsBody />
    </Screen>
  );
}

function AccountsBody() {
  const { t, i18n } = useTranslation();
  const density = usePrefs((s) => s.density);
  const setDensity = usePrefs((s) => s.setDensity);
  const reloadTick = useUi((s) => s.reloadTick);

  const data = useAsync(() => api.identity.accounts(), [reloadTick]);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);

  const accounts = useMemo(() => data.data?.accounts ?? [], [data.data]);
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

  // The summary line: how many, what the filter found, how many own the instance and how many are switched off.
  const query = q.trim();
  const reading = data.loading && accounts.length === 0;
  const n = (v: number) => v.toLocaleString(i18n.language);
  const owners = accounts.filter((a) => a.is_owner).length;
  const off = accounts.filter((a) => a.status === "disabled").length;
  const summary = (
    <>
      {query ? (
        <SummaryCount>{t("common.found", { n: n(filtered.length) })}</SummaryCount>
      ) : (
        <SummaryCount n={accounts.length} />
      )}
      {query ? <SummaryPart label={t("common.filter")} value={<Clip>{query}</Clip>} active /> : null}
      <SummaryPart label={t("screen.accounts.partOwners")} value={n(owners)} />
      {off > 0 ? <SummaryPart label={t("screen.accounts.partDisabled")} value={n(off)} /> : null}
    </>
  );

  const empty: { title: string; icon: IconName; actionLabel?: string; onAction?: () => void } = query
    ? {
        title: t("common.nothingFound"),
        icon: "searchIcon",
        actionLabel: t("common.resetFilters"),
        onAction: () => setQ(""),
      }
    : { title: t("screen.accounts.empty"), icon: "user" };

  const columns: Column<AccountRow>[] = [
    {
      key: "acc",
      label: t("screen.accounts.colAccount"),
      width: "2fr",
      render: (a) => (
        <span style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <Avatar label={initialsOf(nameOf(a))} size={18} />
          <AccountName a={a} style={{ fontWeight: 500 }} />
          {a.display_name && a.handle ? <span style={{ ...HANDLE, flexShrink: 4 }}>{a.handle}</span> : null}
          {a.is_owner ? <OwnerChip /> : null}
        </span>
      ),
    },
    { key: "pub", label: t("screen.accounts.colPubkey"), width: "1.6fr", render: (a) => <PubkeyChip value={a.member_pubkey} /> },
    { key: "dev", label: t("screen.accounts.colDevices"), width: "96px", numeric: true, render: (a) => a.device_count },
    {
      key: "status",
      label: t("screen.accounts.colStatus"),
      width: "104px",
      render: (a) => <AccountState a={a} />,
    },
    {
      key: "chev",
      label: "",
      width: "16px",
      align: "right",
      render: () => <Icon name="chevronRight" size={16} color="var(--muted-foreground)" />,
    },
  ];

  return (
    <>
      <ZkBanner>{t("zk.accounts")}</ZkBanner>

      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
        <div className="id-filter">
          <Icon name="searchIcon" size={16} color="var(--muted-foreground)" />
          <TextInput
            value={q}
            onChange={setQ}
            placeholder={t("screen.accounts.filterPlaceholder")}
            ariaLabel={t("screen.accounts.filterPlaceholder")}
            style={{ paddingLeft: 32 }}
          />
        </div>
        <div style={{ marginLeft: "auto" }}>
          <Segmented
            size="md"
            value={density}
            onChange={setDensity}
            ariaLabel={t("settings.density")}
            options={[
              { value: "cards", label: t("common.cards"), icon: "grid" },
              { value: "list", label: t("common.list"), icon: "menu" },
            ]}
          />
        </div>
      </div>

      {density === "cards" ? (
        <div style={{ display: "grid", gap: 8 }}>
          {data.error && accounts.length === 0 ? null : (
            <SummaryLine loading={reading} style={{ minHeight: 16, padding: 0, borderBottom: 0 }}>
              {reading ? null : summary}
            </SummaryLine>
          )}
          {data.error ? (
            <ErrorCard message={data.error} onRetry={data.reload} retrying={data.loading} />
          ) : null}
          {reading ? (
            <div role="status" aria-busy="true" style={CARD_GRID}>
              <span className="u-sr-only">{t("common.loading")}</span>
              {Array.from({ length: 3 }, (_, i) => (
                <Card key={i} style={{ display: "grid", gap: 12 }}>
                  <Skeleton width="60%" height={20} />
                  <Skeleton height={32} />
                  <Skeleton width="40%" height={16} />
                </Card>
              ))}
            </div>
          ) : filtered.length === 0 ? (
            data.error ? null : (
              <EmptyState
                icon={empty.icon}
                title={empty.title}
                actionLabel={empty.actionLabel}
                onAction={empty.onAction}
              />
            )
          ) : (
            <div style={CARD_GRID}>
              {filtered.map((a) => (
                <div key={a.account_id} className="id-card">
                  {/* The name has the whole line (two at most); the handle and the chips go on the line under it. */}
                  <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                    <Avatar label={initialsOf(nameOf(a))} size={20} />
                    <div style={{ flex: 1, minWidth: 0, display: "grid", gap: 4 }}>
                      <button
                        type="button"
                        className="id-card__open"
                        onClick={() => setSel(a.account_id)}
                        style={{
                          display: "block",
                          justifySelf: "start",
                          fontSize: 15,
                          fontWeight: 600,
                          lineHeight: "20px",
                          letterSpacing: "-0.025em",
                        }}
                      >
                        <AccountName a={a} clamp />
                      </button>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0, minHeight: 20 }}>
                        {a.display_name && a.handle ? <span style={HANDLE}>{a.handle}</span> : null}
                        {a.is_owner ? <OwnerChip /> : null}
                        <AccountState a={a} />
                      </div>
                    </div>
                  </div>
                  <Well style={{ display: "flex", alignItems: "center", gap: 8, padding: "2px 2px 2px 10px" }}>
                    <Icon name="key" size={14} color="var(--muted-foreground)" />
                    <span className="id-card__over" style={{ display: "flex", flex: 1, minWidth: 0 }}>
                      <PubkeyChip value={a.member_pubkey} />
                    </span>
                  </Well>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      fontSize: 12,
                      lineHeight: "16px",
                      color: "var(--muted-foreground)",
                    }}
                  >
                    <Icon name="fingerprint" size={14} />
                    {t("screen.accounts.deviceCount", { count: a.device_count })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        <DataTable
          columns={columns}
          rows={filtered}
          rowKey={(a) => a.account_id}
          onRowClick={(a) => setSel(a.account_id)}
          loading={data.loading}
          error={data.error}
          onRetry={data.reload}
          summary={reading ? true : summary}
          ariaLabel={t("screen.accounts.title")}
          empty={empty}
        />
      )}

      {selected ? (
        <AccountDrawer account={selected} onClose={() => setSel(null)} onChanged={() => data.reload()} />
      ) : null}
    </>
  );
}

/**
 * An account's name: its display name, else its handle (mono), else its id (mono, muted). One line cut with an
 * ellipsis; `clamp`: up to two lines, then the ellipsis (a card, where the name has its line to itself).
 */
function AccountName({ a, style, clamp }: { a: AccountRow; style?: CSSProperties; clamp?: boolean }) {
  const fit = clamp ? undefined : TRUNC;
  const cls = clamp ? "id-card__name" : undefined;
  if (a.display_name)
    return (
      <span className={cls} style={{ ...fit, ...style }}>
        {a.display_name}
      </span>
    );
  if (a.handle)
    return (
      <span className={cls} style={{ ...fit, ...style, fontFamily: MONO, fontSize: 12 }}>
        {a.handle}
      </span>
    );
  return (
    <span className={cls} style={{ ...fit, ...style, fontFamily: MONO, fontSize: 12, color: "var(--muted-foreground)" }}>
      {truncId(a.account_id)}
    </span>
  );
}

/** Owner is a role, not a state: a neutral chip, never a colour. */
function OwnerChip() {
  const { t } = useTranslation();
  return <Tag>{t("screen.accounts.ownerBadge")}</Tag>;
}

function AccountState({ a }: { a: AccountRow }) {
  const { t } = useTranslation();
  const active = a.status === "active";
  return <StateBadge state={active ? "active" : "disabled"} label={active ? t("common.active") : t("common.disabled")} />;
}

/** A value of a summary part that the reader typed: cut, so a long filter cannot stretch the line. */
function Clip({ children }: { children: ReactNode }) {
  return (
    <span
      style={{
        display: "inline-block",
        maxWidth: "24ch",
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
        verticalAlign: "bottom",
      }}
    >
      {children}
    </span>
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
  const titleId = useId();

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
    <Drawer onClose={onClose} labelledBy={titleId}>
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: 12,
          padding: 16,
          borderBottom: "1px solid var(--rule)",
        }}
      >
        <Avatar label={initialsOf(name)} size={24} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
            <h2
              id={titleId}
              style={{
                ...TRUNC,
                margin: 0,
                fontSize: 18,
                fontWeight: 600,
                lineHeight: "24px",
                letterSpacing: "-0.025em",
              }}
            >
              <AccountName a={account} />
            </h2>
            {account.is_owner ? <OwnerChip /> : null}
          </div>
          {account.display_name && account.handle ? (
            <div style={{ ...HANDLE, display: "block", marginTop: 2 }}>{account.handle}</div>
          ) : null}
        </div>
        <IconBtn icon="x" title={t("common.close")} onClick={onClose} />
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: 16, display: "grid", alignContent: "start", gap: 16 }}>
        <DrawerRow label={t("screen.accounts.accountIdLabel")} code="account_id">
          <PubkeyChip value={account.account_id} />
        </DrawerRow>
        <DrawerRow label={t("screen.accounts.memberPubkeyLabel")} code="member_pubkey">
          <PubkeyChip value={account.member_pubkey} />
        </DrawerRow>
        <DrawerRow label={t("screen.accounts.x25519Label")} code="x25519_pub">
          {account.x25519_pub ? <PubkeyChip value={account.x25519_pub} /> : <Missing />}
        </DrawerRow>
        <DrawerRow label={t("common.status")}>
          <AccountState a={account} />
        </DrawerRow>
        <DrawerRow label={t("screen.accounts.drawerDevices")}>
          <span style={{ fontFamily: MONO, fontSize: 12 }}>{account.device_count}</span>
        </DrawerRow>

        <Well style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
          <Icon name="shield" size={16} color="var(--muted-foreground)" style={{ marginTop: 2 }} />
          <p style={{ margin: 0, fontSize: 14, lineHeight: "20px", color: "var(--foreground)" }}>
            {t("screen.accounts.serverVisibilityNote")}
          </p>
        </Well>
      </div>

      <div style={{ display: "grid", gap: 8, padding: 16, borderTop: "1px solid var(--rule)" }}>
        <Btn full variant={account.is_owner ? "danger" : "outline"} icon="shield" onClick={toggleOwner}>
          {account.is_owner ? t("screen.accounts.ownerRevokeTitle") : t("screen.accounts.ownerGrantTitle")}
        </Btn>
        <Btn full variant="outline" icon="shieldcheck" onClick={() => go("grants")}>
          {t("screen.accounts.issueGrant")}
        </Btn>
        <Btn full variant={disabled ? "outline" : "danger"} icon={disabled ? "unlock" : "lock"} onClick={toggleDisabled}>
          {disabled ? t("screen.accounts.enableTitle") : t("screen.accounts.disableTitle")}
        </Btn>
      </div>
    </Drawer>
  );
}

function DrawerRow({ label, code, children }: { label: string; code?: string; children: ReactNode }) {
  return (
    <div style={{ display: "grid", gap: 8, minWidth: 0 }}>
      <SectionLabel>
        {label}
        {code ? <span style={{ ...HANDLE, display: "inline", marginLeft: 8, textTransform: "none" }}>{code}</span> : null}
      </SectionLabel>
      <div style={{ minWidth: 0 }}>{children}</div>
    </div>
  );
}

const TRUNC: CSSProperties = {
  minWidth: 0,
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};

/** A handle beside or under a name: mono, muted. */
const HANDLE: CSSProperties = {
  ...TRUNC,
  fontFamily: MONO,
  fontSize: 12,
  lineHeight: "16px",
  color: "var(--muted-foreground)",
};

const CARD_GRID: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
  gap: 12,
};
