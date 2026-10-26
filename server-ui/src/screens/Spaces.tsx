import { useId, useMemo, useState, type CSSProperties } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { AccountRow, SpaceInfo } from "../api/types";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { DataTable, type Column } from "../ui/DataTable";
import {
  Avatar,
  Btn,
  Field,
  IconBtn,
  InlineError,
  PubkeyChip,
  RoleBadge,
  Segmented,
  TextInput,
  initialsOf,
} from "../ui/primitives";
import { Icon } from "../ui/icons";
import { Modal } from "../ui/overlays";
import { MONO } from "../theme/tokens";
import { Screen } from "./Screen";

export function Spaces() {
  const { t } = useTranslation();
  const toast = useUi((s) => s.toast);
  const reloadTick = useUi((s) => s.reloadTick);

  const list = useAsync(() => api.spaces.list(), [reloadTick]);
  const [creating, setCreating] = useState(false);
  const [addMemberTo, setAddMemberTo] = useState<SpaceInfo | null>(null);

  const columns: Column<SpaceInfo>[] = [
    {
      key: "name",
      label: t("screen.spaces.colName"),
      width: "2fr",
      render: (s) => (
        <span style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <Avatar label={initialsOf(s.name) || "·"} size={18} />
          <span style={NAME}>{s.name}</span>
        </span>
      ),
    },
    {
      key: "id",
      label: t("screen.spaces.colId"),
      width: "1.6fr",
      render: (s) => <PubkeyChip value={s.space_id} head={10} tail={6} />,
    },
    {
      key: "role",
      label: t("screen.spaces.colRole"),
      width: "110px",
      render: (s) => <RoleBadge role={s.role} />,
    },
    {
      key: "actions",
      label: "",
      width: "28px",
      align: "right",
      // Only an admin of the space adds members; an empty cell, not a missing value, for the others.
      render: (s) =>
        s.role === "admin" ? (
          <IconBtn icon="plus" title={t("screen.spaces.addMember")} onClick={() => setAddMemberTo(s)} />
        ) : (
          <span aria-hidden="true" />
        ),
    },
  ];

  return (
    <Screen
      title={t("screen.spaces.title")}
      sub={t("screen.spaces.sub")}
      actions={
        <Btn variant="primary" icon="plus" onClick={() => setCreating(true)}>
          {t("screen.spaces.create")}
        </Btn>
      }
    >
      <DataTable
        columns={columns}
        rows={list.data?.spaces ?? []}
        rowKey={(s) => s.space_id}
        loading={list.loading}
        error={list.error}
        onRetry={list.reload}
        summary
        minWidth={560}
        ariaLabel={t("screen.spaces.title")}
        empty={{
          title: t("screen.spaces.emptyTitle"),
          hint: t("screen.spaces.emptyHint"),
          icon: "box",
          actionLabel: t("screen.spaces.create"),
          onAction: () => setCreating(true),
        }}
      />

      {creating ? (
        <CreateSpaceModal
          onClose={() => setCreating(false)}
          onDone={() => {
            setCreating(false);
            toast("success", t("screen.spaces.created"));
            list.reload();
          }}
        />
      ) : null}

      {addMemberTo ? (
        <AddMemberModal
          space={addMemberTo}
          onClose={() => setAddMemberTo(null)}
          onDone={() => {
            setAddMemberTo(null);
            toast("success", t("screen.spaces.memberAdded"));
          }}
        />
      ) : null}
    </Screen>
  );
}

function CreateSpaceModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();
  const subId = useId();
  const nameId = useId();

  const create = async () => {
    if (!name.trim()) {
      setError(t("screen.spaces.errName"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.spaces.create(name.trim());
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("common.error"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal onClose={onClose} width={420} labelledBy={titleId} describedBy={subId}>
      <div style={{ padding: 24 }}>
        <h2 id={titleId} style={DIALOG_TITLE}>
          {t("screen.spaces.createTitle")}
        </h2>
        <p id={subId} style={DIALOG_SUB}>
          {t("screen.spaces.createSub")}
        </p>
        <div style={{ marginTop: 16 }}>
          {error ? <InlineError>{error}</InlineError> : null}
          <Field label={t("screen.spaces.nameLabel")} htmlFor={nameId} style={{ marginBottom: 0 }}>
            <TextInput
              id={nameId}
              value={name}
              onChange={setName}
              placeholder={t("screen.spaces.namePlaceholder")}
            />
          </Field>
        </div>
      </div>
      <div style={DIALOG_FOOT}>
        <Btn variant="outline" onClick={onClose}>
          {t("common.cancel")}
        </Btn>
        <Btn variant="primary" loading={busy} onClick={create}>
          {t("screen.spaces.create")}
        </Btn>
      </div>
    </Modal>
  );
}

const MEMBER_ROLES = ["member", "admin"] as const;

function AddMemberModal({
  space,
  onClose,
  onDone,
}: {
  space: SpaceInfo;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  // Pick the person by name; the bare account ID is the way in only when the list can't be read.
  const accounts = useAsync(() => api.identity.accounts(), []);
  const [query, setQuery] = useState("");
  const [picked, setPicked] = useState<string | null>(null);
  const [accountId, setAccountId] = useState("");
  const pickable = !accounts.error;
  const matches = useMemo(() => {
    const s = query.trim().toLowerCase();
    return (accounts.data?.accounts ?? [])
      .filter((a) => a.status === "active")
      .filter(
        (a) =>
          !s ||
          (a.display_name ?? "").toLowerCase().includes(s) ||
          (a.handle ?? "").toLowerCase().includes(s) ||
          a.account_id.toLowerCase() === s,
      );
  }, [accounts.data, query]);
  // The choice never outlives the search: a person filtered out of sight is no longer the one being added.
  const shownPick = picked && matches.some((a) => a.account_id === picked) ? picked : null;
  const [role, setRole] = useState<(typeof MEMBER_ROLES)[number]>("member");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();
  const subId = useId();
  const accountFieldId = useId();

  const add = async () => {
    const target = pickable ? shownPick : accountId.trim();
    if (!target) {
      setError(pickable ? t("screen.spaces.errPerson") : t("screen.spaces.errAccount"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.spaces.addMember(space.space_id, target, role);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("common.error"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal onClose={onClose} width={440} labelledBy={titleId} describedBy={subId}>
      <div style={{ padding: 24 }}>
        <h2 id={titleId} style={DIALOG_TITLE}>
          {t("screen.spaces.addMemberTitle")}
        </h2>
        <p id={subId} style={{ ...DIALOG_SUB, overflowWrap: "anywhere" }}>
          {space.name}
        </p>
        <div style={{ marginTop: 16 }}>
          {error ? <InlineError>{error}</InlineError> : null}
          {pickable ? (
            <Field label={t("screen.spaces.personLabel")} hint={t("screen.spaces.personHint")} htmlFor={accountFieldId}>
              <TextInput
                id={accountFieldId}
                value={query}
                onChange={setQuery}
                autoFocus
                placeholder={t("screen.spaces.personPlaceholder")}
              />
              <PersonList
                loading={accounts.loading && !accounts.data}
                people={matches}
                picked={shownPick}
                onPick={setPicked}
                label={t("screen.spaces.personLabel")}
              />
            </Field>
          ) : (
            <Field label={t("screen.spaces.accountLabel")} hint={t("screen.spaces.accountHint")} htmlFor={accountFieldId}>
              <TextInput
                id={accountFieldId}
                mono
                value={accountId}
                onChange={setAccountId}
                placeholder={t("screen.spaces.accountPlaceholder")}
              />
            </Field>
          )}
          <Field label={t("screen.spaces.roleLabel")} style={{ marginBottom: 0 }}>
            <Segmented
              size="md"
              value={role}
              onChange={setRole}
              ariaLabel={t("screen.spaces.roleLabel")}
              options={MEMBER_ROLES.map((r) => ({ value: r, label: t(`role.${r}`) }))}
            />
          </Field>
        </div>
      </div>
      <div style={DIALOG_FOOT}>
        <Btn variant="outline" onClick={onClose}>
          {t("common.cancel")}
        </Btn>
        <Btn variant="primary" loading={busy} onClick={add}>
          {t("screen.spaces.addMember")}
        </Btn>
      </div>
    </Modal>
  );
}

/**
 * The people a search finds, as a short scrolling list of choices: avatar, name, login. The chosen one is
 * --elevated with a check; a click on it again keeps it chosen.
 */
function PersonList({
  loading,
  people,
  picked,
  onPick,
  label,
}: {
  loading: boolean;
  people: AccountRow[];
  picked: string | null;
  onPick: (id: string) => void;
  label: string;
}) {
  const { t } = useTranslation();
  if (loading) return <p style={LIST_NOTE}>{t("common.loading")}</p>;
  if (people.length === 0) return <p style={LIST_NOTE}>{t("screen.spaces.personNone")}</p>;
  return (
    <div role="group" aria-label={label} style={PEOPLE}>
      {people.map((a) => {
        const name = a.display_name || a.handle || a.account_id;
        const on = a.account_id === picked;
        return (
          <button
            key={a.account_id}
            type="button"
            aria-pressed={on}
            onClick={() => onPick(a.account_id)}
            style={{ ...PERSON, background: on ? "var(--elevated)" : "transparent" }}
          >
            <Avatar label={initialsOf(name)} size={18} />
            <span style={{ ...NAME, fontWeight: on ? 600 : 500 }}>{name}</span>
            {a.display_name && a.handle ? <span style={HANDLE}>{a.handle}</span> : null}
            {on ? <Icon name="check" size={14} style={{ marginLeft: "auto", flexShrink: 0 }} /> : null}
          </button>
        );
      })}
    </div>
  );
}

const PEOPLE: CSSProperties = {
  display: "grid",
  marginTop: 8,
  maxHeight: 200,
  overflowY: "auto",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-md)",
};
const PERSON: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 8,
  minWidth: 0,
  minHeight: 36,
  padding: "6px 10px",
  border: 0,
  borderBottom: "1px solid var(--rule)",
  color: "var(--foreground)",
  font: "inherit",
  fontSize: 13,
  textAlign: "left",
  cursor: "pointer",
};
const HANDLE: CSSProperties = {
  minWidth: 0,
  fontFamily: MONO,
  fontSize: 12,
  color: "var(--muted-foreground)",
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};
const LIST_NOTE: CSSProperties = { margin: "8px 0 0", fontSize: 13, color: "var(--muted-foreground)" };

/** A name in a row: 13/500, cut with an ellipsis. */
const NAME: CSSProperties = {
  minWidth: 0,
  fontWeight: 500,
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};

/** A dialog's head and foot, as the confirm dialog draws them. */
const DIALOG_TITLE: CSSProperties = {
  margin: 0,
  fontSize: 18,
  fontWeight: 600,
  lineHeight: "24px",
  letterSpacing: "-0.025em",
};
const DIALOG_SUB: CSSProperties = {
  margin: "8px 0 0",
  fontSize: 14,
  lineHeight: "20px",
  maxWidth: "72ch",
  color: "var(--muted-foreground)",
};
const DIALOG_FOOT: CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  justifyContent: "flex-end",
  gap: 8,
  padding: "16px 24px",
  borderTop: "1px solid var(--rule)",
};
