import { useId, useState, type CSSProperties } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { SpaceInfo } from "../api/types";
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
import { Modal } from "../ui/overlays";
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
      label: "space_id",
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
  const [accountId, setAccountId] = useState("");
  const [role, setRole] = useState<(typeof MEMBER_ROLES)[number]>("member");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();
  const subId = useId();
  const accountFieldId = useId();

  const add = async () => {
    if (!accountId.trim()) {
      setError(t("screen.spaces.errAccount"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.spaces.addMember(space.space_id, accountId.trim(), role);
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
          <Field label={t("screen.spaces.accountLabel")} htmlFor={accountFieldId}>
            <TextInput
              id={accountFieldId}
              mono
              value={accountId}
              onChange={setAccountId}
              placeholder={t("screen.spaces.accountPlaceholder")}
            />
          </Field>
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
