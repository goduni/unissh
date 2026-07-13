import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { SpaceInfo } from "../api/types";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { DataTable, type Column } from "../ui/DataTable";
import { Btn, Field, Tag, TextInput, gradientFor } from "../ui/primitives";
import { KeysetGate, Modal } from "../ui/overlays";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Spaces() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.spaces.title")} sub={t("screen.spaces.sub")}>
      <KeysetGate>
        <SpacesBody />
      </KeysetGate>
    </Screen>
  );
}

function SpacesBody() {
  const { t } = useTranslation();
  const toast = useUi((s) => s.toast);
  const reloadTick = useUi((s) => s.reloadTick);

  const list = useAsync(() => api.spaces.list(), [reloadTick]);
  const [creating, setCreating] = useState(false);
  const [addMemberTo, setAddMemberTo] = useState<SpaceInfo | null>(null);

  const roleTone = (role: string): "amber" | "neutral" => (role === "admin" ? "amber" : "neutral");

  const columns: Column<SpaceInfo>[] = [
    {
      key: "name",
      label: t("screen.spaces.colName"),
      width: "2fr",
      render: (s) => (
        <span style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
          <span style={tile(s.space_id)}>{(s.name[0] || "·").toUpperCase()}</span>
          <span style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
            <span
              style={{
                fontSize: 13,
                fontWeight: 600,
                color: "var(--txt)",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {s.name}
            </span>
            <span style={{ fontFamily: MONO, fontSize: 11, color: "var(--txt3)" }}>
              {truncId(s.space_id, 10, 6)}
            </span>
          </span>
        </span>
      ),
    },
    {
      key: "role",
      label: t("screen.spaces.colRole"),
      width: "120px",
      render: (s) => <Tag tone={roleTone(s.role)}>{s.role}</Tag>,
    },
    {
      key: "actions",
      label: "",
      width: "160px",
      align: "right",
      render: (s) =>
        s.role === "admin" ? (
          <Btn size="sm" icon="plus" onClick={() => setAddMemberTo(s)}>
            {t("screen.spaces.addMember")}
          </Btn>
        ) : null,
    },
  ];

  return (
    <>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 14 }}>
        <Btn variant="primary" icon="plus" onClick={() => setCreating(true)}>
          {t("screen.spaces.create")}
        </Btn>
      </div>
      <DataTable
        columns={columns}
        rows={list.data?.spaces ?? []}
        rowKey={(s) => s.space_id}
        loading={list.loading}
        error={list.error}
        onRetry={list.reload}
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
    </>
  );
}

function CreateSpaceModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
    <Modal onClose={onClose} width={420}>
      <div style={{ padding: 22 }}>
        <div style={{ fontSize: 16, fontWeight: 800, marginBottom: 4 }}>
          {t("screen.spaces.createTitle")}
        </div>
        <div style={{ fontSize: 12.5, color: "var(--txt3)", marginBottom: 16 }}>
          {t("screen.spaces.createSub")}
        </div>
        <Field label={t("screen.spaces.nameLabel")}>
          <TextInput value={name} onChange={setName} placeholder={t("screen.spaces.namePlaceholder")} />
        </Field>
        {error ? (
          <div style={{ fontSize: 12.5, color: "var(--red)", marginBottom: 12 }}>{error}</div>
        ) : null}
        <div style={{ display: "flex", gap: 9 }}>
          <Btn full onClick={onClose}>
            {t("common.cancel")}
          </Btn>
          <Btn full variant="primary" loading={busy} onClick={create}>
            {t("screen.spaces.create")}
          </Btn>
        </div>
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
    <Modal onClose={onClose} width={440}>
      <div style={{ padding: 22 }}>
        <div style={{ fontSize: 16, fontWeight: 800, marginBottom: 4 }}>
          {t("screen.spaces.addMemberTitle")}
        </div>
        <div style={{ fontSize: 12.5, color: "var(--txt3)", marginBottom: 16 }}>{space.name}</div>
        <Field label={t("screen.spaces.accountLabel")}>
          <TextInput
            mono
            value={accountId}
            onChange={setAccountId}
            placeholder={t("screen.spaces.accountPlaceholder")}
          />
        </Field>
        <Field label={t("screen.spaces.roleLabel")}>
          <div style={{ display: "flex", gap: 8 }}>
            {MEMBER_ROLES.map((r) => {
              const on = role === r;
              return (
                <button
                  key={r}
                  onClick={() => setRole(r)}
                  style={{
                    flex: 1,
                    padding: "8px 0",
                    borderRadius: 8,
                    border: on ? "1px solid var(--accentLine)" : "1px solid var(--line)",
                    background: on ? "var(--accentSoft)" : "var(--bg2)",
                    color: on ? "var(--accent)" : "var(--txt2)",
                    fontFamily: "inherit",
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
                  {r}
                </button>
              );
            })}
          </div>
        </Field>
        {error ? (
          <div style={{ fontSize: 12.5, color: "var(--red)", marginBottom: 12 }}>{error}</div>
        ) : null}
        <div style={{ display: "flex", gap: 9 }}>
          <Btn full onClick={onClose}>
            {t("common.cancel")}
          </Btn>
          <Btn full variant="primary" loading={busy} onClick={add}>
            {t("screen.spaces.addMember")}
          </Btn>
        </div>
      </div>
    </Modal>
  );
}

function tile(seed: string): React.CSSProperties {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) | 0;
  return {
    width: 26,
    height: 26,
    borderRadius: 7,
    background: gradientFor(Math.abs(h)),
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "#fff",
    fontWeight: 700,
    fontSize: 12,
    flexShrink: 0,
  };
}
