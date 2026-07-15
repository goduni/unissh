// GroupsModal.tsx — host group management (create / rename / delete / assign).
// Pixel-perfect port of groups-modal.jsx, wired to the real store + core.
// Groups are user-created organizational folders (app-level, on top of core
// host records). Membership is groups[].memberIds; a group carries no icon/count
// fields in the core, so rows use a fixed folder icon and a live member count.

import { useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { UI } from "@/theme/tokens";
import { Btn, Icon, NO_AUTOCORRECT } from "@/components/primitives";
import { useApp } from "@/store/app";
import { useIsMobile, useNarrow } from "@/store/responsive";
import { useDialogFocus, useDialogKeys } from "@/components/a11y";
import { toast } from "@/store/toast";
import { guard } from "@/store/action";
import type { ServerGroup } from "@/bridge/types";
import * as api from "@/bridge/api";
import { useTranslation } from "@/i18n";

// Gate: mount the body (and its dialog hooks) only while open, so Escape/focus
// register per-open per the useDialogKeys contract rather than for App's lifetime.
export function GroupsModal() {
  const groupsModal = useApp((s) => s.groupsModal);
  if (!groupsModal) return null;
  return <GroupsModalBody />;
}

function GroupsModalBody() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const narrow = useNarrow();
  const setGroupsModal = useApp((s) => s.setGroupsModal);
  const groups = useApp((s) => s.groups);
  const hosts = useApp((s) => s.hosts);
  const setConfirm = useApp((s) => s.setConfirm);

  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [selHost, setSelHost] = useState<string | null>(null);

  const close = () => setGroupsModal(false);
  useDialogKeys(close);
  const cardRef = useDialogFocus<HTMLDivElement>();

  const reload = () => useApp.getState().reloadVault();

  // member count = profiles that still exist in this vault
  const memberCount = (g: ServerGroup) =>
    g.memberIds.filter((id) => hosts.some((h) => h.profileId === id)).length;

  // hosts that belong to no group
  const ungrouped = hosts.filter(
    (h) => !groups.some((g) => g.memberIds.includes(h.profileId)),
  );

  const startEdit = (g: ServerGroup) => {
    setEditing(g.groupId);
    setDraft(g.label);
  };

  const commit = async (g: ServerGroup) => {
    const label = draft.trim();
    setEditing(null);
    if (!label || label === g.label) return;
    const vaultId = useApp.getState().vaultId;
    if (!vaultId) return;
    await guard(async () => {
      await api.saveGroup(vaultId, { ...g, label });
      await reload();
      toast(t("groups.renamed"), "ok");
    });
  };

  const addGroup = async () => {
    const vaultId = useApp.getState().vaultId;
    if (!vaultId) return;
    const groupId = `group-${Date.now()}`;
    await guard(async () => {
      await api.saveGroup(vaultId, {
        groupId,
        label: t("groups.newGroupName"),
        memberIds: [],
        parentId: null,
      });
      await reload();
      setEditing(groupId);
      setDraft(t("groups.newGroupName"));
    });
  };

  const del = (g: ServerGroup) =>
    setConfirm({
      title: t("groups.deleteTitle"),
      body: t("groups.deleteBody", {
        label: g.label,
        hosts: t("count.hostsRemain", { count: memberCount(g) }),
      }),
      danger: true,
      confirmLabel: t("groups.deleteConfirm"),
      icon: "trash",
      onConfirm: async () => {
        const vaultId = useApp.getState().vaultId;
        if (!vaultId) return;
        await guard(async () => {
          await api.deleteGroup(vaultId, g.groupId);
          await reload();
          toast(t("groups.deleted"), "ok");
        });
      },
    });

  // assign the currently selected ungrouped host to a group
  const assignTo = async (g: ServerGroup) => {
    if (!selHost) return;
    const vaultId = useApp.getState().vaultId;
    if (!vaultId) {
      setSelHost(null);
      return;
    }
    if (g.memberIds.includes(selHost)) {
      setSelHost(null);
      return;
    }
    try {
      await guard(async () => {
        await api.saveGroup(vaultId, { ...g, memberIds: [...g.memberIds, selHost] });
        await reload();
        toast(t("groups.hostMoved"), "ok");
      });
    } finally {
      setSelHost(null);
    }
  };

  return (
    <div
      onClick={close}
      style={{
        position: "absolute",
        inset: 0,
        zIndex: 130,
        display: "flex",
        alignItems: isMobile ? "flex-start" : "center",
        justifyContent: "center",
        background: p.name === "dark" ? "rgba(6,7,11,0.6)" : "rgba(40,44,60,0.35)",
        backdropFilter: "blur(3px)",
        ...(isMobile ? { padding: 12, paddingTop: "calc(env(safe-area-inset-top) + 16px)" } : null),
      }}
    >
      <div
        ref={cardRef}
        role="dialog"
        aria-modal="true"
        aria-label={t("groups.title")}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 560,
          maxWidth: "92%",
          maxHeight: "88%",
          display: "flex",
          flexDirection: "column",
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 18,
          boxShadow: p.shadow,
          overflow: "hidden",
          animation: "uhPop .2s ease-out",
          color: p.txt,
          outline: "none",
          ...(isMobile ? { width: "100%", maxWidth: "100%", maxHeight: "100%" } : null),
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 11,
            padding: "18px 22px",
            borderBottom: `1px solid ${p.line}`,
          }}
        >
          <span
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: p.bg3,
              border: `1px solid ${p.line}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon name="folders" size={18} color={p.txt2} />
          </span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 17, fontWeight: 800, letterSpacing: -0.3, color: p.txt }}>
              {t("groups.title")}
            </div>
            <div style={{ fontSize: 12, color: p.txt3 }}>
              {t("groups.subtitle", {
                groups: t("count.groups", { count: groups.length }),
              })}
            </div>
          </div>
          <button
            onClick={close}
            title={t("common.close")}
            aria-label={t("common.close")}
            style={{
              width: isMobile ? 44 : 30,
              height: isMobile ? 44 : 30,
              borderRadius: 8,
              border: `1px solid ${p.line}`,
              background: p.bg2,
              color: p.txt3,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              ...(isMobile ? { flexShrink: 0 } : null),
            }}
          >
            <Icon name="x" size={15} />
          </button>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "10px 22px 16px" }} className="uh-stagger">
          {groups.map((g, i) => (
            <div
              key={g.groupId}
              onClick={() => selHost && assignTo(g)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "12px 0",
                borderTop: i === 0 ? undefined : `1px solid ${p.line}`,
                background: selHost ? p.bg2 : "transparent",
                animationDelay: i * 40 + "ms",
                cursor: selHost ? "copy" : "default",
              }}
            >
              <span
                style={{
                  width: 36,
                  height: 36,
                  borderRadius: 10,
                  background: p.bg3,
                  border: `1px solid ${p.line}`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexShrink: 0,
                }}
              >
                <Icon name="folder" size={17} color={p.txt2} />
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                {editing === g.groupId ? (
                  <input
                    autoFocus
                    {...NO_AUTOCORRECT}
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    onBlur={() => commit(g)}
                    onKeyDown={(e) => e.key === "Enter" && commit(g)}
                    style={{
                      width: "100%",
                      background: p.bg0,
                      border: `1px solid ${p.accentLine}`,
                      borderRadius: 7,
                      padding: isMobile ? "9px 11px" : "5px 9px",
                      color: p.txt,
                      fontSize: 14,
                      fontWeight: 700,
                      fontFamily: UI,
                      outline: "none",
                    }}
                  />
                ) : (
                  <div style={{ fontSize: 14.5, fontWeight: 700, color: p.txt }}>{g.label}</div>
                )}
                <div style={{ fontSize: 12, color: p.txt3, marginTop: 2 }}>
                  {t("count.hosts", { count: memberCount(g) })}
                </div>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  startEdit(g);
                }}
                title={t("groups.rename")}
                aria-label={t("groups.rename")}
                style={{
                  width: isMobile ? 44 : 30,
                  height: isMobile ? 44 : 30,
                  borderRadius: 8,
                  border: `1px solid ${p.line}`,
                  background: p.bg1,
                  color: p.txt3,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  ...(isMobile ? { flexShrink: 0 } : null),
                }}
              >
                <Icon name="pencil" size={14} />
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  del(g);
                }}
                title={t("common.delete")}
                aria-label={t("common.delete")}
                style={{
                  width: isMobile ? 44 : 30,
                  height: isMobile ? 44 : 30,
                  borderRadius: 8,
                  border: `1px solid ${p.line}`,
                  background: p.bg1,
                  color: p.txt3,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  ...(isMobile ? { flexShrink: 0 } : null),
                }}
              >
                <Icon name="trash" size={14} />
              </button>
            </div>
          ))}
          <button
            onClick={addGroup}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 9,
              width: "100%",
              marginTop: 12,
              padding: 13,
              borderRadius: 12,
              border: `1px dashed ${p.line2}`,
              background: "transparent",
              color: p.txt2,
              cursor: "pointer",
              fontSize: 13.5,
              fontWeight: 600,
              ...(isMobile ? { minHeight: 44 } : null),
            }}
          >
            <Icon name="plus" size={16} />
            {t("groups.newGroup")}
          </button>

          {ungrouped.length > 0 && (
            <>
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: 0.6,
                  color: p.txt3,
                  textTransform: "uppercase",
                  margin: "16px 0 8px",
                }}
              >
                {t("groups.ungroupedHeading")}
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
                {ungrouped.map((h) => {
                  const on = selHost === h.profileId;
                  return (
                    <span
                      key={h.profileId}
                      onClick={() => setSelHost(on ? null : h.profileId)}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        padding: isMobile ? "10px 14px" : "6px 11px",
                        borderRadius: 20,
                        background: on ? p.bg3 : p.bg2,
                        border: `1px solid ${on ? p.line2 : p.line}`,
                        fontSize: 12.5,
                        fontWeight: on ? 600 : 400,
                        color: p.txt,
                        cursor: "grab",
                      }}
                    >
                      <Icon name="server" size={13} color={on ? p.txt2 : p.txt3} />
                      {h.label}
                      <Icon name="cd" size={12} color={on ? p.txt2 : p.txt3} />
                    </span>
                  );
                })}
              </div>
              <div
                style={{
                  fontSize: 11.5,
                  color: p.txt3,
                  marginTop: 8,
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <Icon name="alert" size={13} color={p.txt3} />
                {selHost
                  ? t("groups.hintSelectGroup")
                  : t("groups.hintSelectHost")}
              </div>
            </>
          )}
        </div>

        <div
          style={{
            display: "flex",
            alignItems: narrow ? "stretch" : "center",
            flexDirection: narrow ? "column" : undefined,
            // wrap so the long footer note reflows above "Готово" instead of crowding it
            flexWrap: "wrap",
            gap: 10,
            padding: "14px 22px",
            borderTop: `1px solid ${p.line}`,
            background: p.bg0,
          }}
        >
          <span style={{ fontSize: 12, color: p.txt3, minWidth: 0 }}>
            {t("groups.footerNote")}
          </span>
          {!narrow && <div style={{ flex: 1 }} />}
          <Btn icon="check" full={narrow} style={isMobile ? { minHeight: 44 } : undefined} onClick={close}>
            {t("common.done")}
          </Btn>
        </div>
      </div>
    </div>
  );
}
