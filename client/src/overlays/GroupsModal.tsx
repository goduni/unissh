// GroupsModal.tsx — host group management (create / rename / delete / assign).
// Pixel-perfect port of groups-modal.jsx, wired to the real store + core.
// Groups are user-created organizational folders (app-level, on top of core
// host records). Membership is groups[].memberIds; the count is live. A group
// may carry a colour tag and an icon (#134), edited here under "Appearance".

import React, { useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { rem, TEXT, UI } from "@/theme/tokens";
import { Btn, Icon, NO_AUTOCORRECT } from "@/components/primitives";
import { useApp } from "@/store/app";
import { useIsMobile, useNarrow } from "@/store/responsive";
import { useDialogFocus, useDialogKeys } from "@/components/a11y";
import { toast } from "@/store/toast";
import { guard } from "@/store/action";
import type { ServerGroup } from "@/bridge/types";
import * as api from "@/bridge/api";
import { useTranslation } from "@/i18n";
import { isUngrouped } from "@/support/hostGroups";
import { groupColor } from "@/support/hostAppearance";
import { AppearancePicker } from "@/components/AppearancePicker";
import { ColorTickSlot, useAppearanceIndex } from "@/components/ColorTick";
import { appearanceIcon, isKnownColor, swatchColor } from "@/components/appearance";

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
  // The group whose Appearance panel is open, with the unsaved choice. A draft,
  // not a write per pick: the pickers select on every arrow key, and each save
  // is a new vault item version that syncs to every device. On touch the panel
  // is the group's one edit control, so it carries the name as well.
  const [styling, setStyling] = useState<{
    groupId: string;
    label: string;
    color: string | null;
    icon: string | null;
  } | null>(null);
  const appearance = useAppearanceIndex();

  // The open draft's group, and whether the draft differs from it — what
  // saving would write. A dirty draft is not thrown away by opening another
  // group's panel or closing the dialog without asking first.
  const draftGroup = styling ? groups.find((g) => g.groupId === styling.groupId) : undefined;
  const draftDirty =
    !!styling &&
    !!draftGroup &&
    ((styling.label.trim() || draftGroup.label) !== draftGroup.label ||
      (draftGroup.color ?? null) !== styling.color ||
      (draftGroup.icon ?? null) !== styling.icon);
  const leaveDraft = (then: () => void) => {
    if (!draftDirty || !draftGroup) return then();
    setConfirm({
      title: t("groups.discardTitle"),
      body: t("groups.discardBody", { label: draftGroup.label }),
      danger: true,
      confirmLabel: t("groups.discard"),
      onConfirm: () => {
        setStyling(null);
        then();
      },
    });
  };

  const close = () => leaveDraft(() => setGroupsModal(false));
  useDialogKeys(close);
  const cardRef = useDialogFocus<HTMLDivElement>();

  const reload = () => useApp.getState().reloadVault();

  // member count = profiles that still exist in this vault
  const memberCount = (g: ServerGroup) =>
    g.memberIds.filter((id) => hosts.some((h) => h.profileId === id)).length;

  // hosts that belong to no group
  const ungrouped = hosts.filter((h) => isUngrouped(appearance.byHost, h.profileId));

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

  const saveAppearance = async (g: ServerGroup) => {
    const vaultId = useApp.getState().vaultId;
    if (!styling || !vaultId) return;
    const { color, icon } = styling;
    const label = styling.label.trim() || g.label;
    const restyled = (g.color ?? null) !== color || (g.icon ?? null) !== icon;
    if (!restyled && label === g.label) {
      setStyling(null);
      return;
    }
    // The draft stays open until the write lands: a failed save must not throw
    // the user's choice away along with the panel.
    const ok = await guard(async () => {
      await api.saveGroup(vaultId, { ...g, label, color, icon });
      await reload();
      toast(t(!restyled ? "groups.renamed" : label !== g.label ? "groups.saved" : "appearance.saved"), "ok");
    });
    if (ok) setStyling(null);
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
        ...(isMobile ? { padding: rem(12), paddingTop: "calc(env(safe-area-inset-top) + 16px)" } : null),
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
          width: rem(560),
          maxWidth: "92%",
          maxHeight: "88%",
          display: "flex",
          flexDirection: "column",
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 16,
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
            gap: rem(11),
            padding: `${rem(18)} ${rem(22)}`,
            borderBottom: `1px solid ${p.line}`,
          }}
        >
          <span
            style={{
              width: rem(36),
              height: rem(36),
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
            <div style={{ fontSize: TEXT.lead, fontWeight: 800, letterSpacing: rem(-0.3), color: p.txt }}>
              {t("groups.title")}
            </div>
            <div style={{ fontSize: TEXT.small, color: p.txt3 }}>
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
              width: isMobile ? rem(44) : rem(30),
              height: isMobile ? rem(44) : rem(30),
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

        <div style={{ flex: 1, overflowY: "auto", padding: `${rem(10)} ${rem(22)} ${rem(16)}` }} className="uh-stagger">
          {groups.map((g, i) => {
            const tag = groupColor(g.groupId, appearance);
            const parentTag = g.parentId ? groupColor(g.parentId, appearance) : null;
            return (
              <React.Fragment key={g.groupId}>
                <div
                  onClick={() => selHost && assignTo(g)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: rem(12),
                    padding: `${rem(12)} 0`,
                    borderTop: i === 0 ? undefined : `1px solid ${p.line}`,
                    background: selHost ? p.bg2 : "transparent",
                    animationDelay: i * 40 + "ms",
                    cursor: selHost ? "copy" : "default",
                  }}
                >
                  <span
                    style={{
                      width: rem(36),
                      height: rem(36),
                      borderRadius: 10,
                      background: p.bg3,
                      border: `1px solid ${p.line}`,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      flexShrink: 0,
                    }}
                  >
                    <Icon
                      name={appearanceIcon(g.icon, "folder")}
                      size={17}
                      color={swatchColor(tag, p) ?? p.txt2}
                    />
                  </span>
                  <ColorTickSlot color={tag} height={18} />
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
                          borderRadius: 8,
                          padding: isMobile ? `${rem(9)} ${rem(11)}` : `${rem(5)} ${rem(9)}`,
                          color: p.txt,
                          fontSize: TEXT.body,
                          fontWeight: 700,
                          fontFamily: UI,
                          outline: "none",
                        }}
                      />
                    ) : (
                      // Ellipsized: on a phone the row's buttons leave the name
                      // little room, and a wrapped label pushes them off-row.
                      <div
                        style={{
                          fontSize: TEXT.body,
                          fontWeight: 700,
                          color: p.txt,
                          minWidth: 0,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {g.label}
                      </div>
                    )}
                    <div style={{ fontSize: TEXT.small, color: p.txt3, marginTop: rem(2) }}>
                      {t("count.hosts", { count: memberCount(g) })}
                    </div>
                  </div>
                  {/* On touch, Rename lives in the edit panel: three 44px buttons
                      beside the name would leave a phone row almost no label. */}
                  {!isMobile && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        startEdit(g);
                      }}
                      title={t("groups.rename")}
                      aria-label={t("groups.rename")}
                      style={{
                        width: rem(30),
                        height: rem(30),
                        borderRadius: 8,
                        border: `1px solid ${p.line}`,
                        background: p.bg1,
                        color: p.txt3,
                        cursor: "pointer",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <Icon name="pencil" size={14} />
                    </button>
                  )}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      // Toggling the open panel shut is the explicit "put it
                      // away"; opening another group's panel would drop the
                      // draft silently, so that one asks.
                      if (styling?.groupId === g.groupId) setStyling(null);
                      else
                        leaveDraft(() =>
                          setStyling({ groupId: g.groupId, label: g.label, color: g.color ?? null, icon: g.icon ?? null }),
                        );
                    }}
                    title={isMobile ? t("groups.edit") : t("appearance.edit")}
                    aria-label={isMobile ? t("groups.edit") : t("appearance.edit")}
                    aria-expanded={styling?.groupId === g.groupId}
                    style={{
                      width: isMobile ? rem(44) : rem(30),
                      height: isMobile ? rem(44) : rem(30),
                      borderRadius: 8,
                      border: `1px solid ${p.line}`,
                      background: styling?.groupId === g.groupId ? p.bg3 : p.bg1,
                      color: p.txt3,
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      ...(isMobile ? { flexShrink: 0 } : null),
                    }}
                  >
                    <Icon name={isMobile ? "pencil" : "sliders"} size={14} />
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      del(g);
                    }}
                    title={t("common.delete")}
                    aria-label={t("common.delete")}
                    style={{
                      width: isMobile ? rem(44) : rem(30),
                      height: isMobile ? rem(44) : rem(30),
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
                {styling?.groupId === g.groupId && (
                  <div
                    role="group"
                    aria-label={`${t("appearance.title")} — ${g.label}`}
                    style={{ padding: `${rem(4)} 0 ${rem(14)} ${isMobile ? 0 : rem(48)}` }}
                  >
                    {isMobile && (
                      <label style={{ display: "block", marginBottom: rem(14) }}>
                        <div style={{ fontSize: TEXT.small, fontWeight: 600, color: p.txt2, marginBottom: rem(6) }}>
                          {t("groups.name")}
                        </div>
                        <input
                          {...NO_AUTOCORRECT}
                          value={styling.label}
                          onChange={(e) => setStyling({ ...styling, label: e.target.value })}
                          style={{
                            width: "100%",
                            boxSizing: "border-box",
                            background: p.bg0,
                            border: `1px solid ${p.line2}`,
                            borderRadius: 8,
                            padding: `${rem(9)} ${rem(11)}`,
                            color: p.txt,
                            fontSize: TEXT.body,
                            fontFamily: UI,
                          }}
                        />
                      </label>
                    )}
                    <AppearancePicker
                      color={styling.color}
                      icon={styling.icon}
                      onColor={(color) => setStyling({ ...styling, color })}
                      onIcon={(icon) => setStyling({ ...styling, icon })}
                      inheritedColor={isKnownColor(parentTag) ? parentTag : null}
                    />
                    <div style={{ display: "flex", gap: rem(8), marginTop: rem(12) }}>
                      <Btn size="sm" icon="check" onClick={() => void saveAppearance(g)}>
                        {t("common.save")}
                      </Btn>
                      <Btn size="sm" variant="ghost" onClick={() => setStyling(null)}>
                        {t("common.cancel")}
                      </Btn>
                    </div>
                  </div>
                )}
              </React.Fragment>
            );
          })}
          <button
            onClick={addGroup}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: rem(9),
              width: "100%",
              marginTop: rem(12),
              padding: rem(13),
              borderRadius: 12,
              border: `1px dashed ${p.line2}`,
              background: "transparent",
              color: p.txt2,
              cursor: "pointer",
              fontSize: TEXT.base,
              fontWeight: 600,
              ...(isMobile ? { minHeight: rem(44) } : null),
            }}
          >
            <Icon name="plus" size={16} />
            {t("groups.newGroup")}
          </button>

          {ungrouped.length > 0 && (
            <>
              <div
                style={{
                  fontSize: TEXT.micro,
                  fontWeight: 700,
                  letterSpacing: rem(0.6),
                  color: p.txt3,
                  textTransform: "uppercase",
                  margin: `${rem(16)} 0 ${rem(8)}`,
                }}
              >
                {t("groups.ungroupedHeading")}
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: rem(7) }}>
                {ungrouped.map((h) => {
                  const on = selHost === h.profileId;
                  return (
                    <span
                      key={h.profileId}
                      onClick={() => setSelHost(on ? null : h.profileId)}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: rem(6),
                        padding: isMobile ? `${rem(10)} ${rem(14)}` : `${rem(6)} ${rem(11)}`,
                        borderRadius: 20,
                        background: on ? p.bg3 : p.bg2,
                        border: `1px solid ${on ? p.line2 : p.line}`,
                        fontSize: TEXT.base,
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
                  fontSize: TEXT.small,
                  color: p.txt3,
                  marginTop: rem(8),
                  display: "flex",
                  alignItems: "center",
                  gap: rem(6),
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
            gap: rem(10),
            padding: `${rem(14)} ${rem(22)}`,
            borderTop: `1px solid ${p.line}`,
            background: p.bg0,
          }}
        >
          <span style={{ fontSize: TEXT.small, color: p.txt3, minWidth: 0 }}>
            {t("groups.footerNote")}
          </span>
          {!narrow && <div style={{ flex: 1 }} />}
          <Btn icon="check" full={narrow} style={isMobile ? { minHeight: rem(44) } : undefined} onClick={close}>
            {t("common.done")}
          </Btn>
        </div>
      </div>
    </div>
  );
}
