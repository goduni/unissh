// Modals — the three "create / edit" overlays (host, key, tunnel). Pixel-faithful
// port of view-newhost.jsx (MShell / MSeg / NHField / NHInput helpers + the three
// modal bodies). Mock data is replaced with real store data and api.* calls; the
// component self-gates on store.modal and renders nothing when no modal is open.

import React, { useEffect, useRef, useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { useTranslation, tDyn } from "@/i18n";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import {
  MONO,
  UI,
  rgba,
  selAlpha,
  TERM_EDITOR_FIELDS,
  toHexInput,
  validateTermThemeImport,
} from "@/theme/tokens";
import type { TermEditorField, TermTheme, TermThemePalette } from "@/theme/tokens";
import { BTN_RESET, Btn, Icon, IconName, NO_AUTOCORRECT, Spinner, Tag, Toggle } from "@/components/primitives";
import { useDialogFocus, useDialogKeys } from "@/components/a11y";
import { Modal } from "@/components/Modal";
import { toast } from "@/store/toast";
import { useApp } from "@/store/app";
import { useCtx } from "@/store/ctx";
import { useIsMobile } from "@/store/responsive";
import * as api from "@/bridge/api";
import { apiErrorMessage, ItemType, profileToAuth } from "@/bridge/types";
import { serverShortLabel, vaultLoc } from "@/bridge/vaults";
import type {
  ConnectionProfile,
  Identity,
  IdentityBinding,
  JumpHost,
  ProfileAuth,
  ServerGroup,
  SyncTarget,
  VaultInfo,
} from "@/bridge/types";
import type { ConnectArgs } from "@/bridge/api";
import type { TunnelType } from "@/store/app";

// ── Form atoms (ported 1:1 from the prototype) ─────────────────
function NHField({
  label,
  children,
  hint,
  w,
}: {
  label: string;
  children: React.ReactNode;
  hint?: string;
  w?: string;
}) {
  const p = usePalette();
  return (
    <label style={{ display: "block", width: w || "auto" }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: p.txt2, marginBottom: 6 }}>
        {label}
        {hint && <span style={{ color: p.txt3, fontWeight: 500 }}> · {hint}</span>}
      </div>
      {children}
    </label>
  );
}

function NHInput({
  value,
  placeholder,
  mono,
  accent,
  onChange,
  type,
}: {
  value: string;
  placeholder?: string;
  mono?: boolean;
  accent?: boolean;
  onChange?: (v: string) => void;
  type?: string;
}) {
  const p = usePalette();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        height: 40,
        padding: "0 12px",
        borderRadius: 9,
        background: p.bg2,
        border: `1px solid ${accent ? p.accentLine : p.line2}`,
        boxShadow: accent ? `0 0 0 3px ${p.accentSoft}` : "none",
      }}
    >
      <input
        {...NO_AUTOCORRECT}
        value={value}
        placeholder={placeholder}
        type={type || "text"}
        onChange={(e) => onChange?.(e.target.value)}
        style={{
          flex: 1,
          minWidth: 0,
          background: "none",
          border: "none",
          outline: "none",
          fontFamily: mono ? MONO : UI,
          fontSize: 13.5,
          color: p.txt,
        }}
      />
    </div>
  );
}

interface MSegOption<T extends string> {
  id: T;
  label: string;
  icon: IconName;
  desc?: string;
}
function MSeg<T extends string>({
  value,
  set,
  options,
}: {
  value: T;
  set: (v: T) => void;
  options: MSegOption<T>[];
}) {
  const p = usePalette();
  return (
    <div style={{ display: "flex", gap: 8 }}>
      {options.map((o) => (
        <button
          key={o.id}
          onClick={() => set(o.id)}
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            alignItems: "flex-start",
            gap: 2,
            padding: "9px 12px",
            borderRadius: 9,
            cursor: "pointer",
            textAlign: "left",
            background: value === o.id ? p.accentSoft : p.bg2,
            color: value === o.id ? p.txt : p.txt2,
            border: `1px solid ${value === o.id ? p.accentLine : p.line}`,
          }}
        >
          <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, fontWeight: 700 }}>
            <Icon name={o.icon} size={14} color={value === o.id ? p.accent : p.txt3} />
            {o.label}
          </span>
          {o.desc && <span style={{ fontSize: 10.5, color: p.txt3, fontWeight: 500 }}>{o.desc}</span>}
        </button>
      ))}
    </div>
  );
}

// Inline picker — re-uses NHInput's chrome to render a clickable <select> for
// choosing a stored key / password item.
function NHSelect({
  value,
  onChange,
  options,
  empty,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  empty: string;
}) {
  const p = usePalette();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        height: 40,
        padding: "0 12px",
        borderRadius: 9,
        background: p.bg2,
        border: `1px solid ${p.line2}`,
      }}
    >
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          flex: 1,
          minWidth: 0,
          background: "none",
          border: "none",
          outline: "none",
          fontFamily: MONO,
          fontSize: 13.5,
          color: options.length ? p.txt : p.txt3,
          appearance: "none",
          cursor: "pointer",
        }}
      >
        {options.length === 0 && <option value="">{empty}</option>}
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <Icon name="cd" size={15} color={p.txt3} />
    </div>
  );
}

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "host";

// ── New / edit host ────────────────────────────────────────────
type AuthSeg = "key" | "password" | "ask" | "personal";

/** Sentinel `groupId` meaning "create a new group (named `newGroupName`) on save".
 *  Group ids are `slug-timestamp`, so this can never collide with a real one. */
const NEW_GROUP = "__new__";

function NewHostModal({ edit, onClose }: { edit?: ConnectionProfile; onClose: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const ctx = useCtx();
  // This modal carries its own shell (not MShell) — give it the same Escape /
  // focus-trap-in / focus-restore contract.
  useDialogKeys(onClose);
  const hostCardRef = useDialogFocus<HTMLDivElement>();
  const vault = useApp((s) => s.vaultId);
  const vaultInfo = useApp((s) => s.vaults.find((v) => v.vaultId === s.vaultId));
  const items = useApp((s) => s.items);
  const groups = useApp((s) => s.groups);
  const hosts = useApp((s) => s.hosts);
  const allVaults = useApp((s) => s.vaults);
  const servers = useApp((s) => s.servers);

  const keyItems = items.filter((i) => i.itemType === ItemType.SshKey);
  const pwItems = items.filter((i) => i.itemType === ItemType.Password);

  // Personal identities must live in a PRIVATE vault: a local one, or a cloud vault
  // in a space you own. These are the vaults a host can bind an identity from.
  const privateVaults = allVaults.filter(
    (v) =>
      v.syncTarget !== "cloud" ||
      servers.some((s) => s.tenantId && s.tenantId === v.syncTenant && s.owned),
  );
  const pvKey = privateVaults.map((v) => v.vaultId).join("|");

  const initialGroup = edit
    ? groups.find((g) => g.memberIds.includes(edit.profileId))?.groupId ?? ""
    : "";

  const [label, setLabel] = useState(edit?.label ?? "");
  const [host, setHost] = useState(edit?.host ?? "");
  const [port, setPort] = useState(edit ? String(edit.port) : "22");
  const [user, setUser] = useState(edit?.user ?? "");
  const [auth, setAuth] = useState<AuthSeg>(
    edit
      ? edit.auth.type === "key"
        ? "key"
        : edit.auth.type === "vaultPassword"
          ? "password"
          : edit.auth.type === "personal"
            ? "personal"
            : "ask"
      : "key",
  );
  const [usernameTemplate, setUsernameTemplate] = useState(edit?.usernameTemplate ?? "");
  // Inline personal-identity binding (auth = "personal"): pick the identity right
  // here instead of the old "no creds" dead-end + a separate bind modal.
  const [bindVault, setBindVault] = useState<string | null>(null);
  const [pIdentities, setPIdentities] = useState<Identity[]>([]);
  const [boundIdentity, setBoundIdentity] = useState<string>("");
  const [pLoaded, setPLoaded] = useState(false);
  const [keyId, setKeyId] = useState(
    edit?.auth.type === "key" ? edit.auth.keyItemId : keyItems[0]?.itemId ?? "",
  );
  const [pwId, setPwId] = useState(
    edit?.auth.type === "vaultPassword" ? edit.auth.passwordItemId : pwItems[0]?.itemId ?? "",
  );
  const [newPw, setNewPw] = useState("");

  // Inline "add a key" inside the host modal (auth = key) — see addKeyInline.
  const [showNewKey, setShowNewKey] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyAlgo, setNewKeyAlgo] = useState<Algo>("ed25519");
  const [newKeyImport, setNewKeyImport] = useState("");
  const [newKeyFileName, setNewKeyFileName] = useState<string | null>(null);
  const [newKeyBusy, setNewKeyBusy] = useState(false);

  const [useJump, setUseJump] = useState(edit ? edit.jumps.length > 0 : false);
  const jump0 = edit?.jumps[0];
  const [jHost, setJHost] = useState(jump0?.host ?? "");
  const [jPort, setJPort] = useState(jump0 ? String(jump0.port) : "22");
  const [jUser, setJUser] = useState(jump0?.user ?? "");
  const [jKeyId, setJKeyId] = useState(
    jump0?.auth.type === "agent" ? jump0.auth.keyItemId : keyItems[0]?.itemId ?? "",
  );
  // B2.2 UI: a jump hop can either be an inline bastion (host/user/key above) or
  // a REFERENCE to another saved profile (by its immutable uid), resolved to that
  // profile's host/auth at connect. Profiles referenceable = saved hosts in this
  // vault, minus the one being edited (no self-reference).
  const refHosts = hosts.filter(
    (h) =>
      h.uid &&
      h.profileId !== edit?.profileId &&
      // A hop must present a usable credential; Personal/Ask profiles can't serve
      // as a jump (the core errors on a non-credentialed referenced profile), so
      // don't offer them — else an unusable bastion saves and fails only at connect.
      (h.auth.type === "key" || h.auth.type === "vaultPassword"),
  );
  const [jMode, setJMode] = useState<"inline" | "ref">(jump0?.hopRef ? "ref" : "inline");
  const [jRef, setJRef] = useState(jump0?.hopRef?.profileUid ?? refHosts[0]?.uid ?? "");
  // The ref picker renders ONLY when there are referenceable hosts; the save path
  // must use the SAME predicate, or a stuck jMode==="ref" (e.g. editing a now-
  // dangling ref with no other hosts) shows inline fields yet silently persists a
  // stale hopRef over the user's typed inline input.
  const jumpIsRef = jMode === "ref" && refHosts.length > 0;

  const [groupId, setGroupId] = useState(initialGroup);
  // Inline "create a new group" inside the host modal. `groupId === NEW_GROUP`
  // means "assign to a group named newGroupName, created on save" — deferring the
  // create until save means a cancelled modal never leaves an orphan empty group.
  const [newGroupName, setNewGroupName] = useState("");
  const [addingGroup, setAddingGroup] = useState(false);
  const [tags, setTags] = useState<string[]>(edit?.tags ?? []);
  const [tagDraft, setTagDraft] = useState("");

  // B5.3(b): in a SHARED (multi-member) cloud vault, default a NEW host to
  // Personal auth so a member doesn't accidentally store personal creds into the
  // shared vault (they'd be VK-shared with everyone). Only nudges the default —
  // the user can still pick Key/Password. Editing an existing host is untouched.
  const [sharedVaultDefault, setSharedVaultDefault] = useState(false);
  // Set once the user picks an auth segment themselves — the async shared-vault
  // default must NOT clobber a deliberate in-flight choice (or void a typed pw).
  const authTouched = useRef(false);
  useEffect(() => {
    if (edit || !vault || vaultInfo?.syncTarget !== "cloud") return;
    let cancelled = false;
    api
      .serverListMembers(vault)
      .then((ms) => {
        if (!cancelled && !authTouched.current && ms.length > 1) {
          setAuth("personal");
          setSharedVaultDefault(true);
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Pick the initial identity vault to bind from: for an edited host, whichever private
  // vault already holds its binding; otherwise the account default, else the first
  // private vault. The identity list itself is loaded by the effect below (keyed on the
  // chosen vault), so switching vaults in the picker re-loads without re-running this.
  useEffect(() => {
    let alive = true;
    (async () => {
      if (!privateVaults.length) {
        if (alive) {
          setBindVault(null);
          setPIdentities([]);
          setPLoaded(true);
        }
        return;
      }
      let target = privateVaults[0].vaultId;
      let preIdentity = "";
      if (edit?.uid && vault) {
        for (const v of privateVaults) {
          const b = await api.getBinding(v.vaultId, vault, edit.uid).catch(() => null);
          if (!alive) return;
          if (b?.identityItemId) {
            target = v.vaultId;
            preIdentity = b.identityItemId;
            break;
          }
        }
      }
      if (!preIdentity) {
        const pv = await api.getPersonalVault().catch(() => null);
        if (!alive) return;
        if (pv && privateVaults.some((v) => v.vaultId === pv)) target = pv;
      }
      if (!alive) return;
      setBindVault(target);
      setBoundIdentity(preIdentity);
      setPLoaded(true);
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pvKey, vault, edit?.uid]);

  // Load the chosen vault's identities and keep a valid selection. A fresh vault pick
  // (identity not present there) falls back to that vault's first identity.
  useEffect(() => {
    let alive = true;
    (async () => {
      if (!bindVault) {
        if (alive) setPIdentities([]);
        return;
      }
      const ids = await api.listIdentities(bindVault).catch(() => [] as Identity[]);
      if (!alive) return;
      setPIdentities(ids);
      setBoundIdentity((cur) =>
        cur && ids.some((i) => i.identityId === cur) ? cur : ids[0]?.identityId ?? "",
      );
    })();
    return () => {
      alive = false;
    };
  }, [bindVault]);

  const pickGroup = (id: string) => {
    setGroupId(id);
    setNewGroupName("");
    setAddingGroup(false);
  };
  const confirmNewGroup = () => {
    if (newGroupName.trim()) setGroupId(NEW_GROUP);
    else setGroupId("");
    setAddingGroup(false);
  };

  const addTag = () => {
    const t = tagDraft.trim().replace(/^#/, "");
    if (t && !tags.includes(t)) setTags([...tags, t]);
    setTagDraft("");
  };

  const seg = (id: AuthSeg, lbl: string, icon: IconName) => (
    <button
      key={id}
      onClick={() => {
        authTouched.current = true;
        setAuth(id);
      }}
      style={{
        flex: 1,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 7,
        height: 38,
        borderRadius: 8,
        cursor: "pointer",
        fontFamily: UI,
        fontSize: 13,
        fontWeight: auth === id ? 700 : 600,
        background: auth === id ? p.accentSoft : p.bg2,
        color: auth === id ? p.accent : p.txt2,
        border: `1px solid ${auth === id ? p.accentLine : p.line}`,
      }}
    >
      <Icon name={icon} size={15} />
      {lbl}
    </button>
  );

  // A pasted/loaded key is imported regardless of the algo toggle (the core
  // detects the actual key type); a bare ed25519 with no key material is the only
  // case that generates a fresh keypair.
  const newKeyWillImport = newKeyImport.trim().length > 0 || newKeyAlgo !== "ed25519";

  // Pick a private-key file into the inline import buffer (any key type → vault).
  const loadKeyFromFile = async () => {
    try {
      const picked = await openDialog({ multiple: false, directory: false });
      if (!picked || Array.isArray(picked)) return;
      const text = await readTextFile(picked);
      setNewKeyImport(text);
      setNewKeyFileName(picked.split(/[/\\]/).pop() || picked);
      // pre-fill the key name from the file's basename if the user hasn't typed one
      if (!newKeyName.trim()) {
        const base = (picked.split(/[/\\]/).pop() || "").replace(/\.[^.]+$/, "");
        if (base) setNewKeyName(base);
      }
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  // Create a key from the inline host-modal form, then auto-select it.
  const addKeyInline = async () => {
    if (!vault) {
      ctx.toast(t("modals.noActiveVault"), "err");
      return;
    }
    const name = newKeyName.trim();
    if (!name) {
      ctx.toast(t("modals.key.enterName"), "warn");
      return;
    }
    // The core silently overwrites a same-id key's private material — guard it.
    if (keyItems.some((k) => k.itemId === name)) {
      ctx.toast(t("modals.host.keyNameTaken"), "warn");
      return;
    }
    if (newKeyWillImport && !newKeyImport.trim()) {
      ctx.toast(t("modals.key.pasteToImport"), "warn");
      return;
    }
    setNewKeyBusy(true);
    try {
      if (newKeyWillImport) await api.importSshKey(vault, name, newKeyImport.trim());
      else await api.generateSshKey(vault, name);
      await useApp.getState().reloadVault();
      setKeyId(name); // auto-select the freshly created key
      setShowNewKey(false);
      setNewKeyName("");
      setNewKeyImport("");
      setNewKeyFileName(null);
      ctx.toast(newKeyWillImport ? t("modals.key.imported") : t("modals.key.generated"), "ok");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    } finally {
      setNewKeyBusy(false);
    }
  };

  const save = async () => {
    if (!vault) {
      ctx.toast(t("modals.noActiveVault"), "err");
      return;
    }
    // Personal auth takes the login from the identity → no host username required.
    if (!label.trim() || !host.trim() || (auth !== "personal" && !user.trim())) {
      ctx.toast(t("modals.host.fillRequired"), "warn");
      return;
    }
    let profileAuth: ProfileAuth;
    if (auth === "key") {
      if (!keyId) {
        ctx.toast(t("modals.host.selectKey"), "warn");
        return;
      }
      profileAuth = { type: "key", keyItemId: keyId };
    } else if (auth === "password") {
      if (newPw.trim()) {
        // store the entered password as a new vault secret and reference it
        const pwItemId = `${slug(label)}-pw-${Date.now()}`;
        try {
          await api.savePassword(vault, pwItemId, newPw);
        } catch (e) {
          ctx.toast(apiErrorMessage(e), "err");
          return;
        }
        profileAuth = { type: "vaultPassword", passwordItemId: pwItemId };
      } else if (pwId) {
        profileAuth = { type: "vaultPassword", passwordItemId: pwId };
      } else {
        ctx.toast(t("modals.host.enterOrSelectPassword"), "warn");
        return;
      }
    } else if (auth === "personal") {
      // No creds stored here — the member logs in with their personal identity
      // via a binding (B4). Nothing to collect at save time.
      profileAuth = { type: "personal" };
    } else {
      profileAuth = { type: "promptPassword" };
    }

    const jumps: JumpHost[] = [];
    if (useJump) {
      // Mirror the render predicate (jumpIsRef) exactly — never save a hopRef the
      // UI wasn't showing (a stuck jMode==="ref" with no referenceable hosts falls
      // through to the inline branch instead of persisting a stale reference).
      if (jumpIsRef && jRef) {
        // Reference a saved profile — inline fields are ignored at connect; the
        // core resolves host/port/user/auth from the referenced profile's uid.
        jumps.push({
          host: "",
          port: 22,
          user: "",
          auth: { type: "agent", vaultId: vault, keyItemId: "" },
          hopRef: { vaultId: vault, profileUid: jRef },
        });
      } else if (jHost.trim()) {
        jumps.push({
          host: jHost.trim(),
          port: parseInt(jPort, 10) || 22,
          user: jUser.trim(),
          auth: { type: "agent", vaultId: vault, keyItemId: jKeyId },
        });
      }
    }

    const profileId = edit?.profileId || `${slug(label)}-${Date.now()}`;
    const profile: ConnectionProfile = {
      profileId,
      // Carry the immutable uid through edits; empty on create → core mints it.
      uid: edit?.uid ?? "",
      // Username template only applies to Personal auth (gateway login shaping).
      usernameTemplate:
        auth === "personal" && usernameTemplate.trim() ? usernameTemplate.trim() : null,
      label: label.trim(),
      host: host.trim(),
      port: parseInt(port, 10) || 22,
      user: user.trim(),
      auth: profileAuth,
      jumps,
      tags,
    };

    try {
      await api.saveConnection(vault, profile);

      // Inline personal binding: link the chosen identity to this host. The uid is
      // minted by the core on create, so re-read the saved profile to get it.
      if (auth === "personal" && bindVault && boundIdentity) {
        try {
          const uid =
            edit?.uid ||
            (await api.listConnections(vault)).find((c) => c.profileId === profileId)?.uid ||
            "";
          if (uid) {
            const dest = await api.personalDestination(
              profile.host,
              profile.port,
              profile.usernameTemplate,
              profile.jumps,
            );
            const existing = await api.getBinding(bindVault, vault, uid).catch(() => null);
            await api.setBinding(
              bindVault,
              {
                teamVaultId: vault,
                profileUid: uid,
                identityItemId: boundIdentity,
                destinationPin: dest,
              },
              existing !== null,
            );
          }
        } catch (e) {
          ctx.toast(apiErrorMessage(e), "err");
        }
      }

      // Resolve the target group. A pending new group is created here (on save) so
      // a cancelled modal never leaves an orphan empty group behind.
      let targetGroupId = groupId;
      if (groupId === NEW_GROUP && newGroupName.trim()) {
        const created: ServerGroup = {
          groupId: `${slug(newGroupName)}-${Date.now()}`,
          label: newGroupName.trim(),
          memberIds: [profileId],
          parentId: null,
        };
        await api.saveGroup(vault, created);
        targetGroupId = created.groupId;
      } else if (targetGroupId) {
        const g = groups.find((x) => x.groupId === targetGroupId);
        if (g && !g.memberIds.includes(profileId)) {
          await api.saveGroup(vault, { ...g, memberIds: [...g.memberIds, profileId] });
        }
      } else {
        targetGroupId = ""; // "No group"
      }

      // On edit, moving to another group (or to none) must drop the host from any
      // group it was previously in — otherwise it lingers in both.
      if (edit) {
        for (const g of groups) {
          if (g.groupId !== targetGroupId && g.memberIds.includes(profileId)) {
            await api.saveGroup(vault, {
              ...g,
              memberIds: g.memberIds.filter((id) => id !== profileId),
            });
          }
        }
      }

      await useApp.getState().reloadVault();
      onClose();
      ctx.toast(edit ? t("modals.host.updated") : t("modals.host.saved"), "ok");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  const remove = () => {
    if (!vault || !edit) return;
    // Deleting a host is irreversible — gate it behind the same danger-confirm the
    // detail rail uses, instead of wiping it on a single stray click in the footer.
    const profileId = edit.profileId;
    ctx.confirm({
      title: t("hosts.deleteTitle"),
      body: t("hosts.deleteBody", { label: edit.label }),
      danger: true,
      confirmLabel: t("common.delete"),
      icon: "trash",
      onConfirm: async () => {
        try {
          await api.deleteConnection(vault, profileId);
          await useApp.getState().reloadVault();
          onClose();
          ctx.toast(t("modals.host.deleted"), "ok");
        } catch (e) {
          ctx.toast(apiErrorMessage(e), "err");
        }
      },
    });
  };

  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        zIndex: 150,
        display: "flex",
        alignItems: isMobile ? "flex-start" : "center",
        justifyContent: "center",
        ...(isMobile
          ? {
              padding: "calc(env(safe-area-inset-top) + 16px) 12px 16px",
              boxSizing: "border-box",
            }
          : null),
      }}
    >
      <div
        onClick={onClose}
        style={{
          position: "absolute",
          inset: 0,
          background: "rgba(6,7,11,0.55)",
          backdropFilter: "blur(3px)",
        }}
      />
      <div
        ref={hostCardRef}
        role="dialog"
        aria-modal="true"
        aria-label={edit ? t("modals.host.editTitle") : t("modals.host.newTitle")}
        tabIndex={-1}
        style={{
          position: "relative",
          width: isMobile ? "100%" : "min(560px, calc(100% - 24px))",
          maxWidth: isMobile ? "100%" : undefined,
          maxHeight: isMobile ? "calc(100dvh - 80px)" : "90%",
          overflow: "auto",
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 18,
          boxShadow: p.shadow,
          outline: "none",
        }}
      >
        {/* header */}
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
              background: p.accentSoft,
              border: `1px solid ${p.accentLine}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon name="server" size={18} color={p.accent} />
          </span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 17, fontWeight: 800, letterSpacing: -0.3 }}>
              {edit ? t("modals.host.editTitle") : t("modals.host.newTitle")}
            </div>
            <div style={{ fontSize: 12, color: p.txt3, display: "flex", alignItems: "center", gap: 5 }}>
              {t("modals.host.intoVault")}
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: p.accent }} />
              <b style={{ color: p.txt2 }}>{vaultInfo?.name ?? "—"}</b>
            </div>
          </div>
          <button
            onClick={onClose}
            title={t("common.close")}
            aria-label={t("common.close")}
            style={{
              width: 30,
              height: 30,
              borderRadius: 8,
              border: `1px solid ${p.line}`,
              background: p.bg2,
              color: p.txt3,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon name="x" size={15} />
          </button>
        </div>

        {/* body */}
        <div
          style={{
            padding: isMobile ? 16 : 22,
            display: "flex",
            flexDirection: "column",
            gap: 16,
          }}
        >
          <NHField label={t("modals.host.label")}>
            <NHInput value={label} placeholder="web-04" accent onChange={setLabel} />
          </NHField>

          <div style={{ display: "flex", flexDirection: isMobile ? "column" : "row", gap: 12 }}>
            <NHField label={t("modals.host.hostAddress")} w="100%">
              <NHInput value={host} placeholder="web-04.prod.example.net" mono onChange={setHost} />
            </NHField>
            <NHField label={t("modals.host.port")} w={isMobile ? "100%" : "96px"}>
              <NHInput value={port} mono onChange={setPort} />
            </NHField>
          </div>
          {/* Personal auth derives the login from the chosen identity (see the
              Personal section below), so no separate username field there. */}
          {auth !== "personal" && (
            <NHField label={t("modals.host.user")}>
              <NHInput value={user} placeholder="deploy" mono onChange={setUser} />
            </NHField>
          )}

          <NHField label={t("modals.host.auth")}>
            <div style={{ display: "flex", gap: 8 }}>
              {seg("key", t("modals.host.authKey"), "key")}
              {seg("password", t("modals.host.authPassword"), "lock")}
              {seg("ask", t("modals.host.authAsk"), "eye")}
              {seg("personal", t("modals.host.authPersonal"), "fingerprint")}
            </div>
            <div style={{ marginTop: 10 }}>
              {auth === "key" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {keyItems.length > 0 && !showNewKey && (
                    <NHSelect
                      value={keyId}
                      onChange={(v) => (v === "__newkey__" ? setShowNewKey(true) : setKeyId(v))}
                      options={[
                        ...keyItems.map((k) => ({
                          value: k.itemId,
                          label: t("modals.host.itemFromVault", { id: k.itemId }),
                        })),
                        { value: "__newkey__", label: t("modals.host.addNewKey") },
                      ]}
                      empty={t("modals.host.noKeys")}
                    />
                  )}
                  {keyItems.length === 0 && !showNewKey && (
                    <Btn variant="ghost" size="sm" icon="plus" onClick={() => setShowNewKey(true)}>
                      {t("modals.host.addNewKey")}
                    </Btn>
                  )}
                  {showNewKey && (
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: 8,
                        padding: 10,
                        borderRadius: 9,
                        border: `1px solid ${p.line}`,
                        background: p.bg2,
                      }}
                    >
                      <NHInput
                        value={newKeyName}
                        placeholder="prod-deploy"
                        accent
                        onChange={setNewKeyName}
                      />
                      <MSeg
                        value={newKeyAlgo}
                        set={setNewKeyAlgo}
                        options={[
                          { id: "ed25519", label: "ed25519", icon: "zap", desc: t("modals.key.algoEd25519Desc") },
                          { id: "ecdsa", label: "ECDSA", icon: "key", desc: t("modals.key.algoImportOnly") },
                          { id: "rsa", label: "RSA", icon: "lock", desc: t("modals.key.algoImportOnly") },
                        ]}
                      />
                      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                        <Btn variant="ghost" size="sm" icon="upload" onClick={loadKeyFromFile}>
                          {t("modals.key.loadFromFile")}
                        </Btn>
                        {newKeyFileName && (
                          <span
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: 6,
                              minWidth: 0,
                              fontFamily: MONO,
                              fontSize: 12,
                              color: p.txt2,
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                            }}
                          >
                            <Icon name="key" size={13} color={p.accent} />
                            {newKeyFileName}
                          </span>
                        )}
                      </div>
                      {(newKeyWillImport || newKeyFileName) && (
                        <textarea
                          {...NO_AUTOCORRECT}
                          value={newKeyImport}
                          placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
                          onChange={(e) => {
                            setNewKeyImport(e.target.value);
                            if (newKeyFileName) setNewKeyFileName(null); // edited by hand
                          }}
                          style={{
                            width: "100%",
                            minHeight: 90,
                            resize: "vertical",
                            padding: 10,
                            borderRadius: 9,
                            background: p.bg0,
                            border: `1px solid ${p.line2}`,
                            outline: "none",
                            fontFamily: MONO,
                            fontSize: 12,
                            color: p.txt,
                            boxSizing: "border-box",
                          }}
                        />
                      )}
                      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                        <Btn variant="ghost" size="sm" onClick={() => setShowNewKey(false)}>
                          {t("common.cancel")}
                        </Btn>
                        <Btn
                          size="sm"
                          icon={newKeyWillImport ? "download" : "zap"}
                          onClick={addKeyInline}
                          disabled={newKeyBusy}
                        >
                          {newKeyWillImport ? t("modals.key.import") : t("modals.key.generate")}
                        </Btn>
                      </div>
                    </div>
                  )}
                </div>
              )}
              {auth === "password" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <NHInput
                    value={newPw}
                    placeholder={t("modals.host.newPasswordPlaceholder")}
                    type="password"
                    onChange={(v) => {
                      setNewPw(v);
                      if (v) setPwId("");
                    }}
                  />
                  {pwItems.length > 0 && (
                    <>
                      <div style={{ fontSize: 11.5, color: p.txt3 }}>{t("modals.host.orSelectSaved")}</div>
                      <NHSelect
                        value={pwId}
                        onChange={(v) => {
                          setPwId(v);
                          setNewPw("");
                        }}
                        options={pwItems.map((k) => ({
                          value: k.itemId,
                          label: t("modals.host.itemFromVault", { id: k.itemId }),
                        }))}
                        empty={t("modals.host.noPasswords")}
                      />
                    </>
                  )}
                  <div style={{ fontSize: 11.5, color: p.txt3 }}>
                    {t("modals.host.passwordStoredHint")}
                  </div>
                </div>
              )}
              {auth === "ask" && (
                <div style={{ fontSize: 12.5, color: p.txt3, padding: "2px 2px" }}>
                  {t("modals.host.askHint")}
                </div>
              )}
              {auth === "personal" &&
                (() => {
                  // The connect login = the identity's username, optionally shaped by a
                  // template (%u = that username). So the "Login" field below IS the
                  // template: empty → the identity's username; `%u:prod-db` → a gateway.
                  const idUser =
                    pIdentities.find((i) => i.identityId === boundIdentity)?.user ?? "";
                  const resolved = usernameTemplate.trim()
                    ? usernameTemplate.replace(/%u/g, idUser)
                    : idUser;
                  const hasIds = !!bindVault && pIdentities.length > 0;
                  return (
                    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                      {sharedVaultDefault && (
                        <div
                          style={{ fontSize: 12, color: p.accent, fontWeight: 600, padding: "2px 2px" }}
                        >
                          {t("modals.host.sharedVaultPersonalHint")}
                        </div>
                      )}
                      <div style={{ fontSize: 12.5, color: p.txt3, padding: "2px 2px" }}>
                        {t("modals.host.personalHint")}
                      </div>

                      {pLoaded && !bindVault && (
                        <div style={{ fontSize: 12, color: p.amber, padding: "2px 2px", lineHeight: 1.5 }}>
                          {t("modals.host.personalNoVault")}
                        </div>
                      )}

                      {/* Which of your private vaults the identity lives in — e.g. a
                          work vault on the company server vs. your own personal server. */}
                      {privateVaults.length > 1 && (
                        <NHField label={t("secrets.identityVault")}>
                          <NHSelect
                            value={bindVault ?? ""}
                            onChange={setBindVault}
                            options={privateVaults.map((v) => {
                              const loc = vaultLoc(v, servers);
                              return {
                                value: v.vaultId,
                                label: `${v.name || v.vaultId} · ${loc.local ? t("secrets.locLocal") : t("secrets.locCloud", { server: loc.server ?? "cloud" })}`,
                              };
                            })}
                            empty=""
                          />
                        </NHField>
                      )}
                      {pLoaded && bindVault && pIdentities.length === 0 && (
                        <div style={{ fontSize: 12, color: p.amber, padding: "2px 2px", lineHeight: 1.5 }}>
                          {t("modals.host.personalNoIdentities")}
                        </div>
                      )}
                      {hasIds && (
                        <NHField label={t("modals.host.personalIdentity")}>
                          <NHSelect
                            value={boundIdentity}
                            onChange={setBoundIdentity}
                            options={pIdentities.map((i) => ({
                              value: i.identityId,
                              label: (i.label || i.identityId) + (i.user ? ` · ${i.user}` : ""),
                            }))}
                            empty={t("modals.host.personalNoIdentities")}
                          />
                        </NHField>
                      )}

                      {/* One optional Login field = the username template. Placeholder
                          shows the identity's username (the default), so most hosts leave
                          it blank; a gateway types `%u:target`. */}
                      {hasIds && (
                        <NHField label={t("modals.host.user")}>
                          <NHInput
                            value={usernameTemplate}
                            placeholder={idUser || t("modals.host.personalLoginPlaceholder")}
                            mono
                            onChange={setUsernameTemplate}
                          />
                          <div
                            style={{ fontSize: 11.5, color: p.txt3, padding: "5px 2px 0", lineHeight: 1.5 }}
                          >
                            {resolved && (
                              <span style={{ color: p.txt2 }}>
                                {t("modals.host.personalLoginResolved", { login: resolved })}{" "}
                              </span>
                            )}
                            {t("modals.host.personalLoginHint")}
                          </div>
                        </NHField>
                      )}
                    </div>
                  );
                })()}
            </div>
          </NHField>

          {/* ProxyJump */}
          <div style={{ borderRadius: 11, border: `1px solid ${p.line}`, background: p.bg2, padding: 12 }}>
            <label
              onClick={() => setUseJump(!useJump)}
              style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }}
            >
              <span
                style={{
                  width: 34,
                  height: 20,
                  borderRadius: 11,
                  background: useJump ? p.accent : p.bg4,
                  position: "relative",
                  flexShrink: 0,
                }}
              >
                <span
                  style={{
                    position: "absolute",
                    top: 2,
                    left: useJump ? 16 : 2,
                    width: 16,
                    height: 16,
                    borderRadius: "50%",
                    background: "#fff",
                    transition: "left .15s",
                  }}
                />
              </span>
              <Icon name="branch" size={15} color={useJump ? p.purple : p.txt3} />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 600 }}>{t("modals.host.proxyJump")}</div>
                <div style={{ fontSize: 11, color: p.txt3 }}>{t("modals.host.proxyJumpDesc")}</div>
              </div>
            </label>
            {useJump && (
              <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 10 }}>
                {refHosts.length > 0 && (
                  <div style={{ display: "flex", gap: 8 }}>
                    {(["inline", "ref"] as const).map((m) => (
                      <button
                        key={m}
                        type="button"
                        onClick={() => setJMode(m)}
                        style={{
                          flex: 1,
                          padding: "7px 10px",
                          borderRadius: 8,
                          cursor: "pointer",
                          fontSize: 12.5,
                          fontWeight: jMode === m ? 700 : 600,
                          background: jMode === m ? p.accentSoft : p.bg2,
                          color: jMode === m ? p.accent : p.txt2,
                          border: `1px solid ${jMode === m ? p.accentLine : p.line}`,
                        }}
                      >
                        {m === "inline"
                          ? t("modals.host.jumpModeInline")
                          : t("modals.host.jumpModeRef")}
                      </button>
                    ))}
                  </div>
                )}
                {jumpIsRef ? (
                  <NHField label={t("modals.host.jumpRefProfile")} w="100%">
                    <NHSelect
                      value={jRef}
                      onChange={setJRef}
                      options={refHosts.map((h) => ({
                        value: h.uid,
                        label: h.label || `${h.user}@${h.host}`,
                      }))}
                      empty={t("modals.host.jumpRefEmpty")}
                    />
                    <div style={{ fontSize: 11.5, color: p.txt3, padding: "4px 2px 0" }}>
                      {t("modals.host.jumpRefHint")}
                    </div>
                  </NHField>
                ) : (
                  <>
                    <div style={{ display: "flex", flexDirection: isMobile ? "column" : "row", gap: 12 }}>
                      <NHField label={t("modals.host.bastionHost")} w="100%">
                        <NHInput value={jHost} placeholder="bastion.corp.net" mono onChange={setJHost} />
                      </NHField>
                      <NHField label={t("modals.host.port")} w={isMobile ? "100%" : "96px"}>
                        <NHInput value={jPort} mono onChange={setJPort} />
                      </NHField>
                    </div>
                    <div style={{ display: "flex", flexDirection: isMobile ? "column" : "row", gap: 12 }}>
                      <NHField label={t("modals.host.user")} w="100%">
                        <NHInput value={jUser} placeholder="ops" mono onChange={setJUser} />
                      </NHField>
                      <NHField label={t("modals.host.key")} w="100%">
                        <NHSelect
                          value={jKeyId}
                          onChange={setJKeyId}
                          options={keyItems.map((k) => ({ value: k.itemId, label: k.itemId }))}
                          empty={t("modals.host.noKeys")}
                        />
                      </NHField>
                    </div>
                  </>
                )}
              </div>
            )}
          </div>

          {/* group */}
          <div style={{ display: "flex", gap: 12 }}>
            <NHField label={t("modals.host.group")} w="100%">
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {groups.map((g) => {
                  const on = groupId === g.groupId;
                  return (
                    <span
                      key={g.groupId}
                      onClick={() => pickGroup(g.groupId)}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        padding: "7px 12px",
                        borderRadius: 9,
                        cursor: "pointer",
                        fontSize: 13,
                        fontWeight: 600,
                        background: on ? p.accentSoft : p.bg2,
                        color: on ? p.accent : p.txt2,
                        border: `1px solid ${on ? p.accentLine : p.line}`,
                      }}
                    >
                      <Icon name="folder" size={14} />
                      {g.label}
                    </span>
                  );
                })}
                {/* pending new group (created on save) shown as a selected chip */}
                {groupId === NEW_GROUP && newGroupName.trim() && (
                  <span
                    onClick={() => setAddingGroup(true)}
                    title={t("modals.host.editNewGroup")}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6,
                      padding: "7px 12px",
                      borderRadius: 9,
                      cursor: "pointer",
                      fontSize: 13,
                      fontWeight: 600,
                      background: p.accentSoft,
                      color: p.accent,
                      border: `1px solid ${p.accentLine}`,
                    }}
                  >
                    <Icon name="folder" size={14} />
                    {newGroupName.trim()}
                  </span>
                )}
                {/* create a new group inline */}
                {addingGroup ? (
                  <input
                    {...NO_AUTOCORRECT}
                    autoFocus
                    value={newGroupName}
                    placeholder={t("modals.host.newGroupPlaceholder")}
                    onChange={(e) => setNewGroupName(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        confirmNewGroup();
                      } else if (e.key === "Escape") {
                        e.preventDefault();
                        setAddingGroup(false);
                        if (groupId === NEW_GROUP && !newGroupName.trim()) setGroupId("");
                      }
                    }}
                    onBlur={confirmNewGroup}
                    style={{
                      width: 150,
                      height: 34,
                      padding: "0 10px",
                      borderRadius: 9,
                      fontSize: 13,
                      fontWeight: 600,
                      background: p.bg2,
                      color: p.txt,
                      border: `1px solid ${p.accentLine}`,
                      outline: "none",
                    }}
                  />
                ) : (
                  <span
                    onClick={() => setAddingGroup(true)}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 5,
                      padding: "7px 12px",
                      borderRadius: 9,
                      cursor: "pointer",
                      fontSize: 13,
                      fontWeight: 600,
                      background: "transparent",
                      color: p.txt3,
                      border: `1px dashed ${p.line2}`,
                    }}
                  >
                    <Icon name="plus" size={13} />
                    {t("modals.host.newGroup")}
                  </span>
                )}
                {/* no group */}
                <span
                  onClick={() => pickGroup("")}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    padding: "7px 12px",
                    borderRadius: 9,
                    cursor: "pointer",
                    fontSize: 13,
                    fontWeight: 600,
                    background: groupId === "" ? p.accentSoft : "transparent",
                    color: groupId === "" ? p.accent : p.txt3,
                    border: `1px solid ${groupId === "" ? p.accentLine : p.line2}`,
                  }}
                >
                  {t("modals.host.noGroup")}
                </span>
              </div>
            </NHField>
          </div>

          {/* tags */}
          <div style={{ display: "flex", gap: 12 }}>
            <NHField label={t("modals.host.tags")} w="100%">
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  flexWrap: "wrap",
                  minHeight: 40,
                  padding: "0 10px",
                  borderRadius: 9,
                  background: p.bg2,
                  border: `1px solid ${p.line2}`,
                }}
              >
                {tags.map((tg) => (
                  <span
                    key={tg}
                    onClick={() => setTags(tags.filter((x) => x !== tg))}
                    style={{ cursor: "pointer" }}
                    title={t("modals.host.removeTag")}
                  >
                    <Tag mono>#{tg}</Tag>
                  </span>
                ))}
                <input
                  {...NO_AUTOCORRECT}
                  value={tagDraft}
                  placeholder={t("modals.host.addTagPlaceholder")}
                  onChange={(e) => setTagDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === ",") {
                      e.preventDefault();
                      addTag();
                    }
                  }}
                  onBlur={addTag}
                  style={{
                    flex: 1,
                    minWidth: 70,
                    height: 38,
                    background: "none",
                    border: "none",
                    outline: "none",
                    fontFamily: UI,
                    fontSize: 12.5,
                    color: p.txt,
                  }}
                />
              </div>
            </NHField>
          </div>
        </div>

        {/* footer */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: isMobile ? "14px 16px" : "14px 22px",
            borderTop: `1px solid ${p.line}`,
            background: p.bg0,
            ...(isMobile ? { flexWrap: "wrap" } : null),
          }}
        >
          <span style={{ fontSize: 11.5, color: p.txt3, display: "flex", alignItems: "center", gap: 6 }}>
            <Icon name="shieldcheck" size={13} color={p.green} />
            {t("modals.host.tofuNote")}
          </span>
          <div style={{ flex: isMobile ? "1 1 100%" : 1 }} />
          {edit && (
            <Btn
              variant="ghost"
              size="sm"
              icon="trash"
              style={{
                color: p.red,
                borderColor: rgba(p.red, 0.4),
                ...(isMobile ? { minHeight: 44, flex: "1 1 100%" } : null),
              }}
              onClick={remove}
            >
              {t("common.delete")}
            </Btn>
          )}
          <Btn
            variant="ghost"
            onClick={onClose}
            style={isMobile ? { minHeight: 44, flex: 1 } : undefined}
          >
            {t("common.cancel")}
          </Btn>
          <Btn icon="check" onClick={save} style={isMobile ? { minHeight: 44, flex: 1 } : undefined}>
            {edit ? t("common.save") : t("modals.host.saveHost")}
          </Btn>
        </div>
      </div>
    </div>
  );
}

// ── New SSH key ────────────────────────────────────────────────
type Algo = "ed25519" | "ecdsa" | "rsa";

function NewKeyModal({ onClose }: { onClose: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const ctx = useCtx();
  const vault = useApp((s) => s.vaultId);

  const [algo, setAlgo] = useState<Algo>("ed25519");
  const [name, setName] = useState("");
  const [imported, setImported] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);

  // The core's generate_ssh_key always produces Ed25519. For other algorithms
  // (or a key loaded from a file / pasted) we import the existing OpenSSH key.
  const canGenerate = algo === "ed25519";
  // Once a key is provided (pasted or loaded from a file) we import it regardless
  // of the algorithm toggle — the core parses the actual key type itself.
  const willImport = imported.trim().length > 0 || !canGenerate;

  // Pick a private-key file and load it into the import field. Works for any key
  // type, so importing e.g. an Ed25519 key from disk doesn't need the algo toggle.
  const loadFromFile = async () => {
    try {
      const picked = await openDialog({ multiple: false, directory: false });
      if (!picked || Array.isArray(picked)) return;
      const text = await readTextFile(picked);
      setImported(text);
      setFileName(picked.split(/[/\\]/).pop() || picked);
      // pre-fill the item name from the file's basename if the user hasn't typed one
      if (!name.trim()) {
        const base = (picked.split(/[/\\]/).pop() || "").replace(/\.[^.]+$/, "");
        if (base) setName(base);
      }
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  const clearFile = () => {
    setImported("");
    setFileName(null);
  };

  const run = async () => {
    if (!vault) {
      ctx.toast(t("modals.noActiveVault"), "err");
      return;
    }
    if (!name.trim()) {
      ctx.toast(t("modals.key.enterName"), "warn");
      return;
    }
    setBusy(true);
    try {
      if (willImport) {
        if (!imported.trim()) {
          ctx.toast(t("modals.key.pasteToImport"), "warn");
          setBusy(false);
          return;
        }
        await api.importSshKey(vault, name.trim(), imported.trim(), passphrase.trim() || undefined);
        ctx.toast(t("modals.key.imported"), "ok");
      } else {
        await api.generateSshKey(vault, name.trim());
        ctx.toast(t("modals.key.generated"), "ok");
      }
      await useApp.getState().reloadVault();
      onClose();
    } catch (e) {
      // Encrypted key: keep the modal open and hint about the passphrase
      // (the messages are stable English strings from the core, see AgentError).
      const msg = apiErrorMessage(e);
      if (/passphrase is required|passphrase-protected/i.test(msg)) {
        ctx.toast(t("modals.key.needPassphrase"), "warn");
      } else if (/incorrect passphrase/i.test(msg)) {
        ctx.toast(t("modals.key.wrongPassphrase"), "err");
      } else {
        ctx.toast(msg, "err");
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      position="absolute"
      zIndex={150}
      w={540}
      icon="key"
      title={t("modals.key.title")}
      subtitle={t("modals.key.subtitle")}
      onClose={onClose}
      footer={
        <React.Fragment>
          <span style={{ fontSize: 11.5, color: p.txt3, display: "flex", alignItems: "center", gap: 6 }}>
            <Icon name="shieldcheck" size={13} color={p.green} />
            {t("modals.key.encryptNote")}
          </span>
          <div style={{ flex: isMobile ? "1 1 100%" : 1 }} />
          <Btn
            variant="ghost"
            onClick={onClose}
            style={isMobile ? { minHeight: 44, flex: 1 } : undefined}
          >
            {t("common.cancel")}
          </Btn>
          <Btn
            icon={willImport ? "download" : "zap"}
            onClick={run}
            disabled={busy}
            style={isMobile ? { minHeight: 44, flex: 1 } : undefined}
          >
            {willImport ? t("modals.key.import") : t("modals.key.generate")}
          </Btn>
        </React.Fragment>
      }
    >
      <NHField label={t("modals.host.label")}>
        <NHInput value={name} placeholder="prod-deploy" accent onChange={setName} />
      </NHField>
      <NHField label={t("modals.key.algorithm")}>
        <MSeg
          value={algo}
          set={setAlgo}
          options={[
            { id: "ed25519", label: "ed25519", icon: "zap", desc: t("modals.key.algoEd25519Desc") },
            { id: "ecdsa", label: "ECDSA", icon: "key", desc: t("modals.key.algoImportOnly") },
            { id: "rsa", label: "RSA", icon: "lock", desc: t("modals.key.algoImportOnly") },
          ]}
        />
      </NHField>
      {/* Import an existing private key from a file (any key type → vault). */}
      <button
        onClick={loadFromFile}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 8,
          padding: "11px 12px",
          borderRadius: 10,
          border: `1px dashed ${p.line2}`,
          background: "transparent",
          color: p.txt2,
          cursor: "pointer",
          fontSize: 13,
          fontWeight: 600,
        }}
      >
        <Icon name="upload" size={15} />
        {t("modals.key.loadFromFile")}
      </button>
      {fileName && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "8px 12px",
            borderRadius: 9,
            background: p.accentSoft,
            border: `1px solid ${p.accentLine}`,
            fontSize: 12.5,
          }}
        >
          <Icon name="key" size={13} color={p.accent} />
          <span
            style={{
              flex: 1,
              fontFamily: MONO,
              color: p.txt2,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {fileName}
          </span>
          <button
            onClick={clearFile}
            title={t("common.remove")}
            aria-label={t("common.remove")}
            style={{ ...BTN_RESET, display: "inline-flex", opacity: 0.7 }}
          >
            <Icon name="x" size={13} />
          </button>
        </div>
      )}
      {willImport ? (
        <React.Fragment>
          <NHField label={t("modals.key.privateKeyLabel")} hint={t("modals.key.privateKeyHint")}>
            <textarea
              {...NO_AUTOCORRECT}
              value={imported}
              placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
              onChange={(e) => {
                setImported(e.target.value);
                if (fileName) setFileName(null); // edited by hand → no longer "the file"
              }}
              style={{
                width: "100%",
                minHeight: 132,
                resize: "vertical",
                padding: 12,
                borderRadius: 9,
                background: p.bg2,
                border: `1px solid ${p.line2}`,
                outline: "none",
                fontFamily: MONO,
                fontSize: 12,
                lineHeight: 1.5,
                color: p.txt,
                boxSizing: "border-box",
              }}
            />
          </NHField>
          {/* Key passphrase: only needed for encrypted keys; for unencrypted
              ones the core simply ignores it. */}
          <NHField label={t("modals.key.passphraseLabel")} hint={t("modals.key.passphraseHint")}>
            <NHInput
              value={passphrase}
              type="password"
              placeholder="••••••••"
              onChange={setPassphrase}
            />
          </NHField>
        </React.Fragment>
      ) : (
        <div
          style={{
            borderRadius: 11,
            border: `1px solid ${p.line}`,
            background: p.bg2,
            padding: 12,
            fontSize: 12.5,
            color: p.txt3,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Icon name="zap" size={15} color={p.accent} />
          {t("modals.key.generateInfo")}
        </div>
      )}
    </Modal>
  );
}

// ── New tunnel ─────────────────────────────────────────────────
type TLetter = "L" | "R" | "D";

interface TMeta {
  type: TunnelType;
  /** Palette token, not a raw hex — Candy/light themes get their own hues. */
  colorKey: "accent" | "purple" | "green";
  src: string;
  dst: string;
  srcLKey: string;
  dstLKey: string;
}
const T_META: Record<TLetter, TMeta> = {
  L: {
    type: "local",
    colorKey: "accent",
    src: "127.0.0.1:5432",
    dst: "db-primary:5432",
    srcLKey: "modals.tunnel.localBind",
    dstLKey: "modals.tunnel.remoteAddress",
  },
  R: {
    type: "remote",
    colorKey: "purple",
    src: "0.0.0.0:9000",
    dst: "127.0.0.1:3000",
    srcLKey: "modals.tunnel.remoteBind",
    dstLKey: "modals.tunnel.localAddress",
  },
  D: {
    type: "dynamic",
    colorKey: "green",
    src: "127.0.0.1:1080",
    dst: "SOCKS5",
    srcLKey: "modals.tunnel.localBind",
    dstLKey: "modals.tunnel.proxy",
  },
};

function splitHostPort(s: string): { host: string; port: number } {
  const i = s.lastIndexOf(":");
  if (i < 0) return { host: s, port: 0 };
  return { host: s.slice(0, i), port: parseInt(s.slice(i + 1), 10) || 0 };
}

function NewTunnelModal({ onClose }: { onClose: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const ctx = useCtx();
  const vault = useApp((s) => s.vaultId);
  const hosts = useApp((s) => s.hosts);

  const [type, setType] = useState<TLetter>("L");
  const [name, setName] = useState("");
  const [viaId, setViaId] = useState(hosts[0]?.profileId ?? "");
  const m = T_META[type];
  const [src, setSrc] = useState(m.src);
  const [dst, setDst] = useState(m.dst);

  const setKind = (t: TLetter) => {
    setType(t);
    setSrc(T_META[t].src);
    setDst(T_META[t].dst);
  };

  const open = async () => {
    if (!vault) {
      ctx.toast(t("modals.noActiveVault"), "err");
      return;
    }
    const via = hosts.find((h) => h.profileId === viaId);
    if (!via) {
      ctx.toast(t("modals.tunnel.selectVia"), "warn");
      return;
    }
    if (via.auth.type === "promptPassword") {
      ctx.toast(t("modals.tunnel.needKeyOrPassword"), "warn");
      return;
    }
    try {
      // Personal via-host resolves in-core (binding + anti-redirect) first.
      const { user, auth } = await api.resolveConnectAuth(via, vault);
      const args: ConnectArgs = {
        host: via.host,
        port: via.port,
        user,
        auth,
        jumps: via.jumps,
      };
      let opened: { id: string; bindAddress: string };
      let route: string;
      if (type === "L") {
        const rem = splitHostPort(dst);
        opened = await api.tunnelOpenLocal(args, src, rem.host, rem.port);
        route = `${opened.bindAddress} → ${rem.host}:${rem.port}`;
      } else if (type === "R") {
        const rb = splitHostPort(src);
        const loc = splitHostPort(dst);
        opened = await api.tunnelOpenRemote(args, rb.host, rb.port, loc.host, loc.port);
        route = `${rb.host}:${rb.port} → ${loc.host}:${loc.port}`;
      } else {
        opened = await api.tunnelOpenDynamic(args, src);
        route = `${opened.bindAddress} → SOCKS5`;
      }
      useApp.getState().addTunnel({
        id: opened.id,
        label: name.trim() || via.label,
        type: m.type,
        bindAddress: opened.bindAddress,
        route,
        via: via.label,
        on: true,
      });
      onClose();
      ctx.toast(t("modals.tunnel.opened"), "ok");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  return (
    <Modal
      position="absolute"
      zIndex={150}
      w={540}
      icon="branch"
      iconColor={p.purple}
      title={t("modals.tunnel.title")}
      subtitle={t("modals.tunnel.subtitle")}
      onClose={onClose}
      footer={
        <React.Fragment>
          <span style={{ fontSize: 11.5, color: p.txt3, display: "flex", alignItems: "center", gap: 6 }}>
            <Icon name="alert" size={13} color={p.amber} />
            {t("modals.tunnel.autoCloseNote")}
          </span>
          <div style={{ flex: isMobile ? "1 1 100%" : 1 }} />
          <Btn
            variant="ghost"
            onClick={onClose}
            style={isMobile ? { minHeight: 44, flex: 1 } : undefined}
          >
            {t("common.cancel")}
          </Btn>
          <Btn icon="check" onClick={open} style={isMobile ? { minHeight: 44, flex: 1 } : undefined}>
            {t("modals.tunnel.openTunnel")}
          </Btn>
        </React.Fragment>
      }
    >
      <NHField label={t("modals.host.label")}>
        <NHInput value={name} placeholder="Postgres prod" accent onChange={setName} />
      </NHField>
      <NHField label={t("modals.tunnel.forwardType")}>
        <MSeg
          value={type}
          set={setKind}
          options={[
            { id: "L", label: "Local -L", icon: "ar", desc: t("modals.tunnel.localDesc") },
            { id: "R", label: "Remote -R", icon: "cl", desc: t("modals.tunnel.remoteDesc") },
            { id: "D", label: "Dynamic -D", icon: "globe", desc: t("modals.tunnel.dynamicDesc") },
          ]}
        />
      </NHField>
      <NHField label={t("modals.tunnel.viaHost")}>
        {hosts.length ? (
          <NHSelect
            value={viaId}
            onChange={setViaId}
            options={hosts.map((h) => ({ value: h.profileId, label: `${h.user}@${h.host}` }))}
            empty={t("modals.tunnel.noHosts")}
          />
        ) : (
          <div style={{ fontSize: 12.5, color: p.txt3, padding: "2px 2px" }}>
            {t("modals.tunnel.noSavedHosts")}
          </div>
        )}
      </NHField>
      <div
        style={{
          display: "flex",
          flexDirection: isMobile ? "column" : "row",
          alignItems: isMobile ? "stretch" : "flex-end",
          gap: 12,
        }}
      >
        <NHField label={tDyn(m.srcLKey)} w="100%">
          <NHInput value={src} mono accent onChange={setSrc} />
        </NHField>
        <span
          style={{
            height: isMobile ? "auto" : 40,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: p[m.colorKey],
            transform: isMobile ? "rotate(90deg)" : undefined,
          }}
        >
          <Icon name="ar" size={18} color={p[m.colorKey]} />
        </span>
        <NHField label={tDyn(m.dstLKey)} w="100%">
          {type === "D" ? (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                height: 40,
                padding: "0 12px",
                borderRadius: 9,
                background: p.bg2,
                border: `1px solid ${p.line2}`,
                fontFamily: MONO,
                fontSize: 13.5,
                color: p.txt3,
              }}
            >
              SOCKS5
            </div>
          ) : (
            <NHInput value={dst} mono onChange={setDst} />
          )}
        </NHField>
      </div>
    </Modal>
  );
}

function NewVaultModal({
  edit,
  onCreated,
  keepActive,
  onClose,
}: {
  edit?: VaultInfo;
  onCreated?: (vaultId: string) => void;
  keepActive?: boolean;
  onClose: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const ctx = useCtx();
  const servers = useApp((s) => s.servers);
  const activeServerId = useApp((s) => s.activeServerId);
  const [name, setName] = useState(edit?.name ?? "");
  // A cloud vault can be created on ANY linked server with a live session — pick which.
  const cloudServers = servers.filter((s) => s.connected && s.hasSession && s.serverId);
  const cloudReady = cloudServers.length > 0;
  const [target, setTarget] = useState<SyncTarget>("local");
  const [cloudServer, setCloudServer] = useState<string>(() =>
    activeServerId && cloudServers.some((s) => s.serverId === activeServerId)
      ? activeServerId
      : cloudServers[0]?.serverId ?? "",
  );
  const [busy, setBusy] = useState(false);

  const save = async () => {
    const nm = name.trim();
    if (!nm || busy) return;
    setBusy(true);
    try {
      if (edit) {
        await api.renameVault(edit.vaultId, nm);
        await useApp.getState().reloadVaults();
        onClose();
        ctx.toast(t("vault.renamed"), "ok");
      } else if (target === "cloud") {
        const id = await api.serverCreateCloudVault(nm, cloudServer || undefined);
        await useApp.getState().reloadVaults();
        if (!keepActive) await useApp.getState().setVault(id);
        onCreated?.(id);
        onClose();
        ctx.toast(t("shell.vaultCloudCreated"), "ok");
      } else {
        const id = `vault-${Date.now()}`;
        await api.createVault(id, nm);
        await useApp.getState().reloadVaults();
        if (!keepActive) await useApp.getState().setVault(id);
        onCreated?.(id);
        onClose();
        ctx.toast(t("vault.created"), "ok");
      }
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  return (
    <Modal
      position="absolute"
      zIndex={150}
      w={540}
      icon="layers"
      iconColor={p.accent}
      title={edit ? t("vault.renameTitle") : t("vault.newTitle")}
      onClose={onClose}
      footer={
        <React.Fragment>
          <div style={{ flex: isMobile ? "1 1 100%" : 1 }} />
          <Btn
            variant="ghost"
            onClick={onClose}
            disabled={busy}
            style={isMobile ? { minHeight: 44, flex: 1 } : undefined}
          >
            {t("common.cancel")}
          </Btn>
          <Btn
            icon="check"
            onClick={save}
            disabled={busy}
            style={isMobile ? { minHeight: 44, flex: 1 } : undefined}
          >
            {edit ? t("common.save") : t("common.create")}
          </Btn>
        </React.Fragment>
      }
    >
      <NHField label={t("vault.nameLabel")}>
        <NHInput value={name} placeholder={t("vault.namePlaceholder")} accent onChange={setName} />
      </NHField>
      {!edit && (
        <NHField label={t("vault.target")}>
          <MSeg
            value={target}
            set={(v) => {
              if (v === "cloud" && !cloudReady) {
                ctx.toast(t("vault.cloudNeedsServer"), "warn");
                return;
              }
              setTarget(v);
            }}
            options={[
              {
                id: "local",
                label: t("vault.targetLocal"),
                icon: "drive",
                desc: t("vault.targetLocalDesc"),
              },
              {
                id: "cloud",
                label: t("vault.targetCloud"),
                icon: "cloud",
                desc: cloudReady ? t("vault.targetCloudDesc") : t("vault.cloudNeedsServer"),
              },
            ]}
          />
        </NHField>
      )}
      {!edit && target === "cloud" && cloudServers.length > 1 && (
        <NHField label={t("vault.cloudServer")}>
          <NHSelect
            value={cloudServer}
            onChange={setCloudServer}
            options={cloudServers.map((s) => ({
              value: s.serverId as string,
              label: serverShortLabel(s) + (s.owned ? ` · ${t("vault.ownedSpace")}` : ""),
            }))}
            empty=""
          />
        </NHField>
      )}
    </Modal>
  );
}

/** Purpose-built "create a vault to hold identities" flow. Unlike the generic vault
 *  modal it can BOOTSTRAP a new Space on a server (URL + enrollment grant) and put the
 *  vault in it — the path that was missing, so a company identity vault could not be
 *  created from here. Never touches the global active vault. */
function IdentityVaultModal({
  onCreated,
  onClose,
}: {
  onCreated?: (vaultId: string) => void;
  onClose: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const ctx = useCtx();
  const servers = useApp((s) => s.servers);
  const activeServerId = useApp((s) => s.activeServerId);

  // Spaces you OWN with a live session — where a cloud identity vault can live.
  const ownedSpaces = servers.filter((s) => s.connected && s.hasSession && s.owned && s.serverId);
  const NEW_SPACE = "__new__";

  const [name, setName] = useState<string>(t("identityVault.nameDefault"));
  const [target, setTarget] = useState<SyncTarget>(ownedSpaces.length ? "cloud" : "local");
  const [space, setSpace] = useState<string>(
    () =>
      (activeServerId && ownedSpaces.some((s) => s.serverId === activeServerId)
        ? activeServerId
        : ownedSpaces[0]?.serverId) ?? NEW_SPACE,
  );
  const [url, setUrl] = useState("");
  const [grant, setGrant] = useState("");
  const [busy, setBusy] = useState(false);

  const newSpace = target === "cloud" && (ownedSpaces.length === 0 || space === NEW_SPACE);

  const save = async () => {
    const nm = name.trim();
    if (!nm || busy) return;
    if (newSpace && !url.trim()) {
      ctx.toast(t("identityVault.needUrl"), "warn");
      return;
    }
    setBusy(true);
    try {
      let vid: string;
      if (target === "local") {
        vid = `vault-${Date.now()}`;
        await api.createVault(vid, nm);
        await useApp.getState().reloadVaults();
      } else {
        let serverId: string | undefined;
        if (newSpace) {
          // Bootstrap a NEW Space on this server with the enrollment grant, then put the
          // vault in it — creating your (company) Space right from the identity flow.
          const status = await api.serverBootstrap(url.trim(), {
            spaceName: nm,
            bootstrapToken: grant.trim() || undefined,
          });
          await useApp.getState().reloadServerStatus();
          serverId = status.serverId ?? undefined;
        } else {
          serverId = space;
        }
        vid = await api.serverCreateCloudVault(nm, serverId);
        await useApp.getState().reloadVaults();
      }
      onCreated?.(vid);
      onClose();
      ctx.toast(t("identityVault.created"), "ok");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
      setBusy(false);
    }
  };

  return (
    <Modal
      position="absolute"
      zIndex={150}
      w={540}
      icon="fingerprint"
      iconColor={p.accent}
      title={t("identityVault.title")}
      subtitle={t("identityVault.subtitle")}
      onClose={onClose}
      footer={
        <React.Fragment>
          <div style={{ flex: isMobile ? "1 1 100%" : 1 }} />
          <Btn
            variant="ghost"
            onClick={onClose}
            disabled={busy}
            style={isMobile ? { minHeight: 44, flex: 1 } : undefined}
          >
            {t("common.cancel")}
          </Btn>
          <Btn
            icon="check"
            onClick={save}
            disabled={busy}
            style={isMobile ? { minHeight: 44, flex: 1 } : undefined}
          >
            {t("common.create")}
          </Btn>
        </React.Fragment>
      }
    >
      <NHField label={t("identityVault.nameLabel")}>
        <NHInput
          value={name}
          placeholder={t("identityVault.namePlaceholder")}
          accent
          onChange={setName}
        />
      </NHField>
      <NHField label={t("identityVault.location")}>
        <MSeg
          value={target}
          set={setTarget}
          options={[
            {
              id: "local",
              label: t("vault.targetLocal"),
              icon: "drive",
              desc: t("identityVault.localDesc"),
            },
            {
              id: "cloud",
              label: t("vault.targetCloud"),
              icon: "cloud",
              desc: t("identityVault.cloudDesc"),
            },
          ]}
        />
      </NHField>
      {target === "cloud" && ownedSpaces.length > 0 && (
        <NHField label={t("identityVault.space")}>
          <NHSelect
            value={space}
            onChange={setSpace}
            options={[
              ...ownedSpaces.map((s) => ({ value: s.serverId as string, label: serverShortLabel(s) })),
              { value: NEW_SPACE, label: t("identityVault.newSpace") },
            ]}
            empty=""
          />
        </NHField>
      )}
      {newSpace && (
        <>
          <NHField label={t("identityVault.serverUrl")}>
            <NHInput
              value={url}
              placeholder={t("serverCloud.baseUrlPlaceholder")}
              mono
              onChange={setUrl}
            />
          </NHField>
          <NHField label={t("serverCloud.bootstrapToken")}>
            <NHInput
              value={grant}
              placeholder={t("serverCloud.bootstrapTokenPlaceholder")}
              mono
              onChange={setGrant}
            />
          </NHField>
          <div style={{ fontSize: 11.5, color: p.txt3, lineHeight: 1.5, padding: "0 2px" }}>
            {t("identityVault.newSpaceHint")}
          </div>
        </>
      )}
    </Modal>
  );
}

// ── Terminal-theme editor ──────────────────────────────────────

/** Drop the install-local id/custom flag, keeping the portable palette. */
function stripThemeId(t: TermTheme): TermThemePalette {
  // Rest-omit: drop the install-local id/custom flag, keep the portable palette.
  const { id, custom, ...palette } = t;
  return palette;
}

/** Hidden native colour input behind a swatch that shows the exact colour
 *  (including the translucent `sel`). Mirrors the appearance of the grid cards. */
function ColorSwatch({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (hex: string) => void;
}) {
  const p = usePalette();
  return (
    <label style={{ display: "flex", alignItems: "center", gap: 9, cursor: "pointer", minWidth: 0 }}>
      <span style={{ position: "relative", width: 30, height: 30, flexShrink: 0 }}>
        <span
          style={{
            display: "block",
            width: 30,
            height: 30,
            borderRadius: 8,
            background: value,
            border: `1px solid ${p.line2}`,
          }}
        />
        <input
          type="color"
          value={toHexInput(value)}
          onChange={(e) => onChange(e.target.value)}
          style={{ position: "absolute", inset: 0, width: "100%", height: "100%", opacity: 0, cursor: "pointer" }}
        />
      </span>
      <span style={{ fontSize: 12.5, color: p.txt2, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {label}
      </span>
    </label>
  );
}

/** Live mini-terminal preview using the in-progress palette. */
function ThemePreview({ pal }: { pal: TermThemePalette }) {
  const p = usePalette();
  return (
    <div style={{ borderRadius: 11, overflow: "hidden", border: `1px solid ${p.line}` }}>
      <div style={{ padding: "12px 14px", background: pal.bg, fontFamily: MONO, fontSize: 12, lineHeight: 1.6 }}>
        <div>
          <span style={{ color: pal.green }}>$</span> <span style={{ color: pal.fg }}>ssh</span>{" "}
          <span style={{ color: pal.blue }}>web-01</span> <span style={{ color: pal.dimc }}># prod</span>
        </div>
        <div>
          <span style={{ color: pal.purple }}>git</span> <span style={{ color: pal.fg }}>push</span>{" "}
          <span style={{ color: pal.red }}>--force</span>
        </div>
        <div>
          <span style={{ color: pal.yellow }}>warning:</span>{" "}
          <span style={{ background: pal.sel, color: pal.fg }}>selected text</span>{" "}
          <span style={{ color: pal.cyan }}>200 OK</span>
        </div>
      </div>
    </div>
  );
}

function TermThemeModal({ edit, onClose }: { edit?: TermTheme; onClose: () => void }) {
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const { addTermTheme, updateTermTheme, setTermThemeId, termTheme } = useTheme();
  // New theme seeds from the active theme so the user starts somewhere sensible.
  const seedRef = useRef<TermThemePalette | null>(null);
  if (seedRef.current === null) {
    seedRef.current = edit
      ? stripThemeId(edit)
      : { ...stripThemeId(termTheme), name: t("termtheme.defaultName") };
  }
  const [pal, setPal] = useState<TermThemePalette>(() => seedRef.current as TermThemePalette);

  const setColor = (k: TermEditorField, hex: string) => setPal((c) => ({ ...c, [k]: hex }));
  // `sel` is the translucent selection highlight — re-pick the hue but keep the
  // current opacity (so an imported theme's custom alpha survives an edit).
  const setSel = (hex: string) => setPal((c) => ({ ...c, sel: rgba(hex, selAlpha(c.sel)) }));

  const save = () => {
    const name = pal.name.trim();
    if (!name) {
      toast(t("termtheme.nameRequired"), "warn");
      return;
    }
    const clean = { ...pal, name };
    if (edit) {
      updateTermTheme(edit.id, clean);
    } else {
      const created = addTermTheme(clean);
      setTermThemeId(created.id); // select the freshly-made theme
    }
    toast(t("termtheme.saved"), "ok");
    onClose();
  };

  const exportJson = async () => {
    try {
      const { save: saveDialog } = await import("@tauri-apps/plugin-dialog");
      const { writeTextFile } = await import("@tauri-apps/plugin-fs");
      const base = pal.name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
      const path = await saveDialog({
        defaultPath: `${base || "unissh-theme"}.json`,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (!path) return;
      await writeTextFile(path, JSON.stringify(pal, null, 2) + "\n");
      toast(t("termtheme.exported"), "ok");
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  };

  const doImport = async () => {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const { readTextFile } = await import("@tauri-apps/plugin-fs");
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (!selected || Array.isArray(selected)) return;
      const text = await readTextFile(selected);
      const parsed = validateTermThemeImport(JSON.parse(text));
      if (!parsed) {
        toast(t("termtheme.importInvalid"), "err");
        return;
      }
      setPal(parsed); // load into the editor for review before saving
      seedRef.current = parsed; // imported theme is the new "clean" baseline
      toast(t("termtheme.imported"), "ok");
    } catch {
      // malformed JSON or read failure — same honest "invalid file" message
      toast(t("termtheme.importInvalid"), "err");
    }
  };

  const importJson = () => {
    // Importing replaces the editor's contents; if the user has unsaved edits,
    // confirm before discarding them. A pristine editor imports straight away.
    const dirty = JSON.stringify(pal) !== JSON.stringify(seedRef.current);
    if (dirty) {
      useApp.getState().setConfirm({
        title: t("termtheme.importReplaceTitle"),
        body: t("termtheme.importReplaceBody"),
        confirmLabel: t("termtheme.import"),
        onConfirm: () => void doImport(),
      });
    } else {
      void doImport();
    }
  };

  return (
    <Modal
      position="absolute"
      zIndex={150}
      icon="terminal"
      title={edit ? t("termtheme.editTitle") : t("termtheme.newTitle")}
      subtitle={t("termtheme.subtitle")}
      onClose={onClose}
      w={560}
      footer={
        <>
          <Btn
            variant="ghost"
            icon="upload"
            onClick={importJson}
            style={isMobile ? { minHeight: 44, flex: "1 1 calc(50% - 5px)" } : undefined}
          >
            {t("termtheme.import")}
          </Btn>
          <Btn
            variant="ghost"
            icon="download"
            onClick={exportJson}
            style={isMobile ? { minHeight: 44, flex: "1 1 calc(50% - 5px)" } : undefined}
          >
            {t("termtheme.export")}
          </Btn>
          {!isMobile && <div style={{ flex: 1 }} />}
          <Btn
            variant="ghost"
            onClick={onClose}
            style={isMobile ? { minHeight: 44, flex: "1 1 calc(50% - 5px)" } : undefined}
          >
            {t("common.cancel")}
          </Btn>
          <Btn
            icon="check"
            onClick={save}
            style={isMobile ? { minHeight: 44, flex: "1 1 calc(50% - 5px)" } : undefined}
          >
            {t("termtheme.save")}
          </Btn>
        </>
      }
    >
      <NHField label={t("termtheme.nameLabel")}>
        <NHInput
          value={pal.name}
          placeholder={t("termtheme.defaultName")}
          onChange={(v) => setPal((c) => ({ ...c, name: v }))}
        />
      </NHField>
      <ThemePreview pal={pal} />
      <div
        style={{
          display: "grid",
          gridTemplateColumns: isMobile ? "1fr" : "repeat(2, 1fr)",
          gap: "12px 18px",
        }}
      >
        {TERM_EDITOR_FIELDS.map((f) => (
          <ColorSwatch
            key={f}
            label={tDyn(`termtheme.fields.${f}`)}
            value={pal[f] ?? "#ffffff"}
            onChange={(hex) => setColor(f, hex)}
          />
        ))}
        <ColorSwatch label={t("termtheme.fields.sel")} value={pal.sel} onChange={setSel} />
      </div>
    </Modal>
  );
}

// ── Copy public key to server (ssh-copy-id style) ──────────────
function CopyKeyToServerModal({
  openssh,
  keyItemId,
  onClose,
}: {
  openssh: string;
  keyItemId: string;
  onClose: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const ctx = useCtx();
  const vault = useApp((s) => s.vaultId);
  const hosts = useApp((s) => s.hosts);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [pw, setPw] = useState("");
  const [skipPwHosts, setSkipPwHosts] = useState(true);
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  const needsPw = (h: ConnectionProfile) => h.auth.type === "promptPassword";
  const chosen = hosts.filter((h) => selected.has(h.profileId));
  const anyNeedsPw = chosen.some(needsPw);

  const toggle = (id: string) =>
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const selectAll = () => setSelected(new Set(hosts.map((h) => h.profileId)));
  const clearAll = () => setSelected(new Set());

  const install = async () => {
    if (!vault) {
      ctx.toast(t("modals.noActiveVault"), "err");
      return;
    }
    if (chosen.length === 0) {
      ctx.toast(t("modals.copyKey.selectHost"), "warn");
      return;
    }
    // Single-quote the key so the remote shell treats it literally; OpenSSH public
    // keys never contain a single quote, but escape defensively all the same.
    const q = "'" + openssh.trim().replace(/'/g, "'\\''") + "'";
    // Idempotent ssh-copy-id: create ~/.ssh with the perms sshd's StrictModes
    // requires, then append the key only if an identical line isn't already there.
    const cmd =
      `mkdir -p ~/.ssh && chmod 700 ~/.ssh && ` +
      `touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && ` +
      `{ grep -qxF ${q} ~/.ssh/authorized_keys || printf '%s\\n' ${q} >> ~/.ssh/authorized_keys; }`;

    setBusy(true);
    setErrors([]);
    let ok = 0;
    let failed = 0;
    let skipped = 0;
    const errs: string[] = [];
    await Promise.allSettled(
      chosen.map(async (h) => {
        if (needsPw(h) && !pw.trim()) {
          if (skipPwHosts) {
            skipped++;
            return;
          }
          failed++;
          errs.push(`${h.label}: ${t("modals.copyKey.needsPassword")}`);
          return;
        }
        // Personal hosts need a per-host binding + anti-redirect resolution;
        // they can't be batch-connected here (connect them individually — B6).
        if (h.auth.type === "personal") {
          skipped++;
          return;
        }
        try {
          const args: ConnectArgs = {
            host: h.host,
            port: h.port,
            user: h.user,
            auth: profileToAuth(h.auth, vault, needsPw(h) ? pw : undefined),
            jumps: h.jumps,
          };
          const r = await api.sshExec(args, cmd);
          if (r.exitStatus === 0) ok++;
          else {
            failed++;
            errs.push(`${h.label}: ${(r.stderr || "").trim() || `exit ${r.exitStatus}`}`);
          }
        } catch (e) {
          failed++;
          errs.push(`${h.label}: ${apiErrorMessage(e)}`);
        }
      }),
    );
    setBusy(false);
    setErrors(errs);
    if (failed === 0 && skipped === 0) {
      ctx.toast(t("modals.copyKey.installed", { ok }), "ok");
      onClose();
    } else {
      ctx.toast(
        t("modals.copyKey.summary", { ok, failed, skipped }),
        failed > 0 ? (ok > 0 ? "warn" : "err") : "ok",
      );
    }
  };

  return (
    <Modal
      position="absolute"
      zIndex={150}
      icon="upload"
      title={t("modals.copyKey.title")}
      subtitle={t("modals.copyKey.subtitle", { item: keyItemId })}
      onClose={onClose}
      w={520}
      footer={
        <React.Fragment>
          <span style={{ fontSize: 11.5, color: p.txt3 }}>
            {t("modals.copyKey.selectedCount", { count: chosen.length })}
          </span>
          <div style={{ flex: isMobile ? "1 1 100%" : 1 }} />
          <Btn
            variant="ghost"
            onClick={onClose}
            style={isMobile ? { minHeight: 44, flex: 1 } : undefined}
          >
            {t("common.cancel")}
          </Btn>
          <Btn
            icon="upload"
            onClick={install}
            disabled={busy || chosen.length === 0}
            style={isMobile ? { minHeight: 44, flex: 1 } : undefined}
          >
            {t("modals.copyKey.install")}
          </Btn>
        </React.Fragment>
      }
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 2 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: p.txt2, flex: 1 }}>
          {t("modals.copyKey.hostsLabel")}
        </div>
        <span onClick={selectAll} style={{ fontSize: 12, color: p.accent, cursor: "pointer" }}>
          {t("modals.copyKey.selectAll")}
        </span>
        <span onClick={clearAll} style={{ fontSize: 12, color: p.txt3, cursor: "pointer" }}>
          {t("modals.copyKey.clear")}
        </span>
      </div>
      {hosts.length === 0 ? (
        <div style={{ fontSize: 13, color: p.txt3, padding: "10px 2px" }}>
          {t("modals.copyKey.noHosts")}
        </div>
      ) : (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 6,
            maxHeight: 260,
            overflowY: "auto",
            paddingRight: 2,
          }}
        >
          {hosts.map((h) => {
            const on = selected.has(h.profileId);
            return (
              <div
                key={h.profileId}
                onClick={() => toggle(h.profileId)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "9px 11px",
                  borderRadius: 9,
                  cursor: "pointer",
                  background: on ? p.accentSoft : p.bg2,
                  border: `1px solid ${on ? p.accentLine : p.line}`,
                }}
              >
                <span
                  style={{
                    width: 17,
                    height: 17,
                    borderRadius: 5,
                    flexShrink: 0,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    background: on ? p.accent : "transparent",
                    border: `1px solid ${on ? p.accent : p.line2}`,
                    color: "#fff",
                  }}
                >
                  {on && <Icon name="check" size={12} />}
                </span>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {h.label}
                  </div>
                  <div style={{ fontFamily: MONO, fontSize: 11, color: p.txt3 }}>
                    {h.user}@{h.host}
                    {h.port !== 22 ? `:${h.port}` : ""}
                  </div>
                </div>
                {needsPw(h) && (
                  <Tag mono>{t("modals.copyKey.needsPasswordTag")}</Tag>
                )}
              </div>
            );
          })}
        </div>
      )}

      {anyNeedsPw && (
        <React.Fragment>
          <NHField
            label={t("modals.copyKey.passwordLabel")}
            hint={t("modals.copyKey.passwordHint")}
          >
            <NHInput value={pw} type="password" onChange={setPw} />
          </NHField>
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              cursor: "pointer",
              fontSize: 12.5,
              color: p.txt2,
            }}
          >
            <Toggle checked={skipPwHosts} onChange={setSkipPwHosts} />
            {t("modals.copyKey.skipPwHosts")}
          </label>
        </React.Fragment>
      )}

      {errors.length > 0 && (
        <div
          style={{
            borderRadius: 10,
            border: `1px solid ${rgba(p.red, 0.4)}`,
            background: rgba(p.red, 0.08),
            padding: 10,
            display: "flex",
            flexDirection: "column",
            gap: 4,
            maxHeight: 120,
            overflowY: "auto",
          }}
        >
          {errors.map((e, i) => (
            <div key={i} style={{ fontFamily: MONO, fontSize: 11.5, color: p.txt2 }}>
              {e}
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}

// ── Link a personal identity to a Personal host (B5.2c) ─────────
function BindHostModal({
  host,
  vaultId,
  onClose,
}: {
  host: ConnectionProfile;
  vaultId: string;
  onClose: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const vaults = useApp((s) => s.vaults);
  const servers = useApp((s) => s.servers);
  // Private vaults an identity may live in: local, or a cloud vault in a space you own.
  const privateVaults = vaults.filter(
    (v) =>
      v.syncTarget !== "cloud" ||
      servers.some((s) => s.tenantId && s.tenantId === v.syncTenant && s.owned),
  );
  const pvKey = privateVaults.map((v) => v.vaultId).join("|");
  const [bindVault, setBindVault] = useState<string | null>(null);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [binding, setBinding] = useState<IdentityBinding | null>(null);
  const [selected, setSelected] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [busy, setBusy] = useState(false);

  // Pick the vault to bind from: whichever private vault already holds a binding for
  // this host, else the account default, else the first private vault.
  useEffect(() => {
    let alive = true;
    (async () => {
      if (!privateVaults.length) {
        if (alive) {
          setBindVault(null);
          setLoaded(true);
        }
        return;
      }
      let target = privateVaults[0].vaultId;
      let found = false;
      for (const v of privateVaults) {
        const b = await api.getBinding(v.vaultId, vaultId, host.uid).catch(() => null);
        if (!alive) return;
        if (b?.identityItemId) {
          target = v.vaultId;
          found = true;
          break;
        }
      }
      if (!found) {
        const pv = await api.getPersonalVault().catch(() => null);
        if (!alive) return;
        if (pv && privateVaults.some((v) => v.vaultId === pv)) target = pv;
      }
      if (alive) setBindVault(target);
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pvKey, vaultId, host.uid]);

  // Load the chosen vault's identities + its binding for this host.
  useEffect(() => {
    let alive = true;
    (async () => {
      if (!bindVault) {
        if (alive) {
          setIdentities([]);
          setBinding(null);
        }
        return;
      }
      // #15: surface a real load failure instead of masking it as an empty
      // "no identities / unbound" state (which would look like nothing to bind).
      try {
        const ids = await api.listIdentities(bindVault);
        const b = await api.getBinding(bindVault, vaultId, host.uid);
        if (!alive) return;
        setIdentities(ids);
        setBinding(b);
        setSelected((cur) =>
          b?.identityItemId ||
          (cur && ids.some((i) => i.identityId === cur) ? cur : ids[0]?.identityId ?? ""),
        );
      } catch (e) {
        if (!alive) return;
        setLoadError(true);
        toast(apiErrorMessage(e), "err");
      } finally {
        if (alive) setLoaded(true);
      }
    })();
    return () => {
      alive = false;
    };
  }, [bindVault, vaultId, host.uid]);

  const doBind = async () => {
    if (!bindVault || !selected) return;
    setBusy(true);
    try {
      const dest = await api.personalDestination(
        host.host,
        host.port,
        host.usernameTemplate,
        host.jumps,
      );
      // Re-binding (an existing binding present) is an explicit user action here,
      // so allow a changed destination pin; a first bind never needs the flag.
      await api.setBinding(
        bindVault,
        {
          teamVaultId: vaultId,
          profileUid: host.uid,
          identityItemId: selected,
          destinationPin: dest,
        },
        binding !== null,
      );
      toast(t("bind.done"), "ok");
      onClose();
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    } finally {
      setBusy(false);
    }
  };

  const unbind = async () => {
    if (!bindVault) return;
    setBusy(true);
    try {
      await api.deleteBinding(bindVault, vaultId, host.uid);
      toast(t("bind.removed"), "ok");
      onClose();
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    } finally {
      setBusy(false);
    }
  };

  const pvName = vaults.find((v) => v.vaultId === bindVault)?.name ?? "";

  return (
    <Modal
      position="absolute"
      zIndex={150}
      w={540}
      icon="fingerprint"
      iconColor={p.purple}
      title={t("bind.title")}
      subtitle={`${host.user ? host.user + "@" : ""}${host.host}:${host.port}`}
      onClose={onClose}
      footer={
        <>
          <Btn variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Btn>
          {binding && (
            <Btn variant="ghost" onClick={unbind} disabled={busy}>
              {t("bind.unlink")}
            </Btn>
          )}
          <Btn
            icon="check"
            onClick={doBind}
            disabled={busy || !bindVault || !selected}
          >
            {t("bind.link")}
          </Btn>
        </>
      }
    >
      {!loaded ? (
        <div style={{ display: "flex", justifyContent: "center", padding: 24 }}>
          <Spinner />
        </div>
      ) : !bindVault ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 12, alignItems: "flex-start" }}>
          <div style={{ fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
            {t("bind.noPersonalVault")}
          </div>
          <Btn
            size="sm"
            icon="key"
            onClick={() => {
              onClose();
              useApp.getState().go("identities");
            }}
          >
            {t("bind.setUpPersonal")}
          </Btn>
        </div>
      ) : loadError ? (
        <div style={{ fontSize: 13, color: p.red, lineHeight: 1.5 }}>{t("bind.loadError")}</div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {/* Which private vault the identity lives in (work vs. personal server). */}
          {privateVaults.length > 1 && (
            <NHField label={t("secrets.identityVault")}>
              <NHSelect
                value={bindVault ?? ""}
                onChange={setBindVault}
                options={privateVaults.map((v) => {
                  const loc = vaultLoc(v, servers);
                  return {
                    value: v.vaultId,
                    label: `${v.name || v.vaultId} · ${loc.local ? t("secrets.locLocal") : t("secrets.locCloud", { server: loc.server ?? "cloud" })}`,
                  };
                })}
                empty=""
              />
            </NHField>
          )}
          {identities.length === 0 ? (
            <div style={{ fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
              {t("bind.noIdentities", { vault: pvName })}
            </div>
          ) : (
            <>
              <div style={{ fontSize: 12.5, color: p.txt3, lineHeight: 1.5 }}>
                {t("bind.intro", { vault: pvName })}
              </div>
              <NHField label={t("bind.identity")}>
                <NHSelect
                  value={selected}
                  onChange={setSelected}
                  options={identities.map((i) => ({
                    value: i.identityId,
                    label: `${i.label} · ${i.user || "—"}`,
                  }))}
                  empty={t("bind.noIdentities", { vault: pvName })}
                />
              </NHField>
              {binding && (
                <div style={{ fontSize: 11.5, color: p.txt3 }}>
                  {t("bind.currentPin", { pin: binding.destinationPin })}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </Modal>
  );
}

// ── Root dispatcher ────────────────────────────────────────────
export function Modals() {
  const modal = useApp((s) => s.modal);
  const closeModal = useApp((s) => s.closeModal);
  if (!modal) return null;
  if (modal.kind === "host") return <NewHostModal edit={modal.edit} onClose={closeModal} />;
  if (modal.kind === "bindHost")
    return <BindHostModal host={modal.host} vaultId={modal.vaultId} onClose={closeModal} />;
  if (modal.kind === "key") return <NewKeyModal onClose={closeModal} />;
  if (modal.kind === "tunnel") return <NewTunnelModal onClose={closeModal} />;
  if (modal.kind === "vault")
    return (
      <NewVaultModal
        edit={modal.edit}
        onCreated={modal.onCreated}
        keepActive={modal.keepActive}
        onClose={closeModal}
      />
    );
  if (modal.kind === "identityVault")
    return <IdentityVaultModal onCreated={modal.onCreated} onClose={closeModal} />;
  if (modal.kind === "termtheme") return <TermThemeModal edit={modal.edit} onClose={closeModal} />;
  if (modal.kind === "copyKeyToServer")
    return (
      <CopyKeyToServerModal
        openssh={modal.openssh}
        keyItemId={modal.keyItemId}
        onClose={closeModal}
      />
    );
  return null;
}
