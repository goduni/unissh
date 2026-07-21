// Secrets — Keys / Passwords / Notes. Reveal + copy, wired to the real vault.
// Pixel-faithful port of view-secrets.jsx; mock data replaced with store items
// and api.* calls. Active tab follows store.route (keys|passwords|notes).

import { useEffect, useRef, useState, type CSSProperties } from "react";
import { writeSecretToClipboard } from "@/bridge/clipboard";
import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { useTranslation } from "@/i18n";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, UI } from "@/theme/tokens";
import { Btn, Icon, NO_AUTOCORRECT, VaultBadge } from "@/components/primitives";
import { UnderlineTabs, fmtRelative, FlatAvatar, MetaChip, RowOverflowMenu, Card, HairlineRow } from "@/components/mono";
import { useApp } from "@/store/app";
import { useCtx } from "@/store/ctx";
import { useNarrow } from "@/store/responsive";
import * as api from "@/bridge/api";
import { apiErrorMessage, ItemType } from "@/bridge/types";
import type { ItemInfo, Identity, ServerStatus, VaultInfo } from "@/bridge/types";
import { isOwnedCloud, serverShortLabel, vaultLoc, vaultServer } from "@/bridge/vaults";

type SecretTab = "keys" | "passwords" | "notes" | "identities";

async function copy(text: string, ok: () => void, fail: (e: unknown) => void) {
  try {
    await writeSecretToClipboard(text);
    ok();
  } catch (e) {
    fail(e);
  }
}

/** Transient "copied ✓" flag for copy-to-clipboard buttons: `flash()` turns
 *  `copied` on, then auto-resets it after `resetMs`. Pass `flash` as the success
 *  callback of `copy(...)`. */
function useCopied(resetMs = 1200) {
  const [copied, setCopied] = useState(false);
  const flash = () => {
    setCopied(true);
    setTimeout(() => setCopied(false), resetMs);
  };
  return { copied, flash };
}

/** How many hosts in the active vault still depend on a given SSH key — as their
 *  own login or via a jump hop. Drives the "in use" caution before deleting it. */
function countKeyRefs(keyItemId: string): number {
  let n = 0;
  for (const h of useApp.getState().hosts) {
    if (
      (h.auth.type === "key" && h.auth.keyItemId === keyItemId) ||
      h.jumps.some((j) => j.auth.type === "agent" && j.auth.keyItemId === keyItemId)
    )
      n++;
  }
  return n;
}

function TabBar({
  tab,
  setTab,
  counts,
  isMobile,
}: {
  tab: SecretTab;
  setTab: (t: SecretTab) => void;
  counts: Record<SecretTab, number>;
  isMobile: boolean;
}) {
  const { t } = useTranslation();
  const tabs: { id: SecretTab; icon: "key" | "lock" | "note" | "fingerprint"; label: string }[] = [
    { id: "keys", icon: "key", label: t("nav.keys") },
    { id: "passwords", icon: "lock", label: t("nav.passwords") },
    { id: "identities", icon: "fingerprint", label: t("nav.identities") },
    { id: "notes", icon: "note", label: t("nav.notes") },
  ];
  return (
    <div style={{ overflowX: isMobile ? "auto" : "visible", minWidth: 0 }}>
      <UnderlineTabs<SecretTab>
        ariaLabel={t("nav.secrets")}
        value={tab}
        onChange={setTab}
        tabs={tabs.map((tb) => ({
          value: tb.id,
          label: (
            <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
              <Icon name={tb.icon} size={15} stroke={1.8} />
              {tb.label}
            </span>
          ),
          count: counts[tb.id],
        }))}
      />
    </div>
  );
}

/** Masked field that lazily reveals its value via `load` on first reveal. */
function RevealField({
  load,
  onError,
  mono = true,
}: {
  load: () => Promise<string>;
  onError: (e: unknown) => void;
  mono?: boolean;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const [shown, setShown] = useState(false);
  const { copied, flash } = useCopied();
  const [value, setValue] = useState<string | null>(null);

  const toggle = async () => {
    if (shown) {
      // Hiding: drop the cached plaintext so it doesn't linger in state (showing
      // again re-reads via load()). Narrows the secret's lifetime in memory.
      setShown(false);
      setValue(null);
      return;
    }
    if (value === null) {
      try {
        setValue(await load());
      } catch (e) {
        onError(e);
        return;
      }
    }
    setShown(true);
  };

  const doCopy = async () => {
    let v = value;
    if (v === null) {
      try {
        v = await load();
        setValue(v);
      } catch (e) {
        onError(e);
        return;
      }
    }
    await copy(v, flash, onError);
  };

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        height: 34,
        padding: "0 6px 0 12px",
        borderRadius: 8,
        background: p.bg0,
        border: `1px solid ${p.line}`,
      }}
    >
      <span
        style={{
          flex: 1,
          fontFamily: mono ? MONO : UI,
          fontSize: 13,
          color: shown ? p.txt : p.txt3,
          letterSpacing: shown ? 0 : 2,
          whiteSpace: "nowrap",
          overflow: "hidden",
        }}
      >
        {shown ? (value ?? "") : "•".repeat(14)}
      </span>
      <button
        onClick={toggle}
        title={shown ? t("common.hide") : t("common.show")}
        aria-label={shown ? t("common.hide") : t("common.show")}
        aria-pressed={shown}
        style={{
          width: 28,
          height: 26,
          borderRadius: 8,
          border: "none",
          background: "transparent",
          color: p.txt3,
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Icon name="eye" size={15} />
      </button>
      <button
        onClick={doCopy}
        title={t("common.copy")}
        aria-label={t("common.copy")}
        style={{
          width: 28,
          height: 26,
          borderRadius: 8,
          border: "none",
          background: copied ? p.accentSoft : "transparent",
          color: copied ? p.accentText : p.txt3,
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Icon name={copied ? "check" : "copy"} size={14} />
      </button>
    </div>
  );
}

// ── Keys ───────────────────────────────────────────────────────
function KeyRow({ item, isMobile, first }: { item: ItemInfo; isMobile: boolean; first?: boolean }) {
  const p = usePalette();
  const { t, i18n } = useTranslation();
  const ctx = useCtx();
  const uses = countKeyRefs(item.itemId);
  const vault = useApp((s) => s.vaultId);
  const [fp, setFp] = useState<string | null>(null);
  const [openssh, setOpenssh] = useState<string | null>(null);
  const { copied, flash } = useCopied();

  useEffect(() => {
    let alive = true;
    if (!vault) return;
    (async () => {
      try {
        const pk = await api.getPublicKey(vault, item.itemId);
        if (alive) {
          setFp(pk.fingerprint);
          setOpenssh(pk.openssh);
        }
      } catch {
        /* leave unknown */
      }
    })();
    return () => {
      alive = false;
    };
  }, [vault, item.itemId]);

  const doCopy = () => {
    if (!openssh) return;
    copy(openssh, flash, (e) => ctx.toast(apiErrorMessage(e), "err"));
  };

  // Export the private key to a user-chosen file (backup/migration). Gated by an
  // explicit confirm; the save dialog is the second deliberate step.
  const onExport = () => {
    if (!vault) return;
    ctx.confirm({
      title: t("secrets.exportKeyTitle"),
      body: t("secrets.exportKeyBody", { item: item.itemId }),
      danger: true,
      confirmLabel: t("secrets.exportKeyConfirm"),
      icon: "download",
      onConfirm: async () => {
        try {
          const pem = await api.exportSshKey(vault, item.itemId);
          const path = await save({ defaultPath: item.itemId, title: t("secrets.exportKeyTitle") });
          if (!path) return; // user cancelled the save dialog
          await writeTextFile(path, pem);
          ctx.toast(t("secrets.keyExported"), "ok");
        } catch (e) {
          ctx.toast(apiErrorMessage(e), "err");
        }
      },
    });
  };

  // Rotate in place: new keypair under the same item id, so every host
  // referencing it follows automatically. Only the servers' authorized_keys
  // must be updated with the new public key (shown/copyable after rotation).
  const onRotate = () => {
    if (!vault) return;
    ctx.confirm({
      title: t("secrets.rotateKeyTitle"),
      body: t("secrets.rotateKeyBody", { item: item.itemId }),
      danger: true,
      confirmLabel: t("secrets.rotateKeyConfirm"),
      icon: "refresh",
      onConfirm: async () => {
        try {
          await api.rotateSshKey(vault, item.itemId);
          // Refresh the item list so the row's version + cert badge update
          // (rotation bumps the version and drops the now-invalid certificate).
          await useApp.getState().reloadVault();
          const pk = await api.getPublicKey(vault, item.itemId);
          setFp(pk.fingerprint);
          setOpenssh(pk.openssh);
          ctx.toast(t("secrets.keyRotated"), "ok");
        } catch (e) {
          ctx.toast(apiErrorMessage(e), "err");
        }
      },
    });
  };

  const onDelete = () => {
    if (!vault) return;
    // Warn if the key still backs any host login (direct auth or a jump hop), so
    // deleting it doesn't silently break those connections.
    ctx.confirm({
      title: t("secrets.deleteKeyTitle"),
      body: uses > 0 ? t("secrets.deleteKeyInUse", { item: item.itemId, count: uses }) : item.itemId,
      danger: true,
      confirmLabel: t("common.delete"),
      icon: "trash",
      onConfirm: async () => {
        try {
          await api.deleteItem(vault, item.itemId);
          await useApp.getState().reloadVault();
          ctx.toast(t("secrets.keyDeleted"), "ok");
        } catch (e) {
          ctx.toast(apiErrorMessage(e), "err");
        }
      },
    });
  };

  const actBtn = {
    width: isMobile ? 40 : 28,
    height: isMobile ? 40 : 28,
    borderRadius: 8,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  } as const;
  return (
    <HairlineRow
      first={first}
      style={{
        alignItems: isMobile ? "stretch" : "center",
        flexDirection: isMobile ? "column" : "row",
        gap: isMobile ? 10 : 14,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: isMobile ? 12 : 14, minWidth: 0 }}>
        <span
          style={{
            width: 40,
            height: 40,
            borderRadius: 12,
            background: p.bg3,
            border: `1px solid ${p.line}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name="key" size={18} color={p.txt2} />
        </span>
        <div style={{ width: isMobile ? "auto" : 150, flexShrink: 0, minWidth: 0 }}>
          <div style={{ fontSize: 14, fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {item.itemId}
          </div>
          <div style={{ fontFamily: MONO, fontSize: 11, color: p.txt3 }}>
            {t("secrets.updatedAgo", { ago: fmtRelative(item.updatedAt, i18n.language) })}
            {item.hasCertificate ? " · cert" : ""}
          </div>
        </div>
      </div>
      <span
        style={{
          flex: 1,
          width: isMobile ? "100%" : undefined,
          fontFamily: MONO,
          fontSize: 12,
          color: p.txt2,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {fp ?? "…"}
      </span>
      <MetaChip icon="link" tone={uses === 0 ? "warn" : "neutral"}>
        {uses === 0 ? t("secrets.unused") : t("secrets.usedByHosts", { count: uses })}
      </MetaChip>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: isMobile ? 10 : 14,
          flexWrap: isMobile ? "wrap" : "nowrap",
          justifyContent: isMobile ? "flex-end" : "flex-start",
        }}
      >
        <button
          onClick={doCopy}
          title={t("secrets.copyPublicKey")}
          aria-label={t("secrets.copyPublicKey")}
          disabled={!openssh}
          style={{
            ...actBtn,
            border: `1px solid ${p.line}`,
            background: copied ? p.accentSoft : p.bg2,
            color: copied ? p.accentText : p.txt3,
            cursor: openssh ? "pointer" : "default",
            opacity: openssh ? 1 : 0.5,
          }}
        >
          <Icon name={copied ? "check" : "copy"} size={14} />
        </button>
        <RowOverflowMenu
          ariaLabel={t("secrets.keyActions")}
          items={[
            {
              label: t("secrets.copyToServer"),
              icon: "upload",
              onClick: () => {
                if (openssh)
                  ctx.openModal({ kind: "copyKeyToServer", openssh, keyItemId: item.itemId });
              },
            },
            { label: t("secrets.rotateKey"), icon: "refresh", onClick: onRotate },
            { label: t("secrets.exportPrivateKey"), icon: "download", onClick: onExport },
          ]}
        />
        <button
          onClick={onDelete}
          title={t("common.delete")}
          aria-label={t("common.delete")}
          style={{
            ...actBtn,
            border: `1px solid ${p.line}`,
            background: p.bg2,
            color: p.red,
            cursor: "pointer",
          }}
        >
          <Icon name="trash" size={14} />
        </button>
      </div>
    </HairlineRow>
  );
}

function KeysTab({ keys, isMobile }: { keys: ItemInfo[]; isMobile: boolean }) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div>
        {keys.map((k, i) => (
          <KeyRow key={k.itemId} item={k} isMobile={isMobile} first={i === 0} />
        ))}
      </div>
      <button
        onClick={() => ctx.openModal({ kind: "key" })}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 8,
          padding: 13,
          borderRadius: 12,
          border: `1px dashed ${p.line2}`,
          background: "transparent",
          color: p.txt2,
          cursor: "pointer",
          fontSize: 13,
          fontWeight: 600,
        }}
      >
        <Icon name="plus" size={15} />
        {t("secrets.generateKeyPair")}
      </button>
    </div>
  );
}

// ── Passwords ──────────────────────────────────────────────────
function NewPasswordCard({ openSignal }: { openSignal: number }) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const vault = useApp((s) => s.vaultId);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const nameRef = useRef<HTMLInputElement>(null);
  const lastSignal = useRef(openSignal);

  // Open from the header "+" button (signal bump). Compare against the mount
  // value so a tab switch that remounts with a stale signal doesn't auto-open.
  useEffect(() => {
    if (openSignal !== lastSignal.current) {
      lastSignal.current = openSignal;
      setOpen(true);
    }
  }, [openSignal]);
  useEffect(() => {
    if (open) {
      nameRef.current?.focus();
      nameRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [open]);

  const save = async () => {
    if (!vault || !name.trim() || !value) return;
    try {
      await api.savePassword(vault, name.trim(), value);
      await useApp.getState().reloadVault();
      ctx.toast(t("secrets.passwordSaved"), "ok");
      setOpen(false);
      setName("");
      setValue("");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 8,
          padding: 15,
          borderRadius: 12,
          border: `1px dashed ${p.line2}`,
          background: "transparent",
          color: p.txt2,
          cursor: "pointer",
          fontSize: 13,
          fontWeight: 600,
        }}
      >
        <Icon name="plus" size={15} />
        {t("secrets.newPassword")}
      </button>
    );
  }
  return (
    <div style={{ padding: 15, borderRadius: 12, background: p.bg1, border: `1px solid ${p.line}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <span
          style={{
            width: 34,
            height: 34,
            borderRadius: 8,
            background: p.bg3,
            border: `1px solid ${p.line}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name="lock" size={16} color={p.txt2} />
        </span>
        <input
          ref={nameRef}
          {...NO_AUTOCORRECT}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={t("secrets.namePlaceholder")}
          style={{
            flex: 1,
            minWidth: 0,
            height: 34,
            padding: "0 10px",
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: p.bg0,
            color: p.txt,
            fontFamily: MONO,
            fontSize: 13,
          }}
        />
      </div>
      <input
        {...NO_AUTOCORRECT}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder={t("secrets.valuePlaceholder")}
        style={{
          width: "100%",
          height: 34,
          padding: "0 12px",
          borderRadius: 8,
          border: `1px solid ${p.line}`,
          background: p.bg0,
          color: p.txt,
          fontFamily: MONO,
          fontSize: 13,
          marginBottom: 10,
        }}
      />
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
        <Btn variant="ghost" size="sm" onClick={() => setOpen(false)}>
          {t("common.cancel")}
        </Btn>
        <Btn icon="check" size="sm" onClick={save} disabled={!name.trim() || !value}>
          {t("common.save")}
        </Btn>
      </div>
    </div>
  );
}

function PasswordCard({ item }: { item: ItemInfo }) {
  const p = usePalette();
  const { t, i18n } = useTranslation();
  const ctx = useCtx();
  const vault = useApp((s) => s.vaultId);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");

  // Edit overwrites the same item id, so any host referencing it follows along.
  const startEdit = async () => {
    if (!vault) return;
    try {
      setDraft(await api.getPassword(vault, item.itemId));
      setEditing(true);
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };
  const saveEdit = async () => {
    if (!vault || !draft) return;
    try {
      await api.savePassword(vault, item.itemId, draft);
      await useApp.getState().reloadVault();
      setEditing(false);
      ctx.toast(t("secrets.passwordSaved"), "ok");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  const onDelete = () => {
    if (!vault) return;
    ctx.confirm({
      title: t("secrets.deletePasswordTitle"),
      body: item.itemId,
      danger: true,
      confirmLabel: t("common.delete"),
      icon: "trash",
      onConfirm: async () => {
        try {
          await api.deleteItem(vault, item.itemId);
          await useApp.getState().reloadVault();
          ctx.toast(t("secrets.passwordDeleted"), "ok");
        } catch (e) {
          ctx.toast(apiErrorMessage(e), "err");
        }
      },
    });
  };

  return (
    <Card>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <span
          style={{
            width: 34,
            height: 34,
            borderRadius: 8,
            background: p.bg3,
            border: `1px solid ${p.line}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name="lock" size={16} color={p.txt2} />
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 14, fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {item.itemId}
          </div>
          <div style={{ fontFamily: MONO, fontSize: 11, color: p.txt3 }}>
            {t("secrets.updatedAgo", { ago: fmtRelative(item.updatedAt, i18n.language) })}
          </div>
        </div>
        <button
          onClick={editing ? saveEdit : startEdit}
          title={editing ? t("common.save") : t("common.edit")}
          aria-label={editing ? t("common.save") : t("common.edit")}
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: p.bg2,
            color: editing ? p.accentText : p.txt3,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name={editing ? "check" : "pencil"} size={14} />
        </button>
        <button
          onClick={onDelete}
          title={t("common.delete")}
          aria-label={t("common.delete")}
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: p.bg2,
            color: p.txt3,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name="trash" size={14} />
        </button>
      </div>
      {editing ? (
        <input
          autoFocus
          {...NO_AUTOCORRECT}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={t("secrets.valuePlaceholder")}
          style={{
            width: "100%",
            height: 34,
            padding: "0 12px",
            borderRadius: 8,
            border: `1px solid ${p.line2}`,
            background: p.bg0,
            color: p.txt,
            fontFamily: MONO,
            fontSize: 13,
          }}
        />
      ) : (
        <RevealField
          load={() => api.getPassword(vault!, item.itemId)}
          onError={(e) => ctx.toast(apiErrorMessage(e), "err")}
        />
      )}
    </Card>
  );
}

function PasswordsTab({
  passwords,
  openSignal,
  isMobile,
}: {
  passwords: ItemInfo[];
  openSignal: number;
  isMobile: boolean;
}) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: isMobile ? "1fr" : "repeat(2, 1fr)",
        gap: 12,
      }}
    >
      {passwords.map((pw) => (
        <PasswordCard key={pw.itemId} item={pw} />
      ))}
      <NewPasswordCard openSignal={openSignal} />
    </div>
  );
}

// ── Notes ──────────────────────────────────────────────────────
function NoteCard({ item, first }: { item: ItemInfo; first?: boolean }) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const vault = useApp((s) => s.vaultId);
  const [body, setBody] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const { copied, flash } = useCopied();

  const reveal = async () => {
    if (!vault) return;
    try {
      const text = await api.getNote(vault, item.itemId);
      setBody(text);
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  const startEdit = async () => {
    if (!vault) return;
    let text = body;
    if (text === null) {
      try {
        text = await api.getNote(vault, item.itemId);
        setBody(text);
      } catch (e) {
        ctx.toast(apiErrorMessage(e), "err");
        return;
      }
    }
    setDraft(text);
    setEditing(true);
  };

  const saveEdit = async () => {
    if (!vault) return;
    try {
      await api.saveNote(vault, item.itemId, draft);
      await useApp.getState().reloadVault();
      setBody(draft);
      setEditing(false);
      ctx.toast(t("secrets.noteSaved"), "ok");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  const doCopy = async () => {
    let text = body;
    if (text === null) {
      try {
        text = await api.getNote(vault!, item.itemId);
        setBody(text);
      } catch (e) {
        ctx.toast(apiErrorMessage(e), "err");
        return;
      }
    }
    await copy(text, flash, (e) => ctx.toast(apiErrorMessage(e), "err"));
  };

  const onDelete = () => {
    if (!vault) return;
    ctx.confirm({
      title: t("secrets.deleteNoteTitle"),
      body: item.itemId,
      danger: true,
      confirmLabel: t("common.delete"),
      icon: "trash",
      onConfirm: async () => {
        try {
          await api.deleteItem(vault, item.itemId);
          await useApp.getState().reloadVault();
          ctx.toast(t("secrets.noteDeleted"), "ok");
        } catch (e) {
          ctx.toast(apiErrorMessage(e), "err");
        }
      },
    });
  };

  return (
    <HairlineRow first={first} style={{ flexDirection: "column", alignItems: "stretch", gap: 0 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 10 }}>
        <Icon name="note" size={16} color={p.txt2} />
        <span style={{ fontSize: 14, fontWeight: 700 }}>{item.itemId}</span>
        <div style={{ flex: 1 }} />
        <button
          onClick={editing ? saveEdit : startEdit}
          title={editing ? t("common.save") : t("common.edit")}
          aria-label={editing ? t("common.save") : t("common.edit")}
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: p.bg2,
            color: editing ? p.accentText : p.txt3,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name={editing ? "check" : "pencil"} size={14} />
        </button>
        <button
          onClick={doCopy}
          title={t("common.copy")}
          aria-label={t("common.copy")}
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: copied ? p.accentSoft : p.bg2,
            color: copied ? p.accentText : p.txt3,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name={copied ? "check" : "copy"} size={14} />
        </button>
        <button
          onClick={onDelete}
          title={t("common.delete")}
          aria-label={t("common.delete")}
          style={{
            width: 28,
            height: 28,
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
          <Icon name="trash" size={14} />
        </button>
      </div>
      {editing ? (
        <textarea
          autoFocus
          {...NO_AUTOCORRECT}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={5}
          style={{
            width: "100%",
            resize: "vertical",
            fontFamily: MONO,
            fontSize: 13,
            color: p.txt,
            lineHeight: 1.7,
            background: p.bg0,
            border: `1px solid ${p.line2}`,
            borderRadius: 8,
            padding: 10,
          }}
        />
      ) : body === null ? (
        <button
          onClick={reveal}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 7,
            padding: "6px 0",
            background: "transparent",
            border: "none",
            color: p.txt3,
            cursor: "pointer",
            fontFamily: UI,
            fontSize: 13,
          }}
        >
          <Icon name="eye" size={14} />
          {t("secrets.showNote")}
        </button>
      ) : (
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <button
              type="button"
              onClick={() => setBody(null)}
              title={t("secrets.hideNote")}
              aria-label={t("secrets.hideNote")}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                border: "none",
                background: "transparent",
                padding: 0,
                color: p.txt3,
                fontFamily: UI,
                fontSize: 13,
                cursor: "pointer",
              }}
            >
              <Icon name="eye" size={14} />
              {t("secrets.hideNote")}
            </button>
            <div style={{ flex: 1 }} />
            <button
              type="button"
              onClick={async () => {
                await writeSecretToClipboard(body);
                flash();
              }}
              title={t("common.copy")}
              aria-label={t("common.copy")}
              style={{
                display: "inline-flex",
                alignItems: "center",
                border: "none",
                background: "transparent",
                padding: 0,
                color: copied ? p.green : p.txt3,
                cursor: "pointer",
              }}
            >
              <Icon name={copied ? "check" : "copy"} size={14} />
            </button>
          </div>
          <pre
            style={{
              margin: 0,
              fontFamily: MONO,
              fontSize: 13,
              color: p.txt2,
              lineHeight: 1.7,
              whiteSpace: "pre-wrap",
            }}
          >
            {body}
          </pre>
        </div>
      )}
    </HairlineRow>
  );
}

function NewNoteCard({ openSignal }: { openSignal: number }) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const vault = useApp((s) => s.vaultId);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [text, setText] = useState("");
  const nameRef = useRef<HTMLInputElement>(null);
  const lastSignal = useRef(openSignal);

  useEffect(() => {
    if (openSignal !== lastSignal.current) {
      lastSignal.current = openSignal;
      setOpen(true);
    }
  }, [openSignal]);
  useEffect(() => {
    if (open) {
      nameRef.current?.focus();
      nameRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [open]);

  const save = async () => {
    if (!vault || !name.trim()) return;
    try {
      await api.saveNote(vault, name.trim(), text);
      await useApp.getState().reloadVault();
      ctx.toast(t("secrets.noteSaved"), "ok");
      setOpen(false);
      setName("");
      setText("");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 8,
          padding: 16,
          borderRadius: 12,
          border: `1px dashed ${p.line2}`,
          background: "transparent",
          color: p.txt2,
          cursor: "pointer",
          fontSize: 13,
          fontWeight: 600,
        }}
      >
        <Icon name="plus" size={15} />
        {t("secrets.newNote")}
      </button>
    );
  }
  return (
    <div style={{ padding: 16, borderRadius: 12, background: p.bg1, border: `1px solid ${p.line}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 10 }}>
        <Icon name="note" size={16} color={p.txt2} />
        <input
          ref={nameRef}
          {...NO_AUTOCORRECT}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={t("secrets.namePlaceholder")}
          style={{
            flex: 1,
            minWidth: 0,
            height: 32,
            padding: "0 10px",
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: p.bg0,
            color: p.txt,
            fontFamily: MONO,
            fontSize: 13,
          }}
        />
      </div>
      <textarea
        {...NO_AUTOCORRECT}
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={5}
        placeholder={t("secrets.noteTextPlaceholder")}
        style={{
          width: "100%",
          resize: "vertical",
          fontFamily: MONO,
          fontSize: 13,
          color: p.txt,
          lineHeight: 1.7,
          background: p.bg0,
          border: `1px solid ${p.line2}`,
          borderRadius: 8,
          padding: 10,
          marginBottom: 10,
        }}
      />
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
        <Btn variant="ghost" size="sm" onClick={() => setOpen(false)}>
          {t("common.cancel")}
        </Btn>
        <Btn icon="check" size="sm" onClick={save} disabled={!name.trim()}>
          {t("common.save")}
        </Btn>
      </div>
    </div>
  );
}

function NotesTab({ notes, openSignal }: { notes: ItemInfo[]; openSignal: number }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div>
        {notes.map((n, i) => (
          <NoteCard key={n.itemId} item={n} first={i === 0} />
        ))}
      </div>
      <NewNoteCard openSignal={openSignal} />
    </div>
  );
}

// ── Identities ─────────────────────────────────────────────────
// A personal identity = a username + an optional reference to a key or password
// item in the SAME vault. Lives in a personal vault; linked to a shared host via
// a binding (B3). The credential picker below only lists this vault's keys/pws.
const selectStyle = (p: ReturnType<typeof usePalette>) => ({
  width: "100%",
  height: 34,
  padding: "0 10px",
  borderRadius: 8,
  border: `1px solid ${p.line}`,
  background: p.bg0,
  color: p.txt,
  fontFamily: MONO,
  fontSize: 13,
});

// Encode a chosen credential as "none" | "key:<id>" | "pw:<id>".
function credToFields(cred: string): { keyItemId: string | null; passwordItemId: string | null } {
  if (cred.startsWith("key:")) return { keyItemId: cred.slice(4), passwordItemId: null };
  if (cred.startsWith("pw:")) return { keyItemId: null, passwordItemId: cred.slice(3) };
  return { keyItemId: null, passwordItemId: null };
}
function fieldsToCred(id: Identity): string {
  if (id.keyItemId) return `key:${id.keyItemId}`;
  if (id.passwordItemId) return `pw:${id.passwordItemId}`;
  return "none";
}

function CredSelect({
  keys,
  passwords,
  value,
  onChange,
}: {
  keys: ItemInfo[];
  passwords: ItemInfo[];
  value: string;
  onChange: (v: string) => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} style={selectStyle(p)}>
      <option value="none">{t("secrets.identityNoCred")}</option>
      {keys.map((k) => (
        <option key={`key:${k.itemId}`} value={`key:${k.itemId}`}>
          {t("auth.key")}: {k.itemId}
        </option>
      ))}
      {passwords.map((pw) => (
        <option key={`pw:${pw.itemId}`} value={`pw:${pw.itemId}`}>
          {t("auth.password")}: {pw.itemId}
        </option>
      ))}
    </select>
  );
}

function NewIdentityCard({
  openSignal,
  keys,
  passwords,
  vault,
  onChanged,
}: {
  openSignal: number;
  keys: ItemInfo[];
  passwords: ItemInfo[];
  vault: string;
  onChanged: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [user, setUser] = useState("");
  const [cred, setCred] = useState("none");
  const nameRef = useRef<HTMLInputElement>(null);
  const lastSignal = useRef(openSignal);

  useEffect(() => {
    if (openSignal !== lastSignal.current) {
      lastSignal.current = openSignal;
      setOpen(true);
    }
  }, [openSignal]);
  useEffect(() => {
    if (open) {
      nameRef.current?.focus();
      nameRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [open]);

  const save = async () => {
    if (!vault || !name.trim() || !user.trim()) return;
    try {
      await api.saveIdentity(vault, {
        identityId: name.trim(),
        label: name.trim(),
        user: user.trim(),
        ...credToFields(cred),
      });
      onChanged();
      ctx.toast(t("secrets.identitySaved"), "ok");
      setOpen(false);
      setName("");
      setUser("");
      setCred("none");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 8,
          padding: 15,
          borderRadius: 12,
          border: `1px dashed ${p.line2}`,
          background: "transparent",
          color: p.txt2,
          cursor: "pointer",
          fontSize: 13,
          fontWeight: 600,
        }}
      >
        <Icon name="plus" size={15} />
        {t("secrets.newIdentity")}
      </button>
    );
  }
  return (
    <div style={{ padding: 15, borderRadius: 12, background: p.bg1, border: `1px solid ${p.line}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <span
          style={{
            width: 34,
            height: 34,
            borderRadius: 8,
            background: p.bg3,
            border: `1px solid ${p.line}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name="fingerprint" size={16} color={p.txt2} />
        </span>
        <input
          ref={nameRef}
          {...NO_AUTOCORRECT}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={t("secrets.identityNamePlaceholder")}
          style={{
            flex: 1,
            minWidth: 0,
            height: 34,
            padding: "0 10px",
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: p.bg0,
            color: p.txt,
            fontFamily: MONO,
            fontSize: 13,
          }}
        />
      </div>
      <input
        {...NO_AUTOCORRECT}
        value={user}
        onChange={(e) => setUser(e.target.value)}
        placeholder={t("secrets.identityUserPlaceholder")}
        style={{
          width: "100%",
          height: 34,
          padding: "0 12px",
          borderRadius: 8,
          border: `1px solid ${p.line}`,
          background: p.bg0,
          color: p.txt,
          fontFamily: MONO,
          fontSize: 13,
          marginBottom: 10,
        }}
      />
      <div style={{ marginBottom: 10 }}>
        <CredSelect keys={keys} passwords={passwords} value={cred} onChange={setCred} />
      </div>
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
        <Btn variant="ghost" size="sm" onClick={() => setOpen(false)}>
          {t("common.cancel")}
        </Btn>
        <Btn icon="check" size="sm" onClick={save} disabled={!name.trim() || !user.trim()}>
          {t("common.save")}
        </Btn>
      </div>
    </div>
  );
}

function IdentityCard({
  item,
  keys,
  passwords,
  vault,
  onChanged,
}: {
  item: ItemInfo;
  keys: ItemInfo[];
  passwords: ItemInfo[];
  vault: string;
  onChanged: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const [ident, setIdent] = useState<Identity | null>(null);
  const [editing, setEditing] = useState(false);
  const [user, setUser] = useState("");
  const [cred, setCred] = useState("none");

  useEffect(() => {
    if (!vault) return;
    api
      .getIdentity(vault, item.itemId)
      .then(setIdent)
      .catch(() => {});
  }, [vault, item.itemId]);

  const startEdit = () => {
    if (!ident) return;
    setUser(ident.user);
    setCred(fieldsToCred(ident));
    setEditing(true);
  };
  const saveEdit = async () => {
    if (!vault || !user.trim()) return;
    try {
      await api.saveIdentity(vault, {
        identityId: item.itemId,
        label: ident?.label || item.itemId,
        user: user.trim(),
        ...credToFields(cred),
      });
      setIdent(await api.getIdentity(vault, item.itemId));
      onChanged();
      setEditing(false);
      ctx.toast(t("secrets.identitySaved"), "ok");
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };
  const onDelete = async () => {
    if (!vault) return;
    // Best-effort usage check: how many host bindings still point at this identity,
    // so deleting it flags the logins it would leave unbound.
    let uses = 0;
    try {
      const bindings = await api.listBindings(vault);
      uses = bindings.filter((b) => b.identityItemId === item.itemId).length;
    } catch {
      /* bindings unavailable — fall back to the plain confirm */
    }
    ctx.confirm({
      title: t("secrets.deleteIdentityTitle"),
      body:
        uses > 0 ? t("secrets.deleteIdentityInUse", { item: item.itemId, count: uses }) : item.itemId,
      danger: true,
      confirmLabel: t("common.delete"),
      icon: "trash",
      onConfirm: async () => {
        try {
          await api.deleteIdentity(vault, item.itemId);
          onChanged();
          ctx.toast(t("secrets.identityDeleted"), "ok");
        } catch (e) {
          ctx.toast(apiErrorMessage(e), "err");
        }
      },
    });
  };

  const credLabel = ident?.keyItemId
    ? `${t("auth.key")}: ${ident.keyItemId}`
    : ident?.passwordItemId
      ? `${t("auth.password")}: ${ident.passwordItemId}`
      : t("secrets.identityNoCred");

  return (
    <Card>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: editing ? 12 : 0 }}>
        <span
          style={{
            width: 34,
            height: 34,
            borderRadius: 8,
            background: p.bg3,
            border: `1px solid ${p.line}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name="fingerprint" size={16} color={p.txt2} />
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              fontSize: 14,
              fontWeight: 700,
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            {item.itemId}
          </div>
          <div style={{ fontFamily: MONO, fontSize: 11, color: p.txt3 }}>
            {ident ? `${ident.user || "—"} · ${credLabel}` : `v${item.version}`}
          </div>
        </div>
        <button
          onClick={editing ? saveEdit : startEdit}
          title={editing ? t("common.save") : t("common.edit")}
          aria-label={editing ? t("common.save") : t("common.edit")}
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: p.bg2,
            color: editing ? p.accentText : p.txt3,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name={editing ? "check" : "pencil"} size={14} />
        </button>
        <button
          onClick={onDelete}
          title={t("common.delete")}
          aria-label={t("common.delete")}
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: p.bg2,
            color: p.txt3,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name="trash" size={14} />
        </button>
      </div>
      {editing && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <input
            autoFocus
            {...NO_AUTOCORRECT}
            value={user}
            onChange={(e) => setUser(e.target.value)}
            placeholder={t("secrets.identityUserPlaceholder")}
            style={{
              width: "100%",
              height: 34,
              padding: "0 12px",
              borderRadius: 8,
              border: `1px solid ${p.line2}`,
              background: p.bg0,
              color: p.txt,
              fontFamily: MONO,
              fontSize: 13,
            }}
          />
          <CredSelect keys={keys} passwords={passwords} value={cred} onChange={setCred} />
        </div>
      )}
    </Card>
  );
}

/** Identity-vault picker in the app's own switcher idiom (matching the sidebar
 *  VaultSwitcher): gradient avatar + name + location badge, a dropdown of YOUR private
 *  vaults, and a "create identity vault" action that keeps you in the identities context. */
function IdentityVaultSwitcher({
  vaults,
  servers,
  selected,
  onSelect,
  onCreate,
}: {
  vaults: VaultInfo[];
  servers: ServerStatus[];
  selected: string;
  onSelect: (id: string) => void;
  onCreate: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const cur = vaults.find((v) => v.vaultId === selected) ?? vaults[0];
  if (!cur) return null;

  const badgeLabel = (v: VaultInfo) => {
    const loc = vaultLoc(v, servers);
    if (loc.local) return t("secrets.locLocal");
    // Prefer the space/server name (needs a session); else resolve the server
    // session-independently; else it's bound to nothing.
    const server =
      loc.server ??
      (vaultServer(v, servers) ? serverShortLabel(vaultServer(v, servers)!) : null);
    return server
      ? t("secrets.locCloud", { server })
      : t("secrets.locCloud", { server: t("vault.badgeUnbound") });
  };
  const avatar = (v: VaultInfo, sz: number) => <FlatAvatar name={v.name} size={sz} />;
  const row = (base: string): CSSProperties => ({
    display: "flex",
    alignItems: "center",
    gap: 10,
    padding: 8,
    borderRadius: 8,
    cursor: "pointer",
    background: base,
  });

  return (
    <div style={{ position: "relative", maxWidth: 440 }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: p.txt3, marginBottom: 6 }}>
        {t("secrets.identityVaultCaption")}
      </div>
      <div
        onClick={() => setOpen(!open)}
        style={{
          padding: "9px 11px",
          borderRadius: 12,
          background: p.bg1,
          border: `1px solid ${open ? p.accentLine : p.line}`,
          display: "flex",
          alignItems: "center",
          gap: 10,
          cursor: "pointer",
        }}
      >
        {avatar(cur, 30)}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              fontSize: 13,
              fontWeight: 700,
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            {cur.name}
          </div>
          <div style={{ marginTop: 3 }}>
            <VaultBadge target={cur.syncTarget} label={badgeLabel(cur)} size={11} />
          </div>
        </div>
        <Icon
          name={open ? "cr" : "cd"}
          size={15}
          color={p.txt3}
          style={{ transform: open ? "rotate(90deg)" : "none", flexShrink: 0 }}
        />
      </div>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 40 }} />
          <div
            style={{
              position: "absolute",
              top: "100%",
              left: 0,
              right: 0,
              marginTop: 6,
              zIndex: 41,
              background: p.bg3,
              border: `1px solid ${p.line2}`,
              borderRadius: 12,
              padding: 6,
              boxShadow: p.shadow,
              maxHeight: 320,
              overflowY: "auto",
            }}
          >
            {vaults.map((x) => (
              <div
                key={x.vaultId}
                onClick={() => {
                  onSelect(x.vaultId);
                  setOpen(false);
                }}
                style={row(x.vaultId === cur.vaultId ? p.bg4 : "transparent")}
                onMouseEnter={(e) => {
                  if (x.vaultId !== cur.vaultId) e.currentTarget.style.background = p.bg2;
                }}
                onMouseLeave={(e) => {
                  if (x.vaultId !== cur.vaultId) e.currentTarget.style.background = "transparent";
                }}
              >
                {avatar(x, 24)}
                <span
                  style={{
                    flex: 1,
                    fontSize: 13,
                    fontWeight: 600,
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {x.name}
                </span>
                <VaultBadge target={x.syncTarget} label={badgeLabel(x)} size={11} />
                {x.vaultId === cur.vaultId && <Icon name="check" size={14} color={p.accentText} />}
              </div>
            ))}
            <div style={{ height: 1, background: p.line, margin: "6px 4px" }} />
            <div
              onClick={() => {
                onCreate();
                setOpen(false);
              }}
              style={{ ...row("transparent"), color: p.accentText }}
              onMouseEnter={(e) => (e.currentTarget.style.background = p.bg2)}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <span
                style={{
                  width: 24,
                  height: 24,
                  borderRadius: 6,
                  border: `1px dashed ${p.accentLine}`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Icon name="plus" size={13} color={p.accentText} />
              </span>
              <span style={{ fontSize: 13, fontWeight: 600 }}>{t("secrets.newIdentityVault")}</span>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function IdentitiesTab({
  openSignal,
  isMobile,
  privateVaults,
}: {
  openSignal: number;
  isMobile: boolean;
  /** The account's PRIVATE vaults (local, or cloud in a space you own) — the only
   *  valid homes for identities. Identities live here, not in a shared team vault. */
  privateVaults: VaultInfo[];
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const servers = useApp((s) => s.servers);
  const openModal = useApp((s) => s.openModal);
  const [vault, setVault] = useState<string>("");
  const [reload, setReload] = useState(0);
  const [items, setItems] = useState<ItemInfo[]>([]);

  // Open the vault modal and select the vault it creates. NOT silently auto-created:
  // a company member picks Local vs a Cloud vault in their own Space, rather than being
  // defaulted onto on-device storage.
  const newVault = () => openModal({ kind: "identityVault", onCreated: (id) => setVault(id) });

  // Keep a valid selection. Prefer a cloud vault in a Space YOU own (company-perimeter
  // identities) over a local one, so company identities don't default to on-device.
  useEffect(() => {
    if (privateVaults.length && !privateVaults.some((v) => v.vaultId === vault)) {
      const owned = privateVaults.find((v) => isOwnedCloud(v, servers));
      setVault((owned ?? privateVaults[0]).vaultId);
    }
  }, [privateVaults, servers, vault]);

  // Bridge: the host-binding UI still resolves the default identity vault via the
  // account-state pointer. Once we have a private vault, make sure that pointer is set
  // so binding keeps working until it becomes fully multi-vault (next increment).
  useEffect(() => {
    if (!vault) return;
    api
      .getPersonalVault()
      .then((pv) => {
        if (!pv) void api.setPersonalVault(vault);
      })
      .catch(() => {});
  }, [vault]);

  // Load the selected vault's items (identities + keys/passwords for the cred pickers).
  useEffect(() => {
    if (!vault) {
      setItems([]);
      return;
    }
    let alive = true;
    api
      .listItems(vault)
      .then((its) => alive && setItems(its))
      .catch(() => alive && setItems([]));
    return () => {
      alive = false;
    };
  }, [vault, reload]);

  const identities = items.filter((i) => i.itemType === ItemType.Identity);
  const keys = items.filter((i) => i.itemType === ItemType.SshKey);
  const passwords = items.filter((i) => i.itemType === ItemType.Password);
  const onChanged = () => setReload((n) => n + 1);

  if (!privateVaults.length) {
    return (
      <div
        style={{
          border: `1px dashed ${p.line}`,
          borderRadius: 12,
          background: "transparent",
          padding: "20px 18px",
          display: "flex",
          flexDirection: "column",
          gap: 10,
          alignItems: "flex-start",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Icon name="fingerprint" size={16} color={p.txt2} />
          <span style={{ fontSize: 13, fontWeight: 700 }}>{t("secrets.noIdentityVaultTitle")}</span>
        </div>
        <div style={{ fontSize: 13, color: p.txt3, lineHeight: 1.55, maxWidth: 470 }}>
          {t("secrets.noIdentityVaultHint")}
        </div>
        <Btn icon="plus" onClick={newVault}>
          {t("secrets.newIdentityVault")}
        </Btn>
      </div>
    );
  }
  if (!vault) return null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {/* The vault IS the context here — everything below lives in it. Pick a cloud vault
          in a Space you OWN to keep company identities in the company's perimeter, or a
          local one for on-device. A shared team vault can never hold identities. */}
      <IdentityVaultSwitcher
        vaults={privateVaults}
        servers={servers}
        selected={vault}
        onSelect={setVault}
        onCreate={newVault}
      />
      {identities.length === 0 && (
        <div style={{ fontSize: 13, color: p.txt3, lineHeight: 1.5, padding: "0 2px" }}>
          {t("secrets.vaultEmptyHint")}
        </div>
      )}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: isMobile ? "1fr" : "repeat(2, 1fr)",
          gap: 12,
        }}
      >
        {identities.map((id) => (
          <IdentityCard
            key={id.itemId}
            item={id}
            keys={keys}
            passwords={passwords}
            vault={vault}
            onChanged={onChanged}
          />
        ))}
        <NewIdentityCard
          openSignal={openSignal}
          keys={keys}
          passwords={passwords}
          vault={vault}
          onChanged={onChanged}
        />
      </div>
    </div>
  );
}

// ── Screen ─────────────────────────────────────────────────────
export function ViewSecrets() {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const isMobile = useNarrow(); // width-aware: also true on a narrow desktop window
  const route = useApp((s) => s.route);
  const items = useApp((s) => s.items);
  const vaults = useApp((s) => s.vaults);
  const servers = useApp((s) => s.servers);
  // Identities live in one of YOUR PRIVATE vaults (local, or a cloud vault in a space
  // you own) — never a shared team vault (would leak to members). The Identities tab
  // manages them across those vaults; the core enforces single-member on write.
  const privateVaults = vaults.filter(
    (v) => v.syncTarget !== "cloud" || isOwnedCloud(v, servers),
  );

  const tab: SecretTab =
    route === "passwords"
      ? "passwords"
      : route === "notes"
        ? "notes"
        : route === "identities"
          ? "identities"
          : "keys";

  const keys = items.filter((i) => i.itemType === ItemType.SshKey);
  const passwords = items.filter((i) => i.itemType === ItemType.Password);
  const notes = items.filter((i) => i.itemType === ItemType.Note);
  const identities = items.filter((i) => i.itemType === ItemType.Identity);

  const counts: Record<SecretTab, number> = {
    keys: keys.length,
    passwords: passwords.length,
    notes: notes.length,
    identities: identities.length,
  };

  const setTab = (t: SecretTab) => ctx.go(t);

  // Bumped by the header "+" button to open the inline add-card on the active tab.
  const [addSignal, setAddSignal] = useState(0);

  const primaryLabel =
    tab === "keys"
      ? t("secrets.newKey")
      : tab === "passwords"
        ? t("secrets.newPassword")
        : tab === "identities"
          ? t("secrets.newIdentity")
          : t("secrets.newNote");
  const onPrimary = () => {
    if (tab === "keys") ctx.openModal({ kind: "key" });
    // Identities open the inline add-card in the IdentitiesTab (which targets the
    // selected private vault), so no personal-vault gate anymore.
    else setAddSignal((n) => n + 1);
  };

  return (
    // Entry motion comes from the uh-stagger body rise below — no root fade on top.
    <div
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        minWidth: 0,
        background: p.bg0,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: isMobile ? 10 : 14,
          // Always wrap: long RU tab strip + primary button overlap on desktop otherwise.
          flexWrap: "wrap",
          rowGap: 8,
          padding: isMobile ? "14px 14px 10px" : "16px 22px 12px",
        }}
      >
        <h1 style={{ margin: 0, fontSize: 24, fontWeight: 800, letterSpacing: -0.7 }}>{t("secrets.title")}</h1>
        <TabBar tab={tab} setTab={setTab} counts={counts} isMobile={isMobile} />
        <div style={{ flex: 1 }} />
        <Btn icon="plus" size="sm" onClick={onPrimary}>
          {primaryLabel}
        </Btn>
      </div>

      <div
        className="uh-stagger"
        style={{ flex: 1, overflow: "auto", padding: isMobile ? "6px 14px 18px" : "6px 22px 18px" }}
      >
        {tab === "keys" && <KeysTab keys={keys} isMobile={isMobile} />}
        {tab === "passwords" && <PasswordsTab passwords={passwords} openSignal={addSignal} isMobile={isMobile} />}
        {tab === "identities" && (
          <IdentitiesTab openSignal={addSignal} isMobile={isMobile} privateVaults={privateVaults} />
        )}
        {tab === "notes" && <NotesTab notes={notes} openSignal={addSignal} />}
      </div>
    </div>
  );
}
