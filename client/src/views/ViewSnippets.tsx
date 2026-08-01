// ViewSnippets — the command library: create, edit, delete.
//
// Snippets are vault items, so they are encrypted at rest and sync like
// everything else. The list shows the command itself rather than hiding it
// behind the label: a snippet is chosen by recognising what it runs.

import { useCallback, useEffect, useState } from "react";
import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import { useTranslation } from "@/i18n";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rgba } from "@/theme/tokens";
import { Btn, Field, Icon, Input, NO_AUTOCORRECT, Spinner, Tag } from "@/components/primitives";
import { Modal } from "@/components/Modal";
import { toast } from "@/store/toast";
import { useApp } from "@/store/app";
import { useNarrow } from "@/store/responsive";

/** A stable id from the label, so a hand-picked name stays readable in the vault
 *  while still being unique enough not to collide with an existing snippet. */
function mintId(label: string): string {
  const slug =
    label
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 40) || "snippet";
  return `${slug}-${Date.now()}`;
}

function Editor({
  vaultId,
  edit,
  onClose,
  onSaved,
}: {
  vaultId: string;
  edit: api.Snippet | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { t } = useTranslation();
  const p = usePalette();
  const [label, setLabel] = useState(edit?.label ?? "");
  const [command, setCommand] = useState(edit?.command ?? "");
  const [tagDraft, setTagDraft] = useState("");
  const [tags, setTags] = useState<string[]>(edit?.tags ?? []);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    if (!command.trim()) {
      toast(t("snippets.needCommand"), "warn");
      return;
    }
    setBusy(true);
    try {
      await api.saveSnippet(vaultId, {
        // Keep the id on an edit: it is the vault item id, and minting a new one
        // would leave the old snippet behind and break any host referencing it.
        snippetId: edit?.snippetId ?? mintId(label || command),
        label: label.trim() || command.trim().split("\n")[0].slice(0, 40),
        command,
        tags,
      });
      onSaved();
      onClose();
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      icon="terminal"
      title={edit ? t("snippets.editTitle") : t("snippets.newTitle")}
      onClose={onClose}
      w={560}
      zIndex={300}
      footer={
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <Btn variant="ghost" onClick={onClose} disabled={busy}>
            {t("common.cancel")}
          </Btn>
          <Btn onClick={() => void save()} disabled={busy}>
            {t("common.save")}
          </Btn>
        </div>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <Field label={t("snippets.label")}>
          <Input value={label} onChange={setLabel} placeholder={t("snippets.labelHint")} />
        </Field>
        <Field label={t("snippets.command")} hint={t("snippets.commandHint")}>
          <textarea
            {...NO_AUTOCORRECT}
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            rows={5}
            style={{
              width: "100%",
              resize: "vertical",
              fontFamily: MONO,
              fontSize: 13,
              lineHeight: 1.5,
              padding: "10px 12px",
              borderRadius: 9,
              border: `1px solid ${p.line}`,
              background: p.bg2,
              color: p.txt,
              boxSizing: "border-box",
            }}
          />
        </Field>
        <Field label={t("snippets.tags")} group>
          <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
            {tags.map((tg) => (
              <button
                key={tg}
                type="button"
                title={t("common.remove")}
                onClick={() => setTags(tags.filter((x) => x !== tg))}
                style={{ background: "none", border: "none", padding: 0, cursor: "pointer" }}
              >
                <Tag>{tg}</Tag>
              </button>
            ))}
            <Input
              value={tagDraft}
              onChange={setTagDraft}
              placeholder={t("snippets.tagHint")}
              onKeyDown={(e: React.KeyboardEvent) => {
                if (e.key !== "Enter") return;
                const v = tagDraft.trim();
                if (v && !tags.includes(v)) setTags([...tags, v]);
                setTagDraft("");
              }}
            />
          </div>
        </Field>
      </div>
    </Modal>
  );
}

export function ViewSnippets() {
  const { t } = useTranslation();
  const p = usePalette();
  const isMobile = useNarrow();
  const vaultId = useApp((s) => s.vaultId) ?? "";
  const [items, setItems] = useState<api.Snippet[] | null>(null);
  const [editing, setEditing] = useState<{ edit: api.Snippet | null } | null>(null);

  const reload = useCallback(async () => {
    if (!vaultId) {
      setItems([]);
      return;
    }
    try {
      setItems(await api.listSnippets(vaultId));
    } catch (e) {
      toast(apiErrorMessage(e), "err");
      setItems([]);
    }
  }, [vaultId]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const remove = async (s: api.Snippet) => {
    try {
      await api.deleteSnippet(vaultId, s.snippetId);
      await reload();
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  };

  return (
    // `flex: 1`, not `height: 100%`. The route slot is a flex ROW, so a child
    // without a flex basis is sized by its own content — which starts as just this
    // header and only reaches full width once the list below (minWidth 640) has
    // loaded. The header's spacer is measured against that width, so "New snippet"
    // rendered next to the title on the first frame and jumped to the right edge on
    // the second. One frame, but a very visible one on a fast display.
    <div
      className="uh-view"
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
          gap: 10,
          padding: isMobile ? "16px 16px 12px" : "16px 22px 12px",
          flexWrap: isMobile ? "wrap" : "nowrap",
        }}
      >
        <Icon name="terminal" size={20} color={p.accentText} />
        <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800, letterSpacing: -0.7 }}>
          {t("nav.snippets")}
        </h1>
        <span style={{ fontFamily: MONO, fontSize: 12, color: p.txt3 }}>{items?.length ?? 0}</span>
        <div style={{ flex: 1 }} />
        <Btn icon="plus" size="sm" onClick={() => setEditing({ edit: null })}>
          {t("snippets.new")}
        </Btn>
      </div>

      <div
        className="uh-stagger"
        style={{
          flex: 1,
          overflow: "auto",
          padding: isMobile ? "4px 16px 18px" : "4px 22px 18px",
        }}
      >
        {items === null ? (
          <div style={{ padding: "40px 0", textAlign: "center" }}>
            <Spinner />
          </div>
        ) : items.length === 0 ? (
          <div style={{ padding: "40px 0", textAlign: "center", fontSize: 13, color: p.txt3 }}>
            {t("snippets.empty")}
          </div>
        ) : (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 8,
              minWidth: isMobile ? 0 : 640,
            }}
          >
            {items.map((s) => (
              <div
                key={s.snippetId}
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 12,
                  padding: "12px 14px",
                  borderRadius: 12,
                  border: `1px solid ${p.line}`,
                  background: p.bg2,
                  flexWrap: isMobile ? "wrap" : "nowrap",
                }}
              >
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ fontSize: 14, fontWeight: 700 }}>{s.label}</div>
                  <pre
                    style={{
                      margin: "4px 0 0",
                      fontFamily: MONO,
                      fontSize: 11.5,
                      color: p.txt2,
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                    }}
                  >
                    {s.command}
                  </pre>
                  {s.tags.length > 0 && (
                    <div style={{ display: "flex", gap: 4, marginTop: 6, flexWrap: "wrap" }}>
                      {s.tags.map((tg) => (
                        <span
                          key={tg}
                          style={{
                            fontFamily: MONO,
                            fontSize: 10.5,
                            color: p.txt3,
                            padding: "1px 6px",
                            borderRadius: 999,
                            background: rgba(p.txt3, 0.12),
                          }}
                        >
                          {tg}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <Btn variant="ghost" size="sm" icon="sliders" onClick={() => setEditing({ edit: s })}>
                  {t("common.edit")}
                </Btn>
                <Btn variant="ghost" size="sm" icon="trash" onClick={() => void remove(s)}>
                  {t("common.delete")}
                </Btn>
              </div>
            ))}
          </div>
        )}
      </div>

      {editing && (
        <Editor
          vaultId={vaultId}
          edit={editing.edit}
          onClose={() => setEditing(null)}
          onSaved={() => void reload()}
        />
      )}
    </div>
  );
}
