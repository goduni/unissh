import { useState } from "react";
import { Modal } from "@/components/Modal";
import { BTN_RESET, Btn, Field, Input } from "@/components/primitives";
import { useTranslation } from "@/i18n";
import { useApp } from "@/store/app";
import { workspaceCounts, type WorkspaceEditError } from "@/store/workspace";
import { usePalette } from "@/theme/ThemeProvider";
import { rem, TEXT } from "@/theme/tokens";

export function TerminalWorkspaces({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const p = usePalette();
  const entries = useApp((s) => s.namedWorkspaces);
  const ready = useApp((s) => s.workspaceReady && s.workspaceAvailable);
  const hasTabs = useApp((s) => s.terminals.length > 0);
  const vaultName = useApp((s) => s.vaults.find((v) => v.vaultId === s.vaultId)?.name ?? "");
  const [name, setName] = useState("");
  const [editing, setEditing] = useState<string | null>(null);
  const [error, setError] = useState<WorkspaceEditError | null>(null);
  const [pending, setPending] = useState<{ id: string; kind: "update" | "delete" } | null>(null);
  const reset = () => { setEditing(null); setName(""); setError(null); setPending(null); };

  return <Modal icon="grid" title={t("terminal.workspaces.title")} subtitle={vaultName}
    onClose={onClose} w={560}>
    <p style={{ margin: 0, fontSize: TEXT.base, color: p.txt2, lineHeight: 1.5 }}>
      {t("terminal.workspaces.description")}
    </p>
    {!ready && <div role="alert" style={{ color: p.red, fontSize: TEXT.base }}>
      {t("terminal.workspaces.errors.unavailable")}
    </div>}
    <form onSubmit={(event) => {
      event.preventDefault();
      const s = useApp.getState();
      const result = editing ? s.renameNamedWorkspace(editing, name) : s.saveNamedWorkspace(name);
      if (result) setError(result); else reset();
    }} style={{ display: "flex", flexDirection: "column", gap: rem(10) }}>
      <Field label={t(editing ? "terminal.workspaces.rename" : "terminal.workspaces.name")}
        hint={!editing && !hasTabs ? t("terminal.workspaces.errors.emptyLayout") : undefined}>
        <Input key={editing ?? "new"} value={name} autoFocus selectOnFocus
          placeholder={t("terminal.workspaces.placeholder")}
          onChange={(value) => { setName(value); setError(null); }} />
      </Field>
      {error && <div role="alert" style={{ color: p.red, fontSize: TEXT.base }}>
        {t(`terminal.workspaces.errors.${error}`)}
      </div>}
      <div style={{ display: "flex", flexWrap: "wrap", gap: rem(8) }}>
        <Btn type="submit" size="sm" icon={editing ? "check" : "plus"}
          disabled={!ready || !name.trim() || (!editing && !hasTabs)}>
          {t(editing ? "common.save" : "terminal.workspaces.save")}
        </Btn>
        {editing && <Btn variant="ghost" size="sm" onClick={reset}>{t("common.cancel")}</Btn>}
      </div>
    </form>
    <div style={{ borderTop: `1px solid ${p.line}` }}>
      {!entries.length && <p style={{ margin: `${rem(16)} 0 0`, color: p.txt2, fontSize: TEXT.base }}>
        {t("terminal.workspaces.empty")}
      </p>}
      {entries.map((entry) => {
        const counts = workspaceCounts(entry.layout);
        return <div key={entry.id} style={{ padding: `${rem(12)} 0`, borderBottom: `1px solid ${p.line}` }}>
          <div style={{ display: "flex", gap: rem(8), alignItems: "center" }}>
            <button disabled={!ready} aria-label={t("terminal.workspaces.openTitle", { name: entry.name })}
              title={entry.name} onClick={() => { void useApp.getState().openNamedWorkspace(entry.id); }}
              style={{ ...BTN_RESET, flex: 1, minWidth: 0, textAlign: "left", padding: `${rem(6)} 0`, color: p.txt }}>
              <span style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 700, fontSize: TEXT.base }}>{entry.name}</span>
              <span style={{ display: "block", marginTop: rem(4), fontSize: TEXT.small, color: p.txt2 }}>
                {t("terminal.workspaces.counts", counts)}
              </span>
            </button>
            <Btn variant="ghost" size="sm" icon="pencil" disabled={!ready}
              aria-label={t("terminal.workspaces.renameTitle", { name: entry.name })}
              title={t("terminal.workspaces.rename")} onClick={() => {
                setEditing(entry.id); setName(entry.name); setError(null); setPending(null);
              }} />
            <Btn variant="ghost" size="sm" icon="refresh" disabled={!ready || !hasTabs}
              aria-label={t("terminal.workspaces.updateTitle", { name: entry.name })}
              title={t("terminal.workspaces.update")} onClick={() => setPending({ id: entry.id, kind: "update" })} />
            <Btn variant="ghost" size="sm" icon="trash" disabled={!ready}
              aria-label={t("terminal.workspaces.deleteTitle", { name: entry.name })}
              title={t("common.delete")} onClick={() => setPending({ id: entry.id, kind: "delete" })} />
          </div>
          {pending?.id === entry.id && <div style={{ marginTop: rem(12), fontSize: TEXT.base }}>
            <p role="status" style={{ color: p.txt2, margin: `0 0 ${rem(10)}`, lineHeight: 1.5, overflowWrap: "anywhere" }}>
              {t(pending.kind === "delete" ? "terminal.workspaces.deleteBody" : "terminal.workspaces.updateBody", { name: entry.name })}
            </p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: rem(8) }}>
              <Btn size="sm" variant={pending.kind === "delete" ? "danger" : "primary"} disabled={!ready}
                onClick={() => {
                  const s = useApp.getState();
                  if (pending.kind === "delete") { s.deleteNamedWorkspace(entry.id); reset(); }
                  else {
                    const result = s.saveNamedWorkspace(entry.name, entry.id);
                    if (result) setError(result);
                    setPending(null);
                  }
                }}>{t(pending.kind === "delete" ? "common.delete" : "terminal.workspaces.update")}</Btn>
              <Btn size="sm" variant="ghost" onClick={() => setPending(null)}>{t("common.cancel")}</Btn>
            </div>
          </div>}
        </div>;
      })}
    </div>
  </Modal>;
}
