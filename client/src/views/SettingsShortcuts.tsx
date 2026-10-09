import { useEffect, useRef, useState, type RefObject } from "react";
import { Btn, Icon, Input } from "@/components/primitives";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT, UI } from "@/theme/tokens";
import { useTranslation, tDyn } from "@/i18n";
import { isMac } from "@/bridge/platform";
import { useNarrow } from "@/store/responsive";
import { useShortcuts } from "@/store/shortcuts";
import { SHORTCUTS, SHORTCUT_SCOPES, bindingsFor, conflictsFor, eventBinding, formatBinding, sameBinding, shortcutDefinition, validBinding } from "@/support/keybindings";

function ShortcutEditor({ id, onClose, onDirtyChange, recordRef }: { id: string; onClose: (saved?: boolean) => void; onDirtyChange: (dirty: boolean) => void; recordRef: RefObject<HTMLButtonElement | null> }) {
  const p = usePalette();
  const { t } = useTranslation();
  const { overrides, assign, setRecording } = useShortcuts();
  const [draft, setDraft] = useState(() => bindingsFor(id, overrides, isMac()));
  const [capture, setCapture] = useState<"replace" | "add" | null>(null);
  const [invalid, setInvalid] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const addRef = useRef<HTMLButtonElement>(null);
  const live = bindingsFor(id, overrides, isMac());
  const dirty = draft.length !== live.length || draft.some((b, i) => !live[i] || !sameBinding(b, live[i]));
  const conflicts = conflictsFor(id, draft, overrides, isMac());
  useEffect(() => { onDirtyChange(dirty); }, [dirty, onDirtyChange]);
  useEffect(() => {
    recordRef.current?.focus({ preventScroll: true });
    panelRef.current?.scrollIntoView({ block: "nearest" });
  }, [recordRef]);
  useEffect(() => {
    if (!capture) return;
    const control = capture === "add" ? addRef.current : recordRef.current;
    setRecording(true);
    control?.focus();
    const stop = () => { setRecording(false); setCapture(null); };
    const onFocus = (e: FocusEvent) => { if (e.target !== control) stop(); };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Tab" && !e.ctrlKey && !e.metaKey && !e.altKey) { stop(); return; }
      e.preventDefault();
      e.stopImmediatePropagation();
      if (e.key === "Escape") { stop(); return; }
      if (e.repeat || e.isComposing || ["Control", "Shift", "Alt", "Meta", "AltGraph"].includes(e.key)) return;
      const b = eventBinding(e);
      if (e.getModifierState("AltGraph") || !validBinding(b, shortcutDefinition(id).scope)) { setInvalid(true); return; }
      setDraft((list) => capture === "replace" ? [b] : list.some((old) => sameBinding(old, b)) ? list : [...list, b]);
      setInvalid(false);
      stop();
    };
    window.addEventListener("keydown", onKey, true);
    window.addEventListener("blur", stop);
    document.addEventListener("focusin", onFocus);
    return () => {
      setRecording(false);
      window.removeEventListener("keydown", onKey, true);
      window.removeEventListener("blur", stop);
      document.removeEventListener("focusin", onFocus);
    };
  }, [capture, setRecording, recordRef, id]);
  useEffect(() => {
    if (capture) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && panelRef.current?.contains(e.target as Node)) {
        e.preventDefault();
        e.stopPropagation();
        onClose();
      }
    };
    // Consume Escape before Settings' document-level close handler.
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [capture, onClose]);
  const save = (replace: boolean) => {
    const original = shortcutDefinition(id).defaults(isMac());
    const isDefault = draft.length === original.length && draft.every((b, i) => sameBinding(b, original[i]));
    if (assign(id, isDefault ? null : draft, replace)) onClose(true);
  };
  return (
    <div ref={panelRef} id={`shortcut-editor-${id}`} role="group" aria-label={tDyn(shortcutDefinition(id).labelKey)}
      style={{ padding: rem(16), background: p.bg2, border: `1px solid ${p.line2}`, borderRadius: 8, margin: `${rem(6)} 0 ${rem(12)}`, fontSize: TEXT.base }}>
      <div style={{ display: "flex", flexWrap: "wrap", gap: rem(8), marginBottom: rem(12) }}>
        {draft.map((b, i) => <Btn key={i} variant="ghost" size="sm" icon="x" disabled={!!capture}
          aria-label={t("keybindings.removeBinding", { keys: formatBinding(b, isMac()) })}
          onClick={() => { setDraft((list) => list.filter((_, index) => index !== i)); recordRef.current?.focus(); }}>
          <span style={{ fontFamily: MONO, overflowWrap: "anywhere" }}>{formatBinding(b, isMac())}</span>
        </Btn>)}
        {!draft.length && <span style={{ color: p.txt2 }}>{t("keybindings.disabled")}</span>}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: rem(8) }}>
        <Btn btnRef={recordRef} variant="outline" disabled={capture === "add"} onClick={() => { setInvalid(false); setCapture(capture ? null : "replace"); }}>
          {t(capture === "replace" ? "keybindings.listening" : "keybindings.change")}
        </Btn>
        <Btn btnRef={addRef} variant="ghost" disabled={capture === "replace"} onClick={() => { setInvalid(false); setCapture(capture ? null : "add"); }}>
          {t(capture === "add" ? "keybindings.listening" : "keybindings.record")}
        </Btn>
      </div>
      <p role="status" style={{ color: invalid ? p.red : p.txt2, fontSize: TEXT.small, lineHeight: 1.6, maxWidth: "72ch" }}>
        {t(invalid ? "keybindings.invalid" : capture ? "keybindings.recordHint" : dirty ? "keybindings.unsaved" : "keybindings.editHint")}
      </p>
      <p style={{ color: p.txt2, fontSize: TEXT.small, lineHeight: 1.6, maxWidth: "72ch" }}>{t("keybindings.layoutHint")}</p>
      {draft.some((b) => b.ctrl && !b.shift && !b.alt && !b.meta) && (
        <p style={{ color: p.txt2, fontSize: TEXT.small }}>{t("keybindings.shellHint")}</p>
      )}
      {!!conflicts.length && <p role="alert" style={{ color: p.red, lineHeight: 1.6 }}>
        {t("keybindings.conflict", { actions: conflicts.map((s) => tDyn(s.labelKey)).join(", ") })}
      </p>}
      <div style={{ display: "flex", flexWrap: "wrap", gap: rem(8), alignItems: "center" }}>
        {conflicts.length > 0
          ? <Btn disabled={!!capture} onClick={() => save(true)}>{t("keybindings.replace")}</Btn>
          : <Btn disabled={!!capture || !dirty} onClick={() => save(false)}>{t("common.save")}</Btn>}
        <Btn variant="ghost" onClick={() => onClose()}>{t("common.cancel")}</Btn>
        <div style={{ flex: 1 }} />
        <Btn variant="ghost" size="sm" disabled={!!capture || !draft.length} onClick={() => setDraft([])}>{t("keybindings.disable")}</Btn>
        <Btn variant="ghost" size="sm" disabled={!!capture} onClick={() => setDraft(shortcutDefinition(id).defaults(isMac()))}>{t("keybindings.reset")}</Btn>
      </div>
    </div>
  );
}

export function SettingsShortcuts() {
  const narrow = useNarrow();
  const p = usePalette();
  const { t } = useTranslation();
  const { overrides, resetAll, storageError } = useShortcuts();
  const [query, setQuery] = useState("");
  const [modifiedOnly, setModifiedOnly] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [notice, setNotice] = useState("");
  const [confirmReset, setConfirmReset] = useState(false);
  const editedButton = useRef<HTMLButtonElement | null>(null);
  const recordRef = useRef<HTMLButtonElement>(null);
  const searchRef = useRef<HTMLLabelElement>(null);
  const resetRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => { if (confirmReset) confirmRef.current?.focus(); }, [confirmReset]);
  const closeEditor = (saved = false) => {
    setEditing(null); setDirty(false);
    setNotice(saved ? t("keybindings.saved") : "");
    requestAnimationFrame(() => {
      if (editedButton.current?.isConnected) editedButton.current.focus();
      else searchRef.current?.querySelector("input")?.focus();
    });
  };
  const filtered = SHORTCUTS.filter((s) => s.id === editing || ((!modifiedOnly || overrides[s.id] !== undefined)
    && `${tDyn(s.labelKey)} ${tDyn(`keybindings.scopes.${s.scope}`)} ${bindingsFor(s.id, overrides, isMac()).map((b) => formatBinding(b, isMac())).join(" ")}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())));
  return (
    <>
      <p style={{ color: p.txt2, fontSize: TEXT.base, lineHeight: 1.6, maxWidth: "72ch", margin: `0 0 ${rem(16)}` }}>{t("keybindings.description")}</p>
      <label ref={searchRef} style={{ display: "block", marginBottom: rem(12) }}>
        <span style={{ display: "block", fontSize: TEXT.small, marginBottom: rem(6), color: p.txt2 }}>{t("keybindings.search")}</span>
        <Input value={query} onChange={setQuery} icon="search" placeholder={t("keybindings.searchPlaceholder")} />
      </label>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between", gap: rem(12), marginBottom: rem(8) }}>
        <label style={{ display: "flex", alignItems: "center", gap: rem(8), fontSize: TEXT.base }}>
          <input type="checkbox" checked={modifiedOnly} onChange={(e) => setModifiedOnly(e.target.checked)} />
          {t("keybindings.modifiedOnly")}
        </label>
        <Btn btnRef={resetRef} variant="ghost" size="sm" disabled={!Object.keys(overrides).length} onClick={() => setConfirmReset(true)}>{t("keybindings.resetAll")}</Btn>
      </div>
      <div role="status" style={{ color: p.txt2, fontSize: TEXT.small, lineHeight: 1.5 }}>{notice}</div>
      {confirmReset && <div role="group" aria-label={t("keybindings.resetAll")} style={{ margin: `${rem(12)} 0` }}>
        <p style={{ fontSize: TEXT.base }}>{t("keybindings.resetConfirm")}</p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: rem(8) }}>
          <Btn btnRef={confirmRef} onClick={() => {
            resetAll(); setConfirmReset(false); setEditing(null); setDirty(false); setNotice(t("keybindings.restored"));
            searchRef.current?.querySelector("input")?.focus();
          }}>{t("keybindings.resetAll")}</Btn>
          <Btn variant="ghost" onClick={() => { setConfirmReset(false); resetRef.current?.focus(); }}>{t("common.cancel")}</Btn>
        </div>
      </div>}
      {storageError && <p role="alert" style={{ color: p.red }}>{t("keybindings.storageError")}</p>}
      {!filtered.length && <p role="status" style={{ color: p.txt2 }}>{t("keybindings.noResults")}</p>}
      {SHORTCUT_SCOPES.map((scope) => {
        const rows = filtered.filter((s) => s.scope === scope);
        if (!rows.length) return null;
        return <section key={scope} aria-labelledby={`shortcuts-${scope}`} style={{ marginBottom: rem(24) }}>
          <h3 id={`shortcuts-${scope}`} style={{ fontSize: TEXT.lead, margin: `${rem(20)} 0 ${rem(6)}` }}>{tDyn(`keybindings.scopes.${scope}`)}</h3>
          <p style={{ color: p.txt2, fontSize: TEXT.small, lineHeight: 1.6, maxWidth: "72ch", margin: `0 0 ${rem(8)}` }}>{tDyn(`keybindings.scopeHints.${scope}`)}</p>
          {rows.map((s) => {
            const bindings = bindingsFor(s.id, overrides, isMac());
            const keys = bindings.map((b) => formatBinding(b, isMac()));
            const current = keys.join(" / ") || t("keybindings.disabled");
            return <div key={s.id}>
              <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 48%)", alignItems: "center", gap: rem(14), padding: `${rem(10)} 0`, borderBottom: `1px solid ${p.line}`, minHeight: rem(40) }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: TEXT.base, fontWeight: 500 }}>{tDyn(s.labelKey)}</div>
                  {overrides[s.id] !== undefined && <span style={{ fontSize: TEXT.small, color: p.txt2 }}>{t("keybindings.modified")}</span>}
                </div>
                <button type="button" aria-label={t("keybindings.editAction", { action: tDyn(s.labelKey), keys: current })}
                  aria-expanded={editing === s.id} aria-controls={editing === s.id ? `shortcut-editor-${s.id}` : undefined}
                  title={current}
                  onClick={(e) => {
                    if (editing === s.id) return;
                    if (dirty) { setNotice(t("keybindings.finishEditing")); recordRef.current?.focus({ preventScroll: true }); document.getElementById(`shortcut-editor-${editing}`)?.scrollIntoView({ block: "nearest" }); return; }
                    editedButton.current = e.currentTarget; setEditing(s.id); setDirty(false); setNotice("");
                  }}
                  style={{ justifySelf: "end", display: "flex", alignItems: "center", gap: rem(8), maxWidth: "100%", minHeight: rem(narrow ? 44 : 36), padding: `${rem(7)} ${rem(10)}`, border: `1px solid ${editing === s.id ? p.accent : p.line2}`, borderRadius: 7, background: p.bg2, color: p.txt, cursor: "pointer", fontFamily: UI, fontSize: TEXT.small }}>
                  <span style={{ fontFamily: bindings.length ? MONO : UI, overflowWrap: "anywhere", minWidth: 0 }}>{keys[0] || t("keybindings.disabled")}</span>
                  {keys.length > 1 && <span style={{ color: p.txt2, whiteSpace: "nowrap" }}>+{keys.length - 1}</span>}
                  <Icon name="pencil" size={13} color={p.txt2} />
                </button>
              </div>
              {editing === s.id && <ShortcutEditor key={s.id} id={s.id} onClose={closeEditor} onDirtyChange={setDirty} recordRef={recordRef} />}
            </div>;
          })}
        </section>;
      })}
      <p style={{ color: p.txt2, fontSize: TEXT.small, lineHeight: 1.6, maxWidth: "72ch" }}>{t("keybindings.systemHint")}</p>
    </>
  );
}
