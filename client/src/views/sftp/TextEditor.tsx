// In-app text viewer/editor — reads a file via the FileSource (whole-file, the
// core caps remote reads at 1 GiB) and writes it back. Refuses binary or
// oversized files rather than corrupting them, and confirms before discarding
// unsaved edits.

import { useEffect, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO } from "@/theme/tokens";
import { Icon, Btn, Spinner } from "@/components/primitives";
import { useKeyboardInset } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import { toast } from "@/store/toast";
import { guard } from "@/store/action";
import { apiErrorMessage } from "@/bridge/types";
import type { FileSource } from "@/bridge/sources";

const MAX_EDIT_BYTES = 2 * 1024 * 1024; // 2 MiB — sane ceiling for a <textarea>

function isBinary(s: string): boolean {
  // Any NUL, or any U+FFFD (a byte that wasn't valid UTF-8), means the content
  // can't be edited safely: re-encoding a replacement char on save would rewrite
  // bytes the user never touched. Refuse rather than silently corrupt.
  return s.includes("\u0000") || s.includes("\uFFFD");
}

export function TextEditor({
  source,
  path,
  name,
  size,
  onClose,
  onSaved,
}: {
  source: FileSource;
  path: string;
  name: string;
  size: number;
  onClose: () => void;
  onSaved?: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const [text, setText] = useState("");
  const [original, setOriginal] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [binary, setBinary] = useState(false);
  const [tooLarge, setTooLarge] = useState(false);
  const [saving, setSaving] = useState(false);
  const [confirmClose, setConfirmClose] = useState(false);
  const kbInset = useKeyboardInset();

  useEffect(() => {
    if (size > MAX_EDIT_BYTES) {
      setTooLarge(true);
      setLoading(false);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const content = await source.readText(path);
        if (cancelled) return;
        setBinary(isBinary(content));
        setText(content);
        setOriginal(content);
      } catch (e) {
        if (!cancelled) setError(apiErrorMessage(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [source, path, size]);

  const dirty = text !== original;
  const editable = !loading && !error && !binary && !tooLarge;
  const requestClose = () => (dirty ? setConfirmClose(true) : onClose());

  const save = async () => {
    setSaving(true);
    try {
      await guard(async () => {
        await source.writeText(path, text);
        setOriginal(text);
        toast(t("sftp.editor.saved"), "ok");
        onSaved?.();
      });
    } finally {
      setSaving(false);
    }
  };

  // Escape closes (guarded for unsaved edits); ⌘/Ctrl+S saves. Re-bound each
  // render so it sees the current dirty/editable/saving state.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        requestClose();
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        if (editable && dirty && !saving) void save();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const message = (txt: string) => (
    <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: p.txt3, fontSize: 13, padding: 24, textAlign: "center" }}>
      {txt}
    </div>
  );

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 200,
        display: "flex",
        flexDirection: "column",
        background: p.bg0,
        paddingBottom: kbInset, // shrink above the software keyboard (overlays a fixed shell)
        boxSizing: "border-box",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "calc(env(safe-area-inset-top) + 12px) 16px 12px",
          borderBottom: `1px solid ${p.line}`,
          background: p.bg1,
        }}
      >
        <Icon name="note" size={16} color={p.accentText} />
        <span style={{ fontFamily: MONO, fontSize: 13, fontWeight: 600, flex: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {name}
          {dirty ? " •" : ""}
        </span>
        {editable && (
          <Btn size="sm" icon="check" onClick={save} disabled={saving || !dirty}>
            {t("sftp.editor.save")}
          </Btn>
        )}
        <Btn variant="ghost" size="sm" icon="x" onClick={requestClose}>
          {t("common.close")}
        </Btn>
      </div>

      {confirmClose && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "10px 16px",
            background: p.bg2,
            borderBottom: `1px solid ${p.line}`,
          }}
        >
          <span style={{ flex: 1, fontSize: 12.5, color: p.txt2 }}>{t("sftp.editor.discardQ")}</span>
          <Btn variant="ghost" size="sm" onClick={() => setConfirmClose(false)}>
            {t("common.cancel")}
          </Btn>
          <Btn variant="danger" size="sm" onClick={onClose}>
            {t("sftp.editor.discard")}
          </Btn>
        </div>
      )}

      <div style={{ flex: 1, minHeight: 0, display: "flex" }}>
        {loading ? (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Spinner />
          </div>
        ) : error ? (
          message(t("sftp.editor.loadFailed"))
        ) : tooLarge ? (
          message(t("sftp.editor.tooLarge"))
        ) : binary ? (
          message(t("sftp.editor.binary"))
        ) : (
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            style={{
              flex: 1,
              resize: "none",
              border: "none",
              outline: "none",
              background: p.bg0,
              color: p.txt,
              fontFamily: MONO,
              fontSize: 16, // ≥16px avoids iOS zoom-on-focus
              lineHeight: 1.5,
              padding: "16px 16px calc(16px + env(safe-area-inset-bottom))",
              boxSizing: "border-box",
            }}
          />
        )}
      </div>
    </div>
  );
}
