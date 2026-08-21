// SFTP dialogs — styled replacements for window.prompt/confirm and the overwrite
// guard. Each is a controlled component driven by the pane: it reports its result
// through a callback and never mutates anything itself.

import { useEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { Btn, Checkbox, NO_AUTOCORRECT } from "@/components/primitives";
import { Modal } from "@/components/Modal";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { useTranslation } from "@/i18n";
import { useFmt } from "@/i18n/format";
import type { ConflictResolution } from "@/sftp/transfer-runner";
import { validateEntryName, type NameError as NameErrorKind } from "./names";

function TextInput({
  value,
  onChange,
  onEnter,
  placeholder,
  selectBasename,
}: {
  value: string;
  onChange: (v: string) => void;
  onEnter?: () => void;
  placeholder?: string;
  selectBasename?: boolean;
}) {
  const p = usePalette();
  const ref = useRef<HTMLInputElement>(null);
  const [focus, setFocus] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.focus();
    if (selectBasename) {
      const dot = value.lastIndexOf(".");
      el.setSelectionRange(0, dot > 0 ? dot : value.length);
    } else {
      el.select();
    }
    // run once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <input
      ref={ref}
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => {
        if (e.key === "Enter") onEnter?.();
      }}
      onFocus={() => setFocus(true)}
      onBlur={() => setFocus(false)}
      {...NO_AUTOCORRECT}
      style={{
        width: "100%",
        boxSizing: "border-box",
        padding: `${rem(9)} ${rem(11)}`,
        borderRadius: 8,
        border: `1px solid ${focus ? p.accentLine : p.line2}`,
        background: p.bg2,
        color: p.txt,
        fontSize: TEXT.base,
        fontFamily: MONO,
        outline: "none",
      }}
    />
  );
}

// Only "dup" and "invalid" say anything: an empty box is self-evident, and the
// disabled Create button already carries the message.
function NameError({ error }: { error: NameErrorKind }) {
  const p = usePalette();
  const { t } = useTranslation();
  if (error !== "dup" && error !== "invalid") return null;
  return (
    <div style={{ fontSize: TEXT.small, color: p.red }}>
      {error === "dup" ? t("sftp.dlg.nameTaken") : t("sftp.dlg.invalidName")}
    </div>
  );
}

/** Create an empty entry in the current directory — a folder or a file. */
export function NewEntryDialog({
  kind,
  existing,
  onSubmit,
  onClose,
}: {
  kind: "folder" | "file";
  existing: string[];
  onSubmit: (name: string) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [raw, setRaw] = useState("");
  const { name, error } = validateEntryName(raw, existing);
  const submit = () => {
    if (error === null) {
      onSubmit(name);
      onClose();
    }
  };
  return (
    <Modal
      icon={kind === "folder" ? "folders" : "file"}
      title={t(kind === "folder" ? "sftp.dlg.newFolderTitle" : "sftp.dlg.newFileTitle")}
      onClose={onClose}
      footer={
        <>
          <div style={{ flex: 1 }} />
          <Btn variant="ghost" size="sm" onClick={onClose}>
            {t("common.cancel")}
          </Btn>
          <Btn size="sm" onClick={submit} disabled={error !== null}>
            {t("sftp.dlg.create")}
          </Btn>
        </>
      }
    >
      <TextInput
        value={raw}
        onChange={setRaw}
        onEnter={submit}
        placeholder={t(kind === "folder" ? "sftp.dlg.folderName" : "sftp.dlg.fileName")}
      />
      <NameError error={error} />
    </Modal>
  );
}

export function RenameDialog({
  name: initial,
  existing,
  onSubmit,
  onClose,
}: {
  name: string;
  existing: string[];
  onSubmit: (name: string) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [raw, setRaw] = useState(initial);
  const { name, error } = validateEntryName(raw, existing, initial);
  const submit = () => {
    if (error === null) {
      onSubmit(name);
      onClose();
    }
  };
  return (
    <Modal
      icon="pencil"
      title={t("sftp.dlg.renameTitle")}
      subtitle={initial}
      onClose={onClose}
      footer={
        <>
          <div style={{ flex: 1 }} />
          <Btn variant="ghost" size="sm" onClick={onClose}>
            {t("common.cancel")}
          </Btn>
          <Btn size="sm" onClick={submit} disabled={error !== null}>
            {t("sftp.dlg.rename")}
          </Btn>
        </>
      }
    >
      <TextInput value={raw} onChange={setRaw} onEnter={submit} selectBasename />
      <NameError error={error} />
    </Modal>
  );
}

export function ConfirmDeleteDialog({
  names,
  hasDir,
  onConfirm,
  onClose,
}: {
  names: string[];
  hasDir: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  return (
    <Modal
      icon="trash"
      iconColor={p.red}
      title={t("sftp.dlg.deleteTitle")}
      onClose={onClose}
      footer={
        <>
          <div style={{ flex: 1 }} />
          <Btn variant="ghost" size="sm" onClick={onClose}>
            {t("common.cancel")}
          </Btn>
          <Btn
            variant="danger"
            size="sm"
            onClick={() => {
              onConfirm();
              onClose();
            }}
          >
            {t("sftp.dlg.delete")}
          </Btn>
        </>
      }
    >
      <div style={{ fontSize: TEXT.base, color: p.txt }}>
        {names.length === 1
          ? t("sftp.dlg.deleteOne", { name: names[0] })
          : t("sftp.dlg.deleteMany", { count: names.length })}
      </div>
      {hasDir && <div style={{ fontSize: TEXT.small, color: p.amber }}>{t("sftp.dlg.deleteRecursive")}</div>}
    </Modal>
  );
}

export function ConflictDialog({
  name,
  targetSize,
  sourceSize,
  resumable,
  batchable,
  onResolve,
}: {
  name: string;
  targetSize: number;
  sourceSize: number;
  resumable: boolean;
  batchable: boolean;
  onResolve: (res: ConflictResolution) => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const { fmtSize } = useFmt();
  const [applyAll, setApplyAll] = useState(false);
  const pick = (choice: ConflictResolution["choice"]) => onResolve({ choice, applyAll });
  return (
    <Modal
      icon="alert"
      iconColor={p.amber}
      title={t("sftp.dlg.conflictTitle")}
      subtitle={name}
      onClose={() => onResolve({ choice: "skip", applyAll: false })}
      footer={
        <>
          {resumable && (
            <Btn variant="ghost" size="sm" icon="download" onClick={() => pick("resume")}>
              {t("sftp.dlg.resume")}
            </Btn>
          )}
          <Btn variant="ghost" size="sm" onClick={() => pick("skip")}>
            {t("sftp.dlg.skip")}
          </Btn>
          <div style={{ flex: 1 }} />
          {/* Overwrite is destructive — demoted to an outline with a red tone so
              the safe "Keep both" is the visual primary. */}
          <Btn variant="outline" size="sm" onClick={() => pick("overwrite")} style={{ color: p.red, borderColor: p.red }}>
            {t("sftp.dlg.overwrite")}
          </Btn>
          <Btn size="sm" onClick={() => pick("keepboth")}>
            {t("sftp.dlg.keepBoth")}
          </Btn>
        </>
      }
    >
      <div style={{ fontSize: TEXT.base, color: p.txt }}>
        {t("sftp.dlg.conflictBody", { there: fmtSize(targetSize), incoming: fmtSize(sourceSize) })}
      </div>
      {batchable && (
        <Checkbox
          checked={applyAll}
          onChange={setApplyAll}
          label={t("sftp.dlg.applyAll")}
          style={{ display: "flex" }}
        />
      )}
    </Modal>
  );
}

export function ChmodDialog({
  name,
  mode,
  onSubmit,
  onClose,
}: {
  name: string;
  mode: number;
  onSubmit: (mode: number) => void;
  onClose: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const [bits, setBits] = useState(mode & 0o777);
  const octal = bits.toString(8).padStart(3, "0");
  const classes = [
    { label: t("sftp.chmod.owner"), shift: 6 },
    { label: t("sftp.chmod.group"), shift: 3 },
    { label: t("sftp.chmod.other"), shift: 0 },
  ];
  const perms = [
    { label: "r", bit: 4 },
    { label: "w", bit: 2 },
    { label: "x", bit: 1 },
  ];
  return (
    <Modal
      icon="shield"
      title={t("sftp.chmod.title")}
      subtitle={name}
      onClose={onClose}
      footer={
        <>
          <span style={{ fontFamily: MONO, fontSize: TEXT.base, color: p.txt2 }}>{octal}</span>
          <div style={{ flex: 1 }} />
          <Btn variant="ghost" size="sm" onClick={onClose}>
            {t("common.cancel")}
          </Btn>
          <Btn
            size="sm"
            onClick={() => {
              onSubmit(bits);
              onClose();
            }}
          >
            {t("sftp.chmod.apply")}
          </Btn>
        </>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: rem(6) }}>
        {classes.map((cls) => (
          <div key={cls.shift} style={{ display: "flex", alignItems: "center", gap: rem(12) }}>
            <span style={{ width: rem(64), fontSize: TEXT.base, color: p.txt2 }}>{cls.label}</span>
            {perms.map((perm) => {
              const bit = perm.bit << cls.shift;
              const on = (bits & bit) !== 0;
              return (
                <Checkbox
                  key={perm.label}
                  checked={on}
                  onChange={() => setBits((b) => b ^ bit)}
                  label={perm.label}
                  style={{ display: "flex", gap: rem(5) }}
                  labelStyle={{ fontFamily: MONO }}
                />
              );
            })}
          </div>
        ))}
      </div>
    </Modal>
  );
}
