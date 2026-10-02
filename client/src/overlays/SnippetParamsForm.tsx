// SnippetParamsForm — the one form that asks for a snippet's `{{parameters}}`.
// Shared by every entry point that runs a parameterised snippet, so each of
// them asks the same way: fields in order of first appearance, defaults
// pre-filled, Enter submits, Escape (or the close button) cancels.
//
// The form only collects values. What happens next — typing into a pane,
// substituting per target — is the caller's, via `substituteParams`.

import { useState } from "react";
import { Modal } from "@/components/Modal";
import { Btn, Field, Input } from "@/components/primitives";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { useTranslation } from "@/i18n";
import type { BuiltinParam, SnippetParam } from "@/support/snippetParams";

export function SnippetParamsForm({
  label,
  ask,
  fromHost,
  onSubmit,
  onCancel,
}: {
  /** The snippet's name, shown as the dialog's subtitle. */
  label: string;
  ask: SnippetParam[];
  /** Built-ins answered by the target; shown, never asked. */
  fromHost: { name: BuiltinParam; value: string }[];
  onSubmit: (values: Record<string, string>) => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const p = usePalette();
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(ask.map((prm) => [prm.name, prm.default ?? ""])),
  );

  const submit = () => onSubmit(values);
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== "Enter" || e.nativeEvent.isComposing) return;
    e.preventDefault();
    submit();
  };

  return (
    <Modal
      icon="terminal"
      title={t("snippetParams.title")}
      subtitle={label}
      onClose={onCancel}
      zIndex={300}
      footer={
        <div style={{ display: "flex", gap: rem(8), justifyContent: "flex-end", marginLeft: "auto" }}>
          <Btn variant="ghost" onClick={onCancel}>
            {t("common.cancel")}
          </Btn>
          <Btn onClick={submit}>{t("snippetParams.submit")}</Btn>
        </div>
      }
    >
      {ask.map((prm) => (
        <Field key={prm.name} label={prm.name}>
          <Input
            mono
            selectOnFocus
            value={values[prm.name] ?? ""}
            onChange={(v) => setValues((cur) => ({ ...cur, [prm.name]: v }))}
            onKeyDown={onKeyDown}
          />
        </Field>
      ))}
      {fromHost.map((b) => (
        <div key={b.name} style={{ display: "flex", alignItems: "baseline", gap: rem(10), fontSize: TEXT.small }}>
          <span style={{ fontWeight: 600, color: p.txt2 }}>{b.name}</span>
          <span style={{ fontFamily: MONO, color: p.txt, minWidth: 0, overflowWrap: "anywhere" }}>{b.value}</span>
          <span style={{ color: p.txt3, marginLeft: "auto", whiteSpace: "nowrap" }}>{t("snippetParams.fromHost")}</span>
        </div>
      ))}
    </Modal>
  );
}
