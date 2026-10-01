import { Btn } from "@/components/primitives";
import { useApp } from "@/store/app";
import { useTranslation } from "@/i18n";

export function WorkspaceButton() {
  const { t } = useTranslation();
  const ready = useApp((s) => s.workspaceReady);
  return <Btn variant="ghost" size="sm" icon="grid" aria-haspopup="dialog"
    disabled={!ready} onClick={() => useApp.getState().openModal({ kind: "workspaces" })}>
    {t("terminal.workspaces.title")}
  </Btn>;
}
