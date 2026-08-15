// The live external-editor list. Nothing else in the app tells you that a remote
// file is sitting decrypted on your disk and that saves are being pushed for
// you, so this strip is the feature's honesty: what is open, where the copy is,
// how many times it has been sent, and one button to stop.

import { useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO } from "@/theme/tokens";
import { Icon, Btn, IconBtn } from "@/components/primitives";
import { Modal } from "@/components/Modal";
import { useTranslation } from "@/i18n";
import { toast } from "@/store/toast";
import { apiErrorMessage } from "@/bridge/types";
import {
  editErrorText,
  resolveConflict,
  retryExternalEdit,
  stopExternalEdit,
  useExternalEdits,
  type ConflictChoice,
  type LiveEdit,
  type ResolvedSession,
} from "@/sftp/external-edit";

type SessionLookup = (sessionId: string, profileId: string) => ResolvedSession | null;

function stateTone(edit: LiveEdit, p: ReturnType<typeof usePalette>): string {
  if (edit.state === "error") return p.red;
  if (edit.state === "conflict") return p.amber;
  if (edit.state === "uploading") return p.accentText;
  return p.txt3;
}

function EditRow({ edit, sourceFor }: { edit: LiveEdit; sourceFor: SessionLookup }) {
  const p = usePalette();
  const { t } = useTranslation();
  const [asking, setAsking] = useState(false);
  const [confirmStop, setConfirmStop] = useState(false);

  const status =
    edit.state === "error"
      ? (editErrorText(edit) ?? t("sftp.extEdit.failed"))
      : edit.state === "conflict"
        ? t("sftp.extEdit.changedOnServer")
        : edit.state === "uploading"
          ? t("sftp.extEdit.uploading")
          : edit.saves > 0
            ? t("sftp.extEdit.savedCount", { count: edit.saves })
            : t("sftp.extEdit.watching");

  const answer = async (choice: ConflictChoice) => {
    const resolved = sourceFor(edit.sessionId, edit.profileId);
    if (!resolved) {
      toast(t("sftp.extEdit.sessionClosed"), "err");
      return;
    }
    setAsking(false);
    try {
      await resolveConflict(edit.id, choice, resolved.source);
    } catch (e) {
      toast(apiErrorMessage(e), "err");
    }
  };

  return (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", minWidth: 0 }}>
        <Icon name="pencil" size={13} color={stateTone(edit, p)} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div
            style={{
              fontSize: 13,
              color: p.txt,
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            {edit.name}
          </div>
          {/* The copy's path, in full: the point is that the user can find it,
              and delete it themselves if they stop trusting us to. */}
          <div
            style={{
              fontSize: 11,
              fontFamily: MONO,
              color: p.txt3,
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
            title={edit.localPath}
          >
            {edit.localPath}
          </div>
        </div>
        <span style={{ fontSize: 12, color: stateTone(edit, p), flexShrink: 0 }}>{status}</span>
        {edit.state === "conflict" && (
          <Btn size="sm" variant="outline" onClick={() => setAsking(true)}>
            {t("sftp.extEdit.resolve")}
          </Btn>
        )}
        {edit.state === "error" && (
          <Btn size="sm" variant="outline" icon="refresh" onClick={() => retryExternalEdit(edit.id)}>
            {t("sftp.extEdit.retry")}
          </Btn>
        )}
        <IconBtn
          icon="x"
          size={26}
          title={t("sftp.extEdit.stop")}
          // Stopping deletes the copy. That is harmless while saves are landing,
          // but an errored edit is precisely the case where the copy holds work
          // the server has never seen — so that one asks first.
          // A conflict is by definition an edit the server has not seen either.
          onClick={() =>
            edit.state === "error" || edit.state === "conflict"
              ? setConfirmStop(true)
              : void stopExternalEdit(edit.id)
          }
        />
      </div>

      {confirmStop && (
        <Modal
          icon="trash"
          iconColor={p.red}
          title={t("sftp.extEdit.discardTitle")}
          subtitle={edit.localPath}
          onClose={() => setConfirmStop(false)}
          footer={
            <>
              <div style={{ flex: 1 }} />
              <Btn variant="ghost" size="sm" onClick={() => setConfirmStop(false)}>
                {t("common.cancel")}
              </Btn>
              <Btn
                variant="danger"
                size="sm"
                onClick={() => {
                  setConfirmStop(false);
                  void stopExternalEdit(edit.id);
                }}
              >
                {t("sftp.extEdit.discard")}
              </Btn>
            </>
          }
        >
          <div style={{ fontSize: 13, color: p.txt }}>{t("sftp.extEdit.discardBody")}</div>
        </Modal>
      )}

      {asking && (
        <Modal
          icon="alert"
          iconColor={p.amber}
          title={t("sftp.extEdit.conflictTitle")}
          subtitle={edit.remotePath}
          onClose={() => setAsking(false)}
          footer={
            <>
              <Btn variant="ghost" size="sm" onClick={() => void answer("cancel")}>
                {t("sftp.extEdit.keepServer")}
              </Btn>
              <div style={{ flex: 1 }} />
              <Btn
                variant="outline"
                size="sm"
                onClick={() => void answer("overwrite")}
                style={{ color: p.red, borderColor: p.red }}
              >
                {t("sftp.dlg.overwrite")}
              </Btn>
              <Btn size="sm" onClick={() => void answer("copy")}>
                {t("sftp.dlg.keepBoth")}
              </Btn>
            </>
          }
        >
          <div style={{ fontSize: 13, color: p.txt }}>{t("sftp.extEdit.conflictBody")}</div>
        </Modal>
      )}
    </>
  );
}

export function ExternalEdits({ sourceFor }: { sourceFor: SessionLookup }) {
  const p = usePalette();
  const { t } = useTranslation();
  const edits = useExternalEdits((s) => s.edits);
  if (edits.length === 0) return null;
  return (
    <div
      style={{
        borderTop: `1px solid ${p.line}`,
        background: p.bg1,
        padding: "6px 22px 8px",
      }}
    >
      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 0.3, color: p.txt3, textTransform: "uppercase" }}>
        {t("sftp.extEdit.section")}
      </div>
      {edits.map((e) => (
        <EditRow key={e.id} edit={e} sourceFor={sourceFor} />
      ))}
      {/* Said once, under the list, rather than in a dialog nobody reads: the
          copies are plaintext, and they go away when the app does. */}
      <div style={{ fontSize: 11, color: p.txt3, marginTop: 2 }}>{t("sftp.extEdit.plaintextNote")}</div>
    </div>
  );
}
