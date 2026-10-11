// Finish a staged key rotation behind a confirm. The only way in is the
// guided-rotation dialog after a run: the confirm has to say which machines
// would be locked out, and only a run knows that. There is deliberately no
// variant that finishes without that list — except completing a finish that
// was interrupted after the key item already took the candidate (`committed`):
// that changes no key, so there is nothing left for it to lock out.

import { i18n } from "@/i18n";
import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import { useApp } from "@/store/app";
import type { Ctx } from "@/store/ctx";

export function confirmFinishRotation(
  ctx: Ctx,
  {
    vault,
    keyId,
    candidateId,
    lockedOut,
    committed = false,
    onDone,
  }: {
    vault: string;
    keyId: string;
    candidateId: string;
    /** Machines (and the hosts that hop through them) the candidate was not
     *  proven on in the run just made: finishing locks them out. Empty when
     *  the candidate logged in everywhere. */
    lockedOut: string[];
    /** The key item already holds the candidate's key (an interrupted finish). */
    committed?: boolean;
    onDone?: () => void;
  },
) {
  const body = i18n.t(committed ? "secrets.finishRotationCommittedBody" : "secrets.finishRotationBody", {
    item: keyId,
    candidate: candidateId,
  });
  ctx.confirm({
    title: i18n.t("secrets.finishRotationTitle"),
    body:
      lockedOut.length > 0
        ? `${i18n.t("secrets.finishRotationLockout", { hosts: lockedOut.join(", ") })} ${body}`
        : body,
    danger: lockedOut.length > 0,
    confirmLabel: i18n.t("secrets.finishRotationConfirm"),
    icon: "refresh",
    onConfirm: async () => {
      try {
        await api.finishKeyRotation(vault, keyId, candidateId);
        await useApp.getState().reloadVault();
        ctx.toast(i18n.t("secrets.rotationFinished"), "ok");
        onDone?.();
      } catch (e) {
        ctx.toast(apiErrorMessage(e), "err");
      }
    },
  });
}
