// Finish a staged key rotation behind the one confirm both entry points use
// (the Secrets key row and the guided-rotation dialog).

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
    danger = false,
    onDone,
  }: {
    vault: string;
    keyId: string;
    candidateId: string;
    /** Some machine has not switched: finishing can lock it out. */
    danger?: boolean;
    onDone?: () => void;
  },
) {
  ctx.confirm({
    title: i18n.t("secrets.finishRotationTitle"),
    body: i18n.t("secrets.finishRotationBody", { item: keyId, candidate: candidateId }),
    danger,
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
