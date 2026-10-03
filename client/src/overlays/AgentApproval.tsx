// AgentApproval — a forwarded agent, or the system agent, asking whether to sign.
//
// This dialog is the feature. Agent forwarding without it is what OpenSSH gives
// you: while the session lives, anything running as your user on the remote host
// can use your key and nothing anywhere shows it happened. With it, every
// signature is a thing you saw. The system agent asks the same way, naming the
// key and the program on this computer that wants it.
//
// So every path out of here that is not an explicit approval must refuse —
// closing, Escape, a timeout, a dead window. Defaulting the other way would make
// the prompt decorative.

import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { useTranslation } from "@/i18n";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { Modal } from "@/components/Modal";
import { Btn } from "@/components/primitives";

interface ApprovalRequest {
  id: number;
  origin: "forwarded" | "system";
  /** Forwarded: the session's host. */
  host: string;
  /** System agent: the key asked for, and its vault. */
  key: string;
  vault: string;
  /** System agent: the calling process, as the OS reported it (advisory). */
  pid: number | null;
  executable: string | null;
  /** The user an SSH login would log in as; empty otherwise. Never the server. */
  user: string;
}

async function answer(id: number, approved: boolean) {
  try {
    await invoke("submit_agent_approval", { id, approved });
  } catch {
    // The core refuses on its own timeout, so a failed hand-off is safe: the
    // signature does not happen.
  }
}

export function AgentApproval() {
  // Queued, not dropped: a single `git fetch` can ask more than once, and a
  // request nobody sees is a request that quietly times out. The first one is
  // on screen. One the core withdraws (timed out, its client hung up, the
  // agent stopped) is removed wherever it is — it can no longer be answered.
  const [queue, setQueue] = useState<ApprovalRequest[]>([]);

  useEffect(() => {
    const disposers: (() => void)[] = [];
    let alive = true;
    const keep = (un: () => void) => {
      if (alive) disposers.push(un);
      else un();
    };
    void listen<ApprovalRequest>("agent-approval", (e) => {
      setQueue((q) => [...q, e.payload]);
    }).then(keep);
    void listen<number>("agent-approval-cancelled", (e) => {
      setQueue((q) => q.filter((r) => r.id !== e.payload));
    }).then(keep);
    return () => {
      alive = false;
      disposers.forEach((un) => un());
    };
  }, []);

  const req = queue[0];
  if (!req) return null;

  return (
    <Dialog
      key={req.id}
      req={req}
      onDone={() => setQueue((q) => q.filter((r) => r.id !== req.id))}
    />
  );
}

function Dialog({ req, onDone }: { req: ApprovalRequest; onDone: () => void }) {
  const { t } = useTranslation();
  const p = usePalette();
  const [busy, setBusy] = useState(false);
  const system = req.origin === "system";

  const finish = (approved: boolean) => {
    if (busy) return;
    setBusy(true);
    void answer(req.id, approved).then(onDone);
  };

  return (
    <Modal
      icon="shield"
      title={t("agentApproval.title")}
      subtitle={system ? t("agentApproval.systemSubtitle") : req.host}
      // Closing is declining. The safe direction has to be the easy one.
      onClose={() => finish(false)}
      w={420}
      zIndex={500}
      footer={
        <div style={{ display: "flex", gap: rem(8), justifyContent: "flex-end" }}>
          <Btn variant="ghost" onClick={() => finish(false)} disabled={busy}>
            {t("agentApproval.deny")}
          </Btn>
          <Btn onClick={() => finish(true)} disabled={busy}>
            {t("agentApproval.allow")}
          </Btn>
        </div>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: rem(10), fontSize: TEXT.base }}>
        <div>
          {system
            ? t(req.vault ? "agentApproval.systemBodyVault" : "agentApproval.systemBody", {
                key: req.key,
                vault: req.vault,
              })
            : t("agentApproval.body", { host: req.host })}
        </div>
        {system && (
          <div style={{ fontSize: TEXT.small, color: p.txt2, overflowWrap: "anywhere" }}>
            {req.pid == null
              ? t("agentApproval.unknownProcess")
              : req.executable
                ? t("agentApproval.process", { executable: req.executable, pid: req.pid })
                : t("agentApproval.processPidOnly", { pid: req.pid })}
          </div>
        )}
        {req.user ? (
          // The user only, for both origins: the payload's service is always
          // `ssh-connection`, and it never names the server. A forwarded
          // request's host is in the subtitle.
          <div
            style={{
              fontFamily: MONO,
              fontSize: TEXT.small,
              padding: `${rem(8)} ${rem(10)}`,
              borderRadius: 8,
              background: p.bg2,
              border: `1px solid ${p.line}`,
            }}
          >
            {t("agentApproval.wouldLogInUser", { user: req.user })}
          </div>
        ) : (
          // Not an SSH login — a git signature, say. Saying so is better than
          // showing nothing, because "we could not tell" is itself information.
          <div style={{ fontSize: TEXT.small, color: p.txt3 }}>{t("agentApproval.unknownUse")}</div>
        )}
      </div>
    </Modal>
  );
}
