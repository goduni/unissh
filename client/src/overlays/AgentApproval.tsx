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

import { useEffect, useRef, useState } from "react";
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
  /** System agent: the key asked for. */
  key: string;
  /** System agent: the calling process, where the OS reported it. */
  pid: number | null;
  executable: string | null;
  /** `user@service` when the payload is an SSH login; empty otherwise. */
  target: string;
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
  const [req, setReq] = useState<ApprovalRequest | null>(null);
  // Queued, not dropped: a single `git fetch` can ask more than once, and a
  // request nobody sees is a request that quietly times out.
  const queue = useRef<ApprovalRequest[]>([]);

  useEffect(() => {
    let dispose: (() => void) | undefined;
    let alive = true;
    (async () => {
      const un = await listen<ApprovalRequest>("agent-approval", (e) => {
        const next = e.payload;
        setReq((cur) => {
          if (cur) {
            queue.current.push(next);
            return cur;
          }
          return next;
        });
      });
      if (alive) dispose = un;
      else un();
    })();
    return () => {
      alive = false;
      dispose?.();
    };
  }, []);

  if (!req) return null;

  return (
    <Dialog key={req.id} req={req} onDone={() => setReq(queue.current.shift() ?? null)} />
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
            ? t("agentApproval.systemBody", { key: req.key })
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
        {req.target ? (
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
            {t("agentApproval.wouldLogIn", { target: req.target })}
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
