// AuthPrompt — the dialog a server raises mid-connection when it wants something
// no stored credential can answer: a one-time code, a hardware-token response, a
// forced password change.
//
// Unlike the other overlays this one is not opened by the user. The core blocks
// on a background thread waiting for the answer, so two things are load-bearing:
// every path out of here must answer exactly once (Cancel and Escape included,
// or the connection sits blocked until it times out), and the fields must honour
// the server's `echo` flag — that flag is the server stating whether the answer
// is a secret.

import React, { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useTranslation } from "@/i18n";
import { Modal } from "@/components/Modal";
import { Btn, Field, Input, NO_AUTOCORRECT } from "@/components/primitives";
import { useDialogFocus } from "@/components/a11y";

interface PromptField {
  prompt: string;
  echo: boolean;
}

interface PromptRequest {
  id: number;
  host: string;
  port: number;
  user: string;
  name: string;
  instruction: string;
  prompts: PromptField[];
}

async function answer(id: number, answers: string[] | null) {
  try {
    await invoke("submit_auth_prompt", { id, answers });
  } catch {
    // The core gives up on its own timeout. There is nothing the user can do
    // about a failed hand-off, and a toast here would only bury the connection
    // error that follows it.
  }
}

export function AuthPrompt() {
  const [req, setReq] = useState<PromptRequest | null>(null);
  // A queue, not a single slot: a fleet run across many hosts can raise several
  // prompts, and dropping the later ones would leave those connections blocked
  // with nothing on screen to explain why.
  const queue = useRef<PromptRequest[]>([]);

  useEffect(() => {
    let dispose: (() => void) | undefined;
    let alive = true;
    (async () => {
      const { listen } = await import("@tauri-apps/api/event");
      const un = await listen<PromptRequest>("auth-prompt", (e) => {
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

  // Keyed by request id so each prompt gets a fresh mount: state resets, and
  // the focus hook (which runs once per mount) fires for every dialog rather
  // than only the first.
  return (
    <PromptDialog
      key={req.id}
      req={req}
      onDone={() => setReq(queue.current.shift() ?? null)}
    />
  );
}

function PromptDialog({ req, onDone }: { req: PromptRequest; onDone: () => void }) {
  const { t } = useTranslation();
  const [values, setValues] = useState<string[]>(() => req.prompts.map(() => ""));
  const [busy, setBusy] = useState(false);
  const ref = useDialogFocus<HTMLDivElement>();

  const finish = (payload: string[] | null) => {
    if (busy) return;
    setBusy(true);
    void answer(req.id, payload).then(onDone);
  };

  const where = `${req.user}@${req.host}${req.port === 22 ? "" : `:${req.port}`}`;

  return (
    <Modal
      icon="shield"
      title={t("auth.prompt.title")}
      subtitle={where}
      onClose={() => finish(null)}
      w={420}
      zIndex={400}
      footer={
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <Btn variant="ghost" onClick={() => finish(null)} disabled={busy}>
            {t("common.cancel")}
          </Btn>
          <Btn onClick={() => finish(values)} disabled={busy}>
            {t("auth.prompt.submit")}
          </Btn>
        </div>
      }
    >
      <div ref={ref} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {/* Server text, shown verbatim: it is how a server says which factor it
            wants, and paraphrasing would hide that. */}
        {(req.name || req.instruction) && (
          <div style={{ fontSize: 13, opacity: 0.8, whiteSpace: "pre-wrap" }}>
            {[req.name, req.instruction].filter(Boolean).join("\n")}
          </div>
        )}
        {req.prompts.map((p, i) => (
          <Field key={i} label={p.prompt.trim() || t("auth.prompt.answer")}>
            <Input
              value={values[i] ?? ""}
              onChange={(v: string) =>
                setValues((a) => {
                  const next = [...a];
                  next[i] = v;
                  return next;
                })
              }
              // echo=false is the server marking this as hidden input: a
              // password, a one-time code.
              type={p.echo ? "text" : "password"}
              mono={!p.echo}
              onKeyDown={(e: React.KeyboardEvent) => {
                if (e.key === "Enter") finish(values);
              }}
              {...NO_AUTOCORRECT}
            />
          </Field>
        ))}
      </div>
    </Modal>
  );
}
