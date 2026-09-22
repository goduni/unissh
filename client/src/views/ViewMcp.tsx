import { useEffect, useRef, useState, type CSSProperties } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Btn, Field, Icon, Input } from "@/components/primitives";
import { usePalette } from "@/theme/ThemeProvider";
import { useTranslation, tDyn } from "@/i18n";
import { writeSecretToClipboard } from "@/bridge/clipboard";
import * as api from "@/bridge/mcp";
import { refreshMcp, useMcp } from "@/store/mcp";
import { useApp } from "@/store/app";
import { McpAccessEditor } from "./mcp/McpAccessEditor";
import { formatDuration } from "./mcp/duration";
import { McpConnectionGuide } from "./mcp/McpConnectionGuide";
import "./mcp/mcp.css";

export function ViewMcp() {
  const p = usePalette();
  const { t, i18n } = useTranslation();
  const status = useMcp((s) => s.status);
  const failed = useMcp((s) => s.failed);
  const [selected, setSelected] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [label, setLabel] = useState("");
  const [port, setPort] = useState("");
  const [serverOptions, setServerOptions] = useState(false);
  const [token, setToken] = useState<{ id: string; value: string } | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [editor, setEditor] = useState<{
    id: string;
    selection: api.McpSelection;
  } | null>(null);
  const operation = useRef(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    void refreshMcp();
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(null), 2500);
    return () => clearTimeout(timer);
  }, [copied]);
  async function act(f: () => Promise<unknown>) {
    if (!alive.current || operation.current) return;
    operation.current = true;
    setBusy(true);
    setError(false);
    try {
      await f();
      if (alive.current) await refreshMcp();
    } catch {
      if (alive.current) setError(true);
    } finally {
      operation.current = false;
      if (alive.current) setBusy(false);
    }
  }
  const integration =
    status?.integrations.find((i) => i.id === selected) ??
    status?.integrations[0];
  const grant = status?.activity.grants.find(
    (g) => g.integration_id === integration?.id,
  );
  const sessions =
    status?.activity.sessions.filter(
      (s) => s.integration_id === integration?.id,
    ) ?? [];
  const runs =
    status?.activity.runs.filter((r) => r.integration_id === integration?.id) ??
    [];
  const chosenPort = port === "" ? (status?.port ?? 0) : Number(port);
  const validPort =
    Number.isInteger(chosenPort) && chosenPort >= 0 && chosenPort <= 65535;
  const duration = (g: NonNullable<typeof grant>) =>
    g.remaining_seconds === null
      ? t("mcp.noExpiry")
      : t("mcp.remaining", {
          duration: formatDuration(g.remaining_seconds, i18n.language),
        });
  const copy = (kind: string, text: string, secret = false) =>
    void act(async () => {
      if (secret) await writeSecretToClipboard(text);
      else await writeText(text);
      if (alive.current) setCopied(kind);
    });
  const editAccess = () => {
    if (!integration) return;
    const id = integration.id;
    void act(async () => {
      const selection = await api.mcpTargets();
      if (alive.current) setEditor({ id, selection });
    });
  };
  const confirmChange = (rotate: boolean) => {
    if (!integration) return;
    const { id, label: name } = integration;
    useApp.getState().setConfirm({
      title: t(rotate ? "mcp.rotateTitle" : "mcp.deleteTitle", { name }),
      body: t(rotate ? "mcp.rotateBody" : "mcp.deleteBody"),
      danger: true,
      confirmLabel: t(rotate ? "mcp.rotate" : "common.delete"),
      onConfirm: () =>
        act(async () => {
          if (rotate) {
            const result = await api.mcpRotate(id);
            if (alive.current) {
              setSelected(result.id);
              setToken({ id: result.id, value: result.token });
            }
          } else {
            await api.mcpDelete(id);
            if (alive.current) {
              setToken(null);
              setSelected(null);
            }
          }
          if (alive.current) setEditor(null);
        }),
    });
  };
  const style = {
    "--mcp-bg": p.bg0,
    "--mcp-surface": p.bg1,
    "--mcp-hover": p.bg2,
    "--mcp-line": p.line,
    "--mcp-text": p.txt,
    "--mcp-muted": p.txt2,
    "--mcp-accent": p.accent,
    "--mcp-danger": p.red,
  } as CSSProperties;
  return (
    <div className="uh-view mcp-view" style={style}>
      <header className="mcp-heading">
        <div>
          <h1>{t("mcp.tab")}</h1>
          <p>{t("mcp.description")}</p>
        </div>
      </header>
      {!status ? (
        <div className="mcp-loading" role="status">
          <p>{t(failed ? "mcp.error" : "mcp.loading")}</p>
          {failed && (
            <Btn onClick={() => void refreshMcp()}>{t("common.refresh")}</Btn>
          )}
        </div>
      ) : (
        <>
          <section className="mcp-server" aria-label={t("mcp.server")}>
            <div className="mcp-server-info">
              <Icon name="link" size={20} />
              <div>
                <strong>
                  {t(status.enabled ? "mcp.listening" : "mcp.disabled")}
                </strong>
                <div className="mcp-meta">
                  {status.enabled ? (
                    <code>{status.endpoint}</code>
                  ) : (
                    t("mcp.startHint")
                  )}
                </div>
              </div>
            </div>
            <div className="mcp-actions">
              {status.enabled && (
                <Btn
                  variant="outline"
                  disabled={busy}
                  icon="copy"
                  onClick={() => copy("endpoint", status.endpoint)}
                >
                  {t(copied === "endpoint" ? "mcp.copied" : "mcp.copyEndpoint")}
                </Btn>
              )}
              <Btn
                variant="ghost"
                icon="sliders"
                aria-label={t("mcp.serverOptions")}
                aria-expanded={serverOptions}
                onClick={() => setServerOptions(!serverOptions)}
              />
              <Btn
                variant={status.enabled ? "outline" : "primary"}
                disabled={busy || (!status.enabled && !validPort)}
                onClick={() =>
                  void act(() =>
                    api.mcpEnable(
                      !status.enabled,
                      status.enabled ? status.port : chosenPort,
                    ),
                  )
                }
              >
                {t(status.enabled ? "mcp.disable" : "mcp.enable")}
              </Btn>
            </div>
          </section>
          {serverOptions && (
            <section className="mcp-server-options">
              <Field label={t("mcp.port")}>
                <Input
                  type="number"
                  value={port === "" ? String(status.port) : port}
                  onChange={setPort}
                />
              </Field>
              <p>{t("mcp.portHint")}</p>
              <p>{t("mcp.localOnly")}</p>
            </section>
          )}
          {(error || failed || status.error) && (
            <div className="mcp-error" role="alert">
              {status.error ? tDyn(`mcp.${status.error}`) : t("mcp.error")}
            </div>
          )}
          <div className="mcp-workspace">
            <aside className="mcp-apps" aria-label={t("mcp.integrations")}>
              <div className="mcp-section-heading">
                <h2>{t("mcp.integrations")}</h2>
                <Btn
                  icon="plus"
                  variant="ghost"
                  aria-label={t("mcp.add")}
                  onClick={() => setAdding(true)}
                />
              </div>
              <nav className="mcp-app-list" aria-label={t("mcp.integrations")}>
                {status.integrations.map((i) => {
                  const access = status.activity.grants.find(
                    (g) => g.integration_id === i.id,
                  );
                  return (
                    <button
                      key={i.id}
                      className="mcp-app"
                      aria-current={
                        i.id === integration?.id ? "page" : undefined
                      }
                      disabled={busy}
                      onClick={() => {
                        setSelected(i.id);
                        setEditor(null);
                      }}
                    >
                      <Icon name="link" size={17} />
                      <span>
                        <strong>{i.label}</strong>
                        <small>
                          {access ? duration(access) : t("mcp.noGrant")}
                        </small>
                      </span>
                    </button>
                  );
                })}
              </nav>
              {adding || !status.integrations.length ? (
                <form
                  className="mcp-add"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (
                      !label.trim() ||
                      new TextEncoder().encode(label.trim()).length > 120
                    )
                      return;
                    void act(async () => {
                      const result = await api.mcpCreate(label.trim());
                      if (alive.current) {
                        setSelected(result.id);
                        setToken({ id: result.id, value: result.token });
                        setLabel("");
                        setAdding(false);
                        setEditor(null);
                      }
                    });
                  }}
                >
                  <Field label={t("mcp.name")}>
                    <Input
                      autoFocus={adding}
                      value={label}
                      onChange={setLabel}
                      placeholder={t("mcp.nameExample")}
                    />
                  </Field>
                  <div className="mcp-actions">
                    <Btn
                      type="submit"
                      disabled={
                        busy ||
                        !label.trim() ||
                        new TextEncoder().encode(label.trim()).length > 120
                      }
                    >
                      {t("mcp.add")}
                    </Btn>
                    {!!status.integrations.length && (
                      <Btn
                        type="button"
                        variant="ghost"
                        onClick={() => setAdding(false)}
                      >
                        {t("common.cancel")}
                      </Btn>
                    )}
                  </div>
                </form>
              ) : (
                <p className="mcp-aside-hint">{t("mcp.appsHint")}</p>
              )}
              {!!status.activity.grants.length && (
                <Btn
                  variant="ghost"
                  wrap
                  disabled={busy}
                  onClick={() =>
                    void act(async () => {
                      await api.mcpRevoke();
                      if (alive.current) setEditor(null);
                    })
                  }
                >
                  {t("mcp.revokeAll")}
                </Btn>
              )}
            </aside>
            <main className="mcp-detail">
              {!integration ? (
                <div className="mcp-empty">
                  <Icon name="link" size={28} />
                  <h2>{t("mcp.emptyTitle")}</h2>
                  <p>{t("mcp.empty")}</p>
                  <p>{t("mcp.tokenLifetime")}</p>
                </div>
              ) : (
                <>
                  <div className="mcp-detail-heading">
                    <div>
                      <h2>{integration.label}</h2>
                      <p>{t("mcp.tokenLifetime")}</p>
                    </div>
                    <div className="mcp-actions">
                      <Btn
                        variant="ghost"
                        disabled={busy}
                        onClick={() => confirmChange(true)}
                      >
                        {t("mcp.rotate")}
                      </Btn>
                      <Btn
                        variant="ghost"
                        icon="trash"
                        disabled={busy}
                        aria-label={t("common.delete")}
                        onClick={() => confirmChange(false)}
                      />
                    </div>
                  </div>
                  {token?.id === integration.id && (
                    <section
                      className="mcp-token"
                      aria-label={t("mcp.newToken")}
                    >
                      <strong>{t("mcp.newToken")}</strong>
                      <p>{t("mcp.tokenOnce")}</p>
                      <code>{token.value}</code>
                      <div className="mcp-actions">
                        <Btn
                          icon="copy"
                          disabled={busy}
                          onClick={() => copy("token", token.value, true)}
                        >
                          {t(
                            copied === "token" ? "mcp.copied" : "mcp.copyToken",
                          )}
                        </Btn>
                        <Btn variant="ghost" onClick={() => setToken(null)}>
                          {t("mcp.hideToken")}
                        </Btn>
                      </div>
                    </section>
                  )}
                  <section
                    className="mcp-section"
                    aria-label={t("mcp.hostAccess")}
                  >
                    <div className="mcp-section-heading">
                      <div>
                        <h3>{t("mcp.hostAccess")}</h3>
                        <p>{grant ? duration(grant) : t("mcp.noGrant")}</p>
                        {grant && <p className="mcp-policy-summary">{t(`mcp.approvalModes.${grant.approval_mode ?? "manual"}`)}</p>}
                      </div>
                      <div className="mcp-actions">
                        <Btn
                          variant="outline"
                          disabled={busy || !status.enabled}
                          onClick={editAccess}
                        >
                          {t(grant ? "mcp.editAccess" : "mcp.grant")}
                        </Btn>
                        {grant && (
                          <Btn
                            variant="ghost"
                            disabled={busy}
                            onClick={() =>
                              void act(async () => {
                                await api.mcpRevoke(integration.id);
                                if (alive.current) setEditor(null);
                              })
                            }
                          >
                            {t("mcp.revoke")}
                          </Btn>
                        )}
                      </div>
                    </div>
                    {editor?.id === integration.id ? (
                      <McpAccessEditor
                        key={editor.selection.ticket + editor.id}
                        selection={editor.selection}
                        initial={grant?.targets ?? []}
                        initialSeconds={grant?.remaining_seconds ?? null}
                        initialApprovalMode={grant?.approval_mode ?? "manual"}
                        busy={busy}
                        onCancel={() => setEditor(null)}
                        onSave={(targets, seconds, approvalMode) =>
                          void act(async () => {
                            await api.mcpGrant(
                              integration.id,
                              targets,
                              seconds,
                              editor.selection.ticket,
                              approvalMode,
                            );
                            if (alive.current) setEditor(null);
                          })
                        }
                      />
                    ) : grant ? (
                      <GrantedHosts targets={grant.targets} />
                    ) : (
                      <p className="mcp-hint">
                        {t(status.enabled ? "mcp.accessHint" : "mcp.startHint")}
                      </p>
                    )}
                  </section>
                  <section
                    className="mcp-section"
                    aria-label={t("mcp.activity")}
                  >
                    <h3>{t("mcp.activity")}</h3>
                    {!sessions.length && !runs.length && (
                      <p className="mcp-hint">{t("mcp.noActivity")}</p>
                    )}
                    {sessions.map((s) => (
                      <div className="mcp-activity" key={s.session_id}>
                        <Icon name="terminal" size={17} />
                        <div>
                          <strong>{s.target?.label ?? t("mcp.session")}</strong>
                          <p>
                            {t("mcp.session")} · {tDyn(`mcp.state.${s.state}`)}
                            {s.error && ` · ${tDyn(`mcp.errors.${s.error}`)}`}
                            {s.state === "ready" &&
                              ` · ${t("mcp.idle", { seconds: s.idle_seconds })}`}
                          </p>
                        </div>
                        {s.state !== "closed" && (
                          <Btn
                            variant="ghost"
                            disabled={busy}
                            onClick={() =>
                              void act(() => api.mcpCloseSession(s.session_id))
                            }
                          >
                            {t("common.close")}
                          </Btn>
                        )}
                      </div>
                    ))}
                    {runs.map((r) => (
                      <div className="mcp-activity" key={r.run_id}>
                        <Icon name="terminal" size={17} />
                        <div>
                          <strong>{r.target?.label ?? t("mcp.command")}</strong>
                          <p>
                            {t(
                              r.session_id
                                ? "mcp.sessionCommand"
                                : "mcp.oneShot",
                            )}{" "}
                            · {tDyn(`mcp.state.${r.state}`)}
                            {r.error && ` · ${tDyn(`mcp.errors.${r.error}`)}`}
                          </p>
                        </div>
                        {[
                          "awaiting_approval",
                          "queued",
                          "connecting",
                          "running",
                          "cancelling",
                        ].includes(r.state) && (
                          <Btn
                            variant="ghost"
                            disabled={busy}
                            onClick={() =>
                              void act(() => api.mcpCancelCommand(r.run_id))
                            }
                          >
                            {t("common.cancel")}
                          </Btn>
                        )}
                      </div>
                    ))}
                  </section>
                  <details className="mcp-help">
                    <summary>{t("mcp.connectHelp")}</summary>
                    <McpConnectionGuide
                      key={integration.id}
                      endpoint={status.endpoint}
                      enabled={status.enabled}
                      busy={busy}
                      copied={copied}
                      onCopy={copy}
                      onOpenDocs={(url) => void act(() => openUrl(url))}
                    />
                  </details>
                </>
              )}
            </main>
          </div>
          <span className="mcp-feedback" role="status">
            {copied && t("mcp.copied")}
          </span>
        </>
      )}
    </div>
  );
}

function GrantedHosts({ targets }: { targets: api.McpTarget[] }) {
  const vaults = useApp((s) => s.vaults);
  return (
    <div className="mcp-granted">
      {[...new Set(targets.map((t) => t.vault_id))].map((id) => (
        <div key={id} className="mcp-vault-group">
          <div className="mcp-vault-label">
            <Icon name="layers" size={16} />
            <strong>{vaults.find((v) => v.vaultId === id)?.name ?? id}</strong>
          </div>
          {targets
            .filter((t) => t.vault_id === id)
            .map((target) => (
              <div className="mcp-host" key={target.profile_id}>
                <Icon name="server" size={16} />
                <span>
                  <strong>{target.label}</strong>
                  <small>
                    {target.user}@{target.host}:{target.port}
                  </small>
                </span>
              </div>
            ))}
        </div>
      ))}
    </div>
  );
}
