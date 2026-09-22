import { useId, useState } from "react";
import { Btn, Field, Icon, Input } from "@/components/primitives";
import { useTranslation } from "@/i18n";
import type { McpApprovalMode, McpSelection, McpTarget } from "@/bridge/mcp";

import { McpDurationPicker } from "./McpDurationPicker";
import { durationSeconds, initialDuration } from "./duration";

export const targetKey = (target: McpTarget) =>
  JSON.stringify([target.vault_id, target.profile_id]);

export function McpAccessEditor({
  selection,
  initial,
  initialSeconds,
  initialApprovalMode,
  busy,
  onSave,
  onCancel,
}: {
  selection: McpSelection;
  initial: McpTarget[];
  initialSeconds: number | null;
  initialApprovalMode: McpApprovalMode;
  busy: boolean;
  onSave: (targets: McpTarget[], seconds: number | null, approvalMode: McpApprovalMode) => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const [vault, setVault] = useState(initial[0]?.vault_id ?? "");
  const [selected, setSelected] = useState(
    () => new Set(initial.map(targetKey)),
  );
  const [search, setSearch] = useState("");
  const [approvalMode, setApprovalMode] = useState(initialApprovalMode);
  const [consent, setConsent] = useState(false);
  const [duration, setDuration] = useState(() =>
    initialDuration(initialSeconds),
  );
  const seconds = durationSeconds(duration);
  const chosen = selection.targets.filter((target) =>
    selected.has(targetKey(target)),
  );
  const query = search.trim().toLocaleLowerCase();
  const visible = selection.targets.filter(
    (target) =>
      target.vault_id === vault &&
      `${target.label} ${target.user} ${target.host}`
        .toLocaleLowerCase()
        .includes(query),
  );
  const setChecked = (targets: McpTarget[], checked: boolean) =>
    setSelected((previous) => {
      const next = new Set(previous);
      for (const target of targets) {
        if (checked) next.add(targetKey(target));
        else next.delete(targetKey(target));
      }
      return next;
    });
  const allChecked =
    visible.length > 0 &&
    visible.every((target) => selected.has(targetKey(target)));
  return (
    <form
      className="mcp-access-editor"
      onSubmit={(e) => {
        e.preventDefault();
        if (
          !busy &&
          consent &&
          chosen.length > 0 &&
          chosen.length <= 64 &&
          seconds !== undefined
        )
          onSave(chosen, seconds, approvalMode);
      }}
    >
      <fieldset disabled={busy}>
        <div className="mcp-target-picker">
          <fieldset className="mcp-vault-picker">
            <legend className="mcp-field-label">{t("mcp.chooseVault")}</legend>
            <div className="mcp-vault-options">
              {selection.vaults.map((v, index) => {
                const count = selection.targets.filter(
                  (target) => target.vault_id === v.id,
                ).length;
                const selectedCount = chosen.filter(
                  (target) => target.vault_id === v.id,
                ).length;
                return (
                  <label className="mcp-vault-option" key={v.id}>
                    <input
                      type="radio"
                      name={`${id}-vault`}
                      value={v.id}
                      autoFocus={v.id === vault || (!vault && index === 0)}
                      checked={vault === v.id}
                      onChange={() => {
                        setVault(v.id);
                        setSearch("");
                      }}
                    />
                    <span className="mcp-vault-row">
                      <Icon name="layers" size={18} />
                      <span className="mcp-vault-name">
                        <strong>{v.name}</strong>
                        <small>{t("count.hosts", { count })}</small>
                      </span>
                      {!!selectedCount && (
                        <span
                          className="mcp-vault-count"
                          aria-label={t("mcp.selectedHosts", {
                            hosts: t("count.hosts", { count: selectedCount }),
                          })}
                        >
                          <Icon name="check" size={12} />
                          {selectedCount}
                        </span>
                      )}
                    </span>
                  </label>
                );
              })}
            </div>
            {!selection.vaults.length && <p>{t("mcp.noTargets")}</p>}
          </fieldset>
          {vault ? (
            <div className="mcp-host-picker">
              <Field label={t("mcp.searchHosts")}>
                <Input
                  icon="search"
                  value={search}
                  onChange={setSearch}
                  placeholder={t("mcp.searchPlaceholder")}
                />
              </Field>
              {!!visible.length && (
                <label className="mcp-check mcp-select-all">
                  <input
                    type="checkbox"
                    checked={allChecked}
                    onChange={(e) => setChecked(visible, e.target.checked)}
                  />
                  <span>{t("mcp.selectVisible")}</span>
                </label>
              )}
              <div className="mcp-host-options">
                {visible.map((target) => (
                  <label className="mcp-check mcp-host" key={targetKey(target)}>
                    <input
                      type="checkbox"
                      checked={selected.has(targetKey(target))}
                      onChange={(e) => setChecked([target], e.target.checked)}
                    />
                    <span>
                      <strong>{target.label}</strong>
                      <small>
                        {target.user}@{target.host}:{target.port}
                      </small>
                    </span>
                  </label>
                ))}
              </div>
              {!visible.length && (
                <p className="mcp-hint">
                  {t(query ? "mcp.noMatches" : "mcp.vaultEmpty")}
                </p>
              )}
            </div>
          ) : (
            <div className="mcp-picker-empty">
              <Icon name="layers" size={22} />
              <p>{t("mcp.chooseVaultPlaceholder")}</p>
            </div>
          )}
        </div>
        {!!chosen.length && (
          <div className="mcp-selection-summary">
            <strong>
              {t("mcp.selectedHosts", {
                hosts: t("count.hosts", { count: chosen.length }),
              })}
            </strong>
            <div>
              {selection.vaults
                .filter((v) =>
                  chosen.some((target) => target.vault_id === v.id),
                )
                .map((v) => (
                  <span key={v.id}>
                    <Icon name="layers" size={14} />
                    {v.name} ·{" "}
                    {chosen.filter((target) => target.vault_id === v.id).length}
                  </span>
                ))}
            </div>
          </div>
        )}
        {chosen.length > 64 && (
          <p className="mcp-error" role="alert">
            {t("mcp.tooManyHosts")}
          </p>
        )}
        <fieldset className="mcp-approval-policy">
          <legend className="mcp-field-label">{t("mcp.approvalMode")}</legend>
          <div className="mcp-choice-group">
            {(["manual", "trusted"] as const).map((mode) => (
              <label className="mcp-choice" key={mode}>
                <input
                  type="radio"
                  name={`${id}-approval`}
                  checked={approvalMode === mode}
                  aria-describedby={`${id}-approval-hint`}
                  onChange={() => { setApprovalMode(mode); setConsent(false); }}
                />
                <span>{t(`mcp.approvalModes.${mode}`)}</span>
              </label>
            ))}
          </div>
          <p id={`${id}-approval-hint`} className="mcp-policy-hint">
            {t(`mcp.approvalHints.${approvalMode}`)}
          </p>
        </fieldset>
        <McpDurationPicker value={duration} onChange={setDuration} />
        <p className="mcp-lifecycle-hint">{t("mcp.accessLifetime")}</p>
        <label className="mcp-check mcp-consent">
          <input
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
          />
          <span>{t(approvalMode === "trusted" ? "mcp.trustedDisclosure" : "mcp.disclosure")}</span>
        </label>
        <div className="mcp-actions">
          <Btn
            type="submit"
            disabled={
              busy ||
              !consent ||
              !chosen.length ||
              chosen.length > 64 ||
              seconds === undefined
            }
          >
            {t("mcp.allow")}
          </Btn>
          <Btn type="button" variant="ghost" disabled={busy} onClick={onCancel}>
            {t("common.cancel")}
          </Btn>
        </div>
      </fieldset>
    </form>
  );
}
