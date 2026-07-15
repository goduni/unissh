// ImportPreview.tsx — ssh-config import preview overlay.
// Pixel-perfect port of import-preview.jsx, wired to the real store + core.
// The user picks ~/.ssh/config (default homeDir()+/.ssh/config), we parse the
// Host stanzas client-side for the preview list, and the core imports the whole
// file via api.importSshConfig.

import { useEffect, useState } from "react";
import { useTranslation, Trans } from "@/i18n";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO } from "@/theme/tokens";
import { Btn, Icon } from "@/components/primitives";
import { useApp } from "@/store/app";
import { useIsMobile, useNarrow } from "@/store/responsive";
import { useDialogFocus, useDialogKeys } from "@/components/a11y";
import { toast } from "@/store/toast";
import { guard } from "@/store/action";
import { apiErrorMessage, ItemType } from "@/bridge/types";
import * as api from "@/bridge/api";

interface ParsedHost {
  host: string;
  hostname: string;
  user: string;
  port: number;
  dup: boolean;
  /** IdentityFile path from the config (block-local, or inherited from a
   *  wildcard `Host *` block). Used to import the referenced key. */
  identityFile?: string;
}

const isWildcard = (a: string) => a.includes("*") || a.includes("?") || a.startsWith("!");
const stripQuotes = (v: string) => v.replace(/^["']|["']$/g, "").trim();

/** Parse `Host` stanzas (alias, HostName, User, Port, IdentityFile) from an ssh
 *  config. IdentityFile set in a wildcard block (e.g. `Host *`) is applied as a
 *  fallback to hosts that don't set their own — matching OpenSSH inheritance for
 *  the common case (Match/Include directives are not expanded). */
function parseSshConfig(text: string, existing: Set<string>): ParsedHost[] {
  const out: ParsedHost[] = [];
  let cur: ParsedHost | null = null;
  let inWildcard = false;
  let globalIdentity: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^(\S+)\s+(.+)$/);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    if (key === "host") {
      // a Host line may list multiple aliases; take the first non-wildcard
      const alias = val.split(/\s+/).find((a) => !isWildcard(a));
      if (!alias) {
        // wildcard-only block — not its own row, but remember its IdentityFile
        // as a fallback for hosts that don't set one of their own.
        cur = null;
        inWildcard = true;
        continue;
      }
      cur = { host: alias, hostname: "", user: "", port: 22, dup: existing.has(alias) };
      inWildcard = false;
      out.push(cur);
    } else if (cur) {
      if (key === "hostname") cur.hostname = val;
      else if (key === "user") cur.user = val;
      else if (key === "port") {
        const n = parseInt(val, 10);
        if (!Number.isNaN(n)) cur.port = n;
      } else if (key === "identityfile" && !cur.identityFile) {
        cur.identityFile = stripQuotes(val);
      }
    } else if (inWildcard && key === "identityfile" && !globalIdentity) {
      globalIdentity = stripQuotes(val);
    }
  }
  if (globalIdentity) {
    for (const h of out) if (!h.identityFile) h.identityFile = globalIdentity;
  }
  return out;
}

/** Keep only the `Host` blocks whose first concrete alias is selected. Wildcard
 *  blocks (`Host *`, `Host *.example.com`) and the global preamble before the
 *  first `Host` are always kept so inherited settings (User/Port/IdentityFile)
 *  still resolve. A multi-alias `Host a b` line is kept whole if `a` is selected. */
function filterConfigToSelected(text: string, selected: Set<string>): string {
  const out: string[] = [];
  let keep = true; // keep the global preamble before the first Host block
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const m = line.match(/^([Hh]ost)\s+(.+)$/);
    if (m && !line.startsWith("#")) {
      const patterns = m[2].trim().split(/\s+/);
      const allWild = patterns.every(isWildcard);
      const firstAlias = patterns.find((a) => !isWildcard(a));
      keep = allWild || (firstAlias != null && selected.has(firstAlias));
    }
    if (keep) out.push(raw);
  }
  return out.join("\n");
}

/** Resolve `~`, `~/`, `$HOME/` prefixes against the home dir; other paths pass
 *  through unchanged. */
async function resolveKeyPath(
  raw: string,
  home: string,
  join: (...parts: string[]) => Promise<string>,
): Promise<string> {
  const pth = stripQuotes(raw);
  if (!pth) return pth;
  if (home && (pth === "~" || pth === "$HOME")) return home;
  if (home && pth.startsWith("~/")) return join(home, pth.slice(2));
  if (home && pth.startsWith("$HOME/")) return join(home, pth.slice(6));
  return pth;
}

/** A vault item id derived from `base`, made unique against `used`. */
function uniqueItemId(base: string, used: Set<string>): string {
  const root = base || "key";
  if (!used.has(root)) return root;
  let n = 2;
  while (used.has(`${root}-${n}`)) n++;
  return `${root}-${n}`;
}

/** Public-key identity (algorithm + base64), ignoring any trailing comment.
 *  Used to dedupe keys regardless of how they were imported/commented. */
function normPub(openssh: string): string {
  return openssh.trim().split(/\s+/).slice(0, 2).join(" ");
}

/** Standard OpenSSH default identity files (the keys ssh tries when a Host has
 *  no explicit IdentityFile), in priority order. Returns absolute paths; the
 *  caller probes which ones actually exist. */
async function defaultIdentityPaths(
  home: string,
  join: (...parts: string[]) => Promise<string>,
): Promise<string[]> {
  if (!home) return [];
  const names = ["id_ed25519", "id_rsa", "id_ecdsa", "id_ed25519_sk", "id_ecdsa_sk", "id_dsa"];
  return Promise.all(names.map((n) => join(home, ".ssh", n)));
}

/** Coarse reason a key couldn't be imported, for a precise skip message instead
 *  of the old catch-all "encrypted or not found". `forbidden` is the common one:
 *  Tauri's fs scope denies direct reads of ~/.ssh on Unix unless explicitly
 *  allowed (see capabilities/default.json). */
type SkipReason = "encrypted" | "forbidden" | "notFound" | "unsupported" | "parse" | "other";

function classifySkip(msg: string): SkipReason {
  const m = msg.toLowerCase();
  if (/passphrase|is encrypted|legacy openssl/.test(m)) return "encrypted";
  if (/forbidden|not allowed|allowed scope|\bscope\b|permission denied|access is denied|os error 13|eacces/.test(m))
    return "forbidden";
  if (/no such file|not found|cannot find|os error 2|enoent/.test(m)) return "notFound";
  if (/unsupported/.test(m)) return "unsupported";
  if (/parse/.test(m)) return "parse";
  return "other";
}

// Gate: mount the body (and its dialog hooks) only while open, so Escape/focus
// register per-open per the useDialogKeys contract rather than for App's lifetime.
export function ImportPreview() {
  const importing = useApp((s) => s.importing);
  if (!importing) return null;
  return <ImportPreviewBody />;
}

function ImportPreviewBody() {
  const { t } = useTranslation();
  const p = usePalette();
  const isMobile = useIsMobile();
  const narrow = useNarrow();
  const importing = useApp((s) => s.importing);
  const setImporting = useApp((s) => s.setImporting);

  const [path, setPath] = useState<string>("~/.ssh/config");
  const [fileText, setFileText] = useState<string>("");
  const [rows, setRows] = useState<ParsedHost[]>([]);
  const [sel, setSel] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);

  const close = () => setImporting(false);
  useDialogKeys(close);
  const cardRef = useDialogFocus<HTMLDivElement>();

  // On open, pick the file and parse it.
  useEffect(() => {
    if (!importing) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const { open } = await import("@tauri-apps/plugin-dialog");
        const { readTextFile } = await import("@tauri-apps/plugin-fs");
        const { homeDir, join } = await import("@tauri-apps/api/path");
        let defaultPath: string | undefined;
        try {
          defaultPath = await join(await homeDir(), ".ssh", "config");
        } catch {
          defaultPath = undefined;
        }
        const selected = await open({
          multiple: false,
          directory: false,
          title: t("import.title"),
          defaultPath,
        });
        if (cancelled) return;
        if (!selected || Array.isArray(selected)) {
          setImporting(false);
          return;
        }
        const text = await readTextFile(selected);
        if (cancelled) return;
        const existing = new Set(useApp.getState().hosts.map((h) => h.label));
        const parsed = parseSshConfig(text, existing);
        setPath(selected);
        setFileText(text);
        setRows(parsed);
        setSel(parsed.filter((h) => !h.dup).map((h) => h.host));
      } catch (e) {
        if (!cancelled) {
          toast(apiErrorMessage(e), "err");
          setImporting(false);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [importing, setImporting, t]);

  // Reset transient state when the overlay closes.
  useEffect(() => {
    if (!importing) {
      setRows([]);
      setSel([]);
      setFileText("");
      setPath("~/.ssh/config");
    }
  }, [importing]);

  const toggle = (id: string) =>
    setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const count = sel.length;

  const doImport = async () => {
    const vaultId = useApp.getState().vaultId;
    if (!vaultId || !fileText) {
      close();
      return;
    }
    setBusy(true);
    try {
      await guard(async () => {
        const selectedSet = new Set(sel);
        // 1) Create profiles for the SELECTED hosts only — the core imports every
        //    Host block in whatever config text it's handed, so filter it first.
        const filtered = filterConfigToSelected(fileText, selectedSet);
        const created = await api.importSshConfig(vaultId, filtered);
        const createdSet = new Set(created);

        // 2) Import each selected host's IdentityFile key into the vault and link
        //    it to the host. Best-effort: encrypted (passphrase) or missing keys
        //    are skipped and the host still imports (auth falls back to a password
        //    prompt). Desktop only — mobile has no access to ~/.ssh.
        let keysImported = 0;
        // Per-host skip reasons, surfaced precisely (and logged) so any future
        // snag is visible instead of a vague "encrypted or not found".
        const skips: { host: string; reason: SkipReason; raw: string }[] = [];
        // Every selected+created host: take the key from its IdentityFile, or — if
        // it has none — from the standard default ~/.ssh keys, exactly as ssh does.
        const targets = rows.filter((h) => selectedSet.has(h.host) && createdSet.has(h.host));
        if (targets.length) {
          const { readTextFile } = await import("@tauri-apps/plugin-fs");
          const { homeDir, join } = await import("@tauri-apps/api/path");
          let home = "";
          try {
            home = await homeDir();
          } catch {
            home = "";
          }

          // Dedupe by public key so the same key isn't imported twice (re-importing
          // the config, or a key already added by hand). Map existing key items →
          // their public-key identity.
          const items = await api.listItems(vaultId).catch(() => []);
          const used = new Set(items.map((i) => i.itemId));
          const idByPub = new Map<string, string>(); // normalized pub → item id
          for (const it of items) {
            if (it.itemType !== ItemType.SshKey) continue;
            try {
              const pk = await api.getPublicKey(vaultId, it.itemId);
              idByPub.set(normPub(pk.openssh), it.itemId);
            } catch {
              /* ignore unreadable item */
            }
          }

          const pathToItem = new Map<string, string>(); // resolved path → key item id
          for (const h of targets) {
            // Candidate key paths: the explicit IdentityFile, else the default keys.
            const candidates = h.identityFile
              ? [await resolveKeyPath(h.identityFile, home, join)]
              : await defaultIdentityPaths(home, join);

            // First cached / readable private key wins.
            let keyItemId: string | undefined;
            let keyText: string | undefined;
            let keyPath: string | undefined;
            let readErr: unknown;
            for (const cp of candidates) {
              const cached = pathToItem.get(cp);
              if (cached) {
                keyItemId = cached;
                break;
              }
              try {
                keyText = await readTextFile(cp);
                keyPath = cp;
                break;
              } catch (e) {
                readErr = e; // keep the last reason (e.g. permission/not-found)
              }
            }

            if (!keyItemId) {
              if (!keyText || !keyPath) {
                // No key file readable. Only an explicit-but-missing IdentityFile is
                // a real skip; a host that simply has no default key is fine.
                if (h.identityFile) {
                  const raw = apiErrorMessage(readErr);
                  skips.push({ host: h.host, reason: classifySkip(raw), raw });
                }
                continue;
              }
              try {
                const base = (keyPath.split(/[/\\]/).pop() || "key").replace(/\.[^.]+$/, "");
                const candidate = uniqueItemId(base, used);
                const pub = await api.importSshKey(vaultId, candidate, keyText.trim());
                const np = normPub(pub);
                const existing = idByPub.get(np);
                if (existing && existing !== candidate) {
                  // Same key already in the vault → drop the dup, reuse the existing.
                  await api.deleteItem(vaultId, candidate).catch(() => {});
                  keyItemId = existing;
                } else {
                  used.add(candidate);
                  idByPub.set(np, candidate);
                  keyItemId = candidate;
                  keysImported++;
                }
                pathToItem.set(keyPath, keyItemId);
              } catch (e) {
                const raw = apiErrorMessage(e);
                skips.push({ host: h.host, reason: classifySkip(raw), raw });
                continue;
              }
            }

            try {
              const prof = await api.getConnection(vaultId, h.host);
              await api.saveConnection(vaultId, { ...prof, auth: { type: "key", keyItemId } });
            } catch {
              /* leave the host with its default (password-prompt) auth */
            }
          }
        }

        await useApp.getState().reloadVault();
        setImporting(false);
        const hosts = t("count.hosts", { count: created.length });
        toast(
          keysImported > 0
            ? t("import.importedWithKeys", { hosts, keys: t("count.keys", { count: keysImported }) })
            : t("import.imported", { hosts }),
          "ok",
        );
        if (skips.length > 0) {
          for (const s of skips) {
            // eslint-disable-next-line no-console
            console.warn(`[ssh-config import] ${s.host}: key skipped (${s.reason}) — ${s.raw}`);
          }
          const order: SkipReason[] = [
            "forbidden",
            "encrypted",
            "notFound",
            "unsupported",
            "parse",
            "other",
          ];
          const counts = new Map<SkipReason, number>();
          for (const s of skips) counts.set(s.reason, (counts.get(s.reason) ?? 0) + 1);
          const breakdown = order
            .filter((r) => counts.has(r))
            .map((r) => `${counts.get(r)} ${t(`import.skipReason.${r}`)}`)
            .join(", ");
          toast(
            `${t("import.keysSkipped", { keys: t("count.keys", { count: skips.length }) })} — ${breakdown}`,
            "warn",
          );
        }
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      onClick={close}
      style={{
        position: "absolute",
        inset: 0,
        zIndex: 130,
        display: "flex",
        alignItems: isMobile ? "flex-start" : "center",
        justifyContent: "center",
        background: p.name === "dark" ? "rgba(6,7,11,0.6)" : "rgba(40,44,60,0.35)",
        backdropFilter: "blur(3px)",
        ...(isMobile ? { padding: 12, paddingTop: "calc(env(safe-area-inset-top) + 16px)" } : null),
      }}
    >
      <div
        ref={cardRef}
        role="dialog"
        aria-modal="true"
        aria-label={t("import.title")}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 620,
          maxWidth: "92%",
          maxHeight: "88%",
          display: "flex",
          flexDirection: "column",
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 18,
          boxShadow: p.shadow,
          overflow: "hidden",
          outline: "none",
          ...(isMobile ? { width: "100%", maxWidth: "100%", maxHeight: "100%" } : null),
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 11,
            padding: "18px 22px",
            borderBottom: `1px solid ${p.line}`,
          }}
        >
          <span
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: p.bg2,
              border: `1px solid ${p.line}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon name="download" size={18} color={p.txt2} />
          </span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 17, fontWeight: 800, letterSpacing: -0.3 }}>
              {t("import.title")}
            </div>
            <div style={{ fontSize: 12, color: p.txt3 }}>
              {t("import.found", { hosts: t("count.hosts", { count: rows.length }) })}
            </div>
          </div>
          <button
            onClick={close}
            title={t("common.close")}
            aria-label={t("common.close")}
            style={{
              width: isMobile ? 44 : 30,
              height: isMobile ? 44 : 30,
              borderRadius: 8,
              border: `1px solid ${p.line}`,
              background: p.bg2,
              color: p.txt3,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              ...(isMobile ? { flexShrink: 0 } : null),
            }}
          >
            <Icon name="x" size={15} />
          </button>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "10px 22px",
            borderBottom: `1px solid ${p.line}`,
          }}
        >
          <Icon name="file" size={14} color={p.txt3} />
          <span
            style={{
              fontFamily: MONO,
              fontSize: 12,
              color: p.txt3,
              minWidth: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {path}
          </span>
          <div style={{ flex: 1 }} />
          <button
            onClick={() => setSel(rows.map((h) => h.host))}
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: p.accent,
              background: "none",
              border: "none",
              cursor: "pointer",
              ...(isMobile ? { minHeight: 44, padding: "0 8px", flexShrink: 0 } : null),
            }}
          >
            {t("import.selectAll")}
          </button>
          <button
            onClick={() => setSel([])}
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: p.txt3,
              background: "none",
              border: "none",
              cursor: "pointer",
              ...(isMobile ? { minHeight: 44, padding: "0 8px", flexShrink: 0 } : null),
            }}
          >
            {t("import.clear")}
          </button>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: 10 }}>
          {loading ? (
            <div
              style={{
                padding: "40px 0",
                textAlign: "center",
                fontSize: 13,
                color: p.txt3,
              }}
            >
              {t("import.reading")}
            </div>
          ) : rows.length === 0 ? (
            <div
              style={{
                padding: "40px 0",
                textAlign: "center",
                fontSize: 13,
                color: p.txt3,
              }}
            >
              {t("import.empty")}
            </div>
          ) : (
            rows.map((h, i) => {
              const on = sel.includes(h.host);
              return (
                <div
                  key={h.host}
                  onClick={() => toggle(h.host)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    padding: "11px 12px",
                    cursor: "pointer",
                    background: on ? p.bg2 : "transparent",
                    borderTop: i === 0 ? undefined : `1px solid ${p.line}`,
                    opacity: h.dup && !on ? 0.6 : 1,
                    ...(isMobile ? { minHeight: 44 } : null),
                  }}
                >
                  <span
                    style={{
                      width: isMobile ? 26 : 20,
                      height: isMobile ? 26 : 20,
                      borderRadius: 6,
                      flexShrink: 0,
                      border: `1px solid ${on ? p.accent : p.line2}`,
                      background: on ? p.accent : "transparent",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    {on && (
                      <Icon
                        name="check"
                        size={isMobile ? 16 : 13}
                        color={p.accentInk ?? "#fff"}
                        stroke={3}
                      />
                    )}
                  </span>
                  <span
                    style={{
                      width: 34,
                      height: 34,
                      borderRadius: 9,
                      background: p.bg3,
                      border: `1px solid ${p.line}`,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      flexShrink: 0,
                    }}
                  >
                    <Icon name="server" size={16} color={p.txt2} />
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        ...(isMobile ? { minWidth: 0 } : null),
                      }}
                    >
                      <span
                        style={{
                          fontSize: 14,
                          fontWeight: 700,
                          // ellipsize unconditionally: long host aliases/FQDNs spill on desktop too
                          minWidth: 0,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {h.host}
                      </span>
                      {h.dup && (
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 5,
                            fontSize: 10.5,
                            fontWeight: 600,
                            color: p.amber,
                            ...(isMobile ? { flexShrink: 0 } : null),
                          }}
                        >
                          <span
                            style={{
                              width: 5,
                              height: 5,
                              borderRadius: "50%",
                              background: p.amber,
                              flexShrink: 0,
                            }}
                          />
                          {t("import.alreadyExists")}
                        </span>
                      )}
                    </div>
                    <div
                      style={{
                        fontFamily: MONO,
                        fontSize: 11.5,
                        color: p.txt3,
                        // ellipsize unconditionally: user@host:port spills on desktop for long FQDNs
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {h.user || "?"}@{h.hostname || h.host}:{h.port}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        <div
          style={{
            display: "flex",
            alignItems: narrow ? "stretch" : "center",
            flexDirection: narrow ? "column" : undefined,
            gap: 10,
            padding: "14px 22px",
            borderTop: `1px solid ${p.line}`,
            background: p.bg0,
          }}
        >
          <span style={{ fontSize: 12.5, color: p.txt3 }}>
            <Trans
              i18nKey="import.selectedOf"
              components={{ b: <b style={{ color: p.txt }} /> }}
              values={{ count, total: rows.length }}
            />
          </span>
          {!narrow && <div style={{ flex: 1 }} />}
          <Btn
            variant="ghost"
            full={narrow}
            style={isMobile ? { minHeight: 44 } : undefined}
            onClick={close}
          >
            {t("common.cancel")}
          </Btn>
          <Btn
            icon="download"
            full={narrow}
            onClick={doImport}
            disabled={!count || busy}
            style={{
              ...(count && !busy ? {} : { opacity: 0.5 }),
              ...(isMobile ? { minHeight: 44 } : null),
            }}
          >
            {t("import.importN", { count })}
          </Btn>
        </div>
      </div>
    </div>
  );
}
