// ImportPreview.tsx — ssh-config import preview overlay.
// Pixel-perfect port of import-preview.jsx, wired to the real store + core.
// The user picks ~/.ssh/config (default homeDir()+/.ssh/config) and the core
// reads it, follows its `Include` directives, and reports what an import would
// produce; the same path is then handed to api.importSshConfigAtPath.
//
// The preview lists what the CORE resolved rather than a second opinion parsed
// here: once a config's hosts can live in files the client never opened, a
// client-side parser cannot see them, and two parsers would disagree about the
// one thing this dialog exists to promise.
//
// Following includes means reading files the user did not name one by one, so
// every file that was read is shown here, before anything is written.

import { useEffect, useState } from "react";
import { useTranslation, Trans } from "@/i18n";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rgba } from "@/theme/tokens";
import { Btn, Icon } from "@/components/primitives";
import { useApp } from "@/store/app";
import { useIsMobile, useNarrow } from "@/store/responsive";
import { useDialogFocus, useDialogKeys } from "@/components/a11y";
import { toast } from "@/store/toast";
import { guard } from "@/store/action";
import { apiErrorMessage, ItemType } from "@/bridge/types";
import { defaultImportGroup } from "./importTarget";
import {
  groupFile,
  includeGroupName,
  planIncludeGroups,
  planIncludeGroupWrites,
} from "./includeGroups";
import * as api from "@/bridge/api";
import { homeDir, join } from "@tauri-apps/api/path";
import { open } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";

interface ParsedHost {
  host: string;
  hostname: string;
  user: string;
  port: number;
  dup: boolean;
  /** IdentityFile as the core resolved it (the host's own, or one inherited
   *  from a matching wildcard block). Used to import the referenced key. */
  identityFile?: string;
  /** The file this host was written in — null for the config that was picked.
   *  What the row is attributed to, and what its subgroup is derived from. */
  originFile: string | null;
}

const stripQuotes = (v: string) => v.replace(/^["']|["']$/g, "").trim();

const isWildcard = (a: string) => a.includes("*") || a.includes("?") || a.startsWith("!");

/** Keep only the `Host` blocks whose first concrete alias is selected. Wildcard
 *  blocks (`Host *`, `Host *.example.com`) and the global preamble before the
 *  first `Host` are always kept so inherited settings (User/Port/IdentityFile)
 *  still resolve. A multi-alias `Host a b` line is kept whole if `a` is selected.
 *
 *  Only for the text fallback below: a path-based import is told which aliases
 *  to take, because filtering text cannot reach a host in another file. */
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

/** Path components, on either separator. */
const parts = (path: string) => path.split(/[/\\]/).filter(Boolean);

/** A read file as it is worth showing: relative to the picked config's own
 *  directory when it sits under it (`project1/config`), the whole path when it
 *  does not — an include may point anywhere, and hiding that would defeat the
 *  disclosure. */
function shortPath(file: string, configPath: string): string {
  const dir = parts(configPath).slice(0, -1);
  const own = parts(file);
  if (own.length <= dir.length) return file;
  if (dir.every((c, i) => own[i] === c)) return own.slice(dir.length).join("/");
  return file;
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
  // What the core resolved: the hosts, what it cannot carry over, every file it
  // read, and the includes it could not follow. One answer from the thing that
  // will do the importing, not a second opinion about the file.
  const [report, setReport] = useState<api.SshConfigReport | null>(null);
  const skipped = report?.skipped ?? [];
  const filesRead = report?.filesRead ?? [];
  // The include tree, for grouping: a file pulled in by an included file belongs
  // to whatever group THAT file stands for.
  const includeTree = filesRead.map((f) => ({ path: f.path, includedBy: f.includedBy }));
  // The path the CORE opened, not the string the picker handed back. Every other
  // path here comes out of the same report, and comparing them against a
  // different spelling of the same file (`~/.ssh/config` vs the expanded one)
  // would fail to recognise the picked config and put it in a group of its own.
  const configPath = filesRead[0]?.path ?? path;
  const pendingIncludes = report?.pendingIncludes ?? [];
  const [rows, setRows] = useState<ParsedHost[]>([]);
  const [sel, setSel] = useState<string[]>([]);
  // Non-null only in the text fallback (see the picker effect): the file's
  // contents, because that path imports by handing them back to the core.
  const [fileText, setFileText] = useState<string | null>(null);
  // A subgroup per included file, on by default: the directory layout usually
  // IS the grouping, and the common case should need no configuration. Both the
  // switch and the per-file opt-out below are settled here, in the preview,
  // before anything is written.
  const [subgroups, setSubgroups] = useState(true);
  const [optedOut, setOptedOut] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  // Where the imported hosts land. Defaults to the group the sidebar has open —
  // picking a group and then importing into the root is the reported bug — but
  // stays visible and changeable, because the target should never be a guess.
  const groups = useApp((s) => s.groups);
  // Read once, at mount: this body only exists while the overlay is open (the
  // parent gates it), so every open is a fresh mount and a fresh read. Doing it
  // in an effect instead would paint one frame at the wrong target.
  const [target, setTarget] = useState<string | null>(() => {
    const s = useApp.getState();
    return defaultImportGroup(s.hostFilter, s.groups);
  });

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
        // The core reads the file and everything its `Include` lines point at.
        // A failure here is fatal to the dialog, unlike the old best-effort
        // report: there is nothing left to show a preview from.
        //
        // Except on Android, where the picker hands back a `content://` URI: the
        // core opens paths with the filesystem and cannot read one, while Tauri's
        // fs plugin can. Falling back to the text-based report keeps that import
        // working exactly as it did — without following includes, which it never
        // did either.
        let rep: api.SshConfigReport;
        let text: string | null = null;
        try {
          rep = await api.sshConfigReportAtPath(selected);
        } catch {
          text = await readTextFile(selected);
          rep = await api.sshConfigReport(text);
        }
        if (cancelled) return;
        const existing = new Set(useApp.getState().hosts.map((h) => h.label));
        const parsed: ParsedHost[] = rep.hosts.map((h) => ({
          host: h.alias,
          hostname: h.hostname,
          user: h.user ?? "",
          port: h.port,
          dup: existing.has(h.alias),
          identityFile: h.identityFile ? stripQuotes(h.identityFile) : undefined,
          originFile: h.originFile,
        }));
        setPath(selected);
        setFileText(text);
        setReport(rep);
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

  // (There used to be a "reset transient state when the overlay closes" effect
  // here. It could never run: ImportPreview unmounts this body the moment
  // `importing` goes false, so the branch that cleared rows/sel/report/path
  // was dead, and the mount itself is the reset.)

  const toggle = (id: string) =>
    setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const count = sel.length;

  const selectedSet = new Set(sel);
  // Every include the picked config made that a ticked host came from — the
  // rows of the mapping, including the ones opted out (which is how they are
  // opted back in). A host inside a nested include is listed under the include
  // that reached it, because that is the group it lands in.
  const includedFiles = Array.from(
    new Set(
      rows
        .filter((h) => selectedSet.has(h.host) && h.originFile && h.originFile !== configPath)
        .map((h) => groupFile(h.originFile as string, configPath, includeTree))
        .filter((f) => f !== configPath),
    ),
  );
  const toggleFile = (f: string) =>
    setOptedOut((o) => (o.includes(f) ? o.filter((x) => x !== f) : [...o, f]));

  const doImport = async () => {
    const vaultId = useApp.getState().vaultId;
    if (!vaultId || rows.length === 0) {
      close();
      return;
    }
    setBusy(true);
    try {
      await guard(async () => {
        // 1) Create profiles for the SELECTED hosts only. The core re-reads the
        //    file and its includes; the ticked aliases go with the call, because
        //    filtering the config *text* cannot reach hosts in other files —
        //    which is still how the text fallback has to do it.
        const created =
          fileText === null
            ? await api.importSshConfigAtPath(vaultId, path, sel)
            : (
                await api.importSshConfig(vaultId, filterConfigToSelected(fileText, selectedSet))
              ).map((alias) => ({ alias, originFile: null }));
        const createdSet = new Set(created.map((h) => h.alias));

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

        // 3) Place the new hosts: a subgroup per included file where the user
        //    left that on, everything else in the chosen target group. Its own
        //    try/catch, and not part of the guard() above: the profiles are
        //    already written by now, so a failure here must not skip the reload
        //    and the close — that would leave the hosts imported but invisible,
        //    behind an open dialog whose obvious next move is to import them all
        //    again.
        const placement = planIncludeGroups({
          configPath,
          hosts: created.map((h) => ({ alias: h.alias, originFile: h.originFile })),
          files: includeTree,
          subgroups,
          optedOut,
          target,
          groups: useApp.getState().groups,
        });
        let groupLabel: string | null = null;
        let madeGroups = 0;
        try {
          const stamp = Date.now();
          const writes = planIncludeGroupWrites(
            useApp.getState().groups,
            placement,
            target,
            (_label, i) => `group-${stamp}-${i}`,
          );
          for (const g of writes) await api.saveGroup(vaultId, g);
          // Only the ones this import actually created: a run that put its
          // hosts into groups that were already there created nothing, and
          // saying otherwise would send the user looking for them.
          madeGroups = placement.groups.filter((g) => !g.existingId).length;
          // Read AFTER the write, from the live store: a sync could have deleted
          // the group mid-import, in which case nothing was written and naming
          // it here would report a placement that never happened.
          groupLabel =
            target && placement.ungrouped.length
              ? (useApp.getState().groups.find((g) => g.groupId === target)?.label ?? null)
              : null;
        } catch (e) {
          toast(apiErrorMessage(e), "err");
        }

        // The imported hosts are not in the store until something reloads.
        await useApp.getState().reloadVault();
        setImporting(false);
        const hosts = t("count.hosts", { count: created.length });
        toast(
          // Keys win over the placement when both happened: a group is visible
          // in the sidebar the moment this closes, the imported keys are not.
          keysImported > 0
            ? t("import.importedWithKeys", { hosts, keys: t("count.keys", { count: keysImported }) })
            : madeGroups > 0
              ? t("import.importedIntoGroups", {
                  hosts,
                  groups: t("count.groups", { count: madeGroups }),
                })
              : groupLabel
                ? t("import.importedIntoGroup", { hosts, group: groupLabel })
                : t("import.imported", { hosts }),
          "ok",
        );
        if (skips.length > 0) {
          for (const s of skips) {
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
          borderRadius: 16,
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
            <div style={{ fontSize: 16, fontWeight: 800, letterSpacing: -0.3 }}>
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
              color: p.accentText,
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
            <>
              {/* Disclosure. An import of "one file" that reads five is only
                  acceptable if it says which five, before it writes anything. */}
              {filesRead.length > 1 && (
                <div
                  role="note"
                  style={{
                    margin: "0 0 12px",
                    padding: "10px 12px",
                    borderRadius: 8,
                    border: `1px solid ${p.line2}`,
                    background: p.bg2,
                    fontSize: 12.5,
                    color: p.txt2,
                    lineHeight: 1.5,
                  }}
                >
                  <div style={{ fontWeight: 700, color: p.txt, marginBottom: 4 }}>
                    {t("import.filesReadTitle", {
                      files: t("count.files", { count: filesRead.length }),
                    })}
                  </div>
                  <div style={{ marginBottom: 6 }}>{t("import.filesReadDesc")}</div>
                  <div
                    style={{
                      fontFamily: MONO,
                      fontSize: 11.5,
                      color: p.txt3,
                      // The whole list, always — but a config with fifty
                      // includes must not push the hosts off the screen.
                      maxHeight: 72,
                      overflowY: "auto",
                      overflowWrap: "anywhere",
                    }}
                  >
                    {filesRead.map((f) => shortPath(f.path, path)).join("  ·  ")}
                  </div>
                </div>
              )}
              {pendingIncludes.length > 0 && (
                <div
                  role="note"
                  style={{
                    margin: "0 0 12px",
                    padding: "10px 12px",
                    borderRadius: 8,
                    border: `1px solid ${rgba(p.amber, 0.35)}`,
                    background: rgba(p.amber, 0.08),
                    fontSize: 12.5,
                    color: p.txt2,
                    lineHeight: 1.5,
                  }}
                >
                  <div style={{ fontWeight: 700, color: p.txt, marginBottom: 4 }}>
                    {t(
                      fileText === null
                        ? "import.includesSkippedTitle"
                        : "import.includesNotFollowedTitle",
                      { count: pendingIncludes.length },
                    )}
                  </div>
                  {/* Two different facts wearing one shape: a file-based import
                      could not OPEN these, a text-based one never tried. */}
                  <div style={{ marginBottom: 6 }}>
                    {t(
                      fileText === null
                        ? "import.includesSkippedDesc"
                        : "import.includesNotFollowedDesc",
                    )}
                  </div>
                  <div style={{ fontFamily: MONO, fontSize: 11.5, color: p.txt3 }}>
                    {pendingIncludes.join("  ·  ")}
                  </div>
                </div>
              )}
              {skipped.length > 0 && (
                <div
                  role="note"
                  style={{
                    margin: "0 0 12px",
                    padding: "10px 12px",
                    borderRadius: 8,
                    border: `1px solid ${rgba(p.amber, 0.35)}`,
                    background: rgba(p.amber, 0.08),
                    fontSize: 12.5,
                    color: p.txt2,
                    lineHeight: 1.5,
                  }}
                >
                  <div style={{ fontWeight: 700, color: p.txt, marginBottom: 4 }}>
                    {t("import.skippedTitle", { count: skipped.length })}
                  </div>
                  <div style={{ marginBottom: 6 }}>{t("import.skippedDesc")}</div>
                  <div style={{ fontFamily: MONO, fontSize: 11.5, color: p.txt3 }}>
                    {skipped
                      .slice(0, 12)
                      .map(
                        (d) =>
                          `${d.originFile ? `${shortPath(d.originFile, path)}:` : ""}${d.line}: ${d.keyword}${d.insideMatch ? " (Match)" : ""}`,
                      )
                      .join("  ·  ")}
                    {skipped.length > 12 ? "  ·  …" : ""}
                  </div>
                </div>
              )}
              {/* The file → group mapping, correctable here rather than
                  discovered afterwards. */}
              {includedFiles.length > 0 && (
                <div
                  style={{
                    margin: "0 0 12px",
                    padding: "10px 12px",
                    borderRadius: 8,
                    border: `1px solid ${p.line2}`,
                    background: p.bg2,
                    fontSize: 12.5,
                    color: p.txt2,
                    lineHeight: 1.5,
                  }}
                >
                  <label
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      cursor: "pointer",
                      fontWeight: 700,
                      color: p.txt,
                      ...(isMobile ? { minHeight: 44 } : null),
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={subgroups}
                      onChange={(e) => setSubgroups(e.target.checked)}
                      style={{ accentColor: p.accent, width: 15, height: 15 }}
                    />
                    {t("import.subgroupsTitle")}
                  </label>
                  <div style={{ margin: "4px 0 8px" }}>{t("import.subgroupsDesc")}</div>
                  <div style={{ maxHeight: 150, overflowY: "auto" }}>
                    {subgroups &&
                      includedFiles.map((f) => {
                      const on = !optedOut.includes(f);
                      return (
                        <label
                          key={f}
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 8,
                            padding: "3px 0",
                            cursor: "pointer",
                            minWidth: 0,
                            ...(isMobile ? { minHeight: 40 } : null),
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={on}
                            onChange={() => toggleFile(f)}
                            style={{ accentColor: p.accent, width: 14, height: 14, flexShrink: 0 }}
                          />
                          <span
                            style={{
                              fontFamily: MONO,
                              fontSize: 11.5,
                              color: p.txt3,
                              minWidth: 0,
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {shortPath(f, path)}
                          </span>
                          <Icon name="cr" size={12} color={p.txt3} />
                          <span
                            style={{
                              fontSize: 12,
                              fontWeight: 700,
                              color: on ? p.txt : p.txt3,
                              textDecoration: on ? undefined : "line-through",
                              flexShrink: 0,
                            }}
                          >
                            {on ? includeGroupName(f, configPath) : t("import.subgroupOff")}
                            </span>
                          </label>
                        );
                      })}
                  </div>
                </div>
              )}
              {rows.map((h, i) => {
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
                      borderRadius: 8,
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
                            fontSize: 11,
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
                        fontSize: 12,
                        color: p.txt3,
                        // ellipsize unconditionally: user@host:port spills on desktop for long FQDNs
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {h.user || "?"}@{h.hostname || h.host}:{h.port}
                    </div>
                    {/* Where it came from. Only for hosts reached through an
                        include: with everything from the picked file it would be
                        the same line repeated under every row. */}
                    {h.originFile && h.originFile !== configPath && (
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 5,
                          marginTop: 2,
                          fontSize: 11,
                          color: p.txt3,
                          minWidth: 0,
                        }}
                      >
                        <Icon name="file" size={11} color={p.txt3} />
                        <span
                          style={{
                            fontFamily: MONO,
                            minWidth: 0,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {shortPath(h.originFile, path)}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              );
              })}
            </>
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
          <span style={{ fontSize: 13, color: p.txt3 }}>
            <Trans
              i18nKey="import.selectedOf"
              components={{ b: <b style={{ color: p.txt }} /> }}
              values={{ count, total: rows.length }}
            />
          </span>
          {/* Stated, not inferred: the import used to land at the root whatever
              the sidebar had open, and a target you cannot see is one you cannot
              correct. Hidden when the vault has no groups — there is nothing to
              choose between. */}
          {groups.length > 0 && (
            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                fontSize: 13,
                color: p.txt3,
                ...(narrow ? null : { marginLeft: 6 }),
              }}
            >
              {t("import.intoGroup")}
              <select
                value={target ?? ""}
                onChange={(e) => setTarget(e.target.value || null)}
                // The running import captured `target` when it started; a select
                // that keeps moving after that shows a destination the write is
                // not using. The Import button is already disabled the same way.
                disabled={busy}
                style={{
                  // Themes the native option popup — without it the list renders
                  // light while the control above it is dark.
                  colorScheme: p.name === "dark" ? "dark" : "light",
                  height: isMobile ? 44 : 30,
                  maxWidth: 220,
                  padding: "0 8px",
                  borderRadius: 8,
                  border: `1px solid ${p.line}`,
                  background: p.bg0,
                  color: p.txt,
                  fontSize: 13,
                  ...(narrow ? { flex: 1, minWidth: 0 } : null),
                }}
              >
                <option value="">{t("import.intoRoot")}</option>
                {groups.map((g) => (
                  <option key={g.groupId} value={g.groupId}>
                    {g.label}
                  </option>
                ))}
              </select>
            </label>
          )}
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
