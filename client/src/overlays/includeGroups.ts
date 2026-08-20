// Where the hosts behind an `Include` land. Kept out of the overlay for the same
// reason importTarget is: the rule is not obvious, it has three ways to go wrong
// (a name that is not a project, a group that already exists, a target group the
// subgroups have to sit under), and each of those is worth a test.

import type { ServerGroup } from "@/bridge/types";

/** A host the import would create, as the core reports it. */
export interface IncludedHost {
  alias: string;
  /** The file it was written in, or null for the config the user picked. */
  originFile: string | null;
}

/** A group the import would put hosts in. */
export interface IncludeGroup {
  /** The derived name. */
  label: string;
  /** The included files that derived it — usually one, more when two files
   *  produce the same name and are therefore the same group. */
  files: string[];
  /** The aliases that land in it, in the order the config lists them. */
  aliases: string[];
  /** An existing group to put them in instead of creating a second one with the
   *  same name, or null to create it. */
  existingId: string | null;
  /** The group it is created under: the chosen import target, or the vault root. */
  parentId: string | null;
}

export interface IncludeGroupPlan {
  groups: IncludeGroup[];
  /** Hosts that go straight into the target group (or the root): the picked
   *  config's own, and those from a file the user opted out of. */
  ungrouped: string[];
}

/** A file the import read, and the file whose `Include` pulled it in. */
export interface ReadFile {
  path: string;
  /** null for the config the user picked. */
  includedBy: string | null;
}

export interface IncludeGroupPlanInput {
  /** The config the user picked. Its own hosts never form a subgroup. */
  configPath: string;
  hosts: IncludedHost[];
  /** Every file that was read, so a nested include can be traced back to the
   *  include the picked config made. Empty means no include tree is known and
   *  every host is grouped by its own file. */
  files: ReadFile[];
  /** The global "create subgroups" switch. */
  subgroups: boolean;
  /** Included files the user opted out of, by path. */
  optedOut: Iterable<string>;
  /** The chosen import target group, or null for the vault root. */
  target: string | null;
  /** The vault's groups — what the collision rule is checked against. */
  groups: { groupId: string; label: string; parentId?: string | null }[];
}

/** Path components, on either separator: a Windows path has to group the same
 *  way a POSIX one does. */
const parts = (path: string) => path.split(/[/\\]/).filter(Boolean);

/** The group an included file stands for.
 *
 *  The directory usually *is* the grouping — `project1/config` holds the
 *  project1 hosts — so a file named `config` is named after its directory. A
 *  file with a name of its own (`conf.d/work.conf`) is named after the file,
 *  because its directory is shared with its neighbours and would name them all
 *  the same thing. A `config` sitting beside the one that was picked has no
 *  directory of its own to take, so it keeps its file name. */
export function includeGroupName(file: string, configPath: string): string {
  const p = parts(file);
  const name = p[p.length - 1] ?? file;
  const dir = p[p.length - 2];
  const rootDir = parts(configPath).slice(0, -1).join("/");
  const fileDir = p.slice(0, -1).join("/");
  if (name.toLowerCase() === "config" && dir && fileDir !== rootDir) return dir;
  // `work.conf` → `work`, but `config.local` keeps its suffix: stripping it
  // would leave every host in a group called "config".
  const stem = name.replace(/\.(conf|config|cfg)$/i, "");
  return stem || name;
}

/** The file a host is grouped by: the include the PICKED config made, however
 *  many files down the host actually sits.
 *
 *  A nested include is not a group of its own. `project1/config` including
 *  `project1/hosts.conf` is one project with its hosts split across two files,
 *  not two projects — and a deep include tree must not turn into a deep group
 *  tree. One level of subgroup is the whole scope. */
export function groupFile(file: string, configPath: string, files: ReadFile[]): string {
  const by = new Map(files.map((f) => [f.path, f.includedBy]));
  const root = rootOf(configPath, files);
  let cur = file;
  // Bounded by the number of files, so a chain that loops (which the loader
  // already prevents) still cannot spin here.
  for (let i = 0; i <= files.length; i++) {
    const parent = by.get(cur);
    // Stop at the file the picked config included directly — the one whose own
    // parent is the root, or is the root by name.
    if (parent == null || parent === root || by.get(parent) == null) return cur;
    cur = parent;
  }
  return cur;
}

/** The config the report was rooted at: the one file nothing included.
 *
 *  Preferred over the caller's `configPath` because every other path in the plan
 *  comes out of the same report, and two spellings of one file — the string a
 *  file picker returned versus the path the core actually opened — would put the
 *  picked config itself in a group. */
function rootOf(configPath: string, files: ReadFile[]): string {
  return files.find((f) => f.includedBy === null)?.path ?? configPath;
}

/** Group labels compare the way a person reads them, so a repeat import lands in
 *  `Project1` rather than beside it. */
const norm = (label: string) => label.trim().toLowerCase();

/** The subgroups an import should create, and what goes in each.
 *
 *  Derived groups are created **under** the chosen target group, never at the
 *  root — the two features compose rather than fight. A derived name that
 *  matches a group already under that parent reuses it, so importing the same
 *  config twice converges instead of multiplying groups. */
export function planIncludeGroups(input: IncludeGroupPlanInput): IncludeGroupPlan {
  const { configPath, hosts, subgroups, target, files } = input;
  const root = rootOf(configPath, files);
  const optedOut = new Set(input.optedOut);
  const groups: IncludeGroup[] = [];
  const byLabel = new Map<string, IncludeGroup>();
  const ungrouped: string[] = [];

  for (const h of hosts) {
    const file = h.originFile && groupFile(h.originFile, configPath, files);
    if (!subgroups || !file || file === configPath || file === root || optedOut.has(file)) {
      ungrouped.push(h.alias);
      continue;
    }
    const label = includeGroupName(file, root);
    let g = byLabel.get(norm(label));
    if (!g) {
      const existing = input.groups.find(
        (x) => norm(x.label) === norm(label) && (x.parentId ?? null) === target,
      );
      g = {
        label,
        files: [],
        aliases: [],
        existingId: existing?.groupId ?? null,
        parentId: target,
      };
      byLabel.set(norm(label), g);
      groups.push(g);
    }
    if (!g.files.includes(file)) g.files.push(file);
    g.aliases.push(h.alias);
  }

  return { groups, ungrouped };
}

/** The group writes an [`IncludeGroupPlan`] turns into, given the vault's
 *  current groups.
 *
 *  A host belongs to exactly one group, so every host being placed is first
 *  removed from wherever it is — a re-import after moving a file between
 *  includes has to move the host too, not leave it in both. Groups that come out
 *  unchanged are not written: each write is a vault item, a sync object, and a
 *  line in the audit log.
 *
 *  @param newGroupId ids for the groups being created; the caller owns the
 *                    scheme (the store's is `group-<timestamp>`), and it is
 *                    passed in so this stays pure and testable. */
export function planIncludeGroupWrites(
  existing: ServerGroup[],
  plan: IncludeGroupPlan,
  target: string | null,
  newGroupId: (label: string, index: number) => string,
): ServerGroup[] {
  const placed = new Set([...plan.groups.flatMap((g) => g.aliases), ...plan.ungrouped]);
  const writes = new Map<string, ServerGroup>();
  const current = (id: string) =>
    writes.get(id) ?? existing.find((g) => g.groupId === id) ?? null;

  for (const g of existing) {
    const memberIds = g.memberIds.filter((m) => !placed.has(m));
    if (memberIds.length !== g.memberIds.length) writes.set(g.groupId, { ...g, memberIds });
  }

  const into = (group: ServerGroup, aliases: string[]) => {
    const memberIds = Array.from(new Set([...group.memberIds, ...aliases]));
    if (memberIds.length !== group.memberIds.length || writes.has(group.groupId)) {
      writes.set(group.groupId, { ...group, memberIds });
    }
  };

  plan.groups.forEach((g, i) => {
    const found = g.existingId ? current(g.existingId) : null;
    if (found) {
      into(found, g.aliases);
      return;
    }
    const groupId = newGroupId(g.label, i);
    writes.set(groupId, {
      groupId,
      label: g.label,
      memberIds: [...g.aliases],
      parentId: g.parentId,
    });
  });

  // Everything that did not become a subgroup goes where a plain import would
  // have put it. With no target group that is the vault root, which is not a
  // group and needs no write.
  if (target && plan.ungrouped.length) {
    const t = current(target);
    if (t) into(t, plan.ungrouped);
  }

  // A re-import of a host that is already in the right group takes it out and
  // puts it straight back; that is not a change, and writing it would cost a
  // vault item, a sync object and an audit line for nothing.
  const same = (a: string[], b: string[]) =>
    a.length === b.length && new Set(a).size === new Set([...a, ...b]).size;
  return [...writes.values()].filter((w) => {
    const before = existing.find((g) => g.groupId === w.groupId);
    return !before || !same(before.memberIds, w.memberIds);
  });
}
