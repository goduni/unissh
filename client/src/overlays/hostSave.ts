// What the host editor hands the core's one host-save path (`api.saveHost`,
// `Core::save_host`). The rules themselves live in the core, shared with
// `unissh hosts add|edit`; this only maps the form onto the request and
// picks what the form offers.

import type { ConnectionProfile, HostGroupChoice, IdentityLink, JumpHost } from "@/bridge/types";

/** Sentinel `groupId` meaning "create a new group (named `newGroupName`) on
 *  save". The core mints group ids as `slug-timestamp`, so this can never
 *  collide with a real group id. */
export const NEW_GROUP = "__new__";

/** The saved hosts the editor offers as a jump hop of host `editingId`: the
 *  other saved hosts (with a uid) that log in with a key, a stored password
 *  or the system ssh-agent. A host that asks for its password or logs in
 *  personally has no credential a hop could use. The core refuses the same
 *  ones on save; offering them would let an unusable hop be picked. */
export function hopCandidates(
  hosts: readonly ConnectionProfile[],
  editingId: string | undefined,
): ConnectionProfile[] {
  return hosts.filter(
    (h) =>
      !!h.uid &&
      h.profileId !== editingId &&
      (h.auth.type === "key" || h.auth.type === "vaultPassword" || h.auth.type === "systemAgent"),
  );
}

/** The group the picker stands for: a pending new group (created by the
 *  save), a group, or none. A pending group without a name is none, as the
 *  editor never offers to save one. */
export function groupChoice(groupId: string, newGroupName: string): HostGroupChoice {
  if (groupId === NEW_GROUP) {
    const label = newGroupName.trim();
    return label ? { type: "new", label } : { type: "ungrouped" };
  }
  return groupId ? { type: "existing", groupId } : { type: "ungrouped" };
}

/** The identity to link: only for a personal login, and only once one is
 *  picked. Without one the core re-pins the identity already linked. */
export function identityToLink(
  personal: boolean,
  vaultId: string | null,
  identityId: string,
): IdentityLink | null {
  return personal && vaultId && identityId ? { vaultId, identityId } : null;
}

/** The editor changes the first hop; the remaining route is kept verbatim. */
export function editedJumpChain(previous: readonly JumpHost[], first: JumpHost | undefined, enabled: boolean, touched: boolean): JumpHost[] {
  if (!enabled) return [];
  if (!touched && previous.length > 0) return [...previous];
  return first ? [first, ...previous.slice(1)] : [];
}
