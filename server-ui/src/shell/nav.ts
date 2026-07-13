import type { IconName } from "../ui/icons";
import type { Route } from "../store/ui";

export interface NavItemDef {
  route: Route;
  icon: IconName;
  /** i18n key under `nav.*` */
  key: string;
  /** Requires the admin keyset to act (screen shows LockGate when locked). */
  keyset?: boolean;
  /** Which overview counter to show as a badge, if any. */
  count?: "accounts" | "pending_invites" | "devices";
}

export interface NavGroupDef {
  key: string;
  keysetTag?: boolean;
  items: NavItemDef[];
}

export const NAV: NavGroupDef[] = [
  {
    key: "instance",
    items: [
      { route: "overview", icon: "grid", key: "overview" },
      { route: "health", icon: "activity", key: "health", keyset: true },
      { route: "metrics", icon: "zap", key: "metrics", keyset: true },
      { route: "config", icon: "sliders", key: "config", keyset: true },
      { route: "maint", icon: "refresh", key: "maint" },
    ],
  },
  {
    key: "identity",
    items: [
      { route: "spaces", icon: "box", key: "spaces", keyset: true },
      { route: "accounts", icon: "server", key: "accounts", count: "accounts", keyset: true },
      { route: "directory", icon: "user", key: "directory", keyset: true },
      { route: "devices", icon: "fingerprint", key: "devices", keyset: true },
      { route: "sessions", icon: "clock", key: "sessions", keyset: true },
      { route: "invites", icon: "tag", key: "invites", count: "pending_invites", keyset: true },
    ],
  },
  {
    key: "access",
    keysetTag: true,
    items: [
      { route: "vaults", icon: "lock", key: "vaults", keyset: true },
      { route: "grants", icon: "shieldcheck", key: "grants", keyset: true },
      { route: "relay", icon: "link", key: "relay", keyset: true },
    ],
  },
  {
    key: "data",
    keysetTag: true,
    items: [
      { route: "objects", icon: "layers", key: "objects", keyset: true },
      { route: "audit", icon: "eye", key: "audit", keyset: true },
    ],
  },
];
