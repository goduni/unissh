import type { IconName } from "../ui/icons";
import type { Route } from "../store/ui";

export interface NavItemDef {
  route: Route;
  icon: IconName;
  /** i18n key under `nav.*` */
  key: string;
  /** Which overview counter to show as a badge, if any. */
  count?: "accounts" | "pending_invites" | "devices";
}

export interface NavGroupDef {
  key: string;
  items: NavItemDef[];
}

export const NAV: NavGroupDef[] = [
  {
    key: "instance",
    items: [
      { route: "overview", icon: "grid", key: "overview" },
      { route: "health", icon: "activity", key: "health" },
      { route: "metrics", icon: "zap", key: "metrics" },
      { route: "config", icon: "sliders", key: "config" },
      { route: "maint", icon: "refresh", key: "maint" },
    ],
  },
  {
    key: "identity",
    items: [
      { route: "spaces", icon: "box", key: "spaces" },
      { route: "accounts", icon: "server", key: "accounts", count: "accounts" },
      { route: "directory", icon: "user", key: "directory" },
      { route: "devices", icon: "fingerprint", key: "devices" },
      { route: "sessions", icon: "clock", key: "sessions" },
      { route: "invites", icon: "tag", key: "invites", count: "pending_invites" },
    ],
  },
  {
    key: "access",
    items: [
      { route: "vaults", icon: "lock", key: "vaults" },
      { route: "grants", icon: "shieldcheck", key: "grants" },
      { route: "relay", icon: "link", key: "relay" },
    ],
  },
  {
    key: "data",
    items: [
      { route: "objects", icon: "layers", key: "objects" },
      { route: "audit", icon: "eye", key: "audit" },
    ],
  },
];
