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
  /** Hidden behind a disclosure until opened (or until one of its sections is the current one). */
  collapsible?: boolean;
  items: NavItemDef[];
}

/** The sections by what an admin comes to do: the server, its people, their vaults; the internals fold away. */
export const NAV: NavGroupDef[] = [
  {
    key: "server",
    items: [
      { route: "overview", icon: "grid", key: "overview" },
      { route: "health", icon: "activity", key: "health" },
      { route: "audit", icon: "eye", key: "audit" },
      { route: "config", icon: "sliders", key: "config" },
    ],
  },
  {
    key: "people",
    items: [
      { route: "accounts", icon: "user", key: "accounts", count: "accounts" },
      { route: "spaces", icon: "box", key: "spaces" },
      { route: "invites", icon: "tag", key: "invites", count: "pending_invites" },
      { route: "devices", icon: "fingerprint", key: "devices" },
      { route: "sessions", icon: "clock", key: "sessions" },
    ],
  },
  {
    key: "storage",
    items: [
      { route: "vaults", icon: "lock", key: "vaults" },
      { route: "grants", icon: "shieldcheck", key: "grants" },
    ],
  },
  {
    key: "tech",
    collapsible: true,
    items: [
      { route: "metrics", icon: "zap", key: "metrics" },
      { route: "maint", icon: "refresh", key: "maint" },
      { route: "relay", icon: "link", key: "relay" },
      { route: "objects", icon: "layers", key: "objects" },
    ],
  },
];
