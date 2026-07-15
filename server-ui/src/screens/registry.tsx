import type { ComponentType } from "react";
import { useUi, type Route } from "../store/ui";
import { Accounts } from "./Accounts";
import { Audit } from "./Audit";
import { Config } from "./Config";
import { Devices } from "./Devices";
import { Directory } from "./Directory";
import { Grants } from "./Grants";
import { Health } from "./Health";
import { Invites } from "./Invites";
import { Maintenance } from "./Maintenance";
import { Metrics } from "./Metrics";
import { Objects } from "./Objects";
import { Overview } from "./Overview";
import { Relay } from "./Relay";
import { Sessions } from "./Sessions";
import { Spaces } from "./Spaces";
import { Vaults } from "./Vaults";

const SCREENS: Record<Route, ComponentType> = {
  overview: Overview,
  health: Health,
  metrics: Metrics,
  config: Config,
  maint: Maintenance,
  spaces: Spaces,
  accounts: Accounts,
  directory: Directory,
  devices: Devices,
  sessions: Sessions,
  invites: Invites,
  vaults: Vaults,
  grants: Grants,
  relay: Relay,
  objects: Objects,
  audit: Audit,
};

export function ScreenRouter() {
  const route = useUi((s) => s.route);
  const C = SCREENS[route];
  return <C />;
}
