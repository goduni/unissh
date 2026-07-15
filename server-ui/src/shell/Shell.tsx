import { InviteModal } from "../access/InviteModal";
import { ScreenRouter } from "../screens/registry";
import { ConfirmDialog, Toaster } from "../ui/overlays";
import { Sidebar } from "./Sidebar";
import { SettingsPanel } from "./SettingsPanel";
import { Titlebar } from "./Titlebar";

export function Shell() {
  return (
    <>
      <div style={{ height: "100vh", display: "flex" }}>
        <div
          style={{
            flex: 1,
            minWidth: 0,
            overflow: "hidden",
            background: "var(--bg0)",
            color: "var(--txt)",
            display: "flex",
            flexDirection: "column",
            position: "relative",
          }}
        >
          <Titlebar />
          <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
            <Sidebar />
            <ScreenRouter />
          </div>
        </div>
      </div>

      <SettingsPanel />
      <InviteModal />
      <ConfirmDialog />
      <Toaster />
    </>
  );
}
