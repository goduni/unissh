import "./shell.css";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { InviteModal } from "../access/InviteModal";
import { api } from "../api";
import { ScreenRouter } from "../screens/registry";
import { useUi } from "../store/ui";
import { ConfirmDialog, Toaster } from "../ui/overlays";
import { truncId } from "../util/bytes";
import { useAsync } from "../util/useAsync";
import { Header } from "./Header";
import { PRODUCT_NAME } from "./Mark";
import { NAV } from "./nav";
import { NavDrawer, Rail, type InstanceLine } from "./Sidebar";

const RAIL_KEY = "unissh-admin.rail";
/** The tab's own title (index.html); a section stands before it while the shell is up. */
const TAB_TITLE = `${PRODUCT_NAME} Admin`;

function readFolded(): boolean {
  try {
    return localStorage.getItem(RAIL_KEY) === "folded";
  } catch {
    return false;
  }
}

/**
 * Frame of the signed-in panel: the rail from 768 px up (folding to icons, remembered per browser), a drawer on
 * phones, the sticky header with the section and the account, the page with 24 px of padding (16 on a phone). The
 * whole document scrolls, so the header and the head of a long table can stay put. The first stop of the keyboard is
 * a link past the rail to the page.
 */
export function Shell() {
  const { t } = useTranslation();
  const route = useUi((s) => s.route);
  const [folded, setFolded] = useState(readFolded);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const drawerButton = useRef<HTMLButtonElement>(null);

  // This panel administers ONE instance: its identity heads the rail (no tenant to switch between).
  const inst = useAsync(() => api.instance(), []);
  const instance: InstanceLine = {
    name: inst.data?.name || t("access.selfHosted"),
    id: inst.data
      ? `${truncId(inst.data.instance_id, 8, 4)} · v${inst.data.version}`
      : inst.loading
        ? null
        : "—",
  };

  const item = NAV.flatMap((group) => group.items).find((one) => one.route === route);
  const section = item ? t(`nav.${item.key}`) : "";

  useEffect(() => {
    document.title = section ? `${section} · ${TAB_TITLE}` : TAB_TITLE;
    return () => {
      document.title = TAB_TITLE;
    };
  }, [section]);

  // The drawer belongs to a phone: past 768 px the rail is back and the drawer closes.
  useEffect(() => {
    if (!drawerOpen || typeof window.matchMedia !== "function") return;
    const wide = window.matchMedia("(min-width: 768px)");
    const onChange = () => {
      if (wide.matches) setDrawerOpen(false);
    };
    wide.addEventListener("change", onChange);
    return () => wide.removeEventListener("change", onChange);
  }, [drawerOpen]);

  const toggleFold = () => {
    const next = !folded;
    setFolded(next);
    try {
      localStorage.setItem(RAIL_KEY, next ? "folded" : "open");
    } catch {
      // Not remembered in this browser: the fold still works for the visit.
    }
  };

  return (
    <>
      <div className="sh-frame">
        <a
          href="#main"
          className="sh-skip"
          onClick={(e) => {
            e.preventDefault();
            document.getElementById("main")?.focus();
          }}
        >
          {t("nav.skip")}
        </a>
        <Rail folded={folded} onToggleFold={toggleFold} instance={instance} />
        <div className="sh-column">
          <Header
            section={section}
            drawerOpen={drawerOpen}
            onOpenDrawer={() => setDrawerOpen(true)}
            drawerButtonRef={drawerButton}
          />
          <main id="main" tabIndex={-1} className="sh-main">
            <ScreenRouter />
          </main>
        </div>
      </div>

      {drawerOpen ? (
        <NavDrawer onClose={() => setDrawerOpen(false)} returnFocusRef={drawerButton} instance={instance} />
      ) : null}
      <InviteModal />
      <ConfirmDialog />
      <Toaster />
    </>
  );
}
