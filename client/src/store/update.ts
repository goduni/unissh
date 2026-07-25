// Shared state for the desktop updater. Two consumers need it — the shell banner
// and Settings -> About — so it cannot live as local state in either.
//
// Kept out of `store/app.ts` deliberately: that store is already the app's largest
// file, and updating has no coupling to vaults, sessions or routing beyond reading
// the live pane count at install time.

import { create } from "zustand";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  RELEASES_URL,
  checkForUpdate,
  checkForUpdateIfDue,
  installUpdate,
  isAutoCheckEnabled,
  setAutoCheckEnabled,
  type UpdateInfo,
} from "@/bridge/updater";
import { toast } from "@/store/toast";
import { i18n } from "@/i18n";

/** What the About panel shows next to the version. */
export type CheckState =
  | "idle" // never checked this session
  | "checking"
  | "current" // checked, already newest
  | "available"
  | "error"; // check failed — only ever surfaced for a manual check

interface UpdateStore {
  info: UpdateInfo | null;
  state: CheckState;
  installing: boolean;
  /** The banner was dismissed for this session; About still shows the update. */
  dismissed: boolean;
  autoCheck: boolean;

  /** `manual` = the user clicked Check: bypasses the throttle and reports failures. */
  check: (manual: boolean) => Promise<void>;
  install: () => Promise<void>;
  dismiss: () => void;
  setAutoCheck: (on: boolean) => void;
  openReleasePage: () => void;
}

export const useUpdate = create<UpdateStore>((set, get) => ({
  info: null,
  state: "idle",
  installing: false,
  dismissed: false,
  autoCheck: isAutoCheckEnabled(),

  check: async (manual) => {
    if (get().state === "checking" || get().installing) return;
    set({ state: "checking" });

    const res = manual ? await checkForUpdate() : await checkForUpdateIfDue();

    // Throttled out — nothing happened, so say nothing and leave the previous
    // result on screen.
    if (res === null) {
      set({ state: get().info ? "available" : "idle" });
      return;
    }

    switch (res.status) {
      case "available":
        // A newer version than the one already on the banner un-dismisses it:
        // the user dismissed a different update than the one now offered.
        set((s) => ({
          info: res.info,
          state: "available",
          dismissed: s.info?.version === res.info.version ? s.dismissed : false,
        }));
        break;
      case "current":
        set({ info: null, state: "current" });
        if (manual) toast(i18n.t("update.upToDate"), "ok");
        break;
      case "unsupported":
        set({ state: "idle" });
        break;
      case "error":
        set({ state: "error" });
        // Silent when automatic: an offline laptop or a captive portal must not
        // produce an error on every launch. A manual check asked for an answer.
        if (manual) toast(i18n.t("update.checkFailed"), "err");
        break;
    }
  },

  install: async () => {
    if (get().installing || !get().info) return;
    set({ installing: true });

    const res = await installUpdate();
    if (res.status === "manual") {
      // Not necessarily a breakage: a .deb/.rpm install belongs to the system
      // package manager and cannot be swapped in place. Hand the user the page.
      set({ installing: false });
      toast(i18n.t("update.installManual"), "warn");
      get().openReleasePage();
      return;
    }
    // On success the process is replaced or relaunched; if relaunch failed the
    // new version is still on disk and takes effect on the next start.
    set({ installing: false, info: null, state: "current", dismissed: false });
    toast(i18n.t("update.installedRestart"), "ok");
  },

  dismiss: () => set({ dismissed: true }),

  setAutoCheck: (on) => {
    setAutoCheckEnabled(on);
    set({ autoCheck: on });
  },

  openReleasePage: () => {
    void openUrl(RELEASES_URL).catch(() => {
      /* no opener in this context — the toast already named the version */
    });
  },
}));
