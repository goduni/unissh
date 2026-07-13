import { create } from "zustand";

export type Route =
  | "overview"
  | "health"
  | "metrics"
  | "config"
  | "maint"
  | "spaces"
  | "accounts"
  | "directory"
  | "devices"
  | "sessions"
  | "invites"
  | "vaults"
  | "grants"
  | "relay"
  | "objects"
  | "audit";

export interface DrawerRef {
  type: "account" | "vault";
  id: string;
}

export interface ConfirmCfg {
  title: string;
  desc: string;
  danger?: boolean;
  confirmLabel: string;
  /** If set, the user must type this string to enable confirmation. */
  requireText?: string;
  onConfirm: () => void | Promise<void>;
}

export type ToastKind = "info" | "success" | "error";
export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
  retryAfter?: number;
}

interface UiState {
  route: Route;
  panelOpen: boolean;
  keysetModalOpen: boolean;
  inviteOpen: boolean;
  rotateOpen: boolean;
  drawer: DrawerRef | null;
  confirm: ConfirmCfg | null;
  toasts: Toast[];
  /** Generic cross-component reload signal — include in useAsync deps. */
  reloadTick: number;

  go: (r: Route) => void;
  bumpReload: () => void;
  togglePanel: () => void;
  openKeyset: () => void;
  closeKeyset: () => void;
  openInvite: () => void;
  closeInvite: () => void;
  openRotate: () => void;
  closeRotate: () => void;
  openDrawer: (d: DrawerRef) => void;
  closeDrawer: () => void;
  askConfirm: (c: ConfirmCfg) => void;
  clearConfirm: () => void;
  toast: (kind: ToastKind, message: string, retryAfter?: number) => void;
  dismissToast: (id: number) => void;
}

let toastSeq = 1;

export const useUi = create<UiState>()((set) => ({
  route: "overview",
  panelOpen: false,
  keysetModalOpen: false,
  inviteOpen: false,
  rotateOpen: false,
  drawer: null,
  confirm: null,
  toasts: [],
  reloadTick: 0,

  bumpReload: () => set((s) => ({ reloadTick: s.reloadTick + 1 })),
  go: (route) =>
    set({
      route,
      panelOpen: false,
      drawer: null,
    }),
  togglePanel: () => set((s) => ({ panelOpen: !s.panelOpen })),
  openKeyset: () => set({ keysetModalOpen: true }),
  closeKeyset: () => set({ keysetModalOpen: false }),
  openInvite: () => set({ inviteOpen: true }),
  closeInvite: () => set({ inviteOpen: false }),
  openRotate: () => set({ rotateOpen: true }),
  closeRotate: () => set({ rotateOpen: false }),
  openDrawer: (drawer) => set({ drawer }),
  closeDrawer: () => set({ drawer: null }),
  askConfirm: (confirm) => set({ confirm }),
  clearConfirm: () => set({ confirm: null }),
  toast: (kind, message, retryAfter) =>
    set((s) => {
      // Dedup: an identical kind+message already showing just refreshes its
      // retryAfter instead of stacking a duplicate — a burst of the same 401 error
      // shouldn't pile up N copies.
      const dup = s.toasts.find((t) => t.kind === kind && t.message === message);
      if (dup) {
        return { toasts: s.toasts.map((t) => (t === dup ? { ...t, retryAfter } : t)) };
      }
      // Cap the visible stack; drop the oldest overflow so it can't grow unbounded.
      const MAX_TOASTS = 4;
      const next = [...s.toasts, { id: toastSeq++, kind, message, retryAfter }];
      return { toasts: next.length > MAX_TOASTS ? next.slice(next.length - MAX_TOASTS) : next };
    }),
  dismissToast: (id) =>
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));
