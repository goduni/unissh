import { create } from "zustand";

export interface KeysetSession {
  bearer: string;
  refreshToken: string;
  accessExpires: number;
  /** base64 account_id + device_id used to mint this Bearer. */
  accountId: string;
  deviceId: string;
  /** Human label for the header badge (initials / handle). */
  label: string;
}

// Two-level admin session (both established atomically by escrow/claim sign-in):
//   · server-trusted — a live Bearer (`bearer != null`); grants the server-scoped
//     ops/admin endpoints and can be rotated with the refresh token.
//   · keyset-unlocked — the account keyset is decrypted in the wasm module
//     (`keysetUnlocked`); the private key signs challenges + grant rotations and
//     never leaves the tab.
// escrow sign-in fetches+unlocks the keyset FIRST, then challenge→verify mints the
// Bearer, so the two flags flip together; `lock()` clears both. Neither is
// persisted — a reload drops the session and returns to the sign-in screen.
interface SessionState {
  bearer: string | null;
  refreshToken: string | null;
  accessExpires: number | null;
  keysetUnlocked: boolean;
  adminAccountId: string | null;
  adminDeviceId: string | null;
  adminLabel: string | null;

  setKeysetSession: (s: KeysetSession) => void;
  setBearer: (bearer: string, accessExpires: number) => void;
  lock: () => void;
}

export const useSession = create<SessionState>()((set) => ({
  bearer: null,
  refreshToken: null,
  accessExpires: null,
  keysetUnlocked: false,
  adminAccountId: null,
  adminDeviceId: null,
  adminLabel: null,

  setKeysetSession: (s) =>
    set({
      bearer: s.bearer,
      refreshToken: s.refreshToken,
      accessExpires: s.accessExpires,
      keysetUnlocked: true,
      adminAccountId: s.accountId,
      adminDeviceId: s.deviceId,
      adminLabel: s.label,
    }),
  setBearer: (bearer, accessExpires) => set({ bearer, accessExpires }),
  lock: () =>
    set({
      bearer: null,
      refreshToken: null,
      accessExpires: null,
      keysetUnlocked: false,
      adminAccountId: null,
      adminDeviceId: null,
      adminLabel: null,
    }),
}));
