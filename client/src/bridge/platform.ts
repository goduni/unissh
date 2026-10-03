// Compile-time platform of the running binary (via @tauri-apps/plugin-os).
import { platform } from "@tauri-apps/plugin-os";

let cached: string | null = null;

export function osPlatform(): string {
  if (cached) return cached;
  try {
    cached = platform();
  } catch {
    cached = "unknown"; // not in a Tauri context (e.g. plain browser preview)
  }
  return cached;
}

/** macOS shows native traffic lights; other desktops need custom controls. */
export const isMac = (): boolean => osPlatform() === "macos";

export const isWindows = (): boolean => osPlatform() === "windows";

/** The name of this desktop's biometric unlock, for copy that names it. A
 *  product name, so it is not translated. */
export const biometricMethod = (): string => (isWindows() ? "Windows Hello" : "Touch ID");

/** The startup presence gate is in force: a Secret-Key-only vault, the gate
 *  turned on, on a desktop that has the prompt. One answer for boot (which then
 *  skips the remembered-key auto-unlock) and the unlock screen (which then asks
 *  first), so the two can never disagree. */
export const presenceGateApplies = (requiresPassword: boolean | null, gateOn: boolean): boolean =>
  requiresPassword === false && gateOn && (isMac() || isWindows());

/** False in a plain browser preview, where every window API would throw. */
export const isTauri = (): boolean => osPlatform() !== "unknown";

/** Running as a desktop binary — even while the UI previews the phone shell
 *  (Ctrl/Cmd+Shift+M), the frameless window still needs its own drag regions
 *  and window controls. */
export const isDesktopOs = (): boolean =>
  isTauri() && osPlatform() !== "android" && osPlatform() !== "ios";
