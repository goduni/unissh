// Desktop auto-update.
//
// Why this exists at all: UniSSH ships UNSIGNED .dmg/.exe by design (no developer
// identity is attached — see .github/workflows/client.yml), and SECURITY.md says
// there are no back-ports, so the only way a security fix reaches a user is a new
// release. Without an updater, someone who cleared Gatekeeper once on 0.1.0 stays
// on 0.1.0 forever. The updater closes that gap without costing the project its
// anonymity: update payloads are verified against a bare minisign public key (no
// name, no email, no keyserver) baked into tauri.conf.json, which is a stronger
// guarantee than a code-signing certificate and needs no legal identity to obtain.
//
// Scope: desktop only. Android/iOS ship as sideload artifacts the user re-installs
// by hand; the Rust plugin is not even compiled into those targets.
//
// The pure decision logic below (`updatesSupported`, `shouldCheckNow`) is kept free
// of Tauri and localStorage so it can be tested directly — see updater.test.ts.

import { logDebug, logError, logInfo } from "@/bridge/log";
import { osPlatform } from "@/bridge/platform";

/** Where a user is sent when the in-place install could not be completed. */
export const RELEASES_URL = "https://github.com/goduni/unissh/releases/latest";

/**
 * Floor between two checks. A check is one outbound request to github.com, so
 * restarting the app five times in an hour must not mean five requests.
 */
export const MIN_CHECK_GAP_MS = 60 * 60 * 1000; // 1h

/** How often a long-running window re-checks. Sessions here last days. */
export const PERIODIC_CHECK_MS = 6 * 60 * 60 * 1000; // 6h

/** Delay after boot before the first check, so it never competes with unlock/restore. */
export const BOOT_CHECK_DELAY_MS = 8000;

export const AUTO_CHECK_KEY = "unissh.updateAutoCheck";
export const LAST_CHECK_KEY = "unissh.updateLastCheck";

export type UpdateInfo = {
  version: string;
  currentVersion: string;
  notes: string;
  date: string | null;
};

export type CheckResult =
  | { status: "current" }
  | { status: "available"; info: UpdateInfo }
  /** Not a desktop build, or the plugin is absent (mobile, plain browser preview). */
  | { status: "unsupported" }
  | { status: "error"; message: string };

export type InstallResult =
  | { status: "installed" }
  /**
   * The in-place install could not be completed, so the caller points the user at
   * the release page instead. The likeliest cause on Linux is privileges: .deb and
   * .rpm updates shell out to `dpkg -i` / `rpm -U`, which need root, and a machine
   * with no polkit agent and no graphical password dialog falls back to terminal
   * `sudo` — which a desktop launcher cannot answer.
   */
  | { status: "manual"; message: string };

// ── Pure decision logic (unit-tested) ──────────────────────────────────

/**
 * Desktop only. `osPlatform()` returns "unknown" outside a Tauri context, which
 * must NOT count as supported — a plain `vite dev` browser preview has no plugin
 * to call and would only produce noise.
 */
export function updatesSupported(platform: string): boolean {
  return platform === "macos" || platform === "windows" || platform === "linux";
}

/**
 * Whether an automatic (not user-initiated) check may run right now. A manual
 * "Check now" click deliberately bypasses this — the user asked.
 */
export function shouldCheckNow(args: {
  enabled: boolean;
  supported: boolean;
  now: number;
  lastCheckedAt: number | null;
}): boolean {
  const { enabled, supported, now, lastCheckedAt } = args;
  if (!enabled || !supported) return false;
  if (lastCheckedAt === null) return true;
  // A clock that jumped backwards (timezone fix, NTP correction, VM resume) would
  // otherwise wedge checks off until real time caught up with the stale stamp.
  if (lastCheckedAt > now) return true;
  return now - lastCheckedAt >= MIN_CHECK_GAP_MS;
}

// ── Preference storage ─────────────────────────────────────────────────

/**
 * Default ON. The security argument is decisive: unsigned builds, no back-ports,
 * and a user base that will not poll a release page by hand. The trade is one
 * outbound request to github.com, disclosed in Settings -> About and in
 * THREAT_MODEL.md, and switchable off there.
 */
export function isAutoCheckEnabled(): boolean {
  try {
    return localStorage.getItem(AUTO_CHECK_KEY) !== "0";
  } catch {
    return true;
  }
}

export function setAutoCheckEnabled(on: boolean): void {
  try {
    localStorage.setItem(AUTO_CHECK_KEY, on ? "1" : "0");
  } catch {
    /* storage unavailable — the in-memory toggle still governs this session */
  }
}

export function lastCheckedAt(): number | null {
  try {
    const raw = localStorage.getItem(LAST_CHECK_KEY);
    if (!raw) return null;
    const n = parseInt(raw, 10);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

function markChecked(at: number): void {
  try {
    localStorage.setItem(LAST_CHECK_KEY, String(at));
  } catch {
    /* ignore */
  }
}

// ── Plugin interaction ─────────────────────────────────────────────────

/**
 * The handle returned by `check()` owns a Rust-side resource and is what actually
 * performs the download, so it must survive from the check until the user clicks
 * Install. Only the serialisable metadata goes to the UI.
 */
type UpdateHandle = {
  version: string;
  currentVersion: string;
  body?: string;
  date?: string;
  downloadAndInstall: () => Promise<void>;
  /** `Update` extends Tauri's `Resource`; dropping a handle without this leaks
   *  the Rust-side resource it owns. */
  close: () => Promise<void>;
};

let pending: UpdateHandle | null = null;

/** Release the handle a new check is about to supersede. */
function releasePending(): void {
  const stale = pending;
  pending = null;
  void stale?.close().catch(() => {
    /* already gone — nothing to reclaim */
  });
}

/** The update the last successful check found, if it is still un-installed. */
export function pendingUpdate(): UpdateInfo | null {
  if (!pending) return null;
  return {
    version: pending.version,
    currentVersion: pending.currentVersion,
    notes: pending.body ?? "",
    date: pending.date ?? null,
  };
}

/**
 * Ask the endpoint whether a newer release exists.
 *
 * Failures are returned, not thrown, and callers running this automatically are
 * expected to stay silent about them: GitHub being unreachable, a captive portal,
 * or an offline laptop must never produce an error dialog on every launch.
 */
export async function checkForUpdate(): Promise<CheckResult> {
  if (!updatesSupported(osPlatform())) return { status: "unsupported" };

  try {
    const { check } = await import("@tauri-apps/plugin-updater");
    const update = (await check()) as UpdateHandle | null;
    markChecked(Date.now());

    releasePending(); // a periodic re-check supersedes whatever the last one found

    if (!update) {
      logDebug("updater: no update available");
      return { status: "current" };
    }

    pending = update;
    logInfo(`updater: ${update.currentVersion} -> ${update.version} available`);
    return {
      status: "available",
      info: {
        version: update.version,
        currentVersion: update.currentVersion,
        notes: update.body ?? "",
        date: update.date ?? null,
      },
    };
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logDebug(`updater: check failed — ${message}`);
    return { status: "error", message };
  }
}

/**
 * Runs an automatic check subject to the throttle, and reports what it found.
 * Returns null when the throttle (or the preference) said not to check at all.
 */
export async function checkForUpdateIfDue(): Promise<CheckResult | null> {
  const due = shouldCheckNow({
    enabled: isAutoCheckEnabled(),
    supported: updatesSupported(osPlatform()),
    now: Date.now(),
    lastCheckedAt: lastCheckedAt(),
  });
  if (!due) return null;
  return checkForUpdate();
}

/**
 * Download, verify and install the pending update, then relaunch.
 *
 * On Windows the installer terminates this process itself, so `relaunch()` may
 * never be reached — that is expected, not a failure.
 *
 * A rejection does not necessarily mean something broke. Every desktop format is
 * updatable — the bundler stamps the package type into each binary it produces, so
 * an install knows which artifact in the manifest is its own — but .deb/.rpm
 * updates need root, and on a machine with no polkit agent and no graphical
 * password prompt the escalation has nowhere to ask. Rather than pre-guessing
 * which installs can succeed, we attempt it and translate any failure into the
 * manual path.
 */
export async function installUpdate(): Promise<InstallResult> {
  if (!pending) return { status: "manual", message: "no pending update" };

  try {
    await pending.downloadAndInstall();
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    logError(`updater: in-place install unavailable — ${message}`);
    return { status: "manual", message };
  }

  pending = null;
  try {
    const { relaunch } = await import("@tauri-apps/plugin-process");
    // The process is replaced here, so nothing after it runs — including the
    // window close handler that deletes the decrypted external-edit copies.
    const { stopAllExternalEdits } = await import("@/sftp/external-edit");
    await stopAllExternalEdits();
    await relaunch();
  } catch (e) {
    // The new version is already on disk; only the restart failed. Telling the
    // user to restart by hand is honest and loses nothing.
    logError(`updater: relaunch failed — ${e instanceof Error ? e.message : String(e)}`);
  }
  return { status: "installed" };
}

/** Test seam: drops the cached handle so a suite does not leak state across cases. */
export function __resetPendingForTests(): void {
  pending = null;
}
