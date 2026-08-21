// The grace decision behind "lock the vault when the screen locks".
//
// The OS side of this feature is three signals — the session locked, the
// session unlocked, the machine is going to sleep — and the only interesting
// question is which of them is actually worth zeroizing over. That question is
// all this module answers; it never touches vault state itself, it just calls
// the `lock` it was handed, which is the one `lockInstance()` the manual and
// idle paths call.
//
// Two rules do the work:
//
//   * A screen lock is graced. Locking the screen for thirty seconds and coming
//     straight back is common, and an unlock inside the window cancels the
//     pending lock with nothing lost.
//   * A suspend is not. The machine is going down; there is no coming straight
//     back to change one's mind, and a timer armed across a suspend does not
//     run anyway.
//
// Knowing a lock is already owed is load-bearing rather than defensive. On
// Linux both logind and the desktop's own screensaver may announce the same
// lock, and that state is what makes the doubled signal harmless without having
// to work out which desktop is in play and pick a winner. So is the "vault is
// already locked" guard: a screen lock over a lock screen has nothing to
// protect and must not produce a stray second lock.

/** What the OS told us. Mirrors the Rust `SystemLockSignal`. */
export type SystemLockSignal = "screen-lock" | "screen-unlock" | "suspend";

/** Seconds to wait before locking on a screen lock; `null` = feature off.
 *  `0` means lock the moment the screen does. */
export type LockGrace = number | null;

/** Which signal the lock is owed to — what the lock screen goes on to say. */
export type LockCause = Exclude<SystemLockSignal, "screen-unlock">;

export interface SystemLockWatcher {
  /** Feed a signal from the OS. */
  signal: (kind: SystemLockSignal) => void;
  /** Apply a Settings change live. Turning the feature off also disarms a lock
   *  that is already pending — the user said "not this" while it was counting. */
  setGrace: (grace: LockGrace) => void;
  /** Follow the vault. Nothing fires while it is locked, and unlocking clears
   *  the latch so the next screen lock is heard again. */
  setUnlocked: (unlocked: boolean) => void;
  /** Resolves once the lock asked for by the most recent [`signal`] has
   *  finished — immediately when that signal asked for none.
   *
   *  This exists for suspend, where the machine is being held awake for us and
   *  someone has to say when to let go. Never rejects: a lock that failed still
   *  zeroed what it could, and a suspend must not be held open over it. */
  settled: () => Promise<void>;
  /** Drop any pending lock (unmount). */
  dispose: () => void;
}

export interface SystemLockOptions {
  /** The single lock path. Called at most once per lock/unlock cycle, with the
   *  signal that earned it — which is not always the one that armed the timer,
   *  since a suspend can overtake a screen lock still inside its grace.
   *
   *  Anything it returns is awaited by [`SystemLockWatcher.settled`]. */
  lock: (cause: LockCause) => void | Promise<void>;
  grace: LockGrace;
  unlocked: boolean;
}

export function createSystemLockWatcher(opts: SystemLockOptions): SystemLockWatcher {
  let { grace, unlocked } = opts;
  let timer: ReturnType<typeof setTimeout> | undefined;
  // "armed" = a screen lock is counting down its grace; "done" = the lock has
  // been asked for. Both mean a lock is already owed, which is the dedup: the
  // second announcement of one screen lock finds us out of "idle" and is
  // dropped. They are not interchangeable, though — a suspend overtakes an
  // "armed" grace (see below) and is a no-op against a "done" one.
  let state: "idle" | "armed" | "done" = "idle";
  // When the armed grace runs out, as wall-clock rather than as a timer id. The
  // timer is only a prompt to look; this is the answer. See `signal`.
  let deadline = 0;
  // The lock asked for by the signal being handled right now, if any. Cleared
  // at the top of every `signal` so `settled` answers about that signal alone.
  let pending: Promise<void> | undefined;

  const disarm = () => {
    if (timer !== undefined) {
      clearTimeout(timer);
      timer = undefined;
    }
  };

  const reset = () => {
    disarm();
    state = "idle";
  };

  const fire = (cause: LockCause) => {
    timer = undefined;
    state = "done";
    // Swallowed here rather than at the call site: `settled` is a suspend
    // waiting to be released, and a rejected lock is still a finished one.
    pending = Promise.resolve(opts.lock(cause)).then(
      () => {},
      () => {},
    );
  };

  return {
    signal: (kind) => {
      pending = undefined;
      if (kind === "screen-unlock") {
        // The user is back — but "back" is not the same as "in time". A hidden
        // window's timers are throttled by the webview, so an armed grace can
        // still be sitting there un-fired well past the moment it was owed;
        // cancelling on the strength of the callback not having run yet would
        // hand back a lock the user had already earned. The deadline decides,
        // and only then does the next screen lock start from a clean slate.
        if (state === "armed" && Date.now() >= deadline) fire("screen-lock");
        reset();
        return;
      }
      // Nothing to protect: the vault is closed, or the user turned this off.
      if (!unlocked || grace === null) return;
      if (kind === "suspend") {
        // Not graced, and it overtakes a grace already running: a timer armed
        // moments ago will not tick while the machine is asleep, so waiting for
        // it means suspending with the vault open.
        if (state === "done") return;
        disarm();
        fire("suspend");
        return;
      }
      if (state !== "idle") return; // logind and the screensaver, one lock
      if (grace === 0) {
        fire("screen-lock");
        return;
      }
      state = "armed";
      deadline = Date.now() + grace * 1000;
      timer = setTimeout(() => fire("screen-lock"), grace * 1000);
    },
    setGrace: (next) => {
      grace = next;
      if (next === null) reset();
    },
    setUnlocked: (next) => {
      unlocked = next;
      reset();
    },
    settled: () => pending ?? Promise.resolve(),
    dispose: reset,
  };
}
