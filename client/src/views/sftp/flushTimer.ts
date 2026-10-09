// Paces what a running walk puts on screen: however often figures arrive, they
// are committed together, at most once per interval.

export class FlushTimer {
  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor(
    private readonly flush: () => void,
    private readonly ms = 250,
  ) {}

  /** Ask for a flush one interval from now, unless one is already due. */
  arm(): void {
    this.timer ??= setTimeout(() => {
      this.timer = undefined;
      this.flush();
    }, this.ms);
  }

  /** Nothing is waiting any more: no flush is left behind. */
  disarm(): void {
    if (this.timer === undefined) return;
    clearTimeout(this.timer);
    this.timer = undefined;
  }
}
