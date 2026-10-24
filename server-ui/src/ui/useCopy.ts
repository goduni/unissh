import { useCallback, useEffect, useState } from "react";

/**
 * Clipboard copy with its two outcomes. `copy(text)` writes to the clipboard;
 * when the write lands, `copied` is true for `resetMs` (the green check). When
 * the browser refuses it (no permission, an insecure origin, no clipboard API),
 * `failed` turns true and stays so until `dismiss()` or the next successful copy:
 * the caller shows a red cross and says how to copy by hand.
 */
export function useCopy(resetMs = 1500): {
  copied: boolean;
  failed: boolean;
  copy: (text: string) => void;
  dismiss: () => void;
} {
  // Counts successful copies; 0 = the check is not showing. A new copy restarts the timer.
  const [okCount, setOkCount] = useState(0);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!okCount) return;
    const h = setTimeout(() => setOkCount(0), resetMs);
    return () => clearTimeout(h);
  }, [okCount, resetMs]);

  const copy = useCallback((text: string) => {
    const done = () => {
      setFailed(false);
      setOkCount((n) => n + 1);
    };
    const fail = () => {
      setOkCount(0);
      setFailed(true);
    };
    try {
      const write = navigator.clipboard?.writeText(text);
      if (!write) fail();
      else write.then(done, fail);
    } catch {
      fail();
    }
  }, []);

  const dismiss = useCallback(() => setFailed(false), []);

  return { copied: okCount > 0, failed, copy, dismiss };
}
