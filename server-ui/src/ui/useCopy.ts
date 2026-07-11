import { useState } from "react";

/**
 * Clipboard-copy with a transient "copied" flash. `copy(text)` writes to the
 * clipboard, then flips `copied` true for `resetMs` before resetting.
 */
export function useCopy(resetMs = 1200): {
  copied: boolean;
  copy: (text: string) => void;
} {
  const [copied, setCopied] = useState(false);
  const copy = (text: string) => {
    void navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), resetMs);
  };
  return { copied, copy };
}
