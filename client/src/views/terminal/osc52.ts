// OSC 52 clipboard writes from the remote side (zellij, tmux `set-clipboard`,
// nvim's clipboard provider). Write-only on purpose: the "?" form is the remote
// host asking to READ the clipboard, which is an exfiltration channel — we never
// answer it. Anything malformed is ignored rather than clearing or clobbering
// whatever the user has in the clipboard.

/** Longest base64 payload we accept — ~5 MiB decoded. tmux caps its own OSC 52
 *  writes far below this; anything bigger is not a human copying text. */
export const OSC52_MAX_B64 = 7 * 1024 * 1024;

/** `Pc;Pd` → the decoded text to put in the system clipboard, or null when the
 *  sequence should be ignored (query, empty, malformed, oversized). */
export function parseOsc52(data: string): string | null {
  const sep = data.indexOf(";");
  if (sep < 0) return null;
  const payload = data.slice(sep + 1).replace(/\s+/g, "");
  if (!payload || payload === "?" || payload.length > OSC52_MAX_B64) return null;
  let bin: string;
  try {
    bin = atob(payload);
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
