// OSC 52 clipboard writes from the remote side (zellij, tmux `set-clipboard`,
// nvim's clipboard provider). Write-only on purpose: the "?" form is the remote
// host asking to READ the clipboard, which is an exfiltration channel — we never
// answer it. Anything malformed is ignored rather than clearing or clobbering
// whatever the user has in the clipboard.

// No size cap of our own: xterm's parser already aborts OSC payloads over
// 10 MB (PAYLOAD_LIMIT) before they reach any handler, clipboard clobbering
// is size-independent, and a cap here would silently drop a copy the
// multiplexer already reported as done — the exact lie this module exists
// to kill.

/** `Pc;Pd` → the decoded text to put in the system clipboard, or null when the
 *  sequence should be ignored (query, empty, malformed). */
export function parseOsc52(data: string): string | null {
  const sep = data.indexOf(";");
  if (sep < 0) return null;
  const payload = data.slice(sep + 1).replace(/\s+/g, "");
  if (!payload || payload === "?") return null;
  let bin: string;
  try {
    bin = atob(payload);
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
