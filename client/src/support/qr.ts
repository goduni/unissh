// Offline QR generation for the Support tab.
//
// No network request, no third-party image service: the address never leaves the
// machine. That matters less for a public donation address than for the precedent —
// this app does not phone out to render its own UI.
//
// The payload is the BARE address, not a `bitcoin:`/`ethereum:` URI. Bare strings scan
// into every wallet; URI schemes only into the ones that implement that scheme.

import qrcode from "qrcode-generator";

export interface EncodedQr {
  /** Modules per side. */
  count: number;
  isDark: (row: number, col: number) => boolean;
}

/** Encode `text` at error-correction level M (~15% recovery), auto-sizing the symbol.
 *  Throws if the payload does not fit any version — never returns a truncated grid. */
export function encodeQr(text: string): EncodedQr {
  const qr = qrcode(0, "M"); // 0 = pick the smallest version that fits
  qr.addData(text);
  qr.make();
  return { count: qr.getModuleCount(), isDark: (r, c) => qr.isDark(r, c) };
}

/** Paint an encoded QR onto a canvas at roughly `size` CSS px, honouring devicePixelRatio.
 *
 *  Always black on white, regardless of the app theme. A QR drawn in theme ink on a theme
 *  background can drop below the contrast a phone camera needs — and a code that fails to
 *  scan on a dark theme would be a bug nobody reports, they just give up. */
export function drawQr(canvas: HTMLCanvasElement, text: string, size: number): void {
  const qr = encodeQr(text);
  const dpr = typeof devicePixelRatio === "number" && devicePixelRatio > 0 ? devicePixelRatio : 1;
  const quiet = 4; // modules; the spec's mandatory quiet zone
  const modules = qr.count + quiet * 2;
  // Integer module size, so no module lands on a half-pixel and blurs.
  const scale = Math.max(1, Math.floor((size * dpr) / modules));
  const px = modules * scale;

  canvas.width = px;
  canvas.height = px;
  canvas.style.width = `${px / dpr}px`;
  canvas.style.height = `${px / dpr}px`;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, px, px);
  ctx.fillStyle = "#000000";
  for (let r = 0; r < qr.count; r++) {
    for (let c = 0; c < qr.count; c++) {
      if (qr.isDark(r, c)) ctx.fillRect((c + quiet) * scale, (r + quiet) * scale, scale, scale);
    }
  }
}
