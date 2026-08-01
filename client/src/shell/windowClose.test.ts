// The window-close contract, pinned as a test because getting it wrong makes the
// app impossible to quit and nothing in a type-check or a lint can see it.
//
// Registering `onCloseRequested` (App.tsx, the confirm-on-quit prompt) is not a
// passive subscription. Tauri checks for a JS listener on that event and, when it
// finds one, calls `api.prevent_close()` on EVERY native close and hands the whole
// decision to JS (tauri manager/window.rs). The `@tauri-apps/api` wrapper then
// finishes the job itself: `await handler(evt); if (!evt.isPreventDefault()) await
// this.destroy()`.
//
// `destroy` is a different ACL permission from `close`, and it is NOT part of
// `core:window:default` — that set is read-only accessors. So the two have to be
// granted together: with `allow-close` alone the wrapper's `destroy()` is rejected
// by the ACL, the listener callback rejects, and the window is never destroyed. Not
// by the compositor's close, not by the WM hotkey, not by our own title-bar button
// (which calls `close()`, which emits the same prevented CloseRequested). The only
// way out is killing the process.
//
// Found on Arch/niri, where the window manager owns the frame and our title bar is
// gone by design — so the compositor is the ONLY way to close the window, and the
// one path everyone else still had was missing there.

import { describe, expect, it } from "vitest";
import app from "../App.tsx?raw";
import capabilities from "../../src-tauri/capabilities/default.json";

const granted = (): string[] =>
  (capabilities.permissions as (string | { identifier: string })[]).map((p) =>
    typeof p === "string" ? p : p.identifier,
  );

describe("window close capability", () => {
  it("registers onCloseRequested, which is what makes destroy mandatory", () => {
    // The premise of everything below. If this ever stops being true the
    // `allow-destroy` requirement can be revisited — until then it cannot.
    expect(app).toContain("onCloseRequested");
  });

  it("grants core:window:allow-destroy", () => {
    expect(granted()).toContain("core:window:allow-destroy");
  });

  it("grants close and destroy together — close alone cannot close the window", () => {
    const perms = granted();
    if (perms.includes("core:window:allow-close")) {
      expect(perms).toContain("core:window:allow-destroy");
    }
  });
});
