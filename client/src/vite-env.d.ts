/// <reference types="vite/client" />

// `?raw` imports of repo files, used by the cross-surface tests that check the
// published donation addresses agree between the app, the README and the website.
//
// Deliberately this instead of node:fs: pulling in @types/node would make `process`,
// `Buffer` and friends typecheck everywhere in `src`, and none of them exist inside a
// Tauri webview — the app would compile clean and fail at runtime. Vite resolves these
// at test time only; nothing reaches the bundle.
declare module "*.md?raw" {
  const content: string;
  export default content;
}

declare module "*.astro?raw" {
  const content: string;
  export default content;
}
