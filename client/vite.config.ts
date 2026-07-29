import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

const host = process.env.TAURI_DEV_HOST;

// https://vitejs.dev/config/  — tuned for Tauri v2 (desktop + mobile dev)
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  // Tauri expects a fixed port and must not clear the console it pipes through.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: {
      // don't watch the Rust side
      ignored: ["**/src-tauri/**"],
    },
  },
  // Vite 8 transpiles/minifies with oxc + rolldown (no bundled esbuild).
  build: {
    minify: !process.env.TAURI_DEBUG,
    sourcemap: !!process.env.TAURI_DEBUG,
    // The 500 kB default warns about *download* cost over a network. This bundle
    // is read from the local filesystem by a WebView that Tauri ships it to, so
    // that cost does not exist here; what remains is parse time, and splitting
    // moves it around rather than removing it. The floor is xterm + React +
    // the always-mounted views (Hosts, Terminal, SFTP — SFTP stays mounted on
    // purpose, see App.tsx), which clears 500 kB on its own, so no amount of
    // lazy-loading would silence this. Raised deliberately rather than chased.
    // If startup on a low-end Android WebView ever becomes the complaint, the
    // answer is React.lazy on Settings/Secrets/Recordings — measured, not
    // guessed — and this number stays where it is.
    chunkSizeWarningLimit: 1600,
  },
});
