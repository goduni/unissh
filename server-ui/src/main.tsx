import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

// Geologica and JetBrains Mono are self-hosted by @font-face in global.css.
import "./theme/global.css";
import "./i18n";
import { App } from "./App";
import { loadWasmProvider } from "./crypto/wasm-provider";

// Load the real rust-core crypto (wasm) in the background; keyset operations
// stay gracefully disabled until it resolves.
void loadWasmProvider();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
