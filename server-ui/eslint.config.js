// Flat config (ESLint 10) — the admin panel.
//
// This package shipped a `lint` script that never worked: eslint was not in
// devDependencies at all, and the `--ext` flag it passed was removed in ESLint 9.
// The repo had no working linter until now, so the rule set is chosen to be a
// GATE that stays green and still catches real defects — not a wall of findings
// nobody reads. A rule earns its place by catching a class of bug a reviewer
// plausibly misses. Style is not linted: the codebase is internally consistent
// and formatting churn would bury the signal.
//
// Type-aware linting (projectService) is deliberately off. It needs a full TS
// program per run, which is most of a `tsc` again, and `npm run typecheck`
// already does exactly that in the same CI job.

import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // Generated, vendored or not-ours. crypto-wasm/ is the Rust crate plus the
    // wasm-pack output it generates into pkg/.
    ignores: ["dist/", "crypto-wasm/", "node_modules/", "*.config.js"],
  },
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    linterOptions: {
      // A disable comment that no longer suppresses anything is a lie about the
      // code. Three had already gone stale before the linter was ever wired up.
      reportUnusedDisableDirectives: "error",
    },
    languageOptions: {
      globals: { ...globals.browser, ...globals.es2024 },
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      // The two classic hook rules. NOT `reactHooks.configs.recommended`: in
      // plugin v7 that expanded to the full sixteen-rule React Compiler set.
      // Adopting those means reworking effects and refs across both frontends —
      // a project of its own rather than a side effect of turning on a linter.
      // The client's config carries the same decision and the same wording.
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error",

      // The base rule mis-handles TS enums and overloads; the TS-aware one
      // replaces it. `ignoreRestSiblings` is what makes the rest-omit idiom
      // (`const { id, custom, ...palette } = t`) legal — the omitted keys are
      // the whole point of writing it that way.
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          ignoreRestSiblings: true,
          caughtErrors: "none",
        },
      ],

      // `catch { /* why */ }` is used throughout for genuinely best-effort work
      // (storage unavailable, not running under Tauri). Empty blocks elsewhere
      // are still worth flagging.
      "no-empty": ["error", { allowEmptyCatch: true }],

      // Off by design, matching the client: a variable initialised to a safe
      // default before a try/catch whose branches both assign it reads as dead
      // today, but dropping the initialiser means a branch added later silently
      // inherits `undefined` instead of the safe default.
      "no-useless-assignment": "off",
    },
  },
);
