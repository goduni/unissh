// Flat config (ESLint 10).
//
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
    // Generated, vendored or not-ours. src-tauri is Rust plus its own gen/ tree.
    ignores: ["dist/", "src-tauri/", "node_modules/", "*.config.js"],
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
      // The two classic hook rules, both of which the codebase already passes
      // clean. NOT `reactHooks.configs.recommended`: in plugin v7 that expanded
      // to the full sixteen-rule React Compiler set, which fires 46 times here
      // (set-state-in-effect ×22, refs ×17, static-components ×7). Those are
      // worth adopting, but adopting them means reworking effects and refs
      // across the app — a project of its own, not a side effect of turning on
      // a linter. Enabling them now would only mean disabling them again.
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

      // Off by design. This is an SSH client: stripping ANSI/OSC/CSI sequences
      // out of terminal output means matching C0 controls on purpose, and the
      // four hits are exactly that code.
      "no-control-regex": "off",

      // Off by design. The codebase initialises a variable to a safe default
      // before a try/catch whose branches both assign it. The rule is right that
      // today's initialiser is dead — and removing it would be a real
      // regression: a branch added later would silently inherit `undefined`
      // instead of the safe default. A lint tick is not worth that.
      "no-useless-assignment": "off",
    },
  },
  {
    // Tests legitimately reach for looser typing than production code.
    files: ["**/*.test.{ts,tsx}"],
    rules: { "@typescript-eslint/no-explicit-any": "off" },
  },
);
