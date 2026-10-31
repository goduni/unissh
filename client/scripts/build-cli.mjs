// Build the native CLI before Tauri packages or starts the desktop application.
// Native resources stay outside Git and are copied only when the user opts in.
import process from "node:process";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyWindowsCliImports } from "./windows-cli-imports.mjs";

const client = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const root = resolve(client, "..");
const debug = process.argv.includes("--debug");
const run = (program, args, options = {}) => {
  const result = spawnSync(program, args, { cwd: root, stdio: "inherit", ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  return result.stdout?.toString().trim();
};
const target = process.env.TAURI_ENV_TARGET_TRIPLE || run("rustc", ["--print", "host-tuple"], { stdio: "pipe" });
if (target.includes("android") || target.includes("ios")) process.exit(0);
if (!/^(x86_64|aarch64|universal)-(apple-darwin|pc-windows-msvc|unknown-linux-gnu)$/.test(target)) {
  throw new Error(`Unsupported desktop CLI target: ${target}`);
}

// The GUI binary is also called unissh. Sharing its target directory would let
// Cargo mistake the GUI for an up-to-date CLI (or overwrite the GUI).
const targetDir = join(root, "target", "cli-desktop");
const profile = debug ? "debug" : "release";
const extension = target.includes("windows") ? ".exe" : "";
const targets = target === "universal-apple-darwin"
  ? ["aarch64-apple-darwin", "x86_64-apple-darwin"] : [target];
const inputs = [];
const buildEnv = { ...process.env, CARGO_TARGET_DIR: targetDir };
if (target.includes("windows")) {
  // The separately built CLI does not inherit tauri-build's static VC runtime
  // setup. Embed it explicitly, so the optional copy also runs on a clean OS.
  if (buildEnv.CARGO_ENCODED_RUSTFLAGS !== undefined) {
    buildEnv.CARGO_ENCODED_RUSTFLAGS = [buildEnv.CARGO_ENCODED_RUSTFLAGS, "-Ctarget-feature=+crt-static"].filter(Boolean).join("\x1f");
  } else {
    buildEnv.RUSTFLAGS = `${buildEnv.RUSTFLAGS || ""} -Ctarget-feature=+crt-static`.trim();
  }
}
for (const triple of targets) {
  const args = ["build", "--locked", "-p", "unissh-cli", "--bin", "unissh", "--features", "portable", "--target", triple];
  if (!debug) args.push("--release");
  run("cargo", args, { env: buildEnv });
  if (process.argv.includes("--test")) {
    run("cargo", ["test", ...args.slice(1), "--", "--test-threads=1"], { env: buildEnv });
  }
  inputs.push(join(targetDir, triple, profile, `unissh${extension}`));
}
const directory = join(client, "src-tauri", "binaries", "cli");
mkdirSync(directory, { recursive: true });
const destination = join(directory, `unissh-cli${extension}`);
if (inputs.length === 2) run("lipo", ["-create", ...inputs, "-output", destination]);
else copyFileSync(inputs[0], destination);

const version = JSON.parse(readFileSync(join(client, "src-tauri", "tauri.conf.json"), "utf8")).version;
const reported = run(destination, ["--version"], { stdio: "pipe" });
if (reported !== `unissh ${version}`) throw new Error(`Bundled CLI version mismatch: ${reported}`);
if (target.includes("windows")) verifyWindowsCliImports(destination);

// The same tested native binary is also available without installing the GUI.
if (!debug && !target.includes("linux")) {
  const platform = target.includes("darwin") ? "macos" : "windows";
  const architecture = target.split("-")[0];
  const dist = join(client, "src-tauri", "cli-dist");
  mkdirSync(dist, { recursive: true });
  copyFileSync(destination, join(dist, `unissh-cli_${version}_${platform}-${architecture}${extension}`));
}
