// Validate the actual packaged command, including its runtime dependencies.
import process from "node:process";
import { log } from "node:console";
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyWindowsCliImports } from "./windows-cli-imports.mjs";

const client = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const target = join(client, "src-tauri", "target");
const version = JSON.parse(readFileSync(join(client, "src-tauri", "tauri.conf.json"), "utf8")).version;
const mac = process.platform === "darwin";
const release = join(target, ...(mac ? ["universal-apple-darwin"] : []), "release");
const binary = mac
  ? join(release, "bundle", "macos", "UniSSH.app", "Contents", "Resources", "cli", "unissh-cli")
  : join(release, "cli", process.platform === "win32" ? "unissh-cli.exe" : "unissh-cli");
if (!existsSync(binary)) throw new Error(`Desktop bundle is missing its CLI: ${binary}`);
const reported = execFileSync(binary, ["--version"], { encoding: "utf8" }).trim();
if (reported !== `unissh ${version}`) throw new Error(`Packaged CLI version mismatch: ${reported}`);
if (process.platform === "win32") verifyWindowsCliImports(binary);
if (mac) {
  const architectures = execFileSync("lipo", ["-archs", binary], { encoding: "utf8" });
  if (!architectures.includes("x86_64") || !architectures.includes("arm64")) {
    throw new Error(`The macOS CLI must be universal: ${architectures}`);
  }
  const dependencies = execFileSync("otool", ["-L", binary], { encoding: "utf8" });
  if (/\/opt\/homebrew\/|\/usr\/local\/|lib(?:crypto|ssl)\./.test(dependencies)) {
    throw new Error(`The CLI depends on non-system shared libraries: ${dependencies}`);
  }
}
if (process.platform === "linux") {
  const directory = join(release, "bundle", "deb");
  const packages = readdirSync(directory).filter(name => name.endsWith(".deb"));
  if (!packages.length) throw new Error("No Debian package was produced");
  for (const name of packages) {
    const contents = execFileSync("dpkg-deb", ["--contents", join(directory, name)], { encoding: "utf8" });
    if (!/(?:^|\s)(?:\.\/)?usr\/lib\/\S+\/cli\/unissh-cli(?:\r?\n|$)/m.test(contents)) {
      throw new Error(`${name} does not contain the CLI at its resource path:\n${contents}`);
    }
  }
}
log(`Verified bundled unissh-cli ${version}`);
