// Inspect the PE import table rather than relying on DLLs preinstalled on CI.
import { readFileSync } from "node:fs";

export function verifyWindowsCliImports(path) {
  const bytes = readFileSync(path);
  const pe = bytes.readUInt32LE(0x3c);
  if (bytes.toString("ascii", pe, pe + 4) !== "PE\0\0") throw new Error("CLI is not a PE executable");
  const optional = pe + 24;
  const magic = bytes.readUInt16LE(optional);
  if (magic !== 0x20b && magic !== 0x10b) throw new Error("Unknown CLI PE optional header");
  const sections = optional + bytes.readUInt16LE(pe + 20);
  const count = bytes.readUInt16LE(pe + 6);
  const offset = rva => {
    for (let i = 0; i < count; i++) {
      const section = sections + i * 40;
      const start = bytes.readUInt32LE(section + 12);
      const size = Math.max(bytes.readUInt32LE(section + 8), bytes.readUInt32LE(section + 16));
      if (rva >= start && rva < start + size) return bytes.readUInt32LE(section + 20) + rva - start;
    }
    throw new Error(`Invalid CLI import address: ${rva}`);
  };
  const imports = bytes.readUInt32LE(optional + (magic === 0x20b ? 112 : 96) + 8);
  if (!imports) throw new Error("CLI has no PE import table");
  const names = [];
  for (let entry = offset(imports); bytes.readUInt32LE(entry + 12); entry += 20) {
    const start = offset(bytes.readUInt32LE(entry + 12));
    const end = bytes.indexOf(0, start);
    if (end < 0) throw new Error("Unterminated CLI DLL import");
    names.push(bytes.toString("ascii", start, end));
  }
  const external = names.filter(name => /^(?:vcruntime|msvcp|(?:lib)?crypto|(?:lib)?ssl).*\.dll$/i.test(name));
  if (external.length) throw new Error(`CLI requires external runtime DLLs: ${external.join(", ")}`);
  return names;
}
