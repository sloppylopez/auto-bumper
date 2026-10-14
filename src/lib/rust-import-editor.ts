/**
 * Rust use-statement rewrites for crate renames (via --allow-source-migrations).
 */
import fs from "node:fs";
import path from "node:path";
import { backupFile, discardBackup, restoreFile } from "./backup.ts";
import type { SourcePackageRule } from "./maven-renames.ts";

const SKIP_DIR_NAMES = new Set([".git", "target", "node_modules"]);

export interface RustImportApplyResult {
  changed: string[];
  skipped: string[];
  warnings: string[];
}

function rustCrateIdent(crate: string): string {
  return crate.replaceAll("-", "_");
}

function discoverRustFiles(projectRoot: string, _globs: string[]): string[] {
  const files: string[] = [];
  const seen = new Set<string>();
  walkDir(projectRoot, files, seen);
  return files.sort((a, b) => a.localeCompare(b));
}

function walkDir(dir: string, files: string[], seen: Set<string>): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".")) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIR_NAMES.has(entry.name)) continue;
      walkDir(full, files, seen);
      continue;
    }
    if (!entry.name.endsWith(".rs")) continue;
    if (seen.has(full)) continue;
    seen.add(full);
    files.push(full);
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\\$&`);
}

/** Rewrite use/extern crate lines for renamed crates. */
export function rewriteRustImports(content: string, rules: SourcePackageRule[]): { content: string; changed: boolean } {
  if (rules.length === 0) return { content, changed: false };

  let changed = false;
  const out = content.split("\n").map(line => {
    let next = line;
    for (const rule of rules) {
      const fromIdent = rustCrateIdent(rule.fromPackage);
      const toIdent = rustCrateIdent(rule.toPackage);
      const patterns = [
        new RegExp(String.raw`^(\s*use\s+)${escapeRegex(fromIdent)}(::|\s*;)`),
        new RegExp(String.raw`^(\s*extern\s+crate\s+)${escapeRegex(fromIdent)}(\s*;)`),
      ];
      for (const re of patterns) {
        if (!re.test(next)) continue;
        next = next.replace(re, (_m, p1, p2) => {
          changed = true;
          return `${p1}${toIdent}${p2}`;
        });
      }
    }
    return next;
  });

  return { content: out.join("\n"), changed };
}

export function applyRustImportMigrations(
  projectRoot: string,
  rules: SourcePackageRule[],
  _globs: string[] = ["**/*.rs"],
): RustImportApplyResult {
  const result: RustImportApplyResult = { changed: [], skipped: [], warnings: [] };
  if (rules.length === 0) return result;

  const files = discoverRustFiles(projectRoot, _globs);
  if (files.length === 0) {
    result.warnings.push("No Rust sources found for import migration.");
    return result;
  }

  for (const filePath of files) {
    const before = fs.readFileSync(filePath, "utf-8");
    const { content: after, changed } = rewriteRustImports(before, rules);
    if (!changed) {
      result.skipped.push(filePath);
      continue;
    }
    backupFile(filePath);
    fs.writeFileSync(filePath, after, "utf-8");
    result.changed.push(filePath);
  }

  if (result.changed.length > 0) {
    result.warnings.push("Rust use-statement migration applied — verify with cargo build.");
  }
  return result;
}

export function restoreRustImportBackups(filePaths: string[]): number {
  let restored = 0;
  for (const filePath of filePaths) {
    if (restoreFile(filePath)) restored++;
  }
  return restored;
}

export function discardRustImportBackups(filePaths: string[]): void {
  for (const filePath of filePaths) {
    discardBackup(filePath);
  }
}
