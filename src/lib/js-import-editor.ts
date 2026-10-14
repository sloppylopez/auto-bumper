/**
 * JS/TS import rewrites for package renames (via --allow-source-migrations).
 */
import fs from "node:fs";
import path from "node:path";
import { backupFile, discardBackup, restoreFile } from "./backup.ts";
import { isInsideDir } from "../path.ts";
import type { SourcePackageRule } from "./maven-renames.ts";

const SKIP_DIR_NAMES = new Set(["node_modules", "dist", "build", ".git", "coverage", ".next"]);
const SOURCE_EXTS = new Set([".js", ".ts", ".tsx", ".mjs", ".cjs", ".jsx"]);

export interface JsImportApplyResult {
  changed: string[];
  skipped: string[];
  warnings: string[];
}

function discoverSourceFiles(projectRoot: string, globs: string[]): string[] {
  const files: string[] = [];
  const seen = new Set<string>();
  const useAll = globs.some(g => g.startsWith("**"));

  if (useAll) {
    walkDir(projectRoot, files, seen);
    return files.sort((a, b) => a.localeCompare(b));
  }

  const root = path.resolve(projectRoot);
  for (const glob of globs) {
    if (path.isAbsolute(glob) || glob.split(/[\\/]/).includes("..")) continue;
    const base = glob.replace(/\/\*\*.*$/, "");
    const full = path.resolve(projectRoot, base);
    if (!isInsideDir(root, full) || !fs.existsSync(full)) continue;
    if (fs.statSync(full).isFile() && SOURCE_EXTS.has(path.extname(full))) {
      if (!seen.has(full)) {
        seen.add(full);
        files.push(full);
      }
      continue;
    }
    walkDir(full, files, seen);
  }
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
    if (!SOURCE_EXTS.has(path.extname(entry.name))) continue;
    if (seen.has(full)) continue;
    seen.add(full);
    files.push(full);
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\\$&`);
}

/** Rewrite package string literals in import/require lines. */
export function rewriteJsImports(content: string, rules: SourcePackageRule[]): { content: string; changed: boolean } {
  if (rules.length === 0) return { content, changed: false };

  let changed = false;
  let result = content;

  for (const rule of rules) {
    const from = escapeRegex(rule.fromPackage);
    const re = new RegExp(String.raw`(['"])(${from})((?:/[^'"]*)?)(\1)`, "g");
    result = result.replace(re, (_m, quote, _pkg, subpath) => {
      changed = true;
      return `${quote}${rule.toPackage}${subpath || ""}${quote}`;
    });
  }

  return { content: result, changed };
}

export function applyJsImportMigrations(
  projectRoot: string,
  rules: SourcePackageRule[],
  globs: string[] = ["**/*.{js,ts,tsx,mjs,cjs,jsx}"],
): JsImportApplyResult {
  const result: JsImportApplyResult = { changed: [], skipped: [], warnings: [] };
  if (rules.length === 0) return result;

  const files = discoverSourceFiles(projectRoot, globs);
  if (files.length === 0) {
    result.warnings.push("No JS/TS sources found for import migration.");
    return result;
  }

  for (const filePath of files) {
    const before = fs.readFileSync(filePath, "utf-8");
    const { content: after, changed } = rewriteJsImports(before, rules);
    if (!changed) {
      result.skipped.push(filePath);
      continue;
    }
    backupFile(filePath);
    fs.writeFileSync(filePath, after, "utf-8");
    result.changed.push(filePath);
  }

  if (result.changed.length > 0) {
    result.warnings.push("JS/TS import migration applied — verify with your test suite.");
  }
  return result;
}

export function restoreJsImportBackups(filePaths: string[]): number {
  let restored = 0;
  for (const filePath of filePaths) {
    if (restoreFile(filePath)) restored++;
  }
  return restored;
}

export function discardJsImportBackups(filePaths: string[]): void {
  for (const filePath of filePaths) {
    discardBackup(filePath);
  }
}
