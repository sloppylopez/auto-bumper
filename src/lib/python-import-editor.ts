/**
 * Python import rewrites for package renames (via --allow-source-migrations).
 */
import fs from "node:fs";
import path from "node:path";
import { backupFile, discardBackup, restoreFile } from "./backup.ts";
import type { SourcePackageRule } from "./maven-renames.ts";

const SKIP_DIR_NAMES = new Set([".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"]);

export interface PythonImportApplyResult {
  changed: string[];
  skipped: string[];
  warnings: string[];
}

function pythonModuleName(pkg: string): string {
  return pkg.replaceAll("-", "_").toLowerCase();
}

function discoverPythonFiles(projectRoot: string, _globs: string[]): string[] {
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
    if (!entry.name.endsWith(".py")) continue;
    if (seen.has(full)) continue;
    seen.add(full);
    files.push(full);
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\\$&`);
}

/** Rewrite import/from lines for renamed PyPI packages. */
export function rewritePythonImports(content: string, rules: SourcePackageRule[]): { content: string; changed: boolean } {
  if (rules.length === 0) return { content, changed: false };

  let changed = false;
  const out = content.split("\n").map(line => {
    let next = line;
    for (const rule of rules) {
      const fromMod = pythonModuleName(rule.fromPackage);
      const toMod = pythonModuleName(rule.toPackage);
      const patterns = [
        new RegExp(String.raw`^(\s*import\s+)${escapeRegex(fromMod)}(\s*(?:,|#|;|$))`),
        new RegExp(String.raw`^(\s*import\s+)${escapeRegex(fromMod)}(\.\w+)`),
        new RegExp(String.raw`^(\s*from\s+)${escapeRegex(fromMod)}(\s+import)`),
        new RegExp(String.raw`^(\s*from\s+)${escapeRegex(fromMod)}(\.\w+\s+import)`),
      ];
      for (const re of patterns) {
        if (!re.test(next)) continue;
        next = next.replace(re, (_m, p1, p2) => {
          changed = true;
          return `${p1}${toMod}${p2}`;
        });
      }
    }
    return next;
  });

  return { content: out.join("\n"), changed };
}

export function applyPythonImportMigrations(
  projectRoot: string,
  rules: SourcePackageRule[],
  _globs: string[] = ["**/*.py"],
): PythonImportApplyResult {
  const result: PythonImportApplyResult = { changed: [], skipped: [], warnings: [] };
  if (rules.length === 0) return result;

  const files = discoverPythonFiles(projectRoot, _globs);
  if (files.length === 0) {
    result.warnings.push("No Python sources found for import migration.");
    return result;
  }

  for (const filePath of files) {
    const before = fs.readFileSync(filePath, "utf-8");
    const { content: after, changed } = rewritePythonImports(before, rules);
    if (!changed) {
      result.skipped.push(filePath);
      continue;
    }
    backupFile(filePath);
    fs.writeFileSync(filePath, after, "utf-8");
    result.changed.push(filePath);
  }

  if (result.changed.length > 0) {
    result.warnings.push("Python import migration applied — verify with your test suite.");
  }
  return result;
}

export function restorePythonImportBackups(filePaths: string[]): number {
  let restored = 0;
  for (const filePath of filePaths) {
    if (restoreFile(filePath)) restored++;
  }
  return restored;
}

export function discardPythonImportBackups(filePaths: string[]): void {
  for (const filePath of filePaths) {
    discardBackup(filePath);
  }
}
