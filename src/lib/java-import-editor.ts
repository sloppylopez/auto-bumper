/**
 * Java import rewrites for known coordinate migrations (via --allow-source-migrations).
 */
import fs from "node:fs";
import path from "node:path";
import { backupFile, discardBackup, restoreFile } from "./backup.ts";
import { isInsideDir } from "../path.ts";
import type { JavaPackageRule } from "./maven-renames.ts";

const DEFAULT_JAVA_GLOBS = ["src/main/java/**/*.java", "src/test/java/**/*.java"];
const SKIP_DIR_NAMES = new Set(["build", "target", "node_modules", ".git", "out", "generated"]);

export interface JavaImportApplyResult {
  changed: string[];
  skipped: string[];
  warnings: string[];
}

function globBaseDir(glob: string): string {
  const idx = glob.indexOf("/**");
  return idx >= 0 ? glob.slice(0, idx) : path.dirname(glob);
}

function discoverJavaFiles(projectRoot: string, globs: string[]): string[] {
  const files: string[] = [];
  const seen = new Set<string>();

  const root = path.resolve(projectRoot);
  for (const glob of globs) {
    if (path.isAbsolute(glob) || glob.split(/[\\/]/).includes("..")) continue;
    const base = path.resolve(projectRoot, globBaseDir(glob));
    if (!isInsideDir(root, base) || !fs.existsSync(base)) continue;
    walkJavaDir(base, files, seen);
  }

  return files.sort((a, b) => a.localeCompare(b));
}

function walkJavaDir(dir: string, files: string[], seen: Set<string>): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".")) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIR_NAMES.has(entry.name)) continue;
      walkJavaDir(full, files, seen);
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith(".java")) continue;
    if (seen.has(full)) continue;
    seen.add(full);
    files.push(full);
  }
}

function isExcepted(pkg: string, exceptPrefixes: string[]): boolean {
  return exceptPrefixes.some(ex =>
    pkg === ex
    || pkg.startsWith(`${ex}.`)
    || ex.startsWith(`${pkg}.`),
  );
}

/** Apply ordered prefix rules to a Java package name. */
export function rewriteJavaPackage(pkg: string, rules: JavaPackageRule[]): string {
  const sorted = [...rules].sort((a, b) => b.fromPrefix.length - a.fromPrefix.length);
  let result = pkg;

  for (const rule of sorted) {
    const except = rule.exceptPrefixes || [];
    if (isExcepted(result, except)) continue;
    if (result === rule.fromPrefix || result.startsWith(`${rule.fromPrefix}.`)) {
      result = rule.toPrefix + result.slice(rule.fromPrefix.length);
    }
  }

  return result;
}

/** Rewrite import target (package, class, or static member path). */
export function rewriteJavaImportTarget(importTarget: string, rules: JavaPackageRule[]): string {
  const exceptPrefixes = rules.flatMap(r => r.exceptPrefixes || []);
  const parts = importTarget.split(".");
  for (let i = parts.length; i >= 1; i--) {
    const pkg = parts.slice(0, i).join(".");
    if (isExcepted(pkg, exceptPrefixes)) continue;

    const newPkg = rewriteJavaPackage(pkg, rules);
    if (newPkg !== pkg) {
      const suffix = parts.slice(i).join(".");
      return suffix ? `${newPkg}.${suffix}` : newPkg;
    }
  }
  return importTarget;
}

/** Rewrite import lines in Java source. */
export function rewriteJavaImports(content: string, rules: JavaPackageRule[]): { content: string; changed: boolean } {
  if (rules.length === 0) return { content, changed: false };

  let changed = false;
  const lines = content.split("\n");
  const out = lines.map(line => {
    const m = /^(\s*import\s+(?:static\s+)?)([\w.]+)(\.\*)?(\s*;.*)$/.exec(line);
    if (!m) return line;

    const nextTarget = rewriteJavaImportTarget(m[2], rules);
    if (nextTarget === m[2]) return line;

    changed = true;
    return `${m[1]}${nextTarget}${m[3] || ""}${m[4]}`;
  });

  return { content: out.join("\n"), changed };
}

/** Apply Java import migrations under projectRoot. Backs up each changed file. */
export function applyJavaImportMigrations(
  projectRoot: string,
  rules: JavaPackageRule[],
  globs: string[] = DEFAULT_JAVA_GLOBS,
): JavaImportApplyResult {
  const result: JavaImportApplyResult = { changed: [], skipped: [], warnings: [] };
  if (rules.length === 0) return result;

  const files = discoverJavaFiles(projectRoot, globs);
  if (files.length === 0) {
    result.warnings.push("No Java sources found for import migration.");
    return result;
  }

  for (const filePath of files) {
    const before = fs.readFileSync(filePath, "utf-8");
    const { content: after, changed } = rewriteJavaImports(before, rules);
    if (!changed) {
      result.skipped.push(filePath);
      continue;
    }

    backupFile(filePath);
    fs.writeFileSync(filePath, after, "utf-8");
    result.changed.push(filePath);
  }

  if (result.changed.length > 0) {
    result.warnings.push(
      "Java import migration applied — imports only; Jackson 3 API changes may still need manual fixes. Run gradlew build.",
    );
  }

  return result;
}

export function restoreJavaImportBackups(filePaths: string[]): number {
  let restored = 0;
  for (const filePath of filePaths) {
    if (restoreFile(filePath)) restored++;
  }
  return restored;
}

export function discardJavaImportBackups(filePaths: string[]): void {
  for (const filePath of filePaths) {
    discardBackup(filePath);
  }
}

export { DEFAULT_JAVA_GLOBS };
