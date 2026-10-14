/**
 * Python Editor — Bump versions in requirements.txt and pyproject.toml.
 *
 * Supports:
 * - requirements.txt: `name==version` pinned lines
 * - pyproject.toml: `[tool.poetry.dependencies]` section
 */
import fs from "node:fs";
import { backupFile, discardBackup as removeBackups, restoreFile } from "./backup.ts";

export interface BumpRequest {
  packageName: string;
  targetVersion: string;
  because: string[];
}

export interface RenameRequest {
  fromPackage: string;
  toPackage: string;
  targetVersion: string;
  because: string[];
}

export interface ApplyResult {
  bumped: string[];
  missed: string[];
  warnings: string[];
}

// --- requirements.txt ---

export function backupRequirementsTxt(filePath: string): void {
  if (!fs.existsSync(filePath)) return;
  backupFile(filePath);
}

export function restoreRequirementsTxt(filePath: string): boolean {
  return restoreFile(filePath);
}

export function discardRequirementsBackup(filePath: string): void {
  removeBackups(filePath);
}

// --- pyproject.toml ---

export function backupPyprojectToml(filePath: string): void {
  if (!fs.existsSync(filePath)) return;
  backupFile(filePath);
}

export function restorePyprojectToml(filePath: string): boolean {
  return restoreFile(filePath);
}

export function discardPyprojectBackup(filePath: string): void {
  removeBackups(filePath);
}

/** Normalize package name for matching (PEP 50: hyphens, underscores, spaces equivalent) */
function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/[\s_-]+/g, "-");
}

const REQ_LINE = /^(\s*)(\w[\w.-]*)(\[[^\]]+\])?(\s*)(==|>=|<=|~=|!=|>|<)(\s*)([^\s#,]+)/;

/**
 * Apply version bumps to a requirements.txt file.
 * Keeps the existing operator. Skips unpinned lines.
 */
export function applyToRequirementsTxt(filePath: string, bumps: BumpRequest[], _excludes?: { packageName: string }[]): ApplyResult {
  const bumped: string[] = [];
  const missed: string[] = [];
  const warnings: string[] = [];

  if (!fs.existsSync(filePath)) {
    warnings.push(`requirements.txt not found: ${filePath}`);
    return { bumped, missed, warnings };
  }

  let content = fs.readFileSync(filePath, "utf-8");

  for (const bump of bumps) {
    const normTarget = normalizeName(bump.packageName);
    const target = bump.targetVersion;
    let replaced = false;

    let skippedExclusion = false;
    content = content.replace(new RegExp(REQ_LINE.source, "gm"), (match, ...g) => {
      const [indent, name, extras, gap, op, opGap, version] = g;
      if (normalizeName(name) !== normTarget) return match;
      if (op === "!=") {
        skippedExclusion = true;
        return match;
      }
      bumped.push(`${bump.packageName}: ${version} -> ${target}`);
      replaced = true;
      return `${indent}${name}${extras || ""}${gap}${op}${opGap}${target}`;
    });

    if (skippedExclusion) warnings.push(`${bump.packageName}: left != constraint unchanged`);
    if (!replaced) missed.push(bump.packageName);
  }

  fs.writeFileSync(filePath, content);
  return { bumped, missed, warnings };
}

function isPoetryDepSection(section: string): boolean {
  return section === "tool.poetry.dependencies"
    || section === "tool.poetry.dev-dependencies"
    || (section.startsWith("tool.poetry.group.") && section.endsWith(".dependencies"));
}

function isPep621DepSection(section: string): boolean {
  return section === "project" || section.startsWith("project.optional-dependencies");
}

/** Match a PEP 621 requirement line like `  "requests[security]==2.31.0" # pin`. */
function matchRequirementLine(line: string): { indent: string; name: string; extras?: string; gap: string; op: string; opGap: string; version: string; tail: string } | null {
  const pre = /^(\s*"?)(\w[\w.-]*)/.exec(line);
  if (!pre) return null;
  const rest1 = line.slice(pre[0].length);
  const mid = /^(\[[^\]]+\])?(\s*)(==|>=|<=|~=|!=|>|<)(\s*)/.exec(rest1);
  if (!mid) return null;
  const rest2 = rest1.slice(mid[0].length);
  const verM = /^([^"<\s,]+)/.exec(rest2);
  if (!verM) return null;
  return {
    indent: pre[1],
    name: pre[2],
    extras: mid[1],
    gap: mid[2],
    op: mid[3],
    opGap: mid[4],
    version: verM[1],
    tail: rest2.slice(verM[0].length),
  };
}

/** Rewrite one dependency line when its package is pending; returns the new line or the original. */
function bumpDependencyLine(line: string, section: string, pending: Map<string, BumpRequest>, bumped: string[]): string {
  if (isPoetryDepSection(section)) {
    const assign = /^(\s*)(\w[\w.-]*)(\s*=\s*")([^"]*)(".*)$/.exec(line);
    if (assign) {
      const bump = pending.get(normalizeName(assign[2]));
      if (!bump) return line;
      const op = /^(==|>=|<=|~=|!=|>|<|\^|~)/.exec(assign[4]);
      if (op?.[1] === "!=") return line;
      const prefix = op ? op[1] : "";
      bumped.push(`${bump.packageName}: -> ${prefix}${bump.targetVersion}`);
      pending.delete(normalizeName(assign[2]));
      return `${assign[1]}${assign[2]}${assign[3]}${prefix}${bump.targetVersion}${assign[5]}`;
    }
  }
  const req = matchRequirementLine(line);
  if (!req) return line;
  const bump = pending.get(normalizeName(req.name));
  if (!bump || req.op === "!=") return line;
  bumped.push(`${bump.packageName}: -> ${req.op}${bump.targetVersion}`);
  pending.delete(normalizeName(req.name));
  return `${req.indent}${req.name}${req.extras || ""}${req.gap}${req.op}${req.opGap}${bump.targetVersion}${req.tail}`;
}

/** Rewrite dependency lines inside poetry / PEP 621 tables only. */
function bumpPyprojectContent(content: string, bumps: BumpRequest[]): { content: string; bumped: string[]; missed: string[] } {
  const pending = new Map(bumps.map(b => [normalizeName(b.packageName), b]));
  const bumped: string[] = [];
  const lines = content.split("\n");
  let section = "";

  for (let i = 0; i < lines.length; i++) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(lines[i]);
    if (header) {
      section = header[1].trim();
      continue;
    }
    if (!isPoetryDepSection(section) && !isPep621DepSection(section)) continue;
    lines[i] = bumpDependencyLine(lines[i], section, pending, bumped);
  }

  return { content: lines.join("\n"), bumped, missed: [...pending.values()].map(b => b.packageName) };
}

/**
 * Apply version bumps to pyproject.toml dependency tables.
 * Poetry assignments and PEP 621 requirement strings. Operator is kept.
 */
export function applyToPyprojectToml(filePath: string, bumps: BumpRequest[], _excludes?: { packageName: string }[]): ApplyResult {
  const warnings: string[] = [];

  if (!fs.existsSync(filePath)) {
    warnings.push(`pyproject.toml not found: ${filePath}`);
    return { bumped: [], missed: bumps.map(b => b.packageName), warnings };
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const next = bumpPyprojectContent(content, bumps);
  if (next.bumped.length > 0) fs.writeFileSync(filePath, next.content);
  return { bumped: next.bumped, missed: next.missed, warnings };
}

export function applyRenamesToRequirementsTxt(filePath: string, renames: RenameRequest[]): ApplyResult {
  const bumped: string[] = [];
  const missed: string[] = [];
  const warnings: string[] = [];

  if (!fs.existsSync(filePath)) {
    warnings.push(`requirements.txt not found: ${filePath}`);
    return { bumped, missed, warnings };
  }

  let content = fs.readFileSync(filePath, "utf-8");

  for (const rename of renames) {
    const fromNorm = normalizeName(rename.fromPackage);
    let replaced = false;
    content = content.replace(new RegExp(REQ_LINE.source, "gm"), (match, indent, name, extras, gap, op, opGap) => {
      if (normalizeName(name) !== fromNorm || op === "!=") return match;
      bumped.push(`${rename.fromPackage} -> ${rename.toPackage}`);
      replaced = true;
      return `${indent}${rename.toPackage}${extras || ""}${gap}${op}${opGap}${rename.targetVersion}`;
    });
    if (!replaced) missed.push(rename.fromPackage);
  }

  fs.writeFileSync(filePath, content);
  return { bumped, missed, warnings };
}

/** Scan poetry / PEP 621 tables and rename a package inside requirement strings. */
function renameInDepTables(content: string, fromNorm: string, toPackage: string, targetVersion: string): { content: string; replaced: boolean } {
  const lines = content.split("\n");
  let section = "";
  let replaced = false;

  for (let i = 0; i < lines.length; i++) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(lines[i]);
    if (header) {
      section = header[1].trim();
      continue;
    }
    if (!isPep621DepSection(section) && !isPoetryDepSection(section)) continue;
    const req = matchRequirementLine(lines[i]);
    if (!req || normalizeName(req.name) !== fromNorm || req.op === "!=") continue;
    lines[i] = `${req.indent}${toPackage}${req.extras || ""}${req.gap}${req.op}${req.opGap}${targetVersion}${req.tail}`;
    replaced = true;
  }

  return { content: lines.join("\n"), replaced };
}

export function applyRenamesToPyprojectToml(filePath: string, renames: RenameRequest[]): ApplyResult {
  const bumped: string[] = [];
  const missed: string[] = [];
  const warnings: string[] = [];

  if (!fs.existsSync(filePath)) {
    warnings.push(`pyproject.toml not found: ${filePath}`);
    return { bumped, missed, warnings };
  }

  let content = fs.readFileSync(filePath, "utf-8");

  for (const rename of renames) {
    const fromNorm = normalizeName(rename.fromPackage);
    const renamed = bumpPyprojectContent(content, [{
      packageName: rename.fromPackage,
      targetVersion: rename.targetVersion,
      because: rename.because,
    }]);
    let replaced = false;
    if (renamed.bumped.length > 0) {
      const escapedFrom = rename.fromPackage.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
      content = renamed.content.replace(
        new RegExp(String.raw`^(\s*)${escapedFrom}(\s*=)`, "gm"),
        `$1${rename.toPackage}$2`,
      );
      bumped.push(`${rename.fromPackage} -> ${rename.toPackage}`);
      replaced = true;
    } else {
      const fallback = renameInDepTables(content, fromNorm, rename.toPackage, rename.targetVersion);
      if (fallback.replaced) {
        content = fallback.content;
        bumped.push(`${rename.fromPackage} -> ${rename.toPackage}`);
        replaced = true;
      }
    }
    if (!replaced) missed.push(rename.fromPackage);
  }

  fs.writeFileSync(filePath, content);
  return { bumped, missed, warnings };
}
