/**
 * Cargo Editor — Bump versions in Cargo.toml for Rust projects.
 *
 * Strategy:
 * 1. Read Cargo.toml
 * 2. Match deps in [dependencies] and [dev-dependencies] sections
 * 3. Replace version strings keeping semver requirements (=, ^, ~, >, <, *)
 * 4. Write updated Cargo.toml preserving comments and formatting
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

export function backupCargoToml(filePath: string): void {
  if (!fs.existsSync(filePath)) return;
  backupFile(filePath);
}

export function restoreCargoToml(filePath: string): boolean {
  return restoreFile(filePath);
}

export function discardBackup(filePath: string): void {
  removeBackups(filePath);
}

/**
 * Apply version bumps to Cargo.toml.
 * Handles both simple (`tokio = "1.0"`) and table (`tokio = { version = "1.0", features = [...] }`) formats.
 */
export function applyBumps(cargoTomlPath: string, bumps: BumpRequest[], _excludes?: { packageName: string }[]): ApplyResult {
  const bumped: string[] = [];
  const missed: string[] = [];
  const warnings: string[] = [];

  if (!fs.existsSync(cargoTomlPath)) {
    warnings.push(`Cargo.toml not found: ${cargoTomlPath}`);
    return { bumped, missed, warnings };
  }

  let content = fs.readFileSync(cargoTomlPath, "utf-8");

  for (const bump of bumps) {
    const result = tryApplyBump(content, bump.packageName, bump.targetVersion);
    if (result.changed) {
      content = result.newContent;
      bumped.push(result.label);
    } else {
      missed.push(bump.packageName);
    }
  }

  fs.writeFileSync(cargoTomlPath, content);
  return { bumped, missed, warnings };
}

/** Try to apply a single bump — returns changed state with updated content */
interface BumpResult {
  changed: boolean;
  newContent: string;
  label: string;
}

function tryApplyBump(content: string, name: string, target: string): BumpResult {
  // Pattern 1: Simple form — `name = "version"`
  const resultSimple = trySimpleForm(content, name, target);
  if (resultSimple) return resultSimple;

  // Pattern 2: Table form — `name = { version = "x.y.z", ... }`
  const resultTable = tryTableForm(content, name, target);
  if (resultTable) return resultTable;

  return { changed: false, newContent: content, label: `` };
}

function versionWithSameOp(currentVer: string, target: string): string | null {
  const opMatch = /^([=^~><]+)?(\d.*)$/.exec(currentVer);
  if (!opMatch) return null;
  const op = opMatch[1] ?? "";
  const nextOp = op === "<" || op === "<=" ? ">=" : op;
  return `${nextOp}${target}`;
}

function applyIndexedEdits(content: string, edits: Array<{ start: number; end: number; text: string }>): string {
  let next = content;
  const sorted = [...edits].sort((a, b) => b.start - a.start);
  for (const edit of sorted) {
    next = next.slice(0, edit.start) + edit.text + next.slice(edit.end);
  }
  return next;
}

/** Try simple-form replacement: `name = "version"` */
function trySimpleForm(content: string, name: string, target: string): BumpResult | null {
  const escaped = escapeRegex(name);
  const regex = new RegExp(String.raw`(^|\n)([ \t]*)${escaped}([ \t]*=[ \t]*)"([^"]+)"`, "g");
  const edits: Array<{ start: number; end: number; text: string }> = [];

  for (const match of content.matchAll(regex)) {
    const nextVer = versionWithSameOp(match[4], target);
    if (!nextVer) continue;
    const start = match.index ?? 0;
    const prefix = `${match[1]}${match[2]}${name}${match[3]}`;
    edits.push({ start, end: start + match[0].length, text: `${prefix}"${nextVer}"` });
  }

  if (edits.length === 0) return null;
  return { changed: true, newContent: applyIndexedEdits(content, edits), label: `${name}: ${target}` };
}

/** Try table-form replacement: `name = { version = "x.y.z", ... }` */
function tryTableForm(content: string, name: string, target: string): BumpResult | null {
  const escaped = escapeRegex(name);
  const regex = new RegExp(String.raw`(^|\n)([ \t]*)${escaped}([ \t]*=[ \t]*\{[^}\n]*version[ \t]*=[ \t]*)"([^"]+)"`, "g");
  const edits: Array<{ start: number; end: number; text: string }> = [];

  for (const match of content.matchAll(regex)) {
    const nextVer = versionWithSameOp(match[4], target);
    if (!nextVer) continue;
    const start = match.index ?? 0;
    const prefix = `${match[1]}${match[2]}${name}${match[3]}`;
    edits.push({ start, end: start + match[0].length, text: `${prefix}"${nextVer}"` });
  }

  if (edits.length === 0) return null;
  return { changed: true, newContent: applyIndexedEdits(content, edits), label: `${name}: ${target}` };
}

/** Rename crate keys in Cargo.toml dependency sections. */
export function applyRenames(cargoTomlPath: string, renames: RenameRequest[]): ApplyResult {
  const bumped: string[] = [];
  const missed: string[] = [];
  const warnings: string[] = [];

  if (!fs.existsSync(cargoTomlPath)) {
    warnings.push(`Cargo.toml not found: ${cargoTomlPath}`);
    return { bumped, missed, warnings };
  }

  let content = fs.readFileSync(cargoTomlPath, "utf-8");

  for (const rename of renames) {
    const from = escapeRegex(rename.fromPackage);
    const simpleRe = new RegExp(String.raw`^(\s*)${from}(\s*=\s*")([^"]*)(")`, "gm");
    const tableRe = new RegExp(String.raw`^(\s*)${from}(\s*=\s*\{[^}\n]*version\s*=\s*")([^"]*)(")`, "gm");

    if (simpleRe.test(content)) {
      simpleRe.lastIndex = 0;
      content = content.replace(simpleRe, (_m, indent, open, ver, close) => {
        const nextVer = versionWithSameOp(ver, rename.targetVersion) ?? rename.targetVersion;
        return `${indent}${rename.toPackage}${open}${nextVer}${close}`;
      });
      bumped.push(`${rename.fromPackage} -> ${rename.toPackage}`);
      continue;
    }
    if (tableRe.test(content)) {
      tableRe.lastIndex = 0;
      content = content.replace(tableRe, (_m, indent, open, ver, close) => {
        const nextVer = versionWithSameOp(ver, rename.targetVersion) ?? rename.targetVersion;
        return `${indent}${rename.toPackage}${open}${nextVer}${close}`;
      });
      bumped.push(`${rename.fromPackage} -> ${rename.toPackage}`);
      continue;
    }
    missed.push(rename.fromPackage);
  }

  fs.writeFileSync(cargoTomlPath, content);
  return { bumped, missed, warnings };
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}
