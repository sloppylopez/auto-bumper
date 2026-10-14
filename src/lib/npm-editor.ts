/**
 * NPM Editor — Bump versions in package.json.
 *
 * Strategy:
 * 1. Read package.json
 * 2. Match deps in "dependencies" and "devDependencies"
 * 3. Replace version strings with target versions (keeping semver prefix)
 * 4. Write updated package.json
 */
import fs from "node:fs";
import path from "node:path";
import { backupFile, discardBackup as removeBackups, restoreFile } from "./backup.ts";

export interface BumpRequest {
  packageName: string;
  targetVersion: string;
  because: string[];
  /** Ecosystem of the bump; present on --latest bumps that carry no advisory finding. */
  ecosystem?: string;
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

export function backupPackageJson(filePath: string): void {
  if (!fs.existsSync(filePath)) return;
  backupFile(filePath);
}

export function restorePackageJson(filePath: string): boolean {
  return restoreFile(filePath);
}

export function discardBackup(filePath: string): void {
  removeBackups(filePath);
}

/** Find package.json in directory or parents */
export function findPackageJson(dir: string): string | null {
  let current = path.resolve(dir);
  const root = path.dirname(current);
  while (current !== root) {
    const p = path.join(current, "package.json");
    if (fs.existsSync(p)) return p;
    current = path.dirname(current);
  }
  // Check starting dir too
  const p = path.join(path.resolve(dir), "package.json");
  if (fs.existsSync(p)) return p;
  return null;
}

/**
 * Apply version bumps to package.json.
 * Keeps existing semver prefixes (^, ~, >=) and replaces the version number.
 */
export function applyBumps(packageJsonPath: string, bumps: BumpRequest[], _excludes?: { packageName: string }[]): ApplyResult {
  const bumped: string[] = [];
  const missed: string[] = [];
  const warnings: string[] = [];

  if (!fs.existsSync(packageJsonPath)) {
    warnings.push(`package.json not found: ${packageJsonPath}`);
    return { bumped, missed, warnings };
  }

  const content = fs.readFileSync(packageJsonPath, "utf-8");
  const pkg = JSON.parse(content) as PackageJsonShape;
  let dirty = false;

  for (const bump of bumps) {
    const result = processSingleBump(pkg, bump.packageName, bump.targetVersion);
    if (result.warning) warnings.push(result.warning);
    if (!result.changed || !result.change) {
      missed.push(bump.packageName);
    } else {
      bumped.push(result.change);
      dirty = true;
    }
  }

  if (dirty) fs.writeFileSync(packageJsonPath, JSON.stringify(pkg, null, 2) + "\n");

  return { bumped, missed, warnings };
}

type DepSection = "dependencies" | "devDependencies" | "optionalDependencies" | "peerDependencies";

interface PackageJsonShape {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  overrides?: Record<string, string>;
}

const DEP_SECTIONS: DepSection[] = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];

/** Process a single bump request — returns the change string or marks as missed */
function processSingleBump(
  pkg: PackageJsonShape,
  name: string,
  target: string,
): { changed: boolean; change?: string; warning?: string } {
  const section = findDependencySection(pkg, name);
  if (!section) {
    pkg.overrides = pkg.overrides || {};
    if (pkg.overrides[name] === target) return { changed: false };
    pkg.overrides[name] = target;
    return { changed: true, change: `${name}: override -> ${target}` };
  }

  const currentVer = getDependencyVersion(pkg, section, name);
  if (/^(workspace:|file:|link:|portal:|catalog:)/.test(currentVer)) {
    return { changed: false, warning: `${name}: left ${currentVer} unchanged` };
  }
  const newVer = computeNewVersion(currentVer, target);
  if (newVer === currentVer) return { changed: false };
  setDependencyVersion(pkg, section, name, newVer);

  return { changed: true, change: `${name}: ${currentVer} -> ${newVer}` };
}

/** Find which dependency section contains a package */
function findDependencySection(pkg: PackageJsonShape, name: string): DepSection | null {
  for (const section of DEP_SECTIONS) {
    if (pkg[section]?.[name]) return section;
  }
  return null;
}

/** Get current version of a dependency */
function getDependencyVersion(pkg: PackageJsonShape, section: DepSection, name: string): string {
  return pkg[section]![name];
}

/** Set version of a dependency */
function setDependencyVersion(pkg: PackageJsonShape, section: DepSection, name: string, version: string) {
  pkg[section]![name] = version;
}

/** Keep the full operator (`>=`, `^`, `~`), not just its first character. */
function semverOperator(spec: string): string {
  const m = /^(>=|<=|~=|\^|~|>|<|=)/.exec(spec);
  return m ? m[1] : "";
}

/** Parse an `npm:name@version` alias spec (null when not an alias). */
function parseNpmAlias(spec: string): { name: string; version: string } | null {
  if (!spec.startsWith("npm:")) return null;
  const rest = spec.slice(4);
  const at = rest.lastIndexOf("@");
  if (at <= 0) return null;
  return { name: rest.slice(0, at), version: rest.slice(at + 1) };
}

function computeNewVersion(currentVer: string, target: string): string {
  const alias = parseNpmAlias(currentVer);
  if (alias) return `npm:${alias.name}@${semverOperator(alias.version)}${target}`;
  return `${semverOperator(currentVer)}${target}`;
}

/** Rename dependency keys in package.json. */
export function applyRenames(packageJsonPath: string, renames: RenameRequest[]): ApplyResult {
  const bumped: string[] = [];
  const missed: string[] = [];
  const warnings: string[] = [];

  if (!fs.existsSync(packageJsonPath)) {
    warnings.push(`package.json not found: ${packageJsonPath}`);
    return { bumped, missed, warnings };
  }

  const content = fs.readFileSync(packageJsonPath, "utf-8");
  const pkg = JSON.parse(content) as PackageJsonShape;

  for (const rename of renames) {
    const result = processSingleRename(pkg, rename);
    if (result.missed) {
      missed.push(rename.fromPackage);
    } else {
      bumped.push(result.change);
    }
  }

  fs.writeFileSync(packageJsonPath, JSON.stringify(pkg, null, 2) + "\n");
  return { bumped, missed, warnings };
}

/** Process a single rename request — returns the change string or marks as missed */
function processSingleRename(
  pkg: PackageJsonShape,
  rename: RenameRequest,
): { missed: true } | { missed: false; change: string } {
  const section = findDependencySection(pkg, rename.fromPackage);
  if (!section) return { missed: true };

  const currentVer = getDependencyVersion(pkg, section, rename.fromPackage);
  const newVer = /^(workspace:|file:|link:|portal:|catalog:)/.test(currentVer)
    ? currentVer
    : computeNewVersion(currentVer, rename.targetVersion);

  delete pkg[section]![rename.fromPackage];
  pkg[section]![rename.toPackage] = newVer;

  return { missed: false, change: `${rename.fromPackage} -> ${rename.toPackage}: ${newVer}` };
}
