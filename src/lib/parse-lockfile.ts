/**
 * Lockfile parsers for Auto-Bumper.
 * Parses package-lock.json into structured PackageRef arrays.
 */
import * as childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { PackageRef } from "./types.ts";

export interface ParseResult {
  packages: PackageRef[];
  warnings: string[];
  /** Coordinates that failed to resolve (e.g. yanked versions): "group:name@requestedVersion". */
  unresolved?: string[];
}

/** OSV ecosystem identifier for each internal ecosystem key (used for DB filenames). */
export const ECOSYSTEM_OSV_NAME: Record<string, string> = {
  npm: "NPM",
  "crates.io": "CRATES.IO",
  pypi: "PyPI",
  maven: "Maven",
};

/** Normalize package name for matching. PyPI uses PEP 50 (-/_/space equivalent). */
export function normalizePackageName(name: string, ecosystem?: string): string {
  const n = name.trim().toLowerCase();
  if (ecosystem === "pypi") {
    // PEP 50: hyphens, underscores, spaces are equivalent — normalize to hyphen
    return n.replace(/[\s_]+/g, "-");
  }
  return n;
}

/**
 * Supported lockfile registry. Maps filename → { ecosystem, parser }.
 */
interface LockfileSpec {
  filename: string;
  ecosystem: string;
}

// Ecosystem names: always lowercase internally.
// ECOSYSTEM_MAP below converts to OSV database filenames.
const LOCKFILES: LockfileSpec[] = [
  { filename: "package-lock.json", ecosystem: "npm" },
  { filename: "yarn.lock", ecosystem: "npm" },
  { filename: "pnpm-lock.yaml", ecosystem: "npm" },
  { filename: "bun.lock", ecosystem: "npm" },
  { filename: "Cargo.lock", ecosystem: "crates.io" },
  { filename: "requirements.txt", ecosystem: "pypi" },
  { filename: "poetry.lock", ecosystem: "pypi" },
  { filename: "pom.xml", ecosystem: "maven" },
  { filename: "build.gradle", ecosystem: "gradle" },
  { filename: "build.gradle.kts", ecosystem: "gradle" },
];

/** Filenames we advertise in CLI / warnings. */
export const SUPPORTED_LOCKFILE_NAMES = LOCKFILES.map(s => s.filename);

function concreteVersion(spec: string): string | null {
  const trimmed = spec.trim();
  if (/^(workspace:|file:|link:|portal:|catalog:)/.test(trimmed)) return null;
  const alias = /^npm:([^@]+)@(.+)$/.exec(trimmed);
  const body = alias ? alias[1] : trimmed;
  const m = /(\d+(?:\.\d+){0,2})/.exec(body);
  return m ? m[1] : null;
}

function parsePackageJsonManifest(filePath: string): ParseResult {
  const warnings: string[] = [];
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(fs.readFileSync(filePath, "utf-8")) as Record<string, unknown>;
  } catch {
    warnings.push(`package.json is not valid JSON: ${filePath}`);
    return { packages: [], warnings };
  }
  const packages: PackageRef[] = [];
  for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const deps = data[section];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof spec !== "string") continue;
      const version = concreteVersion(spec);
      if (!version) continue;
      packages.push({ ecosystem: "npm", name, version, manifestPath: filePath });
    }
  }
  if (packages.length === 0) warnings.push(`No concrete npm versions in ${filePath}`);
  return { packages, warnings };
}

function parseCargoManifest(filePath: string): ParseResult {
  const packages: PackageRef[] = [];
  const warnings: string[] = [];
  let section = "";
  for (const line of fs.readFileSync(filePath, "utf-8").split(/\r?\n/)) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      section = header[1].trim();
      continue;
    }
    if (section !== "dependencies" && section !== "dev-dependencies" && section !== "build-dependencies") continue;
    const simple = /^\s*([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/.exec(line);
    const table = /^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"/.exec(line);
    const hit = simple || table;
    if (!hit) continue;
    const version = concreteVersion(hit[2]);
    if (!version) continue;
    packages.push({ ecosystem: "crates.io", name: hit[1], version, manifestPath: filePath });
  }
  if (packages.length === 0) warnings.push(`No concrete crate versions in ${filePath}`);
  return { packages, warnings };
}

function pyProjectSectionKind(section: string): "poetry" | "pep" | null {
  if (section === "tool.poetry.dependencies" || section === "tool.poetry.dev-dependencies") return "poetry";
  if (section.startsWith("tool.poetry.group.") && section.endsWith(".dependencies")) return "poetry";
  if (section === "project" || section.startsWith("project.optional-dependencies")) return "pep";
  return null;
}

function parsePyprojectDepLine(line: string, section: string, filePath: string): PackageRef[] {
  const kind = pyProjectSectionKind(section);
  if (!kind) return [];
  const pkgs: PackageRef[] = [];
  if (kind === "poetry") {
    const assign = /^\s*(\w[\w.-]*)\s*=\s*"([^"]*)"/.exec(line);
    if (assign && assign[1] !== "python") {
      const version = concreteVersion(assign[2]);
      if (version) pkgs.push({ ecosystem: "pypi", name: normalizePackageName(assign[1], "pypi"), version, manifestPath: filePath });
    }
  } else {
    const quoted = /["'](\w[\w.-]*)(?:\[[^\]]+\])?\s*(?:==|>=|<=|~=|!=|>|<)\s*([^"'<\s,]+)/.exec(line);
    if (quoted) {
      const version = concreteVersion(quoted[2]);
      if (version) pkgs.push({ ecosystem: "pypi", name: normalizePackageName(quoted[1], "pypi"), version, manifestPath: filePath });
    }
  }
  return pkgs;
}

function parsePyprojectManifest(filePath: string): ParseResult {
  const packages: PackageRef[] = [];
  const warnings: string[] = [];
  let section = "";
  for (const line of fs.readFileSync(filePath, "utf-8").split(/\r?\n/)) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      section = header[1].trim();
      continue;
    }
    packages.push(...parsePyprojectDepLine(line, section, filePath));
  }
  if (packages.length === 0) warnings.push(`No concrete Python versions in ${filePath}`);
  return { packages, warnings };
}

/** When a lockfile is absent, read direct versions from the manifest. */
function appendDirectManifests(resolvedDir: string, allPackages: PackageRef[], warnings: string[]): boolean {
  let found = false;
  const exists = (name: string) => fs.existsSync(path.join(resolvedDir, name));
  const push = (result: ParseResult) => {
    allPackages.push(...result.packages);
    for (const w of result.warnings) {
      if (!warnings.includes(w)) warnings.push(w);
    }
  };
  const hasNpmLock = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"].some(exists);
  if (!hasNpmLock && exists("package.json")) {
    found = true;
    push(parsePackageJsonManifest(path.join(resolvedDir, "package.json")));
  }
  if (!exists("Cargo.lock") && exists("Cargo.toml")) {
    found = true;
    push(parseCargoManifest(path.join(resolvedDir, "Cargo.toml")));
  }
  if (!exists("poetry.lock") && !exists("requirements.txt") && exists("pyproject.toml")) {
    found = true;
    push(parsePyprojectManifest(path.join(resolvedDir, "pyproject.toml")));
  }
  return found;
}

interface LockfileFlags {
  hasPoetryLock: boolean;
  hasPackageLock: boolean;
  hasYarnLock: boolean;
  hasPnpmLock: boolean;
  hasPomXml: boolean;
  hasBuildGradle: boolean;
  hasBuildGradleKts: boolean;
}

function detectLockfiles(resolvedDir: string): LockfileFlags {
  const exists = (name: string) => fs.existsSync(path.join(resolvedDir, name));
  return {
    hasPoetryLock: exists("poetry.lock"),
    hasPackageLock: exists("package-lock.json"),
    hasYarnLock: exists("yarn.lock"),
    hasPnpmLock: exists("pnpm-lock.yaml"),
    hasPomXml: exists("pom.xml"),
    hasBuildGradle: exists("build.gradle"),
    hasBuildGradleKts: exists("build.gradle.kts"),
  };
}

function shouldSkipSpec(spec: LockfileSpec, flags: LockfileFlags): boolean {
  if (spec.filename === "requirements.txt") return flags.hasPoetryLock;
  // Prefer package-lock > yarn > pnpm for npm trees
  switch (spec.filename) {
    case "yarn.lock":
      return flags.hasPackageLock;
    case "pnpm-lock.yaml":
      return flags.hasPackageLock || flags.hasYarnLock;
    case "bun.lock":
      // bun.lock is the Bun-native fallback for npm trees
      return flags.hasPackageLock || flags.hasYarnLock || flags.hasPnpmLock;
    default:
      return false;
  }
}

function parseNonGradleSpec(spec: LockfileSpec, filePath: string, warnings: string[]): ParseResult {
  switch (spec.ecosystem) {
    case "npm": {
      if (spec.filename === "yarn.lock") return parseYarnLock(filePath, warnings);
      if (spec.filename === "pnpm-lock.yaml") return parsePnpmLock(filePath, warnings);
      if (spec.filename === "bun.lock") return parseBunLock(filePath, warnings);
      return parsePackageLock(filePath, warnings);
    }
    case "crates.io":
      return parseCargoLock(filePath);
    case "pypi":
      return spec.filename === "poetry.lock" ? parsePoetryLock(filePath) : parseRequirementsTxt(filePath);
    case "maven":
      return parsePomXml(filePath);
    default:
      warnings.push(`${spec.ecosystem}: no parser for ${spec.filename}`);
      return { packages: [], warnings: [] };
  }
}

function mergeParseResult(
  result: ParseResult,
  allPackages: PackageRef[],
  warnings: string[],
  allUnresolved: string[] | null,
): void {
  allPackages.push(...result.packages);
  for (const w of result.warnings) {
    if (!warnings.includes(w)) warnings.push(w);
  }
  if (allUnresolved) {
    for (const u of result.unresolved ?? []) {
      if (!allUnresolved.includes(u)) allUnresolved.push(u);
    }
  }
}

/**
 * Detect and parse all supported lockfiles in the given directory.
 * Supports npm (package-lock / yarn / pnpm), Rust, Python, Maven, Gradle.
 */
const NESTED_SKIP_DIRS = new Set([
  "node_modules", "target", "build", "dist", "out", "vendor",
  ".git", ".gradle", ".idea", ".auto-bumper",
]);

/** Java manifests below the scan root. The root pom and build files are parsed by the caller. */
export function listNestedJavaManifests(root: string): Array<{ kind: "maven" | "gradle"; filePath: string }> {
  const rootResolved = path.resolve(root);
  const found: Array<{ kind: "maven" | "gradle"; filePath: string }> = [];
  walk(rootResolved);
  return found;

  function walk(dir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    if (dir !== rootResolved) {
      const names = new Set(entries.filter(entry => entry.isFile()).map(entry => entry.name));
      if (names.has("pom.xml")) found.push({ kind: "maven", filePath: path.join(dir, "pom.xml") });
      if (names.has("build.gradle")) found.push({ kind: "gradle", filePath: path.join(dir, "build.gradle") });
      else if (names.has("build.gradle.kts")) found.push({ kind: "gradle", filePath: path.join(dir, "build.gradle.kts") });
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || NESTED_SKIP_DIRS.has(entry.name)) continue;
      walk(path.join(dir, entry.name));
    }
  }
}

function appendNestedJavaManifests(
  root: string,
  allPackages: PackageRef[],
  warnings: string[],
  allUnresolved: string[] | null,
): boolean {
  let found = false;
  for (const manifest of listNestedJavaManifests(root)) {
    const result = manifest.kind === "maven"
      ? parsePomXmlDirect(manifest.filePath)
      : parseBuildGradleDirect(manifest.filePath);
    if (result.packages.length === 0 && result.warnings.length === 0) continue;
    found = true;
    mergeParseResult(result, allPackages, warnings, allUnresolved);
  }
  return found;
}

export function parseLockfile(dirPath: string): ParseResult {
  const allPackages: PackageRef[] = [];
  const warnings: string[] = [];
  const resolvedDir = path.resolve(dirPath);

  let foundAny = false;

  const flags = detectLockfiles(resolvedDir);
  if (flags.hasPomXml && (flags.hasBuildGradle || flags.hasBuildGradleKts)) {
    warnings.push(
      "Both pom.xml and Gradle build file present — scanning both (dual Java layouts).",
    );
  }

  for (const spec of LOCKFILES) {
    const filePath = path.join(resolvedDir, spec.filename);
    if (!fs.existsSync(filePath)) continue;
    if (shouldSkipSpec(spec, flags)) continue;

    foundAny = true;
    const result = spec.ecosystem === "gradle" ? parseBuildGradle(filePath) : parseNonGradleSpec(spec, filePath, warnings);
    mergeParseResult(result, allPackages, warnings, null);
  }

  if (appendDirectManifests(resolvedDir, allPackages, warnings)) foundAny = true;
  if (appendNestedJavaManifests(resolvedDir, allPackages, warnings, null)) foundAny = true;

  if (!foundAny) {
    warnings.push(
      `No supported lockfile found in ${resolvedDir}. Supported: ${SUPPORTED_LOCKFILE_NAMES.join(", ")}`,
    );
  }

  return { packages: allPackages, warnings };
}

interface PackageLockData {
  packages?: Record<string, unknown>;
  dependencies?: Record<string, unknown>;
}

function readLockfileVersion(entry: unknown): string | undefined {
  if (typeof entry === "object" && entry !== null && "version" in entry) {
    const version = entry.version;
    return typeof version === "string" ? version : undefined;
  }
  return undefined;
}

function collectV2Packages(packagesMap: Record<string, unknown>, packages: PackageRef[], lockfilePath: string): void {
  for (const [key, value] of Object.entries(packagesMap)) {
    // Skip root entry (empty key means it's the project itself)
    if (!key) continue;

    // Extract package name from node_modules path
    const name = extractPackageName(key);
    const version = readLockfileVersion(value);
    if (version && name) {
      packages.push({
        ecosystem: "npm",
        name,
        version,
        manifestPath: lockfilePath,
      });
    }
  }
}

function collectV1Packages(dependencies: Record<string, unknown>, packages: PackageRef[], lockfilePath: string): void {
  for (const [name, info] of Object.entries(dependencies)) {
    const version = typeof info === "string" ? info : readLockfileVersion(info);
    if (version) {
      // Strip semver prefixes that might appear in v1
      packages.push({
        ecosystem: "npm",
        name,
        version: version.replace(/^[~^]/, ""),
        manifestPath: lockfilePath,
      });
    }
  }
}

/**
 * Parse npm package-lock.json (v2/v3 format with `packages` key).
 * Falls back to v1 format (`dependencies` key) if needed.
 */
export function parsePackageLock(lockfilePath: string, warnings?: string[]): ParseResult {
  const w = warnings || [];

  if (!fs.existsSync(lockfilePath)) {
    w.push(`Lockfile not found: ${lockfilePath}`);
    return { packages: [], warnings: w };
  }

  const content = fs.readFileSync(lockfilePath, "utf-8");
  const parsed: unknown = JSON.parse(content);
  // Top-level shape is guarded; lockfile fields are optional, values read defensively.
  const data = (typeof parsed === "object" && parsed !== null ? parsed : {}) as PackageLockData;
  const packages: PackageRef[] = [];

  if (data.packages) {
    // v2/v3 format — iterate packages object
    collectV2Packages(data.packages ?? {}, packages, lockfilePath);
  } else if (data.dependencies) {
    // v1 format fallback — iterate dependencies object
    collectV1Packages(data.dependencies ?? {}, packages, lockfilePath);
    w.push("Using legacy v1 lockfile format (limited accuracy)");
  } else {
    w.push(`Lockfile ${lockfilePath} has unexpected structure`);
  }

  return { packages, warnings: w };
}

/**
 * Extract package name from a node_modules path key.
 * Handles scoped packages (@scope/pkg) and nested dependencies.
 */
function extractPackageName(key: string): string {
  // Split on node_modules/ and take the last segment
  const parts = key.split("node_modules/");
  return parts.at(-1) ?? "";
}

/**
 * Parse classic Yarn v1 / Berry yarn.lock into PackageRef[].
 * Prefers the resolved `version` field per descriptor block.
 */
export function parseYarnLock(lockfilePath: string, warnings?: string[]): ParseResult {
  const w = warnings || [];
  if (!fs.existsSync(lockfilePath)) {
    w.push(`yarn.lock not found: ${lockfilePath}`);
    return { packages: [], warnings: w };
  }

  const content = fs.readFileSync(lockfilePath, "utf-8");
  const packages: PackageRef[] = [];
  const seen = new Set<string>();

  // Block: descriptor line(s) then indented fields including version
  const blockRe = /(?:^|\n)("[^"\n]+"|[^:\s][^:\n]*):\n((?:[ \t]+.+\n?)*)/g;

  for (const m of content.matchAll(blockRe)) {
    const descriptor = m[1];
    const body = m[2] || "";
    if (descriptor.includes("__metadata")) continue;

    const verMatch = /^[ \t]+version:?[ \t]+"?([^"\n]+)"?/m.exec(body);
    if (!verMatch) continue;
    const version = verMatch[1].trim();

    const name = yarnDescriptorName(descriptor);
    if (!name || !version) continue;

    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    packages.push({
      ecosystem: "npm",
      name,
      version,
      manifestPath: lockfilePath,
    });
  }

  if (packages.length === 0) {
    w.push(`No packages parsed from yarn.lock (${lockfilePath})`);
  }
  return { packages, warnings: w };
}

/** Strip all leading and trailing double quotes from a string (linear scan). */
function stripQuotes(s: string): string {
  let start = 0;
  let end = s.length;
  while (start < end && s[start] === '"') start++;
  while (end > start && s[end - 1] === '"') end--;
  return s.slice(start, end);
}

/** First package name from a yarn descriptor like `lodash@^4.17.0` or `"@scope/pkg@npm:^1.0.0"`. */
function yarnDescriptorName(descriptor: string): string | null {
  const cleaned = stripQuotes(descriptor).split(",")[0]!.trim();
  // @scope/name@range  OR  name@range  OR  name@npm:range
  const scoped = /^(@[^/]+\/[^@]+)@/.exec(cleaned);
  if (scoped) return scoped[1];
  const plain = /^([^@\s]+)@/.exec(cleaned);
  return plain ? plain[1] : null;
}

/**
 * Parse pnpm-lock.yaml `packages:` keys into PackageRef[].
 * Supports `/name@version`, `/@scope/name@version`, and `name@version` forms.
 */
export function parsePnpmLock(lockfilePath: string, warnings?: string[]): ParseResult {
  const w = warnings || [];
  if (!fs.existsSync(lockfilePath)) {
    w.push(`pnpm-lock.yaml not found: ${lockfilePath}`);
    return { packages: [], warnings: w };
  }

  const content = fs.readFileSync(lockfilePath, "utf-8");
  const packages: PackageRef[] = [];
  const seen = new Set<string>();

  // Only parse under the top-level packages: section
  const packagesIdx = content.search(/^packages:\s*$/m);
  const section = packagesIdx >= 0 ? content.slice(packagesIdx) : content;

  const keyRe = /^ {2}['"/]?(@?[\w.-]+(?:\/[\w.-]+)?)[@/]([^'(\s:]+)['"]?:/gm;
  for (const m of section.matchAll(keyRe)) {
    const name = m[1];
    let version = m[2];
    // Strip peer suffix like "4.17.21(react@18)" → 4.17.21
    const parenIdx = version.indexOf("(");
    if (parenIdx >= 0) version = version.slice(0, parenIdx);
    const underscoreIdx = version.indexOf("_");
    if (underscoreIdx >= 0) version = version.slice(0, underscoreIdx);
    if (!name || !version || version === "link" || version === "file") continue;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    packages.push({
      ecosystem: "npm",
      name,
      version,
      manifestPath: lockfilePath,
    });
  }

  if (packages.length === 0) {
    w.push(`No packages parsed from pnpm-lock.yaml (${lockfilePath})`);
  }
  return { packages, warnings: w };
}

function bunLockEntryToPackage(entry: unknown, lockfilePath: string): PackageRef | null {
  // Entry shape: [resolvedId, source, metadata, hash]
  if (!Array.isArray(entry)) return null;
  const resolvedId = entry[0];
  if (typeof resolvedId !== "string") return null;

  const at = resolvedId.lastIndexOf("@");
  if (at <= 0) return null; // no name@version boundary
  const name = resolvedId.slice(0, at);
  const version = resolvedId.slice(at + 1);
  // Skip non-registry resolutions (git deps, workspace/file links)
  if (!name || !version || /^(git\+|link:|file:|http)/.test(version)) return null;
  return { ecosystem: "npm", name, version, manifestPath: lockfilePath };
}

/**
 * Parse Bun's text lockfile (bun.lock, lockfileVersion 1).
 * `packages` map entries are [name@version, source, metadata, hash];
 * emits one PackageRef per distinct resolved name+version.
 * bun.lock is JSON with trailing commas — stripped before strict parse.
 */
export function parseBunLock(lockfilePath: string, warnings?: string[]): ParseResult {
  const w = warnings || [];
  if (!fs.existsSync(lockfilePath)) {
    w.push(`bun.lock not found: ${lockfilePath}`);
    return { packages: [], warnings: w };
  }

  let data: { packages?: Record<string, unknown> };
  try {
    const content = fs.readFileSync(lockfilePath, "utf-8");
    // Bun emits JSON5-ish output (trailing commas) — strip before strict parse.
    data = JSON.parse(content.replace(/,\s*([}\]])/g, "$1"));
  } catch (e) {
    w.push(`Failed to parse bun.lock (${lockfilePath}): ${e instanceof Error ? e.message : String(e)}`);
    return { packages: [], warnings: w };
  }

  const packages: PackageRef[] = [];
  const seen = new Set<string>();
  const pkgs = data.packages;

  if (pkgs && typeof pkgs === "object") {
    for (const entry of Object.values(pkgs)) {
      const pkg = bunLockEntryToPackage(entry, lockfilePath);
      if (!pkg) continue;
      const key = `${pkg.name}@${pkg.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      packages.push(pkg);
    }
  }

  if (packages.length === 0) {
    w.push(`No packages parsed from bun.lock (${lockfilePath})`);
  }
  return { packages, warnings: w };
}

/**
 * Parse Rust Cargo.lock into structured PackageRef array.
 *
 * Cargo.lock is a simple TOML-like format where each dependency
 * appears as a [[package]] block with 'name' and 'version' fields.
 *
 * Example:
 *   [[package]]
 *   name = "tauri"
 *   version = "2.0.0"
 *   source = "registry+https://github.com/rust-lang/crates.io-index"
 */
export function parseCargoLock(lockfilePath: string): ParseResult {
  const warnings: string[] = [];

  if (!fs.existsSync(lockfilePath)) {
    warnings.push(`Cargo.lock not found: ${lockfilePath}`);
    return { packages: [], warnings };
  }

  const content = fs.readFileSync(lockfilePath, "utf-8");
  const packages: PackageRef[] = [];

  // Split by [[package]] headers
  const sections = content.split(/\[\[package\]\]/);

  for (const section of sections) {
    if (!section.trim()) continue;

    // Extract name and version from this section
    const nameMatch = /name\s*=\s*"([^"]+)"/.exec(section);
    const versionMatch = /version\s*=\s*"([^"]+)"/.exec(section);

    if (nameMatch && versionMatch) {
      packages.push({
        ecosystem: "crates.io",
        name: nameMatch[1],
        version: versionMatch[1],
        manifestPath: lockfilePath,
      });
    }
  }

  return { packages, warnings };
}

/**
 * Parse Python requirements.txt file.
 *
 * Format: one dependency per line, e.g.:
 *   requests==2.31.0
 *   flask>=2.0
 *   numpy
 *
 * Exact pins (==, ===) and floors (>=, >, ~=) are recorded. The floor
 * token is the version we can raise. Ceilings (<, <=) and exclusions
 * (!=) are not an installed version and are skipped.
 */
export function parseRequirementsTxt(filePath: string): ParseResult {
  const warnings: string[] = [];

  if (!fs.existsSync(filePath)) {
    warnings.push(`requirements.txt not found: ${filePath}`);
    return { packages: [], warnings };
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content.split(/\r?\n/);
  const packages: PackageRef[] = [];

  for (const rawLine of lines) {
    let line = rawLine.trim();

    // Skip empty lines, comments, and option flags
    if (!line || line.startsWith("#") || line.startsWith("-") ) continue;

    // Handle inline comments
    const commentIdx = line.indexOf("#");
    if (commentIdx > 0) line = line.slice(0, commentIdx).trim();

    const spec = /^(\w[\w.-]*)(?:\[[^\]]+\])?\s*(===|==|>=|<=|~=|!=|>|<)\s*([^,\s#]+)/.exec(line);
    if (!spec) continue;
    const op = spec[2];
    if (op === "!=" || op === "<" || op === "<=") continue;
    const version = spec[3].replace(/[*,]/g, "");
    if (!/^\d/.test(version)) continue;
    packages.push({
      ecosystem: "pypi",
      name: normalizePackageName(spec[1], "pypi"),
      version,
      manifestPath: filePath,
    });
  }

  return { packages, warnings };
}

/**
 * Parse Python poetry.lock file.
 *
 * Uses the same [[package]] TOML format as Cargo.lock:
 *
 *   [[package]]
 *   name = "requests"
 *   version = "2.31.0"
 */
export function parsePoetryLock(filePath: string): ParseResult {
  const warnings: string[] = [];

  if (!fs.existsSync(filePath)) {
    warnings.push(`poetry.lock not found: ${filePath}`);
    return { packages: [], warnings };
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const packages: PackageRef[] = [];

  // Split by [[package]] headers
  const sections = content.split(/\[\[package\]\]/);

  for (const section of sections) {
    if (!section.trim()) continue;

    const nameMatch = /name\s*=\s*"([^"]+)"/.exec(section);
    const versionMatch = /version\s*=\s*"([^"]+)"/.exec(section);

    if (nameMatch && versionMatch) {
      packages.push({
        ecosystem: "pypi",
        name: normalizePackageName(nameMatch[1], "pypi"),
        version: versionMatch[1],
        manifestPath: filePath,
      });
    }
  }

  return { packages, warnings };
}

/**
 * Parse pom.xml for Maven coordinates.
 *
 * Strategy:
 * 1. Try `mvn dependency:tree` for full resolved tree (direct + transitive)
 * 2. Fallback: parse pom.xml directly for explicit deps only
 *
 * Direct-parser edge cases:
 * - Multiple <dependencies> sections
 * dependencyManagement BOM entries are skipped (their versions are resolved against the pom's own <properties>; unresolvable ones are skipped).
 * - Dependencies without explicit version — skipped (parent POM inheritance)
 */
export function parsePomXml(filePath: string): ParseResult {
  const warnings: string[] = [];

  if (!fs.existsSync(filePath)) {
    warnings.push(`pom.xml not found: ${filePath}`);
    return { packages: [], warnings };
  }

  const dir = path.dirname(filePath);
  const mvn = detectMaven(dir);
  if (mvn) {
    const result = resolveViaMaven(mvn, filePath, dir);
    if (result.packages.length > 0) {
      return result;
    }
    if (result.warnings.length > 0) {
      warnings.push(...result.warnings);
    }
  }

  return parsePomXmlDirect(filePath, warnings);
}

/**
 * `<name>value</name>` pairs from a pom's `<properties>` block, in document order.
 * Linear scan; a value may not contain `<` (same shape constraint as the legacy
 * backtracking regex), and malformed pairs resume scanning right after their open tag.
 */
function parsePomProperties(content: string): Record<string, string> {
  const properties: Record<string, string> = {};
  const openIdx = content.indexOf("<properties>");
  if (openIdx < 0) return properties;
  const closeIdx = content.indexOf("</properties>", openIdx + "<properties>".length);
  if (closeIdx < 0) return properties;
  let rest = content.slice(openIdx + "<properties>".length, closeIdx);
  for (;;) {
    const open = /<([\w.-]+)>/.exec(rest);
    if (!open) break;
    const name = open[1];
    const after = rest.slice(open.index + open[0].length);
    const closeIdx = after.indexOf(`</${name}>`);
    if (closeIdx < 0) {
      rest = after;
      continue;
    }
    const value = after.slice(0, closeIdx).trim();
    if (value.includes("<")) {
      rest = after;
      continue;
    }
    properties[name] = value;
    rest = after.slice(closeIdx + name.length + 3);
  }
  return properties;
}
/** Direct pom.xml parser (fallback when mvn unavailable). */
export function parsePomXmlDirect(filePath: string, warnings: string[] = []): { packages: PackageRef[]; warnings: string[] } {
  const content = fs.readFileSync(filePath, "utf-8");
  const packages: PackageRef[] = [];
  const properties = parsePomProperties(content);

  // Find all <dependency>...</dependency> blocks across the entire file
  // This handles multiple <dependencies> sections automatically
  const depBlocks = content.match(/<dependency>[\s\S]*?<\/dependency>/g);
  if (!depBlocks) {
    warnings.push(`No <dependency> entries found in ${filePath}`);
    return { packages, warnings };
  }

  for (const block of depBlocks) {
    const groupMatch = /<groupId>([^<]+)<\/groupId>/.exec(block);
    const artifactMatch = /<artifactId>([^<]+)<\/artifactId>/.exec(block);
    const versionMatch = /<version>([^<]+)<\/version>/.exec(block);

    if (!groupMatch || !artifactMatch) {
      warnings.push(`Malformed dependency block in ${filePath}: missing groupId or artifactId`);
      continue;
    }

    const rawVersion = versionMatch ? versionMatch[1].trim() : null;
    if (!rawVersion) {
      // Skip dependencies without explicit version (parent POM inheritance)
      warnings.push(
        `Skipping ${groupMatch[1]}:${artifactMatch[1]} — no explicit version (parent POM?)`,
      );
      continue;
    }
    // ${property} refs: resolve against the pom's own <properties>; skip when unresolvable.
    let version = rawVersion;
    if (version.includes("${")) {
      const resolved = version.replace(/\$\{([\w.-]+)\}/g, (_full, name: string) => properties[name] ?? _full);
      if (resolved.includes("${")) {
        warnings.push(`Skipping ${groupMatch[1]}:${artifactMatch[1]} — version uses property ref: ${rawVersion}`);
        continue;
      }
      version = resolved;
    }

    const name = `${groupMatch[1].trim()}:${artifactMatch[1].trim()}`;
    packages.push({
      ecosystem: "maven",
      name,
      version,
      manifestPath: filePath,
    });
  }

  return { packages, warnings };
}

/** Stop at the git root. With no git repo, stay in the start directory. */
function searchCeiling(dir: string): string {
  let current = path.resolve(dir);
  const start = current;
  while (true) {
    if (fs.existsSync(path.join(current, ".git"))) return current;
    const parent = path.dirname(current);
    if (parent === current) return start;
    current = parent;
  }
}

function findUp(dir: string, fileName: string): string | null {
  const stop = searchCeiling(dir);
  let current = path.resolve(dir);
  while (true) {
    const candidate = path.join(current, fileName);
    if (fs.existsSync(candidate)) return candidate;
    if (current === stop) return null;
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

/**
 * cmd.exe /d /s /c line. The outer quotes are stripped by /s, leaving the path quoted
 * so a folder name like `ok & calc` cannot start a second command.
 */
export function windowsBatchArgs(executable: string, args: string[]): string[] {
  const quote = (value: string) => `"${value.replaceAll('"', '""')}"`;
  const command = `"${[quote(executable), ...args.map(quote)].join(" ")}"`;
  return ["/d", "/s", "/c", command];
}

/**
 * Run a command without `shell: true`.
 * Windows batch files go through `cmd.exe /d /s /c` with the path quoted.
 */
function spawnCaptured(
  executable: string,
  args: string[],
  opts: { cwd: string; timeout: number },
): childProcess.SpawnSyncReturns<string> {
  const base = {
    encoding: "utf-8" as const,
    timeout: opts.timeout,
    cwd: opts.cwd,
    maxBuffer: 10 * 1024 * 1024,
    windowsHide: true,
    shell: false as const,
  };
  if (process.platform === "win32" && /\.(cmd|bat)$/i.test(executable)) {
    const comspec = process.env.ComSpec || "cmd.exe";
    return childProcess.spawnSync(comspec, windowsBatchArgs(executable, args), {
      ...base,
      windowsVerbatimArguments: true,
    });
  }
  return childProcess.spawnSync(executable, args, base);
}

/** Find mvnw or system mvn. Wrapper search stops at the git root. */
function detectMaven(dir: string): { executable: string; isWrapper: boolean } | null {
  const isWin = process.platform === "win32";
  const wrapperName = isWin ? "mvnw.cmd" : "mvnw";
  const wrapper = findUp(dir, wrapperName);
  if (wrapper) return { executable: wrapper, isWrapper: true };

  const systemMvn = isWin ? "mvn.cmd" : "mvn";
  const probe = spawnCaptured(systemMvn, ["--version"], { cwd: dir, timeout: 15_000 });
  if (probe.status === 0) return { executable: systemMvn, isWrapper: false };
  return null;
}

const MVN_TREE_SCOPES: Array<string | undefined> = [undefined, "test"];

function runMavenTree(
  mvn: { executable: string; isWrapper: boolean },
  cwd: string,
  scope?: string,
): { output: string; warning?: string; failed?: boolean } | null {
  const isWin = process.platform === "win32";
  // No -q: dependency:tree prints at INFO level; quiet mode suppresses the whole tree.
  const args = ["dependency:tree", "-DoutputType=text"];
  if (scope) args.push(`-Dscope=${scope}`);
  const label = scope ?? "compile";

  if (isWin) {
    const result = spawnCaptured(mvn.executable, args, { cwd, timeout: 180_000 });
    const failed = result.status !== null && result.status !== 0;
    if (failed && !(result.stdout || result.stderr)) {
      return { output: "", warning: `${label}: mvn exited with code ${result.status}`, failed: true };
    }
    return { output: ((result.stdout || "") + (result.stderr || "")).trim(), failed };
  }

  if (mvn.isWrapper) {
    try { fs.chmodSync(mvn.executable, 0o750); } catch {}
  }
  const result = childProcess.spawnSync(mvn.executable, args, {
    encoding: "utf-8",
    timeout: 180_000,
    cwd,
    maxBuffer: 10 * 1024 * 1024,
    shell: false,
  });
  const failed = result.status !== null && result.status !== 0;
  if (failed && !(result.stdout || result.stderr)) {
    return { output: "", warning: `${label}: mvn exited with code ${result.status}`, failed: true };
  }
  return { output: ((result.stdout || "") + (result.stderr || "")).trim(), failed };
}

/** Keep every resolved name@version. A newer test jar must not hide an older runtime jar. */
export function dedupeResolvedPackages(packages: PackageRef[]): PackageRef[] {
  const unique = new Map<string, PackageRef>();
  for (const pkg of packages) {
    const key = `${pkg.name.toLowerCase()}@${pkg.version}`;
    if (!unique.has(key)) unique.set(key, pkg);
  }
  return [...unique.values()];
}

function resolveViaMaven(
  mvn: { executable: string; isWrapper: boolean },
  filePath: string,
  cwd: string,
): ParseResult {
  const allPackages: PackageRef[] = [];
  const warnings: string[] = [];
  const unresolved: string[] = [];

  for (const scope of MVN_TREE_SCOPES) {
    let result;
    try {
      result = runMavenTree(mvn, cwd, scope);
    } catch (err) {
      warnings.push(`${scope ?? "compile"}: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    processMavenScopeResult(result, scope, filePath, allPackages, warnings, unresolved);
  }

  const unique = dedupeResolvedPackages(allPackages);
  const result: ParseResult = { packages: unique.length > 0 ? unique : [], warnings };
  if (unresolved.length > 0) result.unresolved = [...new Set(unresolved)];
  return result;
}

/** Fold one scope's tree output into the accumulating results. */
function processMavenScopeResult(
  result: { output: string; warning?: string; failed?: boolean } | null,
  scope: string | undefined,
  filePath: string,
  allPackages: PackageRef[],
  warnings: string[],
  unresolved: string[],
): void {
  if (!result) {
    warnings.push(`${scope ?? "compile"}: unexpected error`);
    return;
  }
  if (result.warning) warnings.push(result.warning);
  if (!result.output) {
    warnings.push(`${scope ?? "compile"}: empty output`);
    return;
  }
  if (result.failed) unresolved.push(...extractMavenUnresolved(result.output));
  const parsed = parseMavenTree(result.output, filePath);
  allPackages.push(...parsed.packages);
  if (parsed.warnings?.length) warnings.push(...parsed.warnings);
}

/**
 * Extract "group:name@version" coordinates that Maven reported as unresolvable
 * ("The following artifacts could not be resolved: ..." lists and per-artifact
 * "... was not found in ..." lines). Empty when the output carries no such errors.
 */

/** Maven's per-artifact failure marker ("<token> was not found in <repo>"). */
const MAVEN_NOT_FOUND_MARKER = " was not found in ";
/** JS \s whitespace set for linear char scans. */
const LINE_WHITESPACE = " \t\v\f\r\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff";
/** JS line terminators — the m-flag ^ anchors after any of these. */
const LINE_BREAKS = "\n\r\u2028\u2029";

export function extractMavenUnresolved(output: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (coord: string, version: string) => {
    const key = `${coord.toLowerCase()}@${version.toLowerCase()}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(`${coord}@${version}`);
    }
  };
  const parseCoord = (token: string): [string, string] | null => {
    let cleaned = token.trim();
    while (cleaned.endsWith(":")) cleaned = cleaned.slice(0, -1);
    const parts = cleaned.split(":");
    if (parts.length === 4 && /^(jar|pom|war|ear)$/.test(parts[2]!)) return [`${parts[0]}:${parts[1]}`, parts[3]!];
    if (parts.length === 3) return [`${parts[0]}:${parts[1]}`, parts[2]!];
    return null;
  };

  for (const m of output.matchAll(/could not be resolved:\s*([^\n]+)/g)) {
    for (const token of m[1]!.split(",")) {
      const parsed = parseCoord(token);
      if (!parsed) break;
      add(parsed[0], parsed[1]);
    }
  }
  // Per-artifact failures: the token is a line segment's first non-whitespace run,
  // immediately followed by the marker. Scanned with char-class runs (no regex)
  // so matching stays linear regardless of input shape.
  let segStart = 0;
  for (let i = 0; i <= output.length; i++) {
    const ch = output[i];
    if (i === output.length || LINE_BREAKS.includes(ch!)) {
      addNotFoundSegment(output.slice(segStart, i), parseCoord, add);
      segStart = i + 1;
    }
  }
  return out;
}

/** Handle one line segment of "<token> was not found in <repo>"; no-op when the shape does not match. */
function addNotFoundSegment(
  segment: string,
  parseCoord: (token: string) => [string, string] | null,
  add: (coord: string, version: string) => void,
): void {
  let t = 0;
  while (t < segment.length && LINE_WHITESPACE.includes(segment[t]!)) t++;
  let u = t;
  while (u < segment.length && !LINE_WHITESPACE.includes(segment[u]!)) u++;
  if (!segment.startsWith(MAVEN_NOT_FOUND_MARKER, u)) return;
  const token = segment.slice(t, u);
  if (!matchesCoordShape(token)) return;
  const parsed = parseCoord(token);
  if (parsed) add(parsed[0], parsed[1]);
}

/**
 * Whether a token can satisfy the \S+:\S+(?::(?:jar|pom))?:\S+ shape: two colons with at least
 * one char before the first, between them, and after the second (the classifier branch is
 * subsumed by this condition).
 */
function matchesCoordShape(token: string): boolean {
  let firstColon = -1;
  for (let i = 0; i < token.length; i++) {
    if (token[i] !== ":") continue;
    if (firstColon === -1) {
      if (i >= 1) firstColon = i;
    } else if (i - firstColon >= 2 && i <= token.length - 2) {
      return true;
    }
  }
  return false;
}

/** Parse Maven dependency:tree output into PackageRef[]. */
function parseMavenTree(output: string, filePath: string): ParseResult {
  const pkgs: PackageRef[] = [];
  const seen = new Set<string>();

  for (const rawLine of output.split("\n")) {
    const line = rawLine.replace(/^\[INFO\]\s*/, "").trim();
    if (!line || /omitted for duplicate|omitted for conflict/i.test(line)) continue;

    const trimmed = line.replace(/^[|\s+\\-]+/, "");
    const match = /^([\w.-]+):([\w.-]+):[^:]+:([^:\s(]+)/.exec(trimmed);
    if (!match) continue;

    const [, group, artifact, version] = match;
    if (!version || version.startsWith("(")) continue;

    const key = `${group.toLowerCase()}:${artifact.toLowerCase()}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    pkgs.push({
      ecosystem: "maven",
      name: `${group}:${artifact}`,
      version,
      manifestPath: filePath,
    });
  }

  return pkgs.length > 0 ? { packages: pkgs, warnings: [] } : { packages: [], warnings: [] };
}

/**
 * Parse build.gradle (Groovy DSL) for Maven coordinates.
 *
 * Strategy:
 * 1. Try `gradlew dependencies` to get FULL resolved tree (direct + transitive)
 * 2. Fallback: parse build.gradle directly for explicit deps only
 *
 * Handles version variables, BOM imports, constraints, and transitive resolution.
 */
export function parseBuildGradle(filePath: string): ParseResult {
  const warnings: string[] = [];

  if (!fs.existsSync(filePath)) {
    warnings.push(`build.gradle not found: ${filePath}`);
    return { packages: [], warnings };
  }

  // Try gradlew first for full transitive dep tree
  const dir = path.dirname(filePath);
  const gradlew = detectGradlew(dir);
  let gradleUnresolved: string[] | undefined;
  if (gradlew) {
    const result = resolveViaGradlew(gradlew, filePath, dir);
    gradleUnresolved = result.unresolved;
    if (result.packages.length > 0) {
      return result;
    }
    if (result.warnings.length > 0) {
      warnings.push(...result.warnings);
    }
  }

  // Fallback: parse build.gradle directly (only explicit deps)
  const direct = parseBuildGradleDirect(filePath);
  if (gradleUnresolved && gradleUnresolved.length > 0) direct.unresolved = gradleUnresolved;
  return direct;
}

/** Find gradlew. Search stops at the git root so a parent outside the repo is not executed. */
function detectGradlew(dir: string): string | null {
  const name = process.platform === "win32" ? "gradlew.bat" : "gradlew";
  return findUp(dir, name);
}

// Gradle configurations to scan — runtime deps + test deps
export const GRADLE_ALL_CONFIGURATIONS = ['runtimeClasspath', 'testRuntimeClasspath'] as const;
export const GRADLE_RUNTIME_CONFIGURATIONS = ['runtimeClasspath'] as const;

const GRADLE_CONFIGURATIONS = GRADLE_ALL_CONFIGURATIONS;

export interface ParseLockfileOptions {
  /** Gradle configurations for `gradlew dependencies`. Default: runtime + test. */
  gradleConfigurations?: readonly string[];
}

/** Run a single gradlew command and return raw output or null on failure */
function runGradlewConfig(gradlew: string, config: string, cwd: string, _isWin: boolean): { output: string; warning?: string } | null {
  const args = ['dependencies', '--configuration', config, '--quiet'];
  const result = spawnCaptured(gradlew, args, { cwd, timeout: 180_000 });
  if (result.error) {
    return { output: '', warning: `${config}: ${result.error.message}` };
  }
  if (result.status !== null && result.status !== 0 && !(result.stdout || result.stderr)) {
    return { output: '', warning: `${config}: gradlew exited with code ${result.status}` };
  }
  return { output: ((result.stdout || '') + (result.stderr || '')).trim() };
}

function runGradlewConfigAsync(
  gradlew: string,
  config: string,
  cwd: string,
  isWin: boolean,
): Promise<{ output: string; warning?: string } | null> {
  const args = ["dependencies", "--configuration", config, "--quiet"];

  return new Promise(resolve => {
    const child = isWin && /\.(cmd|bat)$/i.test(gradlew)
      ? childProcess.spawn(process.env.ComSpec || "cmd.exe", windowsBatchArgs(gradlew, args), {
        cwd,
        windowsHide: true,
        shell: false,
        windowsVerbatimArguments: true,
        stdio: ["ignore", "pipe", "pipe"],
      })
      : childProcess.spawn(gradlew, args, {
        cwd,
        windowsHide: true,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });

    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk: Buffer | string) => { stdout += String(chunk); });
    child.stderr?.on("data", (chunk: Buffer | string) => { stderr += String(chunk); });

    const timer = setTimeout(() => {
      child.kill();
      resolve({ output: "", warning: `${config}: gradlew timed out after 180s` });
    }, 180_000);

    child.on("error", err => {
      clearTimeout(timer);
      resolve({ output: "", warning: `${config}: ${err.message}` });
    });

    child.on("close", code => {
      clearTimeout(timer);
      const output = (stdout + stderr).trim();
      if (code !== 0 && code !== null && !output) {
        resolve({ output: "", warning: `${config}: gradlew exited with code ${code}` });
        return;
      }
      resolve({ output });
    });
  });
}

interface GradleConfigOutcome {
  packages: PackageRef[];
  warnings: string[];
  unresolved: Set<string>;
}

/** Merge one configuration's parsed tree into the running totals. */
function foldGradleConfigParsed(parsed: ParseResult, outcome: GradleConfigOutcome): void {
  outcome.packages.push(...parsed.packages);
  if (parsed.warnings?.length) outcome.warnings.push(...parsed.warnings);
  for (const u of parsed.unresolved ?? []) outcome.unresolved.add(u);
}

/** Dedupe and attach unresolved coordinates to the final result. */
function finishGradleResolution(
  allPackages: PackageRef[],
  warnings: string[],
  unresolvedSet: Set<string>,
): ParseResult {
  const packages = dedupeResolvedPackages(allPackages);
  const result: ParseResult = packages.length > 0
    ? { packages, warnings }
    : { packages: [], warnings };
  attachUnresolved(result, unresolvedSet, packages);
  return result;
}

/** Accumulators shared across gradle configuration resolutions. */
interface GradleResolutionAccumulators {
  packages: PackageRef[];
  warnings: string[];
  unresolved: Set<string>;
}

/** Run one gradle configuration, folding its resolved packages into the accumulators. */
function processOneGradleConfig(
  gradlew: string,
  config: string,
  cwd: string,
  isWin: boolean,
  filePath: string,
  acc: GradleResolutionAccumulators,
): void {
  let result;
  try {
    if (!isWin) {
      try { fs.chmodSync(gradlew, 0o750); } catch {}
    }
    result = runGradlewConfig(gradlew, config, cwd, isWin);
  } catch (err) {
    acc.warnings.push(`${config}: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }
  if (!result) {
    acc.warnings.push(`${config}: unexpected error`);
    return;
  }
  if (result.warning) acc.warnings.push(result.warning);
  if (!result.output) {
    acc.warnings.push(`${config}: empty output (may not exist in this project)`);
    return;
  }
  foldGradleConfigParsed(parseGradleTree(result.output, filePath), acc);
}

/** Resolve ALL dependencies via gradlew across multiple configurations */
function resolveViaGradlew(
  gradlew: string,
  filePath: string,
  cwd: string,
  configurations: readonly string[] = GRADLE_CONFIGURATIONS,
): ParseResult {
  const allPackages: PackageRef[] = [];
  const warnings: string[] = [];
  const unresolvedSet = new Set<string>();
  const isWin = os.platform() === "win32";
  const acc: GradleResolutionAccumulators = { packages: allPackages, warnings, unresolved: unresolvedSet };

  for (const config of configurations) {
    processOneGradleConfig(gradlew, config, cwd, isWin, filePath, acc);
  }

  return finishGradleResolution(allPackages, warnings, unresolvedSet);
}

async function resolveViaGradlewAsync(
  gradlew: string,
  filePath: string,
  cwd: string,
  onProgress?: (message: string) => void,
  configurations: readonly string[] = GRADLE_CONFIGURATIONS,
): Promise<ParseResult> {
  const allPackages: PackageRef[] = [];
  const warnings: string[] = [];
  const unresolvedSet = new Set<string>();
  const isWin = os.platform() === "win32";

  if (!isWin) {
    try { fs.chmodSync(gradlew, 0o750); } catch {}
  }

  for (const config of configurations) {
    onProgress?.(`Running gradlew ${config}...`);
    let result: { output: string; warning?: string } | null;
    try {
      result = await runGradlewConfigAsync(gradlew, config, cwd, isWin);
    } catch (err) {
      warnings.push(`${config}: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }

    if (!result) {
      warnings.push(`${config}: unexpected error`);
      continue;
    }

    if (result.warning) warnings.push(result.warning);
    if (!result.output) {
      warnings.push(`${config}: empty output (may not exist in this project)`);
      continue;
    }

    foldGradleConfigParsed(parseGradleTree(result.output, filePath), { packages: allPackages, warnings, unresolved: unresolvedSet });
  }

  return finishGradleResolution(allPackages, warnings, unresolvedSet);
}
/** Record coordinates that failed to resolve (skipping ones that resolved in another configuration). */
function attachUnresolved(
  result: ParseResult,
  unresolvedSet: Set<string>,
  resolved: PackageRef[],
): void {
  const resolvedNames = new Set(resolved.map(p => p.name.toLowerCase()));
  const unresolved = [...unresolvedSet].filter(u => !resolvedNames.has(u.split("@")[0]));
  if (unresolved.length === 0) return;
  result.unresolved = unresolved;
  for (const u of unresolved) {
    result.warnings.push(`Dependency failed to resolve (build may be broken): ${u}`);
  }
}

export async function parseBuildGradleAsync(
  filePath: string,
  onProgress?: (message: string) => void,
  options: ParseLockfileOptions = {},
): Promise<ParseResult> {
  const warnings: string[] = [];

  if (!fs.existsSync(filePath)) {
    warnings.push(`build.gradle not found: ${filePath}`);
    return { packages: [], warnings };
  }

  const dir = path.dirname(filePath);
  const gradlew = detectGradlew(dir);
  let gradleUnresolved: string[] | undefined;
  if (gradlew) {
    onProgress?.("Resolving Gradle dependency tree...");
    const result = await resolveViaGradlewAsync(
      gradlew,
      filePath,
      dir,
      onProgress,
      options.gradleConfigurations ?? GRADLE_CONFIGURATIONS,
    );
    gradleUnresolved = result.unresolved;
    if (result.packages.length > 0) {
      return result;
    }
    if (result.warnings.length > 0) {
      warnings.push(...result.warnings);
    }
  }

  onProgress?.("Parsing build.gradle...");
  const direct = parseBuildGradleDirect(filePath);
  if (gradleUnresolved && gradleUnresolved.length > 0) direct.unresolved = gradleUnresolved;
  return direct;
}

export async function parseLockfileAsync(
  dirPath: string,
  onProgress?: (message: string) => void,
  options: ParseLockfileOptions = {},
): Promise<ParseResult> {
  const allPackages: PackageRef[] = [];
  const warnings: string[] = [];
  const allUnresolved: string[] = [];
  const resolvedDir = path.resolve(dirPath);

  let foundAny = false;

  const flags = detectLockfiles(resolvedDir);
  if (flags.hasPomXml && (flags.hasBuildGradle || flags.hasBuildGradleKts)) {
    warnings.push(
      "Both pom.xml and Gradle build file present — scanning both (dual Java layouts).",
    );
  }

  for (const spec of LOCKFILES) {
    const filePath = path.join(resolvedDir, spec.filename);
    if (!fs.existsSync(filePath)) continue;
    if (shouldSkipSpec(spec, flags)) continue;

    foundAny = true;
    const result = spec.ecosystem === "gradle"
      ? await parseBuildGradleAsync(filePath, onProgress, options)
      : parseNonGradleSpec(spec, filePath, warnings);
    mergeParseResult(result, allPackages, warnings, allUnresolved);
  }

  if (appendDirectManifests(resolvedDir, allPackages, warnings)) foundAny = true;
  if (appendNestedJavaManifests(resolvedDir, allPackages, warnings, allUnresolved)) foundAny = true;

  if (!foundAny) {
    warnings.push(
      `No supported lockfile found in ${resolvedDir}. Supported: ${SUPPORTED_LOCKFILE_NAMES.join(", ")}`,
    );
  }

  const out: ParseResult = { packages: allPackages, warnings };
  if (allUnresolved.length > 0) out.unresolved = allUnresolved;
  return out;
}

interface GradleTreeState {
  pkgs: PackageRef[];
  unresolved: string[];
  seen: Set<string>;
  failedSeen: Set<string>;
}

/** Strip Gradle decoration from a tree-line version: "->" resolution, "{strictly x}" braces, "(...)" notes. */
function normalizeGradleTreeVersion(rawVersion: string): string {
  let version = rawVersion.includes('->') ? rawVersion.split('->').pop()!.trim() : rawVersion.trim();
  const braceOpen = version.indexOf("{");
  if (braceOpen >= 0) {
    const braceClose = version.indexOf("}", braceOpen + 1);
    if (braceClose > braceOpen) version = version.slice(braceOpen + 1, braceClose).trim().split(/\s+/).pop() || "";
  }
  const parenOpen = version.indexOf("(");
  const parenClose = version.lastIndexOf(")");
  if (parenOpen >= 0 && parenClose > parenOpen) {
    version = (version.slice(0, parenOpen) + version.slice(parenClose + 1)).trim();
  }
  return version;
}

function parseGradleTreeLine(line: string, filePath: string, state: GradleTreeState): void {
  const match = /^[|\s]*[+\\-]---\s+([\w.@-]+):([\w.@-]+):(.*)$/.exec(line);
  if (!match) return;
  const [, group, name, rawVersionPart] = match;
  const rawVersion = rawVersionPart.trimStart();
  // Gradle marks unresolvable deps with a trailing "FAILED" (e.g. "10.1.58 FAILED" or "1.2 -> 3.4 FAILED")
  if (/\sFAILED$/.test(rawVersion)) {
    const requested = rawVersion.slice(0, -"FAILED".length);
    const reqVersion = (requested.includes('->') ? requested.split('->').pop()! : requested).trim();
    const failedKey = `${group}:${name}`.toLowerCase();
    if (!state.failedSeen.has(failedKey)) {
      state.failedSeen.add(failedKey);
      state.unresolved.push(`${failedKey}@${reqVersion}`);
    }
    return;
  }
  // Take resolved version after -> arrow if present; unwrap "{strictly x}" and "(...)" notes.
  const version = normalizeGradleTreeVersion(rawVersion);
  if (!version || version.startsWith('(')) return;
  const key = `${group}:${name}`.toLowerCase();
  if (state.seen.has(key)) return;
  state.seen.add(key);
  state.pkgs.push({ ecosystem: 'maven', name: `${group}:${name}`, version, manifestPath: filePath });
}

/** Parse Gradle dependency tree output into PackageRef[] */
export function parseGradleTree(output: string, filePath: string): ParseResult {
  const state: GradleTreeState = { pkgs: [], unresolved: [], seen: new Set(), failedSeen: new Set() };
  for (const line of output.split(/\r?\n/)) {
    parseGradleTreeLine(line, filePath, state);
  }
  const result: ParseResult = { packages: state.pkgs, warnings: [] };
  if (state.unresolved.length > 0) result.unresolved = state.unresolved;
  return result;
}

/** Extract a quoted version ("..." or '...') directly after "group:name:"; null when absent or malformed. */
function quotedGradleVersion(rest: string, quote: '"' | "'"): string | null {
  if (!rest.startsWith(':' + quote)) return null;
  const end = rest.indexOf(quote, 2);
  if (end > 2 && !/\s/.test(rest.slice(2, end))) return rest.slice(2, end);
  return null;
}

function gradleDepVersion(
  coordText: string,
  rest: string,
  versionVars: Record<string, string>,
  content: string,
): string | null {
  // Quoted or ${var} version directly after "group:name:"
  const quoted = quotedGradleVersion(rest, '"') ?? quotedGradleVersion(rest, "'");
  if (quoted) return quoted;
  if (rest.startsWith(":${")) {
    const close = rest.indexOf("}", 3);
    if (close > 3) {
      return versionVars[rest.slice(3, close)] || null;
    }
  }
  // Concatenated version: "group:name:" + versionVar (Groovy/Kotlin string concatenation)
  const concat = /^:(["'])\s*\+\s*(\w+)/.exec(rest);
  if (concat) return versionVars[concat[2]] || null;
  // Look ahead for concatenated version
  const idx = content.indexOf(coordText);
  if (idx >= 0) {
    const afterDep = content.slice(idx, idx + 200);
    const concatMatch = /:"?(?:\$\{(\w+)\})?"/.exec(afterDep);
    if (concatMatch?.[1] && versionVars[concatMatch[1]]) return versionVars[concatMatch[1]];
  }
  return null;
}

/** Collect excluded group:module pairs from Groovy and Kotlin exclude syntaxes. */
function collectGradleExcludes(content: string): Set<string> {
  const excludes = new Set<string>();
  for (const em of content.matchAll(/exclude\s+group:\s*"([^"]+)",\s*module:\s*"([^"]+)"/g)) {
    excludes.add(em[1].toLowerCase() + ":" + em[2].toLowerCase());
  }
  // Kotlin form: normalize `group = "x", module = "y"` labels away before matching
  const normalized = content.replace(/(group|module)\s*=\s*/g, "");
  for (const em of normalized.matchAll(/exclude\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*\)/g)) {
    excludes.add(em[1].toLowerCase() + ":" + em[2].toLowerCase());
  }
  return excludes;
}

/** Record a gradle coordinate if it has a version and is not excluded or already seen. */
function recordGradleDep(
  packages: PackageRef[],
  filePath: string,
  group: string,
  name: string,
  version: string | null,
  excludes: Set<string>,
  seen: Set<string>,
): void {
  if (!version) return;
  if (excludes.has(group.toLowerCase() + ":" + name.toLowerCase())) return;
  const key = `${group}:${name}@${version}`;
  if (seen.has(key)) return;
  seen.add(key);
  packages.push({ ecosystem: "maven", name: `${group}:${name}`, version, manifestPath: filePath });
}

/** Whether a char may appear in a gradle coordinate group segment (like [\w.-]). */
function isGradleGroupChar(c: string): boolean {
  return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c === "_" || c === "." || c === "-";
}

/** Whether a char may appear in a gradle coordinate name segment (like [\w-]). */
function isGradleNameChar(c: string): boolean {
  return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c === "_" || c === "-";
}

/**
 * Find all `group:name` coordinates, equivalent to /([\w.-]+):([\w-]+)/g matchAll but linear.
 * restStart points just past the name (where a version would follow).
 */
function findGradleCoordinates(content: string): Array<{ group: string; name: string; restStart: number }> {
  const out: Array<{ group: string; name: string; restStart: number }> = [];
  let i = 0;
  while (i < content.length) {
    const colon = content.indexOf(":", i);
    if (colon < 0) break;
    let gs = colon - 1;
    while (gs >= 0 && isGradleGroupChar(content[gs])) gs--;
    // A match may start at the cursor even when the full run extends before it
    const group = content.slice(Math.max(gs + 1, i), colon);
    if (group.length > 0) {
      let ne = colon + 1;
      while (ne < content.length && isGradleNameChar(content[ne])) ne++;
      const name = content.slice(colon + 1, ne);
      if (name.length > 0) {
        out.push({ group, name, restStart: ne });
        i = ne;
        continue;
      }
    }
    i = colon + 1;
  }
  return out;
}

/** Direct parser for build.gradle (fallback when gradlew unavailable) */
export function parseBuildGradleDirect(filePath: string): ParseResult {
  const warnings: string[] = [];
  const content = fs.readFileSync(filePath, "utf-8");
  const packages: PackageRef[] = [];

  // Extract version variable definitions (Groovy def / Kotlin val)
  const versionVars: Record<string, string> = {};
  for (const m of content.matchAll(/(?:def|val)\s+(\w+_?(?:version|Version|VERSION)?)\s*=\s*"([^"]+)"/g)) {
    versionVars[m[1]] = m[2];
  }

  // Extract exclude blocks - skip excluded group:module pairs (Groovy + Kotlin)
  const excludes = collectGradleExcludes(content);

  // Find all dependency declarations with versions (linear scan; the regex form backtracks superlinearly)
  const seen = new Set<string>();

  for (const coord of findGradleCoordinates(content)) {
    const rest = content.slice(coord.restStart, coord.restStart + 200);
    recordGradleDep(packages, filePath, coord.group, coord.name, gradleDepVersion(`${coord.group}:${coord.name}`, rest, versionVars, content), excludes, seen);
  }
  // Fully-quoted coordinates: "group:name:version" / Kotlin $var interpolation
  const quotedPattern = /["'](\w[\w.@-]*):(\w[\w.-]*):([^"']+)["']/g;
  for (const match of content.matchAll(quotedPattern)) {
    let version: string | null = match[3].trim();
    if (version.startsWith("${")) {
      version = versionVars[version.slice(2, -1)] || null;
    } else if (version.startsWith("$")) {
      version = versionVars[version.slice(1)] || null;
    }
    recordGradleDep(packages, filePath, match[1].trim(), match[2].trim(), version, excludes, seen);
  }

  if (packages.length === 0) {
    warnings.push(`No resolvable dependencies found in ${filePath} (versions may be managed by BOM/platform)`);
  }

  return { packages, warnings };
}

/**
 * Parse multiple directories and merge results.
 */
export function parseMultipleLockfiles(dirPaths: string[]): ParseResult {
  const allPackages: PackageRef[] = [];
  const allWarnings: string[] = [];

  for (const dir of dirPaths) {
    const result = parseLockfile(dir);
    allPackages.push(...result.packages);
    allWarnings.push(...result.warnings);
  }

  return { packages: allPackages, warnings: allWarnings };
}
