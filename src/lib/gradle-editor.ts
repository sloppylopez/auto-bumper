/**
 * Gradle editor — Apply version bumps to build.gradle (Groovy DSL).
 *
 * Direct dependencies are rewritten in place (string literals, map-style
 * declarations, and `def xVersion = "..."` variables). Transitive
 * dependencies get a managed constraints block appended between
 * `// auto-bumper:begin` / `// auto-bumper:end` markers (idempotent on re-runs).
 *
 * Groovy and Kotlin DSL. Version catalogs in gradle/libs.versions.toml are bumped when present.
 */
import fs from "node:fs";
import path from "node:path";
import { compareMavenVersion } from "./matcher.ts";
import {
  isJackson3AnnotationsCoord,
  JACKSON3_ANNOTATIONS_COORD,
  JACKSON3_ANNOTATIONS_VERSION,
} from "./maven-renames.ts";
import {
  GRADLE_MARKER_BEGIN,
  GRADLE_MARKER_END,
  GRADLE_MARKERS,
} from "./brand.ts";

const MARKER_BEGIN = GRADLE_MARKER_BEGIN;
const MARKER_END = GRADLE_MARKER_END;

export interface BumpRequest {
  /** Maven coordinates: "group:artifact" */
  packageName: string;
  targetVersion: string;
  /** Advisory IDs used in the constraint `because` clause. */
  because: string[];
  /** Ecosystem of the bump ("maven" for Maven coordinates); present on --latest bumps that carry no advisory finding. */
  ecosystem?: string;
  /** True when the target is strictly below the installed version (user-approved downgrade). */
  isDowngrade?: boolean;
  /** Installed version reported by the scan, when known; used for minor-line policy decisions. */
  installedVersion?: string;
}

export interface RenameRequest {
  /** Old Maven coordinates */
  fromPackage: string;
  /** New Maven coordinates */
  toPackage: string;
  targetVersion: string;
  because: string[];
}

export interface ApplyRenamesOptions {
  /** When true, add configurations.all exclude for old Maven coords after rename. Default false. */
  excludeOldCoordinates?: boolean;
}

export interface ExcludeRequest {
  /** Maven coordinates: "group:artifact" */
  packageName: string;
}

export interface ApplyResult {
  /** Packages rewritten directly in the build file. */
  direct: string[];
  /** Packages pinned via the managed constraints block. */
  constrained: string[];
  /** Packages excluded from all configurations. */
  excluded: string[];
  /** Packages forced via resolutionStrategy (beats enforcedPlatform). */
  forced: string[];
  warnings: string[];
  /** Version actually written per package (managed pins may be raised to the declared version). */
  appliedTargets?: Record<string, string>;
  /** Managed pins dropped as stale against the platform BOM ("pkg@oldVersion"). */
  droppedStale?: string[];
}

/** A managed pin whose version is at or below what the platform BOM now manages. */
export interface StaleManagedPin {
  packageName: string;
  version: string;
  bomVersion: string;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

/**
 * Try to rewrite a direct dependency declaration in place.
 * Returns true when at least one occurrence was updated.
 * Mutates nothing — returns the new content via the result object.
 */
function rewriteDirect(
  content: string,
  bump: BumpRequest,
  warnings: string[],
): { content: string; changed: boolean } {
  const [group, artifact] = bump.packageName.split(":");
  if (!group || !artifact) {
    warnings.push(`${bump.packageName}: not a valid group:artifact coordinate`);
    return { content, changed: false };
  }

  const g = escapeRegex(group);
  const a = escapeRegex(artifact);
  let changed = false;

  // 1. String literal: "group:artifact:1.2.3" or 'group:artifact:1.2.3'
  //    Version part may not contain quotes/whitespace. Skip ${var} here (case 3).
  const literalRe = new RegExp(String.raw`((["'])${g}:${a}:)([^"'\s$][^"'\s]*)(\2)`, "g");
  content = content.replace(literalRe, (m, pre, _q, oldVer, post) => {
    if (compareMavenVersion(oldVer, bump.targetVersion) >= 0) return m;
    changed = true;
    return `${pre}${bump.targetVersion}${post}`;
  });

  // 2. Map style: group: 'g', name: 'a', version: '1.2.3'  or Kotlin group = "g"
  const mapRe = new RegExp(
    String.raw`(group\s*[:=]\s*(["'])${g}\2\s*,\s*name\s*[:=]\s*(["'])${a}\3\s*,\s*version\s*[:=]\s*(["']))([^"']+)(["'])`,
    "g",
  );
  content = content.replace(mapRe, (m, pre, _q1, _q2, _q3, oldVer, close) => {
    if (compareMavenVersion(oldVer, bump.targetVersion) >= 0) return m;
    changed = true;
    return `${pre}${bump.targetVersion}${close}`;
  });

  // 3. Version variable: "group:artifact:${someVersion}" -> bump `def someVersion = "..."`
  const varRefRe = new RegExp(String.raw`["']${g}:${a}:\$\{(\w+)\}["']`);
  const varRef = varRefRe.exec(content);
  if (varRef) {
    const varName = varRef[1];
  const defRe = new RegExp(String.raw`((?:def|val)\s+${escapeRegex(varName)}\s*=\s*["'])([^"']+)(["'])`);
    if (defRe.test(content)) {
      content = content.replace(defRe, (m, pre, oldVer, close) => {
        if (compareMavenVersion(oldVer, bump.targetVersion) >= 0) return m;
        changed = true;
        return `${pre}${bump.targetVersion}${close}`;
      });
      warnings.push(
        `${bump.packageName}: bumped via shared variable \${${varName}} — other deps using it move too`,
      );
    } else {
      warnings.push(
        `${bump.packageName}: version variable \${${varName}} not defined as \`def\` in this file — falling back to constraint`,
      );
    }
  }

  return { content, changed };
}

/** Rewrite dependency declarations from one Maven coordinate to another. */
function rewriteRename(
  content: string,
  rename: RenameRequest,
  warnings: string[],
): { content: string; changed: boolean } {
  const [fromGroup, fromArt] = rename.fromPackage.split(":");
  const [toGroup, toArt] = rename.toPackage.split(":");
  if (!fromGroup || !fromArt || !toGroup || !toArt) {
    warnings.push(`${rename.fromPackage}: invalid rename coordinates`);
    return { content, changed: false };
  }

  const bumpFrom: BumpRequest = {
    packageName: rename.fromPackage,
    targetVersion: rename.targetVersion,
    because: rename.because,
  };
  let { content: next, changed } = rewriteDirect(content, bumpFrom, warnings);

  const fromCoord = `${fromGroup}:${fromArt}`;
  const toCoord = `${toGroup}:${toArt}`;
  const g = escapeRegex(fromGroup);
  const a = escapeRegex(fromArt);

  // Bare coord without version: "group:artifact" or 'group:artifact'
  const bareRe = new RegExp(String.raw`(["'])${g}:${a}\1`, "g");
  next = next.replace(bareRe, (_m, quote) => {
    changed = true;
    return `${quote}${toCoord}${quote}`;
  });
  if (next.includes(fromCoord)) {
    next = next.split(fromCoord).join(toCoord);
    changed = true;
  }

  const bumpTo: BumpRequest = {
    packageName: rename.toPackage,
    targetVersion: rename.targetVersion,
    because: rename.because,
  };
  const afterSwap = rewriteDirect(next, bumpTo, warnings);
  next = afterSwap.content;
  if (afterSwap.changed) changed = true;

  return { content: next, changed };
}

function mavenArtifact(coord: string): string {
  const idx = coord.lastIndexOf(":");
  return idx >= 0 ? coord.slice(idx + 1) : coord;
}

/** After renames: fix BOM, managed constraints, and any remaining old coord strings. */
function finalizeCoordinateMigration(
  content: string,
  renames: RenameRequest[],
  warnings: string[],
  kotlin = false,
): string {
  if (renames.length === 0) return content;

  // Phase 1: Direct text replacements
  let next = applyDirectReplacements(content, renames);

  // Phase 2: Remove Jackson BOM if migrating to tools.jackson
  next = removeJacksonBom(next, renames, warnings);

  // Phase 3: Update managed dependency block
  const found = findManagedBlock(next);
  if (!found) return next;
  return updateManagedBlock(next, found, renames, kotlin);
}

/** Replace all occurrences of old coordinates with new ones */
function applyDirectReplacements(content: string, renames: RenameRequest[]): string {
  let next = content;
  const renameMap = new Map(renames.map(r => [r.fromPackage, r]));

  for (const [fromCoord, rename] of renameMap) {
    if (next.includes(fromCoord)) {
      next = next.split(fromCoord).join(rename.toPackage);
    }
  }

  return next;
}

/** Remove jackson-bom if any rename targets tools.jackson.core */
function removeJacksonBom(content: string, renames: RenameRequest[], warnings: string[]): string {
  const toToolsJackson = renames.some(r => r.toPackage.startsWith("tools.jackson.core"));
  if (!toToolsJackson) return content;

  const bomLine = /^[ \t]*mavenBom[ \t]+["']com\.fasterxml\.jackson:jackson-bom:[^"']+["'][ \t]*$/gm;
  const replaced = content.replace(bomLine, "");
  if (replaced !== content) {
    warnings.push(
      "Removed com.fasterxml.jackson:jackson-bom — incompatible with tools.jackson (Jackson 3).",
    );
  }
  return replaced;
}

/** Parse and update managed dependency block for renames */
function updateManagedBlock(
  content: string,
  found: { begin: number; end: number; endLen: number },
  renames: RenameRequest[],
  kotlin = false,
): string {
  const { begin, end, endLen } = found;
  const block = content.slice(begin, end + endLen);
  const entries = parseExistingConstraints(block);
  const excludeSet = parseExistingExcludes(block);
  const renameMap = new Map(renames.map(r => [r.fromPackage, r]));
  const toToolsJackson = renames.some(r => r.toPackage.startsWith("tools.jackson.core"));

  for (const rename of renames) {
    updateConstraintEntry(entries, rename);
  }

  if (toToolsJackson) {
    entries.delete("tools.jackson.core:jackson-annotations");
    for (const coord of entries.keys()) {
      if (coord === JACKSON3_ANNOTATIONS_COORD) continue;
      if (!coord.startsWith("com.fasterxml.jackson.core:")) continue;
      const art = mavenArtifact(coord);
      const toolsCoord = `tools.jackson.core:${art}`;
      if (renameMap.has(coord) || renames.some(r => r.toPackage === toolsCoord)) {
        entries.delete(coord);
      }
    }
  }

  const before = collapseTrailingNewlines(content.slice(0, begin));
  const after = content.slice(end + endLen).replace(/^\n+/, "\n");
  const newBlock = renderManagedBlock(entries, excludeSet, new Map(), kotlin);
  return `${before}${newBlock}${after}`;
}

/** Update managed-block constraints for a single rename */
function updateConstraintEntry(
  entries: Map<string, { version: string; because: string }>,
  rename: RenameRequest,
): void {
  const prev = entries.get(rename.fromPackage);
  entries.delete(rename.fromPackage);
  const existing = entries.get(rename.toPackage);

  const because = mergeBecauseReasons(prev?.because, rename.because);
  const mergedBecause = [...new Set(because)].join(", ");

  if (
    !existing
    || compareMavenVersion(rename.targetVersion, existing.version) > 0
  ) {
    entries.set(rename.toPackage, {
      version: rename.targetVersion,
      because: mergedBecause || existing?.because || "",
    });
  }
}

/** Merge 'because' reasons from previous entry and rename request */
function mergeBecauseReasons(
  prevBecause: string | undefined,
  renameBecause: string[],
): string[] {
  return [
    ...(prevBecause ? prevBecause.split(/,\s*/) : []),
    ...renameBecause,
  ].filter(Boolean);
}

/** Parse constraint entries out of an existing auto-bumper managed block. */
function parseExistingConstraints(block: string): Map<string, { version: string; because: string }> {
  const entries = new Map<string, { version: string; because: string }>();
  for (const line of block.split("\n")) {
    const m = /implementation\((["'])([^"']+)\1\)/.exec(line);
    if (!m) continue;
    const coord = m[2];
    const idx1 = coord.indexOf(":");
    if (idx1 <= 0) continue;
    const idx2 = coord.indexOf(":", idx1 + 1);
    if (idx2 <= idx1 + 1) continue;
    const pkg = `${coord.slice(0, idx1)}:${coord.slice(idx1 + 1, idx2)}`;
    const version = coord.slice(idx2 + 1);
    if (!version) continue;
    entries.set(pkg, { version, because: parseBecauseClause(line.slice(m[0].length)) });
  }
  return entries;
}

/** Extract the `because` reason from a rendered constraint suffix. */
function parseBecauseClause(suffix: string): string {
  const m = /^\s*\{\s*because\s+(["'])([^"']*)\1\s*\}/.exec(suffix);
  return m ? m[2] : "";
}

/** Parse exclude entries out of an existing auto-bumper managed block. */
function parseExistingExcludes(block: string): Set<string> {
  const excludes = new Set<string>();
  for (const line of block.split("\n")) {
    if (!line.includes("exclude")) continue;
    const gm = /group\s*[:=]\s*["']([^"']+)["']/.exec(line);
    const mm = /module\s*[:=]\s*["']([^"']+)["']/.exec(line);
    if (gm && mm) excludes.add(`${gm[1]}:${mm[1]}`);
  }
  return excludes;
}

/** Parse resolutionStrategy.force entries from an existing managed block. */
function parseExistingForces(block: string): Map<string, string> {
  const forces = new Map<string, string>();
  const forceRe = /force(?:\s*\(\s*|\s*)["']([^"':]+:[^"':]+):([^"']+)["']/g;
  for (const m of block.matchAll(forceRe)) {
    forces.set(m[1]!, m[2]!);
  }
  return forces;
}

/**
 * Managed pins (constraints and forces) whose version is at or below what the given BOM
 * manages — they would only force an older version than the current platform provides.
 * Pins named in `protectedPins` are never reported stale: dropping them would reintroduce
 * a vulnerability the BOM-managed version still carries (e.g. a downgrade escape when no
 * forward fix exists). Pure — unit-testable.
 */
export function findStaleManagedPins(
  content: string,
  bomManaged: ReadonlyMap<string, string>,
  protectedPins?: ReadonlySet<string>,
): StaleManagedPin[] {
  const found = findManagedBlock(content);
  if (!found) return [];
  const block = content.slice(found.begin, found.end + found.endLen);
  const stale: StaleManagedPin[] = [];
  const reported = new Set<string>();
  for (const [pkg, e] of parseExistingConstraints(block)) {
    if (protectedPins?.has(pkg)) continue;
    const bv = bomManaged.get(pkg);
    if (bv !== undefined && compareMavenVersion(bv, e.version) >= 0) {
      stale.push({ packageName: pkg, version: e.version, bomVersion: bv });
      reported.add(pkg);
    }
  }
  for (const [pkg, v] of parseExistingForces(block)) {
    if (reported.has(pkg)) continue; // same pin reported once when it is both a constraint and a force
    if (protectedPins?.has(pkg)) continue;
    const bv = bomManaged.get(pkg);
    if (bv !== undefined && compareMavenVersion(bv, v) >= 0) {
      stale.push({ packageName: pkg, version: v, bomVersion: bv });
    }
  }
  return stale;
}

/** Render the managed block (constraints + forces + excludes). */
function renderManagedBlock(
  entries: Map<string, { version: string; because: string }>,
  excludes: Set<string>,
  forces: Map<string, string> = new Map(),
  kotlin = false,
): string {
  const lines: string[] = [MARKER_BEGIN];

  if (entries.size > 0) {
    lines.push(...renderConstraintLines(entries, kotlin));
  }

  if (forces.size > 0 || excludes.size > 0) {
    lines.push(
      "configurations.all {",
      ...renderForceLines(forces, kotlin),
      ...renderExcludeLines(excludes, kotlin),
      "}",
    );
  }

  lines.push(MARKER_END);
  return lines.join("\n");
}

function renderConstraintLines(
  entries: Map<string, { version: string; because: string }>,
  kotlin: boolean,
): string[] {
  const lines = ["dependencies {", "    constraints {"];
  const sorted = [...entries.entries()].sort(([a], [b]) => a.localeCompare(b));
  for (const [pkg, { version, because }] of sorted) {
    lines.push(`        ${renderConstraintCall(pkg, version, because, kotlin)}`);
  }
  lines.push("    }", "}");
  return lines;
}

function renderConstraintCall(pkg: string, version: string, because: string, kotlin: boolean): string {
  const q = kotlin ? '"' : "'";
  let call = `implementation(${q}${pkg}:${version}${q})`;
  if (because) {
    call += kotlin ? ` { because("${because}") }` : ` { because '${because}' }`;
  }
  return call;
}

function renderForceLines(forces: Map<string, string>, kotlin: boolean): string[] {
  if (forces.size === 0) return [];
  const lines = ["    resolutionStrategy {"];
  for (const [pkg, version] of [...forces.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    lines.push(kotlin ? `        force("${pkg}:${version}")` : `        force '${pkg}:${version}'`);
  }
  lines.push("    }");
  return lines;
}

function renderExcludeLines(excludes: Set<string>, kotlin: boolean): string[] {
  const q = kotlin ? '"' : "'";
  const lines: string[] = [];
  for (const coord of [...excludes].sort((a, b) => a.localeCompare(b))) {
    const [group, module] = coord.split(":");
    lines.push(
      kotlin
        ? `    exclude(group = ${q}${group}${q}, module = ${q}${module}${q})`
        : `    exclude group: '${group}', module: '${module}'`,
    );
  }
  return lines;
}

/** Strip all trailing newlines from a string. */
function stripTrailingNewlines(s: string): string {
  let end = s.length;
  while (end > 0 && s.codePointAt(end - 1) === 10) end--;
  return s.slice(0, end);
}

/** Collapse one or more trailing newlines into exactly one. */
function collapseTrailingNewlines(s: string): string {
  const stripped = stripTrailingNewlines(s);
  return stripped.length === s.length ? s : `${stripped}\n`;
}

function findManagedBlock(content: string): { begin: number; end: number; endLen: number } | null {
  for (const { begin, end } of GRADLE_MARKERS) {
    const beginIdx = content.indexOf(begin);
    const endIdx = content.indexOf(end);
    if (beginIdx !== -1 && endIdx !== -1 && endIdx > beginIdx) {
      return { begin: beginIdx, end: endIdx, endLen: end.length };
    }
  }
  return null;
}

/**
 * Replace (or append) the auto-bumper managed block, merging new pins/excludes
 * with any existing ones. New pins win on version conflicts. When a BOM managed-version
 * map is given, existing pins at or below the BOM-managed version are dropped first —
 * they would only force an older version than the current platform provides.
 */
function upsertManagedBlock(
  content: string,
  pins: BumpRequest[],
  excludes: ExcludeRequest[],
  forces: BumpRequest[] = [],
  kotlin = false,
  bomManaged: ReadonlyMap<string, string> | null = null,
  droppedOut?: StaleManagedPin[],
  protectedPins?: ReadonlySet<string>,
): string {
  const found = findManagedBlock(content);

  let entries = new Map<string, { version: string; because: string }>();
  let excludeSet = new Set<string>();
  let forceMap = new Map<string, string>();
  let before = content;
  let after = "";
  const hasBlock = found !== null;

  if (hasBlock) {
    const { begin: beginIdx, end: endIdx, endLen } = found;
    const block = content.slice(beginIdx, endIdx + endLen);
    entries = parseExistingConstraints(block);
    excludeSet = parseExistingExcludes(block);
    forceMap = parseExistingForces(block);

    // Drop pins the platform BOM now manages at or above — they only force an older version.
    // Protected pins (vulnerability escapes) survive: the BOM-managed version is itself affected.
    if (bomManaged) {
      const droppedPkgs = new Set<string>();
      for (const [pkg, e] of [...entries]) {
        if (protectedPins?.has(pkg)) continue;
        const bv = bomManaged.get(pkg);
        if (bv !== undefined && compareMavenVersion(bv, e.version) >= 0) {
          entries.delete(pkg);
          droppedOut?.push({ packageName: pkg, version: e.version, bomVersion: bv });
          droppedPkgs.add(pkg);
        }
      }
      for (const [pkg, v] of [...forceMap]) {
        if (droppedPkgs.has(pkg)) {
          forceMap.delete(pkg); // already reported via the constraint entry — still drop the matching force
          continue;
        }
        if (protectedPins?.has(pkg)) continue;
        const bv = bomManaged.get(pkg);
        if (bv !== undefined && compareMavenVersion(bv, v) >= 0) {
          forceMap.delete(pkg);
          droppedOut?.push({ packageName: pkg, version: v, bomVersion: bv });
        }
      }
    }
    before = collapseTrailingNewlines(content.slice(0, beginIdx));
    after = content.slice(endIdx + endLen).replace(/^\n+/, "\n");
  }

  for (const pin of pins) {
    entries.set(pin.packageName, {
      version: pin.targetVersion,
      because: pin.because.join(", "),
    });
  }
  for (const ex of excludes) {
    excludeSet.add(ex.packageName);
    // An excluded package no longer needs a version constraint
    entries.delete(ex.packageName);
  }
  for (const force of forces) {
    const prev = forceMap.get(force.packageName);
    if (force.isDowngrade || !prev || compareMavenVersion(force.targetVersion, prev) > 0) {
      forceMap.set(force.packageName, force.targetVersion);
    }
  }

  if (entries.size === 0 && excludeSet.size === 0 && forceMap.size === 0) {
    // Fully cleaned block: remove it so re-runs stay idempotent.
    if (!found) return content;
    const afterClean = content.slice(found.end + found.endLen).replace(/^\n+/, "");
    return `${collapseTrailingNewlines(content.slice(0, found.begin))}${afterClean}`;
  }

  const block = renderManagedBlock(entries, excludeSet, forceMap, kotlin);
  if (hasBlock) {
    return `${before}${block}${after}`;
  }
  return `${stripTrailingNewlines(content)}\n\n${block}\n`;
}
/**
 * Remove auto-bumper pins (constraint + force) for a package from the managed block.
 * Used to roll back bumps whose target version cannot be resolved (e.g. yanked releases).
 * Returns true when the file was modified.
 */
export function removeManagedPin(filePath: string, packageName: string): boolean {
  const content = fs.readFileSync(filePath, "utf-8");
  const found = findManagedBlock(content);
  if (!found) return false;

  const { begin: beginIdx, end: endIdx, endLen } = found;
  const block = content.slice(beginIdx, endIdx + endLen);
  const entries = parseExistingConstraints(block);
  const excludeSet = parseExistingExcludes(block);
  const forceMap = parseExistingForces(block);

  let changed = false;
  if (entries.delete(packageName)) changed = true;
  if (forceMap.delete(packageName)) changed = true;
  if (!changed) return false;

  const before = collapseTrailingNewlines(content.slice(0, beginIdx));
  const after = content.slice(endIdx + endLen).replace(/^\n+/, "");
  if (entries.size === 0 && excludeSet.size === 0 && forceMap.size === 0) {
    fs.writeFileSync(filePath, `${before}${after}`);
    return true;
  }
  const next = renderManagedBlock(entries, excludeSet, forceMap, filePath.endsWith(".kts"));
  fs.writeFileSync(filePath, `${before}${next}\n${after}`);
  return true;
}

/**
 * Restore a direct declaration to an exact previous version (downgrade allowed).
 * Used when rolling back a bump whose target turned out unresolvable (e.g. yanked).
 * Rewrites literal, map-style, and `def var = "..."` declarations only where the
 * current value is exactly `toVersion`. Returns false when a declaration exists at
 * an unexpected version (file changed since apply); true otherwise (restored,
 * already at fromVersion, or no direct declaration present).
 */
export function restoreDeclaredVersion(
  filePath: string,
  packageName: string,
  fromVersion: string,
  toVersion: string,
): boolean {
  const [group, artifact] = packageName.split(":");
  if (!group || !artifact) return false;
  let content = fs.readFileSync(filePath, "utf-8");
  const g = escapeRegex(group);
  const a = escapeRegex(artifact);
  let changed = false;
  let unexpected = false;

  // String literal: "group:artifact:1.2.3"
  const literalRe = new RegExp(String.raw`((["'])${g}:${a}:)([^"'\s$][^"'\s]*)(\2)`, "g");
  content = content.replace(literalRe, (m, pre, _q, oldVer, post) => {
    if (oldVer === toVersion) {
      changed = true;
      return `${pre}${fromVersion}${post}`;
    }
    if (oldVer !== fromVersion) unexpected = true;
    return m;
  });

  // Map style: group: 'g', name: 'a', version: '1.2.3'
  const mapRe = new RegExp(
    String.raw`(group:\s*(["'])${g}\2\s*,\s*name:\s*(["'])${a}\3\s*,\s*version:\s*(["']))([^"']+)(["'])`,
    "g",
  );
  content = content.replace(mapRe, (m, pre, _q1, _q2, _q3, oldVer, close) => {
    if (oldVer === toVersion) {
      changed = true;
      return `${pre}${fromVersion}${close}`;
    }
    if (oldVer !== fromVersion) unexpected = true;
    return m;
  });

  // Version variable: "group:artifact:${someVersion}" -> def someVersion = "..."
  const varRefRe = new RegExp(String.raw`["']${g}:${a}:\$\{(\w+)\}["']`);
  const varRef = varRefRe.exec(content);
  if (varRef) {
    const defRe = new RegExp(String.raw`((?:def|val)\s+${escapeRegex(varRef[1])}\s*=\s*["'])([^"']+)(["'])`);
    const defM = defRe.exec(content);
    if (defM) {
      if (defM[2] === toVersion) {
        content = content.replace(defRe, (_m, pre, _old, close) => `${pre}${fromVersion}${close}`);
        changed = true;
      } else if (defM[2] !== fromVersion) {
        unexpected = true;
      }
    }
  }

  if (changed) fs.writeFileSync(filePath, content, "utf-8");
  return !unexpected;
}

/** True when a BOM or the Spring dependency plugin can downgrade an explicit version. */
export function hasEnforcedPlatform(content: string): boolean {
  return /(?:enforcedPlatform|platform)\s*\(/.test(content)
    || /mavenBom/.test(content)
    || /io\.spring\.dependency-management/.test(content)
    || /org\.springframework\.boot/.test(content);
}

/** A BOM/platform whose coordinate and version could be resolved from the build file. */
export interface GradlePlatform {
  group: string;
  artifact: string;
  version: string;
  /** Name of the gradle.properties property holding the version, when property-based. */
  property?: string;
}

/** Map of gradle.properties entries plus inline `def`/typed assignments in the build file. */
function readVersionProperties(buildFile: string): Map<string, string> {
  const props = new Map<string, string>();
  const content = fs.readFileSync(buildFile, "utf-8");
  for (const line of content.split(/\r?\n/)) {
    const m = /^\s*(?:(?:def|final)\s+)?(?:(?:String|int|Integer)\s+)?([A-Za-z_]\w*)\s*=\s*["']([^"']+)["']/.exec(line);
    if (m) props.set(m[1]!, m[2]!);
  }
  const propsPath = path.join(path.dirname(buildFile), "gradle.properties");
  if (fs.existsSync(propsPath)) {
    for (const line of fs.readFileSync(propsPath, "utf-8").split(/\r?\n/)) {
      if (line.trim().startsWith("#")) continue;
      const m = /^\s*([A-Za-z_][\w.-]*)\s*[=:]\s*(.+?)\s*$/.exec(line);
      if (m) props.set(m[1]!, m[2]!);
    }
  }
  return props;
}

/** Resolve a literal or `${var}` coordinate part against properties/inline defs. */
function resolveCoordPart(part: string, props: Map<string, string>): string | null {
  const vm = /^\$\{(\w+)\}$/.exec(part);
  if (vm) return props.get(vm[1]!) ?? null;
  return part.length > 0 ? part : null;
}

/** Detect the enforcedPlatform/platform BOM coordinate and resolve its group, artifact, and version. */
export function detectGradlePlatform(buildFile: string): GradlePlatform | null {
  let content: string;
  try {
    content = fs.readFileSync(buildFile, "utf-8");
  } catch {
    return null;
  }
  const m = /(?:enforcedPlatform|platform)\s*\(\s*["']([^"':]+):([^"':]+):([^"':]+)["']/.exec(content);
  if (!m) return null;
  const props = readVersionProperties(buildFile);
  const group = resolveCoordPart(m[1]!, props);
  const artifact = resolveCoordPart(m[2]!, props);
  const version = resolveCoordPart(m[3]!, props);
  if (!group || !artifact || !version) return null;
  const vm = /^\$\{(\w+)\}$/.exec(m[3]!);
  return { group, artifact, version, property: vm?.[1] };
}

/** First two numeric components of a Maven version as [major, minor]; missing parts become "0". */
export function versionLine(v: string): [string, string] {
  const m = /^(\d+)(?:\.(\d+))?/.exec(v);
  return [m?.[1] ?? "0", m?.[2] ?? "0"];
}

/** True when major or minor differs between two versions (qualifiers ignored). */
export function crossesMinorBoundary(from: string, to: string): boolean {
  const [fMaj, fMin] = versionLine(from);
  const [tMaj, tMin] = versionLine(to);
  return tMaj !== fMaj || tMin !== fMin;
}

/** True when two Maven groups are identical or one is a dotted prefix of the other. */
export function sameGroupFamily(a: string, b: string): boolean {
  if (a === b) return true;
  return a.startsWith(`${b}.`) || b.startsWith(`${a}.`);
}


/**
 * Rewrite the platform version (gradle.properties property or inline coordinate).
 * Quarkus: also syncs quarkusPluginVersion when it still equals the old platform version.
 */
export function bumpGradlePlatform(platform: GradlePlatform, buildFile: string, newVersion: string): boolean {
  const dir = path.dirname(buildFile);
  if (platform.property) {
    const propsPath = path.join(dir, "gradle.properties");
    if (!fs.existsSync(propsPath)) return false;
    let text = fs.readFileSync(propsPath, "utf-8");
    const lineRe = new RegExp(`^([ \\t]*${escapeRegex(platform.property)}[ \\t]*=[ \\t]*)${escapeRegex(platform.version)}\\s*$`, "m");
    if (!lineRe.test(text)) return false;
    text = text.replace(lineRe, `$1${newVersion}`);
    const pluginRe = /^([ \t]*quarkusPluginVersion[ \t]*=[ \t]*)(\S+)\s*$/m;
    const pm = pluginRe.exec(text);
    if (pm && pm[2] === platform.version) text = text.replace(pluginRe, `$1${newVersion}`);
    fs.writeFileSync(propsPath, text, "utf-8");
    return true;
  }
  let content = fs.readFileSync(buildFile, "utf-8");
  const coordRe = new RegExp(`(["'])${escapeRegex(platform.group)}:${escapeRegex(platform.artifact)}:${escapeRegex(platform.version)}\\1`);
  if (!coordRe.test(content)) return false;
  content = content.replace(coordRe, `$1${platform.group}:${platform.artifact}:${newVersion}$1`);
  fs.writeFileSync(buildFile, content, "utf-8");
  return true;
}

/**
 * Build force pins for bumps when enforcedPlatform/platform/mavenBom is present.
 * Includes siblings that share the same ${version} variable.
 */
export function collectForcePins(content: string, bumps: BumpRequest[]): BumpRequest[] {
  const forces = new Map<string, BumpRequest>();

  for (const bump of bumps) {
    forces.set(bump.packageName, bump);
    const [group, artifact] = bump.packageName.split(":");
    if (!group || !artifact) continue;
    if (bump.isDowngrade) continue; // never drag shared-variable siblings down with a downgrade

    const varRefRe = new RegExp(
      String.raw`["']${escapeRegex(group)}:${escapeRegex(artifact)}:\$\{(\w+)\}["']`,
    );
    const varRef = varRefRe.exec(content);
    if (!varRef) continue;

    const varName = varRef[1]!;
    const siblingRe = new RegExp(
      String.raw`["']([\w.-]+:[\w.-]+):\$\{${escapeRegex(varName)}\}["']`,
      "g",
    );
    for (const sm of content.matchAll(siblingRe)) {
      const coord = sm[1]!;
      const prev = forces.get(coord);
      if (!prev || compareMavenVersion(bump.targetVersion, prev.targetVersion) > 0) {
        forces.set(coord, {
          packageName: coord,
          targetVersion: bump.targetVersion,
          because: bump.because,
        });
      }
    }
  }

  return [...forces.values()];
}

/**
 * Highest version already declared for a package (literal, ${var} def, or managed pin).
 */
export function readDeclaredVersion(content: string, packageName: string): string | null {
  const [group, artifact] = packageName.split(":");
  if (!group || !artifact) return null;
  const g = escapeRegex(group);
  const a = escapeRegex(artifact);

  const varRef = new RegExp(String.raw`["']${g}:${a}:\$\{(\w+)\}["']`).exec(content);
  if (varRef?.[1]) {
    // Match: def varName = "...", String varName = "...", final String varName = "...", bare varName = "..."
    const varName = varRef[1];
    const defM = new RegExp(
      String.raw`(?:(?:def|final\s+)?(?:String|int|Integer|Long|Float|Double)\s+)?${escapeRegex(varName)}\s*=\s*["']([^"']+)["']`,
    ).exec(content);
    if (defM?.[1]) return defM[1];
  }

  const lit = new RegExp(String.raw`["']${g}:${a}:([^"'\s$][^"'\s]*)["']`).exec(content);
  if (lit?.[1]) return lit[1];

  const found = findManagedBlock(content);
  if (found) {
    const entries = parseExistingConstraints(content.slice(found.begin, found.end + found.endLen));
    return entries.get(packageName)?.version ?? null;
  }
  return null;
}

/** Raise bump target to max(OSV target, version already in the manifest). Downgrades keep their target. */
export function withEffectiveVersion(content: string, bump: BumpRequest): BumpRequest {
  if (bump.isDowngrade) return bump;
  const declared = readDeclaredVersion(content, bump.packageName);
  if (declared && compareMavenVersion(declared, bump.targetVersion) > 0) {
    return { ...bump, targetVersion: declared };
  }
  return bump;
}

/**
 * Merge classified pins with effective bump versions (upgrade stale lower constraints).
 */
function mergePinsToEffective(
  content: string,
  classifiedPins: BumpRequest[],
  effectiveBumps: BumpRequest[],
): BumpRequest[] {
  const pins = new Map<string, BumpRequest>();
  for (const p of classifiedPins) pins.set(p.packageName, p);

  const found = findManagedBlock(content);
  const existing = found
    ? parseExistingConstraints(content.slice(found.begin, found.end + found.endLen))
    : new Map<string, { version: string; because: string }>();

  for (const bump of effectiveBumps) {
    const prevPin = pins.get(bump.packageName);
    const prevConstraint = existing.get(bump.packageName);
    const prevVer = prevPin?.targetVersion ?? prevConstraint?.version;
    if (bump.isDowngrade || !prevVer || compareMavenVersion(bump.targetVersion, prevVer) > 0) {
      pins.set(bump.packageName, bump);
    }
  }

  return [...pins.values()];
}

function catalogFileFor(buildFile: string): string | null {
  const dir = path.dirname(buildFile);
  for (const rel of ["gradle/libs.versions.toml", "libs.versions.toml"]) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

function replaceTomlAlias(content: string, alias: string, version: string): string | null {
  const lines = content.split("\n");
  let inVersions = false;
  let changed = false;
  const aliasRe = new RegExp(String.raw`^(${escapeRegex(alias)}\s*=\s*")([^"]+)(")`);
  for (let i = 0; i < lines.length; i++) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(lines[i]);
    if (header) {
      inVersions = header[1].trim() === "versions";
      continue;
    }
    if (!inVersions) continue;
    const m = aliasRe.exec(lines[i]);
    if (!m) continue;
    if (compareMavenVersion(m[2], version) >= 0) return content;
    lines[i] = `${m[1]}${version}${m[3]}`;
    changed = true;
    break;
  }
  return changed ? lines.join("\n") : null;
}

/** Bump gradle/libs.versions.toml entries that point at these coordinates. */
function applyCatalogBumps(buildFile: string, bumps: BumpRequest[]): string[] {
  const tomlPath = catalogFileFor(buildFile);
  if (!tomlPath || bumps.length === 0) return [];
  let content = fs.readFileSync(tomlPath, "utf-8");
  const changed: string[] = [];
  for (const bump of bumps) {
    const [group, artifact] = bump.packageName.split(":");
    if (!group || !artifact) continue;
    const g = escapeRegex(group);
    const a = escapeRegex(artifact);
    const moduleRef = new RegExp(String.raw`module\s*=\s*["']${g}:${a}["'][^\n]*version\.ref\s*=\s*["']([^"']+)["']`);
    const refFirst = new RegExp(String.raw`version\.ref\s*=\s*["']([^"']+)["'][^\n]*module\s*=\s*["']${g}:${a}["']`);
    const ref = moduleRef.exec(content)?.[1] || refFirst.exec(content)?.[1];
    if (ref) {
      const next = replaceTomlAlias(content, ref, bump.targetVersion);
      if (next && next !== content) {
        content = next;
        changed.push(bump.packageName);
      }
      continue;
    }
    const inline = new RegExp(String.raw`(module\s*=\s*["']${g}:${a}["'][^\n]*version\s*=\s*")([^"]+)(")`);
    const hit = inline.exec(content);
    if (!hit) continue;
    if (compareMavenVersion(hit[2], bump.targetVersion) >= 0) continue;
    content = content.replace(inline, `$1${bump.targetVersion}$3`);
    changed.push(bump.packageName);
  }
  if (changed.length > 0) fs.writeFileSync(tomlPath, content);
  return changed;
}

/**
 * Apply bumps (and optional excludes) to build.gradle. Direct declarations
 * are rewritten in place; everything else is pinned through the managed
 * constraints block. When the file uses enforcedPlatform or mavenBom, also emit
 * resolutionStrategy.force so BOM cannot downgrade the fix. Caller is responsible
 * for backing up the file first. With a BOM managed-version map, existing pins at or below
 * the BOM-managed version are dropped (the BOM already covers them), and new pins that would
 * force a downgrade against the BOM are skipped — except pins in `protectedPins`, whose
 * removal would reintroduce a vulnerability the BOM-managed version still carries.
 */
export function applyBumps(
  filePath: string,
  bumps: BumpRequest[],
  excludes: ExcludeRequest[] = [],
  bomManaged: ReadonlyMap<string, string> | null = null,
  protectedPins?: ReadonlySet<string>,
): ApplyResult {
  const result: ApplyResult = { direct: [], constrained: [], excluded: [], forced: [], warnings: [] };

  const kotlin = filePath.endsWith(".kts");
  let content = fs.readFileSync(filePath, "utf-8");
  // Cleanup-only runs (no bumps/excludes) proceed when the BOM map marks existing pins stale.
  if (bumps.length === 0 && excludes.length === 0) {
    const stale = bomManaged ? findStaleManagedPins(content, bomManaged, protectedPins) : [];
    if (stale.length === 0) return result;
  }
  const catalogDirect = applyCatalogBumps(filePath, bumps);
  let remainingBumps = bumps.filter(b => !catalogDirect.includes(b.packageName));

  // BOM policy: a fix crossing the minor/major line of a BOM-managed artifact family is only safe
  // to force-pin when no sibling shares the installed version's release line — otherwise it
  // desynchronizes them (e.g. netty-codec-http 4.2.x inside a 4.1.x stack breaks the HTTP pipeline).
  // If the artifact belongs to the detected platform's family, bump the whole platform; if a
  // same-line sibling exists, skip and warn; independently-versioned families (e.g. guava) are pinned.
  const enforced = hasEnforcedPlatform(content);
  const platform = detectGradlePlatform(filePath);
  const appliedTargets: Record<string, string> = {};
  if (platform) {
    remainingBumps = routePlatformBumps(platform, filePath, content, remainingBumps, result, appliedTargets);
  }
  if (enforced) {
    remainingBumps = skipCrossMinorBomBumps(content, remainingBumps, result, platform, bomManaged);
  }
  if (bomManaged) {
    remainingBumps = filterBomCoveredBumps(remainingBumps, bomManaged, platform, result);
  }

  const classified = classifyBumps(remainingBumps, content);
  content = classified.content;

  const effectiveBumps = remainingBumps.map(b => withEffectiveVersion(content, b));
  const pins = mergePinsToEffective(content, classified.pinned, effectiveBumps);
  const forces = enforced ? collectForcePins(content, effectiveBumps) : [];
  if (forces.length > 0) {
    result.forced.push(...forces.map(f => f.packageName));
    result.warnings.push(
      `BOM or Spring dependency management detected — added resolutionStrategy.force for ${forces.length} package(s) so the BOM cannot downgrade fixes`,
    );
  }

  const dropped: StaleManagedPin[] = [];
  content = upsertManagedBlock(content, pins, excludes, forces, kotlin, bomManaged, dropped, protectedPins);
  if (dropped.length > 0) {
    result.droppedStale = dropped.map(d => `${d.packageName}@${d.version}`);
    for (const d of dropped) {
      result.warnings.push(`dropped stale pin ${d.packageName}@${d.version} — BOM now manages ${d.bomVersion}`);
    }
  }
  result.direct.push(...catalogDirect, ...classified.direct);
  result.constrained.push(...pins.map(p => p.packageName));
  for (const p of pins) appliedTargets[p.packageName] = p.targetVersion;
  if (Object.keys(appliedTargets).length > 0) result.appliedTargets = appliedTargets;
  result.warnings.push(...classified.warnings);
  emitSpringBootWarnings(result, pins);
  result.excluded = excludes.map(e => e.packageName);
  fs.writeFileSync(filePath, content, "utf-8");
  return result;
}

/**
 * Route BOM-managed family candidates that cross the platform's minor line to a whole-platform bump.
 * Returns the bumps left for the normal pin/force path; records applied/skipped entries on result.
 */
function routePlatformBumps(
  platform: GradlePlatform,
  buildFile: string,
  content: string,
  bumps: BumpRequest[],
  result: ApplyResult,
  appliedTargets: Record<string, string>,
): BumpRequest[] {
  const routed: BumpRequest[] = [];
  const rest: BumpRequest[] = [];
  for (const b of bumps) {
    const group = b.packageName.split(":")[0] || "";
    const crosses = !b.isDowngrade
      && group !== ""
      && sameGroupFamily(group, platform.group)
      && readDeclaredVersion(content, b.packageName) === null
      && compareMavenVersion(b.targetVersion, platform.version) > 0
      && crossesMinorBoundary(platform.version, b.targetVersion);
    if (crosses) routed.push(b); else rest.push(b);
  }
  if (routed.length === 0) return bumps;

  // Unified-version platforms (e.g. Quarkus): the fix target IS a platform version. Other BOMs
  // (e.g. Spring Boot, where artifact versions differ from BOM versions) cannot be mapped — skip.
  const platformMajor = /^(\d+)/.exec(platform.version)?.[1] ?? "";
  const mappable = routed.filter(b => (/^(\d+)/.exec(b.targetVersion)?.[1] ?? "") === platformMajor);
  if (mappable.length === 0) {
    for (const b of routed) result.warnings.push(
      `${b.packageName}: fix ${b.targetVersion} crosses the minor line managed by ${platform.group}:${platform.artifact} ${platform.version}, but artifact versions do not map to platform releases — skipped; bump the platform/BOM manually`,
    );
    return rest;
  }

  const target = mappable.reduce(
    (max, b) => compareMavenVersion(b.targetVersion, max) > 0 ? b.targetVersion : max,
    platform.version,
  );
  if (!bumpGradlePlatform(platform, buildFile, target)) {
    for (const b of routed) result.warnings.push(
      `${b.packageName}: could not rewrite ${platform.group}:${platform.artifact} version — skipped instead of force-pinning across the minor line`,
    );
    return rest;
  }

  for (const b of mappable) {
    result.direct.push(`${b.packageName}: via ${platform.group}:${platform.artifact} ${platform.version} → ${target}`);
    appliedTargets[b.packageName] = target;
  }
  for (const b of routed) {
    if (!mappable.includes(b)) result.warnings.push(
      `${b.packageName}: fix ${b.targetVersion} does not map to a ${platform.group}:${platform.artifact} release — skipped; bump the platform/BOM manually`,
    );
  }
  result.warnings.push(
    `Bumped ${platform.group}:${platform.artifact} ${platform.version} → ${target} — ${mappable.length} fix(es) cross the platform's minor line. Expect API changes; run a full build and tests.`,
  );

  // Family candidates now covered by the new platform version need no pin of their own.
  return rest.filter(b => {
    const group = b.packageName.split(":")[0] || "";
    return !(group !== "" && sameGroupFamily(group, platform.group) && compareMavenVersion(b.targetVersion, target) <= 0);
  });
}

/**
 * Force-pinning an artifact across a minor line desynchronizes it from siblings that share its
 * current release line (e.g. netty-codec-http 4.2.x inside a 4.1.x stack breaks the HTTP pipeline).
 * Skip such candidates (downgrades keep their compile-gated path) and warn to align the family or
 * bump via the BOM/platform. Runs on all enforced-BOM projects, after platform routing.
 *
 * Families whose siblings are versioned independently (e.g. guava: failureaccess 1.0.x,
 * listenablefuture 9999.0) have no shared line to desynchronize — their cross-line fixes are
 * pinned normally. Without a BOM-managed map the risk cannot be ruled out; skip conservatively.
 */
function skipCrossMinorBomBumps(
  content: string,
  bumps: BumpRequest[],
  result: ApplyResult,
  platform: GradlePlatform | null,
  bomManaged: ReadonlyMap<string, string> | null,
): BumpRequest[] {
  const kept: BumpRequest[] = [];
  for (const b of bumps) {
    if (!b.isDowngrade && readDeclaredVersion(content, b.packageName) === null
      && b.installedVersion !== undefined && crossesMinorBoundary(b.installedVersion, b.targetVersion)
      && hasLineSibling(b.packageName, b.installedVersion, bomManaged)) {
      const via = platform ? ` managed by ${platform.group}:${platform.artifact} ${platform.version}` : "";
      result.warnings.push(
        `${b.packageName}: BOM${via}-managed and ${b.installedVersion} → ${b.targetVersion} crosses a minor line — force-pinning would desynchronize its siblings; skipped. Align the whole family or bump via the BOM/platform`,
      );
      continue;
    }
    kept.push(b);
  }
  return kept;
}

/**
 * True when the BOM manages another artifact of the same group family on the installed version's
 * major.minor line — a sibling that tracks the shared release line and would fall behind a
 * cross-line force-pin. Without a BOM map, assume the risk (conservative skip).
 */
function hasLineSibling(pkg: string, installedVersion: string, bomManaged: ReadonlyMap<string, string> | null): boolean {
  if (!bomManaged) return true;
  const group = pkg.split(":")[0] ?? "";
  const [maj, min] = versionLine(installedVersion);
  for (const [other, v] of bomManaged) {
    if (other === pkg) continue;
    if (!sameGroupFamily(other.split(":")[0] ?? "", group)) continue;
    const [oMaj, oMin] = versionLine(v);
    if (oMaj === maj && oMin === min) return true;
  }
  return false;
}

/**
 * A non-downgrade pin whose target is at or below the version the platform BOM already manages
 * would force a downgrade of that artifact against the BOM — skip it; the BOM covers the fix.
 * Downgrades are user-approved and keep their path.
 */
function filterBomCoveredBumps(
  bumps: BumpRequest[],
  bomManaged: ReadonlyMap<string, string>,
  platform: GradlePlatform | null,
  result: ApplyResult,
): BumpRequest[] {
  const kept: BumpRequest[] = [];
  for (const b of bumps) {
    if (!b.isDowngrade) {
      const bv = bomManaged.get(b.packageName);
      if (bv !== undefined && compareMavenVersion(bv, b.targetVersion) >= 0) {
        result.warnings.push(
          `${b.packageName}: target ${b.targetVersion} is at or below ${platform ? `${platform.group}:${platform.artifact} ${platform.version}` : "BOM"}-managed ${bv} — pin would force a downgrade; skipped`,
        );
        continue;
      }
    }
    kept.push(b);
  }
  return kept;
}

/** Try each bump against the file; classify as direct or constrained */
function classifyBumps(bumps: BumpRequest[], initialContent: string): { content: string; pinned: BumpRequest[]; direct: string[]; constrained: string[]; warnings: string[] } {
  let content = initialContent;
  const pinned: BumpRequest[] = [];
  const direct: string[] = [];
  const constrained: string[] = [];
  const warnings: string[] = [];

  for (const bump of bumps) {
    const { content: next, changed } = rewriteDirect(content, bump, warnings);
    content = next;
    if (changed) {
      direct.push(bump.packageName);
      continue;
    }
    if (!shouldPinBump(content, bump)) continue;
    pinned.push(bump);
    constrained.push(bump.packageName);
  }

  return { content, pinned, direct, constrained, warnings };
}

/** Check if a bump should be added as a managed constraint */
function shouldPinBump(content: string, bump: BumpRequest): boolean {
  const found = findManagedBlock(content);
  if (!found) return true;
  const existing = parseExistingConstraints(content.slice(found.begin, found.end + found.endLen));
  const prev = existing.get(bump.packageName);
  if (prev && compareMavenVersion(prev.version, bump.targetVersion) >= 0) return false;
  return true;
}

/** Emit warnings for packages pinned under Spring Boot groups */
function emitSpringBootWarnings(result: ApplyResult, pins: Array<{ packageName: string }>) {
  for (const pin of pins) {
    const group = pin.packageName.split(":")[0] || "";
    if (isSpringGroup(group)) {
      result.warnings.push(
        `${pin.packageName} pinned via managed constraints — prefer bumping Spring Boot plugin/BOM in build.gradle.`,
      );
    }
  }
}

function isSpringGroup(group: string): boolean {
  return group === "org.springframework.boot" || group === "org.springframework";
}

/** Apply Maven coordinate renames (group/artifact migration) in build.gradle. */
export function applyRenames(
  filePath: string,
  renames: RenameRequest[],
  options: ApplyRenamesOptions = {},
): ApplyResult {
  const result: ApplyResult = { direct: [], constrained: [], excluded: [], forced: [], warnings: [] };
  if (renames.length === 0) return result;

  const kotlin = filePath.endsWith(".kts");
  const migrationRenames = renames.filter(r => !isJackson3AnnotationsCoord(r.fromPackage));
  let content = fs.readFileSync(filePath, "utf-8");
  const contentBefore = content;
  const isJackson3Migration = migrationRenames.some(r => r.toPackage.startsWith("tools.jackson.core"));

  // Phase 1: classify each rename as direct or constrained
  const { content: rewritten, pins, direct, constrained } = classifyRenames(migrationRenames, content, result.warnings);
  content = rewritten;
  result.direct.push(...direct);
  result.constrained.push(...constrained);

  // Phase 2: resolve Jackson 3 exclusions or standard excludes
  const finalPinsAndExcludes = resolveExcludesAndPins(isJackson3Migration, migrationRenames, pins, options);

  // Phase 3: finalize and write
  emitSpringBootWarnings(result, finalPinsAndExcludes.pins);
  content = finalizeCoordinateMigration(content, migrationRenames, result.warnings, kotlin);
  content = upsertManagedBlock(content, finalPinsAndExcludes.pins, finalPinsAndExcludes.excludes, [], kotlin);
  result.excluded = finalPinsAndExcludes.excludes.map(e => e.packageName);

  if (content !== contentBefore) {
    fs.writeFileSync(filePath, content, "utf-8");
  }

  if (isJackson3Migration) {
    result.warnings.push(
      "Jackson 3 migration: excluding legacy jackson-core/databind, pinning tools.jackson, keeping com.fasterxml.jackson.core:jackson-annotations 2.x.",
    );
  } else if (!options.excludeOldCoordinates && renames.length > 0) {
    const coords = renames.map(r => r.fromPackage).join(", ");
    result.warnings.push(
      `Rename applied without global exclude for old coords (${coords}). Transitive com.fasterxml copies may remain — scan again after gradlew build.`,
    );
  }

  return result;
}

interface ClassifyRenamesResult {
  content: string;
  pins: BumpRequest[];
  direct: string[];
  constrained: string[];
}

/** Try each rename against the file; classify as direct or constrained */
function classifyRenames(
  renames: RenameRequest[],
  initialContent: string,
  warnings: string[],
): ClassifyRenamesResult {
  let content = initialContent;
  const pins: BumpRequest[] = [];
  const direct: string[] = [];
  const constrained: string[] = [];

  for (const rename of renames) {
    const { content: next, changed } = rewriteRename(content, rename, warnings);
    content = next;
    const label = `${rename.fromPackage} -> ${rename.toPackage}`;
    if (changed) {
      direct.push(label);
      continue;
    }
    if (!shouldPinRename(content, rename)) continue;
    pins.push({
      packageName: rename.toPackage,
      targetVersion: rename.targetVersion,
      because: rename.because,
    });
    constrained.push(label);
  }

  return { content, pins, direct, constrained };
}

/** Check if a rename should be added as a managed constraint */
function shouldPinRename(content: string, rename: RenameRequest): boolean {
  const found = findManagedBlock(content);
  if (!found) return true;
  const existing = parseExistingConstraints(content.slice(found.begin, found.end + found.endLen));
  const prev = existing.get(rename.toPackage);
  if (prev && compareMavenVersion(prev.version, rename.targetVersion) >= 0) return false;
  return true;
}

interface ExcludesAndPins {
  pins: BumpRequest[];
  excludes: ExcludeRequest[];
}

/** Resolve Jackson 3 exclusions/pins or standard excludes based on options */
function resolveExcludesAndPins(
  isJackson3: boolean,
  renames: RenameRequest[],
  basePins: BumpRequest[],
  options: ApplyRenamesOptions,
): ExcludesAndPins {
  if (isJackson3) {
    return resolveJackson3Excludes(renames, basePins);
  }
  const excludes = options.excludeOldCoordinates
    ? renames.map(r => ({ packageName: r.fromPackage }))
    : [];
  return { pins: basePins, excludes };
}

/** Special handling for Jackson → Jackson 3 migration */
function resolveJackson3Excludes(renames: RenameRequest[], basePins: BumpRequest[]): ExcludesAndPins {
  const excludes: ExcludeRequest[] = [];
  const pins: BumpRequest[] = [...basePins];

  for (const rename of renames) {
    if (!excludes.some(e => e.packageName === rename.fromPackage)) {
      excludes.push({ packageName: rename.fromPackage });
    }
    if (!pins.some(p => p.packageName === rename.toPackage)) {
      pins.push({
        packageName: rename.toPackage,
        targetVersion: rename.targetVersion,
        because: rename.because,
      });
    }
  }

  const filteredExcludes = excludes.filter(e => !isJackson3AnnotationsCoord(e.packageName));
  const cleanedPins = pins.filter(p => p.packageName !== "tools.jackson.core:jackson-annotations");

  if (!cleanedPins.some(p => p.packageName === JACKSON3_ANNOTATIONS_COORD)) {
    cleanedPins.push({
      packageName: JACKSON3_ANNOTATIONS_COORD,
      targetVersion: JACKSON3_ANNOTATIONS_VERSION,
      because: ["Jackson 3 uses jackson-annotations 2.x for com.fasterxml.jackson.annotation"],
    });
  }

  return { pins: cleanedPins, excludes: filteredExcludes };
}

export { backupPath, discardBackup } from "./backup.ts";
export { backupFile as backupBuildGradle, restoreFile as restoreBuildGradle } from "./backup.ts";
